#include "net_share_link.h"

#include <chrono>
#include <cstring>

#include "host_log.h"
#include "net_link.h"
#include "net_share_host.h"

static double seconds_now()
{
    std::chrono::steady_clock::duration since = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration<double>(since).count();
}

static bool same_address(const NetAddress* a, const NetAddress* b)
{
    return a->port == b->port && std::memcmp(a->ip, b->ip, sizeof(a->ip)) == 0;
}

// With the lock held: a discovery reply, kept (or refreshed) in `found`.
static void on_discovered(NetShareLink* link, const NetEvent* event, double now)
{
    // This device's own listener answers too (our socket is another one):
    // a device doesn't list itself.
    if (event->discovered.key_id_known &&
        std::memcmp(event->discovered.key_id, link->client.our_key, NET_DISCOVERY_KEY_ID_SIZE) == 0)
    {
        return;
    }
    NetAddress address = event->address;
    address.port = event->discovered.port;
    NetShareLinkFound* slot = nullptr;
    for (uint32_t i = 0; i < link->found_count && slot == nullptr; i++)
    {
        if (same_address(&link->found[i].address, &address))
        {
            slot = &link->found[i];
        }
    }
    if (slot == nullptr)
    {
        if (link->found_count == NET_SHARE_LINK_FOUND_MAX)
        {
            return;
        }
        slot = &link->found[link->found_count];
        link->found_count++;
        slot->address = address;
    }
    // A version 3 device also sends a version 2 reply: the one that comes
    // second must not wipe the key_id the first one gave (same name: same
    // device; another name: another device at this address).
    bool same_device = slot->name == event->discovered.name;
    if (event->discovered.key_id_known || !same_device)
    {
        std::memcpy(slot->key_id, event->discovered.key_id, sizeof(slot->key_id));
        slot->key_id_known = event->discovered.key_id_known;
    }
    slot->name = event->discovered.name;
    slot->kind = event->discovered.kind < NET_APP_KIND_COUNT ? static_cast<NetAppKind>(event->discovered.kind)
                                                                 : NetAppKind::piccolo;
    slot->offers = event->discovered.offers & NET_CAPS_ALL;
    slot->offers_known = event->discovered.version >= 2;
    slot->signed_build = event->discovered.signed_build;
    slot->seen_at = now;
}

// With the lock held: asks the LAN now and then, keeps who answers.
static void discover(NetShareLink* link, double now)
{
    if (!link->discovery_ready)
    {
        return;
    }
    if (now >= link->next_discovery)
    {
        link->next_discovery = now + NET_SHARE_LINK_DISCOVERY_SECONDS;
        net_host_discover_devices(&link->discovery);
    }
    NetEvent event;
    while (net_host_poll(&link->discovery, &event))
    {
        if (event.type == NetEventType::discovered)
        {
            on_discovered(link, &event, now);
        }
    }
    uint32_t kept = 0;
    for (uint32_t i = 0; i < link->found_count; i++)
    {
        if (now - link->found[i].seen_at <= NET_SHARE_LINK_FOUND_SECONDS)
        {
            if (kept != i)
            {
                link->found[kept] = link->found[i];
            }
            kept++;
        }
    }
    link->found_count = kept;
}

// With the lock held: the connection's events, then what the copies send.
static void poll_client(NetShareLink* link)
{
    NetClientEvent event;
    while (net_client_poll(&link->client, &event))
    {
        switch (event.type)
        {
        case NetClientEventType::ready:
            link->state = NetShareLinkState::ready;
            link->refusal = NetClientRefusal::none;
            link->newly_paired = event.newly_paired;
            link->code_needed = false;
            host_log(LogLevel::info, "Network: share: connected to %s", link->client.host.name);
            break;
        case NetClientEventType::code_needed:
            link->code_needed = true;
            link->code_retry = event.retry;
            break;
        case NetClientEventType::refused:
        case NetClientEventType::closed:
            net_share_client_disconnected(&link->share);
            link->state = NetShareLinkState::idle;
            link->code_needed = false;
            if (link->closing)
            {
                link->closing = false;   // ours: not a failure
                link->refusal = NetClientRefusal::none;
            }
            else
            {
                link->refusal = event.type == NetClientEventType::refused ? event.refusal : NetClientRefusal::connection;
            }
            break;
        case NetClientEventType::message:
            net_share_client_handle(&link->share, event.data, event.size);
            break;
        default:
            break;
        }
    }
    // Through the beacon: once its addresses are known (run() looks them up).
    bool waiting = link->connect_beacon && !link->resolved;
    if (link->connect_pending && link->client.state == NetClientState::idle && !waiting)
    {
        link->connect_pending = false;
        link->closing = false;
        link->code_needed = false;
        link->code_retry = false;
        bool started = false;
        if (!link->connect_beacon)
        {
            started = net_client_connect(&link->client, link->connect_address, link->connect_pair);
        }
        else
        {
            const char* name = link->connect_beacon_name.c_str();
            net_client_set_signal(&link->client, net_signal_url(name).c_str(), net_signal_stun(name).c_str());
            if (link->connect_device >= 0)
            {
                started = net_client_connect_beacon(&link->client, link->servers, link->server_count,
                                                    static_cast<uint32_t>(link->connect_device));
            }
            else
            {
                // The code our user typed, shown by the other device in
                // GENERATE PAIRING CODE, which waits in the code's pairing room.
                started = net_client_pair_beacon(&link->client, link->servers, link->server_count,
                                                 link->connect_code.c_str());
            }
            host_log(LogLevel::info, "Network: share: %s through %s (%u address(es))",
                     link->connect_device >= 0 ? "connecting" : "pairing", name,
                     static_cast<unsigned>(link->server_count));
        }
        link->state = started ? NetShareLinkState::connecting : NetShareLinkState::idle;
        link->refusal = started ? NetClientRefusal::none : NetClientRefusal::connection;
    }
    if (link->state != NetShareLinkState::ready)
    {
        return;
    }
    for (;;)
    {
        bool may_send = net_client_pending(&link->client) < NET_SHARE_HOST_PENDING;
        NetChannel channel = NetChannel::control;
        size_t size = net_share_client_take(&link->share, may_send, link->out.data(), link->out.size(), &channel);
        if (size == 0)
        {
            break;
        }
        if (!net_client_send(&link->client, channel, link->out.data(), size))
        {
            net_share_client_cancel(&link->share);   // the host can't take files (an older build)
            break;
        }
    }
}

static void run(NetShareLink* link)
{
    for (;;)
    {
        link->lock.lock();
        if (!link->running)
        {
            link->lock.unlock();
            return;
        }
        if (link->resolve_wanted)
        {
            // The beacon's name, looked up without the lock: DNS may block,
            // and the frontend's calls mustn't wait for it.
            link->resolve_wanted = false;
            std::string name = link->connect_beacon_name;
            link->lock.unlock();
            NetAddress servers[NET_BEACON_MAX_SERVERS];
            uint32_t count = net_address_resolve(name.c_str(), NET_BEACON_DEFAULT_PORT, servers);
            link->lock.lock();
            if (!link->resolve_wanted && link->connect_beacon_name == name)
            {
                // (A newer connect asked meanwhile looks up its own.)
                for (uint32_t i = 0; i < count; i++)
                {
                    link->servers[i] = servers[i];
                }
                link->server_count = count;
                link->resolved = true;
            }
        }
        double now = seconds_now();
        if (!link->beacon.empty() && now >= link->presence_next)
        {
            link->presence_next = now + NET_SHARE_LINK_PRESENCE_SECONDS;
            if (link->presence_name != link->beacon)
            {
                std::string name = link->beacon;   // looked up without the lock (DNS blocks)
                link->lock.unlock();
                NetAddress servers[NET_BEACON_MAX_SERVERS];
                uint32_t count = net_address_resolve(name.c_str(), NET_BEACON_DEFAULT_PORT, servers);
                link->lock.lock();
                link->presence_name = name;
                link->presence_count = count;
                for (uint32_t i = 0; i < count; i++)
                {
                    link->presence_servers[i] = servers[i];
                }
            }
            net_client_ask_presence(&link->client, link->presence_servers, link->presence_count);
        }
        poll_client(link);
        discover(link, now);
        link->lock.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

bool net_share_link_start(NetShareLink* link, const NetKeypair* identity, const NetDeviceInfo* info,
                          const char* devices_path)
{
    if (link->running)
    {
        return true;
    }
    if (!net_client_create(&link->client, identity, info, devices_path))
    {
        net_client_destroy(&link->client);
        return false;
    }
    link->discovery_ready = net_host_create_client(&link->discovery);
    link->out.assign(NET_LINK_MAX_PAYLOAD, 0);
    net_share_client_start(&link->share, &link->folders);
    link->state = NetShareLinkState::idle;
    link->refusal = NetClientRefusal::none;
    link->found_count = 0;
    link->next_discovery = 0.0;
    link->running = true;
    link->thread = std::thread(run, link);
    return true;
}

void net_share_link_stop(NetShareLink* link)
{
    if (!link->thread.joinable())
    {
        return;
    }
    // Close politely first and let the thread see it through (briefly): the
    // host frees our slot now instead of when its timeout notices.
    link->lock.lock();
    link->connect_pending = false;
    if (link->client.state != NetClientState::idle && !link->closing)
    {
        net_client_close(&link->client);
        link->closing = true;
    }
    link->lock.unlock();
    for (int i = 0; i < 500; i++)
    {
        link->lock.lock();
        bool idle = link->client.state == NetClientState::idle;
        link->lock.unlock();
        if (idle)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    link->lock.lock();
    link->running = false;
    link->lock.unlock();
    link->thread.join();
    net_share_client_disconnected(&link->share);
    net_share_client_stop(&link->share);
    net_client_close(&link->client);
    net_client_destroy(&link->client);
    if (link->discovery_ready)
    {
        net_host_destroy(&link->discovery);
        link->discovery_ready = false;
    }
    link->state = NetShareLinkState::off;
}

bool net_share_link_started(const NetShareLink* link)
{
    return link->thread.joinable();
}

void net_share_link_set_folders(NetShareLink* link, const NetShareFolderPaths* paths)
{
    std::lock_guard<std::mutex> guard(link->lock);
    net_share_set_folders(&link->folders, paths);
}

bool net_share_link_connect(NetShareLink* link, NetAddress address, bool pair)
{
    std::lock_guard<std::mutex> guard(link->lock);
    if (!link->running)
    {
        return false;
    }
    if (link->client.state != NetClientState::idle)
    {
        if (!link->closing)
        {
            net_client_close(&link->client);
            link->closing = true;
        }
        net_share_client_disconnected(&link->share);
    }
    // Started by the thread once the client is idle (at its next poll, or
    // once the old connection is gone).
    link->newly_paired = false;
    link->connect_pending = true;
    link->connect_beacon = false;
    link->connect_device = -1;
    link->connect_address = address;
    link->connect_pair = pair;
    link->connect_code.clear();
    link->state = NetShareLinkState::connecting;
    link->refusal = NetClientRefusal::none;
    return true;
}

// With the lock held: closes what runs, then a connect through `beacon`
// once its addresses are looked up (the thread does both).
static void connect_through_beacon(NetShareLink* link, const std::string* beacon)
{
    if (link->client.state != NetClientState::idle)
    {
        if (!link->closing)
        {
            net_client_close(&link->client);
            link->closing = true;
        }
        net_share_client_disconnected(&link->share);
    }
    link->connect_pending = true;
    link->connect_beacon = true;
    link->connect_beacon_name = *beacon;
    link->resolve_wanted = true;
    link->resolved = false;
    link->server_count = 0;
    link->state = NetShareLinkState::connecting;
    link->refusal = NetClientRefusal::none;
}

void net_share_link_set_beacon(NetShareLink* link, const char* server)
{
    std::lock_guard<std::mutex> guard(link->lock);
    link->beacon = server != nullptr ? server : "";
}

bool net_share_link_connect_paired(NetShareLink* link, uint32_t device)
{
    std::lock_guard<std::mutex> guard(link->lock);
    if (!link->running || link->beacon.empty() || device >= link->client.trust.devices.size())
    {
        return false;
    }
    link->connect_device = static_cast<int32_t>(device);
    link->connect_code.clear();
    connect_through_beacon(link, &link->beacon);
    return true;
}

bool net_share_link_pair_beacon(NetShareLink* link, const char* code)
{
    std::lock_guard<std::mutex> guard(link->lock);
    if (!link->running || link->beacon.empty() || code == nullptr || !net_pair_code_valid(code))
    {
        return false;
    }
    link->connect_device = -1;
    link->connect_code = code;
    connect_through_beacon(link, &link->beacon);
    return true;
}

void net_share_link_disconnect(NetShareLink* link)
{
    std::lock_guard<std::mutex> guard(link->lock);
    link->connect_pending = false;
    if (link->running && link->client.state != NetClientState::idle && !link->closing)
    {
        net_client_close(&link->client);
        link->closing = true;
    }
    net_share_client_disconnected(&link->share);
    link->state = link->running ? NetShareLinkState::idle : NetShareLinkState::off;
    link->refusal = NetClientRefusal::none;
}

void net_share_link_status(NetShareLink* link, NetShareLinkStatus* status)
{
    std::lock_guard<std::mutex> guard(link->lock);
    bool ready = link->state == NetShareLinkState::ready;
    status->newly_paired = ready && link->newly_paired;
    std::memcpy(status->host_key, link->client.host_key, NET_KEY_SIZE);
    if (!ready)
    {
        std::memset(status->host_key, 0, NET_KEY_SIZE);
    }
    status->state = link->state;
    status->refusal = link->refusal;
    status->caps = ready ? link->client.caps : 0;
    status->code_needed = link->state == NetShareLinkState::connecting && link->code_needed;
    status->code_retry = status->code_needed && link->code_retry;
    status->host_name = ready || status->code_needed ? link->client.host.name : "";
    status->host_kind = link->client.host.kind;
    status->host_offers = link->client.host.offers;
    status->host_uses = link->client.host.uses;
    status->host_signed = link->client.host_signed;
    status->checking_code = link->state == NetShareLinkState::connecting &&
                            (link->client.state == NetClientState::pairing ||
                             link->client.state == NetClientState::confirming);
    status->device = ready ? link->client.device : -1;
    status->paired_online = link->client.presence_answered &&
                                    link->client.online.size() == link->client.trust.devices.size()
                                ? link->client.online
                                : std::vector<uint8_t>();
    status->found.clear();
    for (uint32_t i = 0; i < link->found_count; i++)
    {
        NetShareLinkFound found = link->found[i];
        // Paired by key, never by name (every install may be called PICCOLO).
        found.paired = found.key_id_known && net_trust_has_key_id(&link->client.trust, found.key_id);
        status->found.push_back(found);
    }
    status->paired.clear();
    for (size_t i = 0; i < link->client.trust.devices.size(); i++)
    {
        status->paired.push_back(link->client.trust.devices[i].name);
    }
    status->paired_devices = link->client.trust.devices;
}

void net_share_link_list(NetShareLink* link, const char* path)
{
    std::lock_guard<std::mutex> guard(link->lock);
    net_share_client_list(&link->share, path);
}

bool net_share_link_listing(NetShareLink* link, std::string* path, NetShareStatus* status,
                            std::vector<NetShareEntry>* entries)
{
    std::lock_guard<std::mutex> guard(link->lock);
    if (!net_share_client_listing(&link->share, path, status, entries))
    {
        return false;
    }
    link->share.list_done = false;   // handed over once
    return true;
}

uint32_t net_share_link_copy(NetShareLink* link, bool to_remote, const char* local, const char* remote, uint64_t size,
                             uint64_t mtime, uint8_t flags)
{
    std::lock_guard<std::mutex> guard(link->lock);
    return net_share_client_copy(&link->share, to_remote, local, remote, size, mtime, flags);
}

void net_share_link_cancel(NetShareLink* link)
{
    std::lock_guard<std::mutex> guard(link->lock);
    net_share_client_cancel(&link->share);
}

void net_share_link_progress(NetShareLink* link, NetShareProgress* progress, NetShareClientCopy* copy,
                             uint32_t* queued)
{
    std::lock_guard<std::mutex> guard(link->lock);
    net_share_client_progress(&link->share, progress, copy, queued);
}

void net_share_link_take_done(NetShareLink* link, std::vector<NetShareClientDone>* done)
{
    std::lock_guard<std::mutex> guard(link->lock);
    done->clear();
    done->swap(link->share.done);
}

bool net_share_link_set_grants(NetShareLink* link, uint32_t device, NetCaps grants)
{
    std::lock_guard<std::mutex> guard(link->lock);
    if (!link->running || device >= link->client.trust.devices.size())
    {
        return false;
    }
    link->newly_paired = false;   // the DONE screen's ticks are in
    net_client_set_grants(&link->client, device, grants);
    return true;
}

bool net_share_link_enter_code(NetShareLink* link, const char* code)
{
    std::lock_guard<std::mutex> guard(link->lock);
    if (!link->running || !link->code_needed || !net_client_enter_code(&link->client, code))
    {
        return false;
    }
    link->code_needed = false;
    return true;
}

bool net_share_link_forget_host(NetShareLink* link, uint32_t device)
{
    std::lock_guard<std::mutex> guard(link->lock);
    return link->running && net_client_unpair(&link->client, device);
}
