#include "net_access.h"

#include <cstdio>

#include <cstring>

#include "host_log.h"
#include "monocypher.h"

static void beacon_refresh_ids(NetAccess* access);

bool net_access_create(NetAccess* access, uint16_t port, const char* name, const NetKeypair* identity,
                       const char* trust_path)
{
    access->trust_path = trust_path;
    access->name = name;
    std::memcpy(access->host_key, identity->public_key, NET_KEY_SIZE);
    access->out.resize(NET_PAIR_MAX_MESSAGE);
    net_trust_load(&access->trust, trust_path);
    if (!net_session_create_listener(&access->session, port, name, identity))
    {
        return false;
    }
    beacon_refresh_ids(access);
    return true;
}

static void peer_reset(NetAccessPeer* peer)
{
    crypto_wipe(peer->isk, sizeof(peer->isk));
    *peer = {};
}

void net_access_destroy(NetAccess* access)
{
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        peer_reset(&access->peers[i]);
    }
    net_access_close_pairing(access);
    net_signal_stop(&access->signal);
    net_session_destroy(&access->session);
}

// The beacon registers one meeting id per paired device; computed again when
// the list changes (only then: a level change leaves the ids alone).
static void beacon_refresh_ids(NetAccess* access)
{
    std::vector<BeaconId> ids;
    ids.reserve(access->trust.devices.size() + 1);
    for (size_t i = 0; i < access->trust.devices.size(); i++)
    {
        BeaconId id;
        if (net_beacon_meeting_id(&access->session.identity, access->trust.devices[i].key, &id))
        {
            ids.push_back(id);
        }
    }
    if (access->pairing_open)
    {
        // The pairing room: a device with the pair link (our key) meets us there.
        BeaconId id;
        net_beacon_pair_id(access->session.identity.public_key, &id);
        ids.push_back(id);
    }
    bool same = ids.size() == access->beacon.ids.size();
    for (size_t i = 0; same && i < ids.size(); i++)
    {
        same = beacon_id_equal(&ids[i], &access->beacon.ids[i]);
    }
    if (!same)
    {
        net_beacon_host_set_ids(&access->beacon, ids.data(), static_cast<uint32_t>(ids.size()));
        // The same pairings as signaling rooms (WebRTC: browsers).
        std::vector<uint8_t> keys(access->trust.devices.size() * NET_KEY_SIZE);
        for (size_t i = 0; i < access->trust.devices.size(); i++)
        {
            std::memcpy(&keys[i * NET_KEY_SIZE], access->trust.devices[i].key, NET_KEY_SIZE);
        }
        net_signal_host_set_rooms(&access->signal, &access->session.identity,
                                  reinterpret_cast<const uint8_t(*)[NET_KEY_SIZE]>(keys.data()),
                                  static_cast<uint32_t>(access->trust.devices.size()), access->pairing_open);
    }
}

static void save_trust(NetAccess* access)
{
    beacon_refresh_ids(access);
    if (!net_trust_save(&access->trust, access->trust_path.c_str()))
    {
        host_log(LogLevel::error, "Network: could not save the paired devices to %s", access->trust_path.c_str());
    }
}

static void send_control(NetAccess* access, uint32_t peer, size_t size)
{
    if (size > 0)
    {
        net_session_send(&access->session, peer, NetChannel::control, access->out.data(), size);
    }
}

bool net_access_open_pairing(NetAccess* access)
{
    if (!net_pair_code_generate(access->code))
    {
        return false;
    }
    if (!access->pairing_open)
    {
        access->pairing_open = true;
        access->pairing_opened_at = net_seconds();
        access->pairing_failures = 0;
        beacon_refresh_ids(access);   // the pairing room joins
    }
    return true;
}

void net_access_close_pairing(NetAccess* access)
{
    bool was_open = access->pairing_open;
    access->pairing_open = false;
    crypto_wipe(access->code, sizeof(access->code));
    if (was_open)
    {
        beacon_refresh_ids(access);   // and leaves
    }
}

double net_access_pairing_seconds_left(const NetAccess* access)
{
    if (!access->pairing_open)
    {
        return 0.0;
    }
    double left = NET_PAIRING_OPEN_SECONDS - (net_seconds() - access->pairing_opened_at);
    return left > 0.0 ? left : 0.0;
}

// An attempt didn't succeed: the code it may have learned something about is
// replaced, and too many failures close pairing. Fills `event`.
static void pairing_failed(NetAccess* access, NetAccessEvent* event)
{
    event->type = NetAccessEventType::pairing_failed;
    if (!access->pairing_open)
    {
        return;
    }
    access->pairing_failures++;
    if (access->pairing_failures >= NET_PAIRING_MAX_FAILURES)
    {
        host_log(LogLevel::warning, "Network: %u failed pairing attempts, pairing closed",
                 static_cast<unsigned>(access->pairing_failures));
        net_access_close_pairing(access);
        return;
    }
    if (!net_pair_code_generate(access->code))
    {
        net_access_close_pairing(access);
    }
}

static bool someone_pairing(const NetAccess* access)
{
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        if (access->peers[i].state == NetAccessPeerState::pairing)
        {
            return true;
        }
    }
    return false;
}

static void on_secured(NetAccess* access, const NetSessionEvent* session_event, NetAccessEvent* event, bool* filled)
{
    uint32_t index = session_event->peer;
    if (index >= NET_MAX_PEERS)
    {
        return;
    }
    NetAccessPeer* peer = &access->peers[index];
    peer_reset(peer);
    std::memcpy(peer->key, session_event->remote_key, NET_KEY_SIZE);
    std::memcpy(peer->handshake_hash, session_event->handshake_hash, NET_HASH_SIZE);
    peer->since = net_seconds();

    int32_t device = net_trust_find(&access->trust, peer->key);
    if (device >= 0)
    {
        peer->state = NetAccessPeerState::authorized;
        peer->device = device;
        NetAccessLevel level = access->trust.devices[static_cast<size_t>(device)].access;
        send_control(access, index,
                     net_message_write_welcome(access->out.data(), access->out.size(), level, access->name.c_str()));
        event->type = NetAccessEventType::authorized;
        event->peer = index;
        event->device = device;
        event->access = level;
        event->address = session_event->address;
        *filled = true;
        return;
    }
    peer->state = NetAccessPeerState::unpaired;
    send_control(access, index,
                 net_message_write_pairing_needed(access->out.data(), access->out.size(), access->pairing_open,
                                                  access->name.c_str()));
    if (!access->pairing_open)
    {
        // Sent first: ENet delivers queued messages before disconnecting.
        // (A client without a code closes on its own; one with a code waits
        // for this.)
        net_session_close(&access->session, index);
    }
}

static void refuse_pairing(NetAccess* access, uint32_t index)
{
    send_control(access, index, net_message_write_pair_result(access->out.data(), access->out.size(), false));
    net_session_close(&access->session, index);
}

static void on_pair_request(NetAccess* access, uint32_t index, const uint8_t* data, size_t size, NetAccessEvent* event,
                            bool* filled)
{
    NetAccessPeer* peer = &access->peers[index];
    uint8_t their_share[NET_CPACE_SHARE_SIZE];
    if (!access->pairing_open || someone_pairing(access) ||
        !net_message_read_pair_request(data, size, their_share, peer->name))
    {
        refuse_pairing(access, index);
        return;
    }
    uint8_t ci[NET_PAIR_CI_SIZE];
    net_pair_ci(peer->key, access->host_key, ci);
    NetCpace cpace;
    uint8_t prs[NET_PAIR_CODE_DIGITS];
    for (size_t i = 0; i < NET_PAIR_CODE_DIGITS; i++)
    {
        prs[i] = static_cast<uint8_t>(access->code[i]);
    }
    bool started = net_cpace_start(&cpace, prs, sizeof(prs), ci, sizeof(ci), peer->handshake_hash, NET_PAIR_SID_SIZE);
    crypto_wipe(prs, sizeof(prs));
    uint8_t our_share[NET_CPACE_SHARE_SIZE];
    std::memcpy(our_share, cpace.share, sizeof(our_share));
    // ADa = the client's name as it sent it, ADb = ours as we send it.
    uint8_t ad_a[NET_DEVICE_NAME_MAX];
    uint8_t ad_b[NET_DEVICE_NAME_MAX];
    size_t ad_a_size = net_pair_name_bytes(peer->name, ad_a);
    size_t ad_b_size = net_pair_name_bytes(access->name.c_str(), ad_b);
    bool finished = started && net_cpace_finish(&cpace, false, their_share, ad_a, ad_a_size, ad_b, ad_b_size,
                                                peer->handshake_hash, NET_PAIR_SID_SIZE, peer->isk);
    net_cpace_wipe(&cpace);
    if (!finished)
    {
        // A low-order share: not an honest client.
        refuse_pairing(access, index);
        pairing_failed(access, event);
        *filled = true;
        return;
    }
    uint8_t confirm[NET_PAIR_CONFIRM_SIZE];
    net_pair_confirm(peer->isk, true, confirm);
    send_control(access, index,
                 net_message_write_pair_response(access->out.data(), access->out.size(), our_share, confirm,
                                                 access->name.c_str()));
    peer->state = NetAccessPeerState::pairing;
    peer->since = net_seconds();
}

static void on_pair_confirm(NetAccess* access, uint32_t index, const uint8_t* data, size_t size, NetAccessEvent* event,
                            bool* filled)
{
    NetAccessPeer* peer = &access->peers[index];
    uint8_t received[NET_PAIR_CONFIRM_SIZE];
    uint8_t expected[NET_PAIR_CONFIRM_SIZE];
    net_pair_confirm(peer->isk, false, expected);
    bool ok = net_message_read_pair_confirm(data, size, received) && crypto_verify32(received, expected) == 0;
    crypto_wipe(peer->isk, sizeof(peer->isk));
    if (!ok)
    {
        peer->state = NetAccessPeerState::unpaired;
        refuse_pairing(access, index);
        pairing_failed(access, event);
        *filled = true;
        return;
    }
    uint32_t device = net_trust_add(&access->trust, peer->key, peer->name);
    save_trust(access);
    send_control(access, index, net_message_write_pair_result(access->out.data(), access->out.size(), true));
    peer->state = NetAccessPeerState::authorized;
    peer->device = static_cast<int32_t>(device);
    net_access_close_pairing(access);   // one device per code shown
    char fingerprint[32];
    net_key_fingerprint(peer->key, fingerprint, sizeof(fingerprint));
    host_log(LogLevel::info, "Network: paired with \"%s\" (%s)", access->trust.devices[device].name.c_str(), fingerprint);
    event->type = NetAccessEventType::paired;
    event->peer = index;
    event->device = static_cast<int32_t>(device);
    event->access = access->trust.devices[device].access;
    *filled = true;
}

// Forgets a paired device (saved at once). Its connections stop reaching
// the frontend (their `closed` still does). Each is told (unpair) and
// closed, except `unpaired_by`: the peer that unpaired itself, which closes
// on its own (NET_NO_PEER: none did).
static void forget_device(NetAccess* access, uint32_t device, uint32_t unpaired_by)
{
    if (device >= access->trust.devices.size())
    {
        return;
    }
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        NetAccessPeer* peer = &access->peers[i];
        if (peer->state != NetAccessPeerState::authorized)
        {
            continue;
        }
        if (peer->device == static_cast<int32_t>(device))
        {
            if (i != unpaired_by)
            {
                // Told first: the close waits for what's queued (disconnect_later).
                uint8_t unpair[1];
                net_session_send(&access->session, i, NetChannel::control, unpair,
                                 net_message_write_unpair(unpair, sizeof(unpair)));
                net_session_close(&access->session, i);
            }
            peer->state = NetAccessPeerState::none;   // nothing more from it reaches the frontend
            peer->device = -1;
            peer->forgotten = true;                   // but its `closed` does (its pads go)
        }
        else if (peer->device > static_cast<int32_t>(device))
        {
            peer->device--;   // indexes after it move down
        }
    }
    net_trust_remove(&access->trust, device);
    save_trust(access);
}

static bool on_message(NetAccess* access, const NetSessionEvent* session_event, NetAccessEvent* event)
{
    uint32_t index = session_event->peer;
    if (index >= NET_MAX_PEERS)
    {
        return false;
    }
    NetAccessPeer* peer = &access->peers[index];
    bool filled = false;
    if (peer->state == NetAccessPeerState::authorized)
    {
        NetAccessLevel level = access->trust.devices[static_cast<size_t>(peer->device)].access;
        if (session_event->channel == NetChannel::control)
        {
            uint8_t type = net_message_type(session_event->data, session_event->size);
            if (net_message_read_unpair(session_event->data, session_event->size))
            {
                // The device forgot us: forget it. It closes the connection;
                // its `closed` comes later (forgotten).
                uint32_t device = static_cast<uint32_t>(peer->device);
                event->type = NetAccessEventType::unpaired;
                event->peer = index;
                event->device = -1;
                event->address = session_event->address;
                std::snprintf(event->name, sizeof(event->name), "%s", access->trust.devices[device].name.c_str());
                forget_device(access, device, index);
                return true;
            }
            if (type == static_cast<uint8_t>(NetMessage::device_name))
            {
                char name[NET_DEVICE_NAME_MAX + 1];
                if (net_message_read_device_name(session_event->data, session_event->size, name) &&
                    net_trust_rename(&access->trust, static_cast<uint32_t>(peer->device), name))
                {
                    save_trust(access);
                }
                return false;
            }
            // Other control messages of this layer aren't the application's,
            // and an application message needs its level.
            if (type < NET_MESSAGE_FIRST_APP || !net_access_allows(level, net_message_required_access(type)))
            {
                if (type >= NET_MESSAGE_FIRST_APP)
                {
                    access->dropped_by_access++;
                }
                return false;
            }
        }
        event->type = NetAccessEventType::message;
        event->access = level;
        event->peer = index;
        event->device = peer->device;
        event->address = session_event->address;
        event->channel = session_event->channel;
        event->data = session_event->data;
        event->size = session_event->size;
        return true;
    }
    if (session_event->channel != NetChannel::control)
    {
        return false;   // input from someone not authorized: ignored
    }
    uint8_t type = net_message_type(session_event->data, session_event->size);
    if (peer->state == NetAccessPeerState::unpaired && type == static_cast<uint8_t>(NetMessage::pair_request))
    {
        on_pair_request(access, index, session_event->data, session_event->size, event, &filled);
    }
    else if (peer->state == NetAccessPeerState::pairing && type == static_cast<uint8_t>(NetMessage::pair_confirm))
    {
        on_pair_confirm(access, index, session_event->data, session_event->size, event, &filled);
    }
    else
    {
        // Anything else before authorization is a protocol error.
        bool was_pairing = peer->state == NetAccessPeerState::pairing;
        refuse_pairing(access, index);
        if (was_pairing)
        {
            pairing_failed(access, event);
            filled = true;
        }
    }
    if (filled)
    {
        event->peer = index;
        event->address = session_event->address;
    }
    return filled;
}

// Pairing's own clock, and peers stuck in a step.
static bool check_timers(NetAccess* access, NetAccessEvent* event)
{
    if (access->pairing_open && net_access_pairing_seconds_left(access) <= 0.0)
    {
        net_access_close_pairing(access);
        event->type = NetAccessEventType::pairing_closed;
        return true;
    }
    double now = net_seconds();
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        NetAccessPeer* peer = &access->peers[i];
        bool waiting = peer->state == NetAccessPeerState::unpaired || peer->state == NetAccessPeerState::pairing;
        if (waiting && now - peer->since > NET_ACCESS_PAIRING_STEP_SECONDS)
        {
            net_session_close(&access->session, i);
            peer->since = now;   // closing takes a moment; don't repeat every frame
        }
    }
    return false;
}

bool net_access_poll(NetAccess* access, NetAccessEvent* event)
{
    *event = {};
    net_beacon_host_update(&access->beacon, &access->session.host, net_seconds());
    net_signal_update(&access->signal, &access->session, net_seconds());
    if (check_timers(access, event))
    {
        return true;
    }
    NetSessionEvent session_event;
    while (net_session_poll(&access->session, &session_event))
    {
        bool filled = false;
        switch (session_event.type)
        {
        case NetSessionEventType::none:
        case NetSessionEventType::discovered:
            break;
        case NetSessionEventType::signal:   // WebRTC: our blob, to the device through the beacon
            net_signal_outgoing(&access->signal, session_event.peer, session_event.data, session_event.size);
            break;
        case NetSessionEventType::beacon:
            net_beacon_host_receive(&access->beacon, &access->session.host, &session_event.beacon,
                                    session_event.address, net_seconds());
            break;
        case NetSessionEventType::secured:
            on_secured(access, &session_event, event, &filled);
            break;
        case NetSessionEventType::message:
            filled = on_message(access, &session_event, event);
            break;
        case NetSessionEventType::closed:
        {
            if (session_event.peer >= NET_MAX_PEERS)
            {
                break;
            }
            net_signal_peer_gone(&access->signal, session_event.peer);
            NetAccessPeer* peer = &access->peers[session_event.peer];
            NetAccessPeerState state = peer->state;
            int32_t device = peer->device;
            bool forgotten = peer->forgotten;
            peer_reset(peer);
            if (state == NetAccessPeerState::pairing)
            {
                // Gone in the middle of pairing (a client that saw a wrong
                // confirmation closes): counts as a failed attempt.
                pairing_failed(access, event);
                event->peer = session_event.peer;
                filled = true;
            }
            else if (state == NetAccessPeerState::authorized || forgotten)
            {
                event->type = NetAccessEventType::closed;
                event->peer = session_event.peer;
                event->device = device;
                event->address = session_event.address;
                filled = true;
            }
            break;
        }
        }
        if (filled)
        {
            return true;
        }
    }
    return false;
}

bool net_access_send(NetAccess* access, uint32_t peer, NetChannel channel, const uint8_t* data, size_t size)
{
    if (peer >= NET_MAX_PEERS || access->peers[peer].state != NetAccessPeerState::authorized)
    {
        return false;
    }
    if (channel == NetChannel::control && net_message_type(data, size) < NET_MESSAGE_FIRST_APP)
    {
        return false;
    }
    return net_session_send(&access->session, peer, channel, data, size);
}

void net_access_close(NetAccess* access, uint32_t peer)
{
    net_session_close(&access->session, peer);
}

void net_access_remove_device(NetAccess* access, uint32_t device)
{
    forget_device(access, device, NET_NO_PEER);
}

void net_access_set_level(NetAccess* access, uint32_t device, NetAccessLevel level)
{
    if (device >= access->trust.devices.size())
    {
        return;
    }
    access->trust.devices[device].access = level;
    save_trust(access);
    // A connected device gets a new welcome with its level (to show what it can use).
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        if (access->peers[i].state == NetAccessPeerState::authorized &&
            access->peers[i].device == static_cast<int32_t>(device))
        {
            send_control(access, i,
                         net_message_write_welcome(access->out.data(), access->out.size(), level, access->name.c_str()));
        }
    }
}

bool net_access_device_connected(const NetAccess* access, uint32_t device)
{
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        if (access->peers[i].state == NetAccessPeerState::authorized &&
            access->peers[i].device == static_cast<int32_t>(device))
        {
            return true;
        }
    }
    return false;
}

bool net_access_peer_stats(const NetAccess* access, uint32_t peer, NetLinkStats* stats)
{
    if (peer >= NET_MAX_PEERS || access->peers[peer].state != NetAccessPeerState::authorized)
    {
        return false;
    }
    return net_host_peer_stats(&access->session.host, peer, stats);
}

bool net_access_peer_address(const NetAccess* access, uint32_t peer, NetAddress* address)
{
    if (peer >= NET_MAX_PEERS || access->peers[peer].state != NetAccessPeerState::authorized)
    {
        return false;
    }
    return net_host_peer_address(&access->session.host, peer, address);
}

void net_access_set_beacon(NetAccess* access, const NetAddress* servers, uint32_t count)
{
    net_beacon_host_set_servers(&access->beacon, servers, count);
    beacon_refresh_ids(access);
}

NetBeaconStatus net_access_beacon_status(const NetAccess* access)
{
    return net_beacon_host_status(&access->beacon, net_seconds());
}

size_t net_access_peer_pending(const NetAccess* access, uint32_t peer)
{
    return net_host_peer_pending(&access->session.host, peer);
}

bool net_access_set_signal(NetAccess* access, const char* url, const char* stun)
{
    if (url == nullptr || url[0] == '\0')
    {
        net_signal_host_start(&access->signal, "");
        return true;
    }
    if (!net_session_enable_rtc(&access->session, stun))
    {
        return false;   // no WebRTC in this build
    }
    net_signal_host_start(&access->signal, url);
    access->beacon.ids.clear();   // computed again: the rooms come with them
    beacon_refresh_ids(access);
    return true;
}

NetSignalStatus net_access_signal_status(const NetAccess* access)
{
    return net_signal_status(&access->signal, net_seconds());
}
