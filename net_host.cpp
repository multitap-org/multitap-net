#include "net_host.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>

#include <enet.h>

#include "host_log.h"
#include "net_memory.h"
#include "net_rtc.h"

// ENet's own global setup is process-wide; we count our users of it.
static uint32_t g_init_count = 0;

// ENet's intercept callback gets the ENetHost and nothing else (ENetHost has
// no user-data field), so the NetHost being polled is kept here while
// net_host_poll is inside enet_host_service, the only place ENet calls the
// callback from. Thread-local: two threads may poll two hosts.
static thread_local NetHost* g_polling = nullptr;

static uint32_t random_u32()
{
    // Only a nonce to match replies to requests (not a secret).
    std::random_device device;
    return device();
}

static void name_copy(std::string* out, const char* name)
{
    size_t length = std::strlen(name);
    // net_discovery_write_reply cuts it too; keeping the cut copy here makes
    // what we log the same as what clients see.
    if (length > NET_DISCOVERY_MAX_NAME)
    {
        length = NET_DISCOVERY_MAX_NAME;
        while (length > 0 && (static_cast<uint8_t>(name[length]) & 0xC0) == 0x80)
        {
            length--;
        }
    }
    out->assign(name, length);
}

static_assert(sizeof(in6_addr) == sizeof(NetAddress::ip), "NetAddress holds an IPv6 address");

static NetAddress address_from_enet(const ENetAddress* address)
{
    NetAddress result;
    std::memcpy(result.ip, &address->host, sizeof(result.ip));
    result.port = address->port;
    result.scope = address->sin6_scope_id;
    return result;
}

static ENetAddress address_to_enet(NetAddress address)
{
    ENetAddress result = {};
    std::memcpy(&result.host, address.ip, sizeof(address.ip));
    result.port = address.port;
    result.sin6_scope_id = address.scope;
    return result;
}

// `data` isn't const only because ENet's buffer type isn't; it is only read.
static bool send_raw(ENetHost* enet, const ENetAddress* to, uint8_t* data, size_t size)
{
    ENetBuffer buffer = {};
    buffer.data = data;
    buffer.dataLength = size;
    return enet_socket_send(enet->socket, to, &buffer, 1) == static_cast<int>(size);
}

// Our datagrams, before ENet looks at them. 1 = ours (handled), 0 = ENet's.
// Anything that isn't exactly one of our packets goes on to ENet, which drops
// what isn't its own (see net_discovery.h for why ours never look like ENet's).
static int ENET_CALLBACK intercept(ENetHost* enet, void* event)
{
    (void)event;
    NetHost* host = g_polling;
    if (host == nullptr || host->enet != enet)
    {
        return 0;
    }
    const uint8_t* data = enet->receivedData;
    size_t size = enet->receivedDataLength;

    uint32_t nonce = 0;
    if (net_discovery_read_request(data, size, &nonce))
    {
        if (host->listener)
        {
            NetDiscoveryReply reply;
            reply.nonce = nonce;
            reply.port = enet->address.port;
            std::snprintf(reply.name, sizeof(reply.name), "%s", host->name.c_str());
            uint8_t packet[NET_DISCOVERY_MAX_PACKET];
            size_t packet_size = net_discovery_write_reply(packet, sizeof(packet), &reply);
            if (packet_size > 0 && send_raw(enet, &enet->receivedAddress, packet, packet_size))
            {
                host->discovery_requests_answered++;
            }
        }
        return 1;   // a client ignores other clients' requests
    }

    // A beacon message: exactly one of beacon_wire's fixed layouts ("MTBC"),
    // checked whole by beacon_decode; queued for net_beacon (listener or client).
    BeaconMessage beacon;
    if (beacon_decode(data, size, &beacon))
    {
        if (host->beacon_count < NET_MAX_BEACON_QUEUED)
        {
            host->beacon_queue[host->beacon_count] = beacon;
            host->beacon_from[host->beacon_count] = address_from_enet(&enet->receivedAddress);
            host->beacon_count++;
        }
        return 1;
    }

    NetDiscoveryReply reply;
    if (net_discovery_read_reply(data, size, &reply))
    {
        // Only answers to our own last request; a full queue drops the rest
        // (the client asks again).
        if (!host->listener && reply.nonce == host->discovery_nonce && host->discovered_count < NET_MAX_DISCOVERED)
        {
            host->discovered[host->discovered_count] = reply;
            host->discovered_from[host->discovered_count] = address_from_enet(&enet->receivedAddress);
            host->discovered_count++;
        }
        return 1;
    }
    return 0;
}

// ENet's memory comes from net_memory's reused size classes (no allocation
// per packet once warmed up). ENet wants its own calling convention here.
static void* ENET_CALLBACK enet_memory_alloc(size_t size)
{
    return net_memory_alloc(size);
}

static void ENET_CALLBACK enet_memory_free(void* memory)
{
    net_memory_free(memory);
}

bool net_init()
{
    ENetCallbacks callbacks = {};
    callbacks.malloc = enet_memory_alloc;
    callbacks.free = enet_memory_free;
    if (g_init_count == 0 && enet_initialize_with_callbacks(ENET_VERSION, &callbacks) != 0)
    {
        host_log(LogLevel::error, "Network: ENet could not start");
        return false;
    }
    g_init_count++;
    return true;
}

void net_shutdown()
{
    if (g_init_count == 0)
    {
        host_log(LogLevel::error, "Network: net_shutdown without net_init");
        return;
    }
    g_init_count--;
    if (g_init_count == 0)
    {
        enet_deinitialize();
        net_memory_release();
    }
}

static void slots_reset(NetHost* host)
{
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        host->slots[i] = {};
        host->enet_slot[i] = NET_NO_PEER;
        host->rtc_slot[i] = NET_NO_PEER;
    }
}

static uint32_t slot_take(NetHost* host, NetTransport transport, uint32_t index)
{
    uint32_t* map = transport == NetTransport::enet ? host->enet_slot : host->rtc_slot;
    if (index >= NET_MAX_PEERS)
    {
        return NET_NO_PEER;
    }
    if (map[index] != NET_NO_PEER)
    {
        return map[index];
    }
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        if (!host->slots[i].used)
        {
            host->slots[i].used = true;
            host->slots[i].transport = transport;
            host->slots[i].index = index;
            map[index] = i;
            return i;
        }
    }
    return NET_NO_PEER;
}

static void slot_free(NetHost* host, uint32_t slot)
{
    if (slot >= NET_MAX_PEERS || !host->slots[slot].used)
    {
        return;
    }
    uint32_t* map = host->slots[slot].transport == NetTransport::enet ? host->enet_slot : host->rtc_slot;
    map[host->slots[slot].index] = NET_NO_PEER;
    host->slots[slot] = {};
}

static const NetHostSlot* slot_get(const NetHost* host, uint32_t peer)
{
    if (peer >= NET_MAX_PEERS || !host->slots[peer].used)
    {
        return nullptr;
    }
    return &host->slots[peer];
}

static bool host_create(NetHost* host, const ENetAddress* bind_address)
{
    slots_reset(host);
    host->enet = enet_host_create(bind_address, NET_MAX_PEERS, NET_CHANNEL_COUNT, 0, 0);
    if (host->enet == nullptr)
    {
        return false;
    }
    host->enet->intercept = intercept;
    return true;
}

bool net_host_create_listener(NetHost* host, uint16_t port, const char* name)
{
    *host = {};
    ENetAddress address = {};
    address.host = ENET_HOST_ANY;
    address.port = port;
    if (!host_create(host, &address))
    {
        host_log(LogLevel::error, "Network: can't listen on UDP port %u (in use?)", static_cast<unsigned>(port));
        return false;
    }
    host->listener = true;
    name_copy(&host->name, name);
    host_log(LogLevel::info, "Network: listening on UDP port %u as \"%s\"", static_cast<unsigned>(net_host_port(host)),
             host->name.c_str());
    return true;
}

bool net_host_create_client(NetHost* host)
{
    *host = {};
    if (!host_create(host, nullptr))
    {
        host_log(LogLevel::error, "Network: can't open a UDP socket");
        return false;
    }
    return true;
}

void net_host_destroy(NetHost* host)
{
    net_rtc_destroy(host->rtc);
    host->rtc = nullptr;
    if (host->held_packet != nullptr)
    {
        enet_packet_destroy(host->held_packet);
        host->held_packet = nullptr;
    }
    if (host->enet != nullptr)
    {
        enet_host_destroy(host->enet);
        host->enet = nullptr;
    }
}

uint16_t net_host_port(const NetHost* host)
{
    if (host->enet == nullptr)
    {
        return 0;
    }
    return host->enet->address.port;
}

static uint32_t enet_index(const NetHost* host, const ENetPeer* peer)
{
    return static_cast<uint32_t>(peer - host->enet->peers);
}

static bool take_discovered(NetHost* host, NetEvent* event)
{
    if (host->discovered_count == 0)
    {
        return false;
    }
    event->type = NetEventType::discovered;
    event->discovered = host->discovered[0];
    event->address = host->discovered_from[0];
    // Keep arrival order; at most NET_MAX_DISCOVERED entries.
    for (uint32_t i = 1; i < host->discovered_count; i++)
    {
        host->discovered[i - 1] = host->discovered[i];
        host->discovered_from[i - 1] = host->discovered_from[i];
    }
    host->discovered_count--;
    return true;
}

static bool take_beacon(NetHost* host, NetEvent* event)
{
    if (host->beacon_count == 0)
    {
        return false;
    }
    event->type = NetEventType::beacon;
    event->beacon = host->beacon_queue[0];
    event->address = host->beacon_from[0];
    for (uint32_t i = 1; i < host->beacon_count; i++)
    {
        host->beacon_queue[i - 1] = host->beacon_queue[i];
        host->beacon_from[i - 1] = host->beacon_from[i];
    }
    host->beacon_count--;
    return true;
}

// Seconds on a steady clock (net_rtc's connect timeout).
static double net_host_clock()
{
    std::chrono::steady_clock::duration since = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration<double>(since).count();
}

// WebRTC's events, after ENet's (nothing when it isn't enabled).
static bool poll_rtc(NetHost* host, NetEvent* event)
{
    if (host->rtc == nullptr)
    {
        return false;
    }
    NetRtcEvent rtc_event;
    while (net_rtc_poll(host->rtc, &rtc_event, net_host_clock()))
    {
        uint32_t slot = host->rtc_slot[rtc_event.index];
        if (slot == NET_NO_PEER)
        {
            continue;   // a peer we already let go
        }
        event->peer = slot;
        switch (rtc_event.type)
        {
        case NetRtcEventType::none:
            continue;
        case NetRtcEventType::connected:
            event->type = NetEventType::connected;
            return true;
        case NetRtcEventType::disconnected:
            slot_free(host, slot);
            event->type = NetEventType::disconnected;
            return true;
        case NetRtcEventType::received:
            event->type = NetEventType::received;
            event->channel = rtc_event.channel;
            event->data = rtc_event.data;
            event->size = rtc_event.size;
            return true;
        case NetRtcEventType::signal:
            event->type = NetEventType::signal;
            event->data = rtc_event.data;
            event->size = rtc_event.size;
            return true;
        }
    }
    return false;
}

bool net_host_poll(NetHost* host, NetEvent* event)
{
    *event = {};
    if (host->held_packet != nullptr)
    {
        enet_packet_destroy(host->held_packet);
        host->held_packet = nullptr;
    }
    if (host->enet == nullptr)
    {
        return poll_rtc(host, event);
    }
    if (take_discovered(host, event) || take_beacon(host, event))
    {
        return true;
    }

    ENetEvent enet_event = {};
    g_polling = host;
    int result = enet_host_service(host->enet, &enet_event, 0);
    g_polling = nullptr;
    if (result < 0)
    {
        host_log(LogLevel::warning, "Network: socket error while polling");
        return false;
    }
    if (result == 0)
    {
        // The intercept may have queued replies during this call.
        return take_discovered(host, event) || take_beacon(host, event) || poll_rtc(host, event);
    }

    uint32_t index = enet_index(host, enet_event.peer);
    event->address = address_from_enet(&enet_event.peer->address);
    switch (enet_event.type)
    {
    case ENET_EVENT_TYPE_CONNECT:
        event->peer = slot_take(host, NetTransport::enet, index);
        if (event->peer == NET_NO_PEER)
        {
            enet_peer_reset(enet_event.peer);   // every slot taken (by WebRTC peers too)
            return poll_rtc(host, event);
        }
        event->type = NetEventType::connected;
        break;
    case ENET_EVENT_TYPE_DISCONNECT:
    case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT:   // zpl-c's ENet tells a timeout apart; same to us
        event->peer = host->enet_slot[index];
        if (event->peer == NET_NO_PEER)
        {
            return poll_rtc(host, event);
        }
        slot_free(host, event->peer);
        event->type = NetEventType::disconnected;
        break;
    case ENET_EVENT_TYPE_RECEIVE:
        event->peer = host->enet_slot[index];
        if (event->peer == NET_NO_PEER)
        {
            enet_packet_destroy(enet_event.packet);
            return poll_rtc(host, event);
        }
        event->type = NetEventType::received;
        event->channel = static_cast<NetChannel>(enet_event.channelID);
        event->data = enet_event.packet->data;
        event->size = enet_event.packet->dataLength;
        host->held_packet = enet_event.packet;
        break;
    case ENET_EVENT_TYPE_NONE:
        return poll_rtc(host, event);
    }
    return true;
}

static bool discover_to(NetHost* host, const ENetAddress* to)
{
    if (host->enet == nullptr)
    {
        return false;
    }
    host->discovery_nonce = random_u32();
    host->discovered_count = 0;   // replies to an older request are stale now
    uint8_t packet[NET_DISCOVERY_REQUEST_SIZE];
    size_t size = net_discovery_write_request(packet, sizeof(packet), host->discovery_nonce);
    if (!send_raw(host->enet, to, packet, size))
    {
        host_log(LogLevel::warning, "Network: discovery request could not be sent");
        return false;
    }
    return true;
}

bool net_host_discover(NetHost* host, uint16_t port)
{
    // 255.255.255.255 as ::ffff:255.255.255.255: the dual-stack socket sends
    // it as an IPv4 broadcast (ENet's own mapping turns 255.255.255.255 into
    // all-ones IPv6, which isn't one).
    NetAddress broadcast;
    broadcast.ip[10] = 0xFF;
    broadcast.ip[11] = 0xFF;
    broadcast.ip[12] = 0xFF;
    broadcast.ip[13] = 0xFF;
    broadcast.ip[14] = 0xFF;
    broadcast.ip[15] = 0xFF;
    broadcast.port = port;
    ENetAddress to = address_to_enet(broadcast);
    return discover_to(host, &to);
}

bool net_host_discover_at(NetHost* host, NetAddress address)
{
    ENetAddress to = address_to_enet(address);
    return discover_to(host, &to);
}

bool net_host_send_datagram(NetHost* host, NetAddress to, const uint8_t* data, size_t size)
{
    if (host->enet == nullptr)
    {
        return false;
    }
    ENetAddress enet_to = address_to_enet(to);
    return send_raw(host->enet, &enet_to, const_cast<uint8_t*>(data), size);
}

bool net_host_connect(NetHost* host, NetAddress address, uint32_t* peer)
{
    if (host->enet == nullptr)
    {
        return false;
    }
    ENetAddress to = address_to_enet(address);
    ENetPeer* enet_peer = enet_host_connect(host->enet, &to, NET_CHANNEL_COUNT, 0);
    if (enet_peer == nullptr)
    {
        host_log(LogLevel::warning, "Network: no free peer slot to connect");
        return false;
    }
    *peer = slot_take(host, NetTransport::enet, enet_index(host, enet_peer));
    if (*peer == NET_NO_PEER)
    {
        enet_peer_reset(enet_peer);
        host_log(LogLevel::warning, "Network: no free peer slot to connect");
        return false;
    }
    return true;
}

// The ENet peer behind a slot, or nullptr (no such peer, or it's WebRTC).
static ENetPeer* enet_peer_of(const NetHost* host, uint32_t peer)
{
    const NetHostSlot* slot = slot_get(host, peer);
    if (host->enet == nullptr || slot == nullptr || slot->transport != NetTransport::enet ||
        slot->index >= host->enet->peerCount)
    {
        return nullptr;
    }
    return &host->enet->peers[slot->index];
}

static bool is_rtc(const NetHost* host, uint32_t peer)
{
    const NetHostSlot* slot = slot_get(host, peer);
    return slot != nullptr && slot->transport == NetTransport::rtc && host->rtc != nullptr;
}

bool net_host_send(NetHost* host, uint32_t peer, NetChannel channel, const uint8_t* data, size_t size)
{
    if (is_rtc(host, peer))
    {
        return net_rtc_send(host->rtc, host->slots[peer].index, channel, data, size);
    }
    ENetPeer* enet_peer = enet_peer_of(host, peer);
    if (enet_peer == nullptr || enet_peer->state != ENET_PEER_STATE_CONNECTED)
    {
        return false;
    }
    // No flag = unreliable but sequenced, which is what `input` wants.
    enet_uint32 flags = channel == NetChannel::control ? ENET_PACKET_FLAG_RELIABLE : 0;
    ENetPacket* packet = enet_packet_create(data, size, flags);
    if (packet == nullptr)
    {
        return false;
    }
    if (enet_peer_send(enet_peer, static_cast<enet_uint8>(channel), packet) != 0)
    {
        enet_packet_destroy(packet);   // ENet only takes ownership on success
        return false;
    }
    return true;
}

bool net_host_peer_stats(const NetHost* host, uint32_t peer, NetLinkStats* stats)
{
    if (is_rtc(host, peer))
    {
        // libdatachannel's C API has no round trip: shown as 0 (unknown) for now.
        *stats = {};
        return net_rtc_connected(host->rtc, host->slots[peer].index);
    }
    const ENetPeer* enet_peer = enet_peer_of(host, peer);
    if (enet_peer == nullptr || enet_peer->state != ENET_PEER_STATE_CONNECTED)
    {
        return false;
    }
    stats->round_trip_ms = enet_peer->roundTripTime;
    stats->jitter_ms = enet_peer->roundTripTimeVariance;
    stats->loss = static_cast<float>(enet_peer->packetLoss) / static_cast<float>(ENET_PEER_PACKET_LOSS_SCALE);
    return true;
}

bool net_host_peer_address(const NetHost* host, uint32_t peer, NetAddress* address)
{
    const ENetPeer* enet_peer = enet_peer_of(host, peer);
    if (enet_peer == nullptr || enet_peer->state != ENET_PEER_STATE_CONNECTED)
    {
        return false;   // WebRTC peers too: their address is the browser's business
    }
    *address = address_from_enet(&enet_peer->address);
    return true;
}

void net_host_disconnect(NetHost* host, uint32_t peer)
{
    if (is_rtc(host, peer))
    {
        net_rtc_close(host->rtc, host->slots[peer].index);
        return;
    }
    ENetPeer* enet_peer = enet_peer_of(host, peer);
    if (enet_peer != nullptr)
    {
        enet_peer_disconnect_later(enet_peer, 0);
    }
}

NetTransport net_host_peer_transport(const NetHost* host, uint32_t peer)
{
    const NetHostSlot* slot = slot_get(host, peer);
    return slot != nullptr ? slot->transport : NetTransport::enet;
}

bool net_host_enable_rtc(NetHost* host, const char* stun)
{
    if (host->rtc != nullptr)
    {
        return true;
    }
    if (!net_rtc_available())
    {
        return false;
    }
    host->rtc = net_rtc_create(stun);
    return host->rtc != nullptr;
}

static bool rtc_open(NetHost* host, bool accept, uint32_t* peer)
{
    uint32_t index = 0;
    if (host->rtc == nullptr || !(accept ? net_rtc_accept(host->rtc, &index) : net_rtc_connect(host->rtc, &index)))
    {
        return false;
    }
    *peer = slot_take(host, NetTransport::rtc, index);
    if (*peer == NET_NO_PEER)
    {
        net_rtc_close(host->rtc, index);
        return false;
    }
    return true;
}

bool net_host_rtc_connect(NetHost* host, uint32_t* peer)
{
    return rtc_open(host, false, peer);
}

bool net_host_rtc_accept(NetHost* host, uint32_t* peer)
{
    return rtc_open(host, true, peer);
}

bool net_host_rtc_signal(NetHost* host, uint32_t peer, const uint8_t* data, size_t size)
{
    return is_rtc(host, peer) && net_rtc_signal(host->rtc, host->slots[peer].index, data, size);
}

bool net_address_from_text(const char* text, uint16_t port, NetAddress* address)
{
    // "[2001:db8::5]" as people write it next to a port: without the brackets.
    char unbracketed[256];
    size_t length = std::strlen(text);
    if (length >= 2 && text[0] == '[' && text[length - 1] == ']' && length - 2 < sizeof(unbracketed))
    {
        std::memcpy(unbracketed, text + 1, length - 2);
        unbracketed[length - 2] = '\0';
        text = unbracketed;
    }
    ENetAddress enet_address = {};
    if (enet_address_set_host_new(&enet_address, text) != 0)
    {
        host_log(LogLevel::warning, "Network: unknown address \"%s\"", text);
        return false;
    }
    enet_address.port = port;
    *address = address_from_enet(&enet_address);
    return true;
}

void net_address_to_text(NetAddress address, char* out, size_t capacity)
{
    ENetAddress enet_address = address_to_enet(address);
    char ip[64] = {};
    // IPv4-mapped addresses come out as plain IPv4 ("192.168.1.20").
    if (enet_address_get_host_ip_new(&enet_address, ip, sizeof(ip)) != 0)
    {
        std::snprintf(ip, sizeof(ip), "?");
    }
    if (net_address_is_ipv4(address))
    {
        std::snprintf(out, capacity, "%s:%u", ip, static_cast<unsigned>(address.port));
    }
    else
    {
        std::snprintf(out, capacity, "[%s]:%u", ip, static_cast<unsigned>(address.port));
    }
}

bool net_address_is_ipv4(NetAddress address)
{
    static const uint8_t mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
    return std::memcmp(address.ip, mapped_prefix, sizeof(mapped_prefix)) == 0;
}

bool net_address_equal(NetAddress a, NetAddress b)
{
    return std::memcmp(a.ip, b.ip, sizeof(a.ip)) == 0 && a.port == b.port && a.scope == b.scope;
}

uint32_t net_address_resolve(const char* text, uint16_t default_port, NetAddress* out)
{
    // Split "name:port", "[v6]:port", "[v6]", "v6" (more than one ':' and no
    // brackets: all address) and "name".
    char name[256];
    uint16_t port = default_port;
    size_t length = std::strlen(text);
    if (length == 0 || length >= sizeof(name))
    {
        return 0;
    }
    const char* port_text = nullptr;
    if (text[0] == '[')
    {
        const char* close = std::strchr(text, ']');
        if (close == nullptr)
        {
            return 0;
        }
        size_t name_length = static_cast<size_t>(close - text - 1);
        std::memcpy(name, text + 1, name_length);
        name[name_length] = '\0';
        if (close[1] == ':')
        {
            port_text = close + 2;
        }
        else if (close[1] != '\0')
        {
            return 0;
        }
    }
    else
    {
        const char* colon = std::strchr(text, ':');
        if (colon != nullptr && std::strchr(colon + 1, ':') == nullptr)
        {
            size_t name_length = static_cast<size_t>(colon - text);
            std::memcpy(name, text, name_length);
            name[name_length] = '\0';
            port_text = colon + 1;
        }
        else
        {
            std::memcpy(name, text, length + 1);
        }
    }
    if (port_text != nullptr)
    {
        char* end = nullptr;
        unsigned long value = std::strtoul(port_text, &end, 10);
        if (*port_text == '\0' || *end != '\0' || value == 0 || value > 65535)
        {
            return 0;
        }
        port = static_cast<uint16_t>(value);
    }

    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* list = nullptr;
    if (getaddrinfo(name, nullptr, &hints, &list) != 0)
    {
        host_log(LogLevel::warning, "Network: unknown server \"%s\"", name);
        return 0;
    }
    bool have_ipv4 = false;
    bool have_ipv6 = false;
    uint32_t count = 0;
    for (addrinfo* item = list; item != nullptr && count < 2; item = item->ai_next)
    {
        NetAddress address;
        if (item->ai_family == AF_INET && !have_ipv4)
        {
            const sockaddr_in* v4 = reinterpret_cast<const sockaddr_in*>(item->ai_addr);
            address.ip[10] = 0xFF;
            address.ip[11] = 0xFF;
            std::memcpy(address.ip + 12, &v4->sin_addr, 4);
            have_ipv4 = true;
        }
        else if (item->ai_family == AF_INET6 && !have_ipv6)
        {
            const sockaddr_in6* v6 = reinterpret_cast<const sockaddr_in6*>(item->ai_addr);
            std::memcpy(address.ip, &v6->sin6_addr, 16);
            address.scope = static_cast<uint16_t>(v6->sin6_scope_id);
            have_ipv6 = true;
        }
        else
        {
            continue;
        }
        address.port = port;
        out[count++] = address;
    }
    freeaddrinfo(list);
    return count;
}
