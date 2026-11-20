#include "net_host.h"

#include <cstdio>
#include <cstring>
#include <random>

#include <enet.h>

#include "host_log.h"
#include "net_memory.h"

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

static bool host_create(NetHost* host, const ENetAddress* bind_address)
{
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

static uint32_t peer_index(const NetHost* host, const ENetPeer* peer)
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
        return false;
    }
    if (take_discovered(host, event))
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
        return take_discovered(host, event);
    }

    event->peer = peer_index(host, enet_event.peer);
    event->address = address_from_enet(&enet_event.peer->address);
    switch (enet_event.type)
    {
    case ENET_EVENT_TYPE_CONNECT:
        event->type = NetEventType::connected;
        break;
    case ENET_EVENT_TYPE_DISCONNECT:
    case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT:   // zpl-c's ENet tells a timeout apart; same to us
        event->type = NetEventType::disconnected;
        break;
    case ENET_EVENT_TYPE_RECEIVE:
        event->type = NetEventType::received;
        event->channel = static_cast<NetChannel>(enet_event.channelID);
        event->data = enet_event.packet->data;
        event->size = enet_event.packet->dataLength;
        host->held_packet = enet_event.packet;
        break;
    case ENET_EVENT_TYPE_NONE:
        return false;
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
    *peer = peer_index(host, enet_peer);
    return true;
}

static ENetPeer* peer_get(NetHost* host, uint32_t peer)
{
    if (host->enet == nullptr || peer >= host->enet->peerCount)
    {
        return nullptr;
    }
    return &host->enet->peers[peer];
}

bool net_host_send(NetHost* host, uint32_t peer, NetChannel channel, const uint8_t* data, size_t size)
{
    ENetPeer* enet_peer = peer_get(host, peer);
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
    if (host->enet == nullptr || peer >= host->enet->peerCount)
    {
        return false;
    }
    const ENetPeer* enet_peer = &host->enet->peers[peer];
    if (enet_peer->state != ENET_PEER_STATE_CONNECTED)
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
    if (host->enet == nullptr || peer >= host->enet->peerCount ||
        host->enet->peers[peer].state != ENET_PEER_STATE_CONNECTED)
    {
        return false;
    }
    *address = address_from_enet(&host->enet->peers[peer].address);
    return true;
}

void net_host_disconnect(NetHost* host, uint32_t peer)
{
    ENetPeer* enet_peer = peer_get(host, peer);
    if (enet_peer != nullptr)
    {
        enet_peer_disconnect_later(enet_peer, 0);
    }
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
