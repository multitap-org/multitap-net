#pragma once

// One UDP port for everything network: ENet (deps/enet, MIT) for connections
// with a reliable and an unreliable channel, and our own datagrams on the same
// socket (LAN discovery today, STUN later) picked out before ENet sees them.
//
// ENet stays behind this module: nothing else includes enet.h. No SDL either,
// so a headless piccolo or a host process could use it as it is.
//
// Two kinds of NetHost:
//   - listener: bound to a known port (NET_DEFAULT_PORT unless configured),
//     accepts connections and answers discovery requests with its name;
//   - client: an ephemeral port; sends discovery requests and connects.
// Both are polled from the caller's loop (net_host_poll, never blocks).
//
// Channels (decided 2026-11-19, see docs/design-notes.md "Netcode"):
//   control  reliable, in order: everything that must arrive
//   input    unreliable, sequenced (late packets are dropped, never
//            reordered): input frames, which carry the last few frames each
//            so a lost packet costs nothing. The same stream serves remote
//            input (piccoletto) and later rollback netplay.
//
// Nothing here authenticates or encrypts yet (milestones 2-3): a frontend
// must not act on what connected peers send until then.
//
// IPv4 only for now (upstream ENet); IPv6 is revisited with NAT traversal.

#include <cstddef>
#include <cstdint>
#include <string>

#include "net_discovery.h"

struct _ENetHost;
struct _ENetPacket;

constexpr uint16_t NET_DEFAULT_PORT = 55420;
constexpr uint32_t NET_MAX_PEERS = 8;
constexpr uint32_t NET_NO_PEER = UINT32_MAX;
constexpr uint32_t NET_MAX_DISCOVERED = 16;   // replies kept between two polls; more are dropped

enum class NetChannel : uint8_t
{
    control = 0,
    input = 1,
};
constexpr uint8_t NET_CHANNEL_COUNT = 2;

// IPv4 address and port. `host` is in network byte order, as ENet keeps it.
struct NetAddress
{
    uint32_t host = 0;
    uint16_t port = 0;
};

enum class NetEventType
{
    none,
    connected,      // a peer finished connecting (either side)
    disconnected,   // a peer left or timed out; `peer` is free again
    received,       // `data`/`size` on `channel`, from `peer`
    discovered,     // a discovery reply (`discovered`, from `address`)
};

struct NetEvent
{
    NetEventType type = NetEventType::none;
    uint32_t     peer = NET_NO_PEER;   // index, stable while connected
    NetAddress   address;              // the peer's or the replying host's
    NetChannel   channel = NetChannel::control;
    const uint8_t* data = nullptr;     // received: valid until the next net_host_poll
    size_t       size = 0;
    NetDiscoveryReply discovered;
};

struct NetHost
{
    _ENetHost*  enet = nullptr;
    bool        listener = false;
    std::string name;                  // answered to discovery requests (listener)
    _ENetPacket* held_packet = nullptr;   // the last `received` packet, freed at the next poll
    uint32_t    discovery_nonce = 0;   // of our last request (client)
    NetDiscoveryReply discovered[NET_MAX_DISCOVERED];
    NetAddress  discovered_from[NET_MAX_DISCOVERED];
    uint32_t    discovered_count = 0;
    uint32_t    discovery_requests_answered = 0;
};

// ENet's global setup (WSAStartup on Windows). Counted: each successful
// net_init() needs one net_shutdown().
bool net_init();
void net_shutdown();

// `port` 0 = any free port (tests). `name` is cut to NET_DISCOVERY_MAX_NAME bytes.
bool net_host_create_listener(NetHost* host, uint16_t port, const char* name);
bool net_host_create_client(NetHost* host);
// Disconnects every peer at once (no goodbye round trip) and frees everything.
void net_host_destroy(NetHost* host);

// The port the host is bound to (0 for a client before its first send).
uint16_t net_host_port(const NetHost* host);

// One event per call; call until it returns false, once per frame. Sends what
// is queued too. Never blocks.
bool net_host_poll(NetHost* host, NetEvent* event);

// Client: ask every listener on the LAN (broadcast to 255.255.255.255:`port`),
// or one address. Replies come back as `discovered` events.
bool net_host_discover(NetHost* host, uint16_t port);
bool net_host_discover_at(NetHost* host, NetAddress address);

// Starts connecting; `connected` (or `disconnected`) follows from net_host_poll.
bool net_host_connect(NetHost* host, NetAddress address, uint32_t* peer);
bool net_host_send(NetHost* host, uint32_t peer, NetChannel channel, const uint8_t* data, size_t size);
// Polite: queued data is sent first, then `disconnected` follows.
void net_host_disconnect(NetHost* host, uint32_t peer);

// "192.168.1.20" or a host name (resolved, may block) -> address.
bool net_address_from_text(const char* text, uint16_t port, NetAddress* address);
// "192.168.1.20:55420".
void net_address_to_text(NetAddress address, char* out, size_t capacity);
