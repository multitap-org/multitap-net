#pragma once

// One UDP port for everything network: ENet (deps/enet, MIT) for connections
// with a reliable and an unreliable channel, and our own datagrams on the same
// socket (LAN discovery, the beacon's messages: net_beacon.h) picked out
// before ENet sees them.
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
// IPv6 and IPv4 on the same socket (zpl-c's ENet, dual-stack): a host listens
// on both, and IPv4 peers show up as IPv4-mapped addresses (::ffff:a.b.c.d).
// LAN discovery is IPv4 broadcast (every LAN has IPv4); IPv6 matters across
// the internet, where it often avoids NAT altogether.

#include <cstddef>
#include <cstdint>
#include <string>

#include "beacon_wire.h"
#include "net_discovery.h"

struct _ENetHost;
struct _ENetPacket;
struct NetRtc;

constexpr uint16_t NET_DEFAULT_PORT = 55420;
constexpr uint16_t NET_PICCOLINO_PORT = 55421;   // piccolino listens here (discovery asks both)
constexpr uint32_t NET_MAX_PEERS = 8;
constexpr uint32_t NET_NO_PEER = UINT32_MAX;
constexpr uint32_t NET_MAX_DISCOVERED = 16;   // replies kept between two polls; more are dropped
constexpr uint32_t NET_MAX_BEACON_QUEUED = 16;   // beacon messages kept between two polls; more are dropped

enum class NetChannel : uint8_t
{
    control = 0,
    input = 1,    // unreliable, sequenced: pads, test packets
    stream = 2,   // unreliable, sequenced: remote play's frames and audio (net_stream.h)
    files = 3,    // reliable, in order: file transfers (piccolo-share), apart from control so a
                  // lost chunk never holds control's sequence up
};
// A peer built before `files` asks for 3 channels: ENet clamps both ways, so
// it still connects; net_host_send refuses `files` to it.
constexpr uint8_t NET_CHANNEL_COUNT = 4;

// An address and port. IPv6, with IPv4 addresses kept IPv4-mapped
// (::ffff:a.b.c.d), as the dual-stack socket sees them.
struct NetAddress
{
    uint8_t  ip[16] = {};   // network byte order
    uint16_t port = 0;
    uint16_t scope = 0;     // the interface of a link-local address (fe80::...), else 0
};

enum class NetEventType
{
    none,
    connected,      // a peer finished connecting (either side)
    disconnected,   // a peer left or timed out; `peer` is free again
    received,       // `data`/`size` on `channel`, from `peer`
    discovered,     // a discovery reply (`discovered`, from `address`)
    beacon,         // a beacon message (`beacon`, from `address`): from a beacon server or a PUNCH from a peer
    signal,         // WebRTC: a blob (`data`/`size`) for the other side of `peer`, to send by signaling
};

// How a peer is connected. The same channels and bytes either way; only
// NetHost knows (Andrés: the flow is the same over RTC or UDP).
enum class NetTransport : uint8_t
{
    enet,   // UDP, our own socket (LAN, beacon hole punching)
    rtc,    // WebRTC data channels (browsers; net_rtc.h)
};

// A peer number as everything above NetHost sees it, and what it is below.
// WebRTC peers have no ENet underneath to say goodbye or measure the round
// trip, so NetHost does both itself with small frames of its own on the
// input channel (net_host.cpp: "NetHost's own frames"). ENet peers don't
// need them.
constexpr double   NET_HOST_PING_SECONDS = 0.5;    // a ping to each WebRTC peer this often
constexpr uint32_t NET_HOST_PING_WINDOW = 8;       // loss: pongs missing out of the last this many pings
constexpr double   NET_HOST_BYE_SECONDS = 0.1;     // a closing WebRTC peer: closed this long after its bye

struct NetHostSlot
{
    bool         used = false;
    NetTransport transport = NetTransport::enet;
    uint32_t     index = 0;   // the backend's peer number
    // WebRTC only (NetHost's own frames):
    double       closing_at = -1.0;     // bye sent: closed then (-1 = not closing)
    double       next_ping = 0.0;
    uint32_t     ping_seq = 0;          // the last ping's number
    uint32_t     window_pings = 0;      // pings and pongs in the current loss window
    uint32_t     window_pongs = 0;
    uint32_t     pongs = 0;             // pongs ever (0 = no round trip known yet)
    float        round_trip_ms = 0.0f;  // smoothed like ENet's (1/8 per sample)
    float        jitter_ms = 0.0f;      // its mean deviation (1/4 per sample)
    float        loss = 0.0f;           // of the last full window, 0..1
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
    BeaconMessage  beacon;
};

struct NetHost
{
    _ENetHost*  enet = nullptr;
    bool        listener = false;
    std::string name;                  // answered to discovery requests (listener)
    uint8_t     discovery_kind = 0;    // and these with it (net_host_set_discovery_info)
    uint32_t    discovery_offers = 0;
    bool        discovery_signed = false;
    uint8_t     discovery_key_id[NET_DISCOVERY_KEY_ID_SIZE] = {};   // net_host_set_discovery_key
    bool        discovery_key_id_known = false;
    _ENetPacket* held_packet = nullptr;   // the last `received` packet, freed at the next poll
    uint32_t    discovery_nonce = 0;   // of our last request (client)
    NetDiscoveryReply discovered[NET_MAX_DISCOVERED];
    NetAddress  discovered_from[NET_MAX_DISCOVERED];
    uint32_t    discovered_count = 0;
    uint32_t    discovery_requests_answered = 0;
    BeaconMessage beacon_queue[NET_MAX_BEACON_QUEUED];
    NetAddress  beacon_from[NET_MAX_BEACON_QUEUED];
    uint32_t    beacon_count = 0;
    NetHostSlot slots[NET_MAX_PEERS];
    uint32_t    enet_slot[NET_MAX_PEERS];   // ENet peer -> slot (NET_NO_PEER)
    uint32_t    rtc_slot[NET_MAX_PEERS];    // WebRTC peer -> slot (NET_NO_PEER)
    NetRtc*     rtc = nullptr;              // WebRTC, once net_host_enable_rtc
    bool        files_refused_logged = false;   // a peer without the `files` channel (logged once)
    uint32_t    rtc_byes_received = 0;      // WebRTC peers that said goodbye (counted for the tests)
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

// Client: ask every listener on the LAN (IPv4 broadcast to 255.255.255.255:`port`),
// or one address. Replies come back as `discovered` events.
bool net_host_discover(NetHost* host, uint16_t port);
// To both ports devices listen on (NET_DEFAULT_PORT, NET_PICCOLINO_PORT), one
// request (the same nonce).
bool net_host_discover_devices(NetHost* host);
// A listener: what it answers besides its name (net_discovery.h).
void net_host_set_discovery_info(NetHost* host, uint8_t kind, uint32_t offers, bool signed_build);
// A listener: its public key (NET_KEY_SIZE bytes), of which discovery answers
// carry the first NET_DISCOVERY_KEY_ID_SIZE (version 3). Without it the
// answers say no key.
void net_host_set_discovery_key(NetHost* host, const uint8_t* public_key);
bool net_host_discover_at(NetHost* host, NetAddress address);

// One datagram of our own (a beacon message) on the host's socket, outside
// ENet: what NAT traversal needs (the beacon must see the socket ENet uses).
bool net_host_send_datagram(NetHost* host, NetAddress to, const uint8_t* data, size_t size);

// Starts connecting; `connected` (or `disconnected`) follows from net_host_poll.
bool net_host_connect(NetHost* host, NetAddress address, uint32_t* peer);
bool net_host_send(NetHost* host, uint32_t peer, NetChannel channel, const uint8_t* data, size_t size);
// How a connection is doing, as ENet measures it on its own (it pings an
// idle peer every 500 ms): the round trip (smoothed), how much it varies
// (jitter) and the share of reliable packets it had to send again. Round
// trip, there and back, not one way.
struct NetLinkStats
{
    uint32_t round_trip_ms = 0;
    uint32_t jitter_ms = 0;
    float    loss = 0.0f;   // 0..1
};

// Bytes of reliable data for this peer still on their way: sent and not yet
// acknowledged, plus queued and not sent yet (control and files). What a
// sender paces against (piccolo-share sends a chunk only below ~128 KiB):
// ENet shares one window between a peer's reliable channels, so this is what
// keeps control from waiting behind file data. 0 if `peer` isn't connected.
size_t net_host_peer_pending(const NetHost* host, uint32_t peer);

// False if `peer` isn't connected.
bool net_host_peer_stats(const NetHost* host, uint32_t peer, NetLinkStats* stats);
bool net_host_peer_address(const NetHost* host, uint32_t peer, NetAddress* address);

// Polite: queued data is sent first, then `disconnected` follows.
void net_host_disconnect(NetHost* host, uint32_t peer);
NetTransport net_host_peer_transport(const NetHost* host, uint32_t peer);

// --- WebRTC (net_rtc.h): the same peers, through data channels -----------
// Signaling is the caller's: `signal` events carry blobs for the other side,
// and what it sends back goes in through net_host_rtc_signal.

// False if this build has no WebRTC. `stun` = "stun:host:port" or nullptr.
bool net_host_enable_rtc(NetHost* host, const char* stun);
// The side that offers (client): its offer comes out as a `signal` event.
bool net_host_rtc_connect(NetHost* host, uint32_t* peer);
// The side that answers (host), for an offer that came by signaling (feed it
// in with net_host_rtc_signal next).
bool net_host_rtc_accept(NetHost* host, uint32_t* peer);
bool net_host_rtc_signal(NetHost* host, uint32_t peer, const uint8_t* data, size_t size);

// "192.168.1.20", "2001:db8::5", "[2001:db8::5]", "fe80::1%wlan0" or a host
// name (resolved, may block; the first address it has) -> address.
bool net_address_from_text(const char* text, uint16_t port, NetAddress* address);
// "192.168.1.20:55420" for IPv4, "[2001:db8::5]:55420" for IPv6.
void net_address_to_text(NetAddress address, char* out, size_t capacity);
// An IPv4 address (IPv4-mapped).
bool net_address_is_ipv4(NetAddress address);
// Same ip, port and scope.
bool net_address_equal(NetAddress a, NetAddress b);

// A server name as people write it: "beacon.example.org", "beacon.example.org:55430",
// "203.0.113.5", "[2001:db8::5]:55430". Resolves it (blocks: DNS) to at most one
// IPv4 and one IPv6 address (`out` holds 2), `default_port` when none is given.
// Returns how many addresses it found (0 = unknown name or bad text).
uint32_t net_address_resolve(const char* text, uint16_t default_port, NetAddress* out);
