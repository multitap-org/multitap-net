#pragma once

// Encrypted connections: net_host.h (ENet, one UDP port, discovery) with a
// net_link.h per peer. What frontends use; they never see a byte in the clear
// from the network that the link hasn't authenticated.
//
// A connection is reported (`secured`) only once its Noise handshake is done,
// with the peer's device key. Whether that key is trusted is the frontend's
// call (pairing, milestone 3); until it decides, it should send nothing and
// act on nothing. A handshake that fails, or doesn't finish within
// NET_SESSION_HANDSHAKE_SECONDS, closes the connection.
//
// Buffers are made at creation: polling and sending don't allocate (ENet
// still allocates a packet per send; see docs/design-notes.md).

#include <cstddef>
#include <cstdint>
#include <vector>

#include "net_host.h"
#include "net_link.h"

constexpr double NET_SESSION_HANDSHAKE_SECONDS = 5.0;

struct NetSessionPeer
{
    bool    connected = false;     // ENet connected (handshake running or done)
    bool    initiator = false;     // we connected to them
    bool    secured_reported = false;
    double  connected_at = 0.0;    // seconds (steady clock), for the handshake deadline
    NetLink link;
};

enum class NetSessionEventType
{
    none,
    discovered,   // a discovery reply (`discovered`, from `address`)
    secured,      // handshake done: `peer`, `remote_key`, `handshake_hash`
    message,      // `data`/`size` on `channel` from a secured `peer`
    closed,       // `peer` is gone (`was_secured`: whether `secured` was ever reported)
};

struct NetSessionEvent
{
    NetSessionEventType type = NetSessionEventType::none;
    uint32_t       peer = NET_NO_PEER;
    NetAddress     address;
    NetChannel     channel = NetChannel::control;
    const uint8_t* data = nullptr;   // message: valid until the next net_session_poll
    size_t         size = 0;
    bool           was_secured = false;
    uint8_t        remote_key[NET_KEY_SIZE] = {};
    uint8_t        handshake_hash[NET_HASH_SIZE] = {};
    NetDiscoveryReply discovered;
};

struct NetSession
{
    NetHost        host;
    NetKeypair     identity;           // our device key
    NetSessionPeer peers[NET_MAX_PEERS];
    std::vector<uint8_t> wire;         // sealed packets / handshake replies
    std::vector<uint8_t> payload;      // opened messages
    double         handshake_seconds = NET_SESSION_HANDSHAKE_SECONDS;   // tests shorten it
};

// `identity` is copied (and wiped on destroy).
bool net_session_create_listener(NetSession* session, uint16_t port, const char* name, const NetKeypair* identity);
bool net_session_create_client(NetSession* session, const NetKeypair* identity);
void net_session_destroy(NetSession* session);

// One event per call; call until false, once per frame. Never blocks.
bool net_session_poll(NetSession* session, NetSessionEvent* event);

bool net_session_discover(NetSession* session, uint16_t port);
bool net_session_discover_at(NetSession* session, NetAddress address);
// `secured` (or `closed`) follows from net_session_poll.
bool net_session_connect(NetSession* session, NetAddress address, uint32_t* peer);
// Only to a secured peer; at most NET_LINK_MAX_PAYLOAD bytes.
bool net_session_send(NetSession* session, uint32_t peer, NetChannel channel, const uint8_t* data, size_t size);
void net_session_close(NetSession* session, uint32_t peer);

// Seconds on a steady clock (for network timers).
double net_seconds();

// A short, readable form of a device key for logs and screens:
// "3fa2-91c0-7d4e-b815" (the first 8 bytes of BLAKE2b(key), hex in groups).
void net_key_fingerprint(const uint8_t* key, char* out, size_t capacity);
