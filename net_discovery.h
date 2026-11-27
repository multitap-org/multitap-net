#pragma once

// LAN discovery packets, as pure functions (no sockets): net_host.h sends and
// receives them on its one UDP port, next to ENet's own traffic.
//
// How discovery works: a client (piccoletto, another piccolo) broadcasts a
// REQUEST to the port; every host that hears it answers the sender with a
// REPLY by unicast. The client asks and the host answers (not the host
// announcing itself) because receiving broadcasts is what platforms make
// hard (Android needs a MulticastLock and filters them with the screen off);
// sending one and getting a unicast answer is not.
//
// Layout (little-endian, fixed offsets), version 2 (2026-11-25):
//   REQUEST  "MTAP" | type 1 | version | 0 0 | nonce (u32)            12 bytes
//   REPLY    "MTAP" | type 2 | version | 0 0 | nonce (u32)
//            | port (u16) | kind (u8) | offers (u32) | flags (u8)
//            | name length (u8) | name (UTF-8, no NUL)                21 + name
// Version 3 (2026-11-26) adds the first 8 bytes of the device's public key
// after the flags, so a list can tell "already paired" by key, not by name
// (every install may be called PICCOLO):
//   REPLY v3 ... | flags (u8) | key_id (8 bytes) | name length (u8) | name   29 + name
// flags bit 1: key_id is filled.
// Requests and replies are both version 3: a host only answers requests of its
// own version, so builds from before it don't see newer ones on the LAN
// (nothing was released with them; Andrés, 2026-11-26).
// The nonce lets a client match replies to its own request and ignore stale
// ones. `port` is where the host's ENet listens (today the same port).
// `kind` and `offers` say what the device is and what it serves (net_trust.h:
// NetAppKind, NetCaps), so a device lists only those it can use (Andrés,
// 2026-11-25: offers go in discovery, never through the beacon). flags bit 0:
// it says it's a signed build (only a hint for the list: the build proof is
// checked once connected). A version 1 reply (port and name only) still reads,
// with no kind or offers.
// Requests go to both ports a device may listen on: NET_DEFAULT_PORT
// (piccolo) and NET_PICCOLINO_PORT (piccolino).
//
// Why ENet never mistakes these for its own packets (they share the socket,
// and our check runs first, see net_host.cpp): ENet reads the first two bytes
// as its header, big-endian. "MT" = 0x4D54 has the COMPRESSED flag set and
// peer id 0xD54 (3412): a host without a compressor, or with fewer than 3413
// peers, drops it. Ours have no compressor and a handful of peers.

#include <cstddef>
#include <cstdint>

constexpr uint8_t NET_DISCOVERY_VERSION = 3;           // the newest reply
constexpr size_t  NET_DISCOVERY_KEY_ID_SIZE = 8;       // the first bytes of the device's public key
constexpr size_t  NET_DISCOVERY_MAX_NAME = 63;   // bytes of UTF-8
constexpr size_t  NET_DISCOVERY_REQUEST_SIZE = 12;
constexpr size_t  NET_DISCOVERY_REPLY_HEADER_SIZE = 21;
constexpr size_t  NET_DISCOVERY_V1_REPLY_HEADER_SIZE = 15;
constexpr size_t  NET_DISCOVERY_V3_REPLY_HEADER_SIZE = NET_DISCOVERY_REPLY_HEADER_SIZE + NET_DISCOVERY_KEY_ID_SIZE;
constexpr size_t  NET_DISCOVERY_MAX_PACKET = NET_DISCOVERY_V3_REPLY_HEADER_SIZE + NET_DISCOVERY_MAX_NAME;

struct NetDiscoveryReply
{
    uint8_t  version = NET_DISCOVERY_VERSION;   // 1: an old device (no kind, no offers); 2: no key_id; written: 2 or 3
    uint32_t nonce = 0;
    uint16_t port = 0;
    uint8_t  kind = 0;          // NetAppKind
    uint32_t offers = 0;        // NetCaps
    bool     signed_build = false;
    uint8_t  key_id[NET_DISCOVERY_KEY_ID_SIZE] = {};   // version 3: the first bytes of its public key
    bool     key_id_known = false;                     // false from a version 1 or 2 device
    char     name[NET_DISCOVERY_MAX_NAME + 1] = {};   // NUL-terminated
};

// Each write returns the packet's size, or 0 if `capacity` is too small. A
// reply is written in its `version`: 3 (the default) or 2 (no key_id).
size_t net_discovery_write_request(uint8_t* out, size_t capacity, uint32_t nonce);

// The name is cut by whoever fills it (net_host cuts at a UTF-8 boundary).
size_t net_discovery_write_reply(uint8_t* out, size_t capacity, const NetDiscoveryReply* reply);

// False (silently: anyone can send anything to an open port) when the data
// isn't exactly that packet (a request of this version; a reply of version 1,
// 2 or 3). The name comes back cleaned (net_name_clean).
bool net_discovery_read_request(const uint8_t* data, size_t size, uint32_t* nonce);
bool net_discovery_read_reply(const uint8_t* data, size_t size, NetDiscoveryReply* reply);
