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
// Layout (little-endian, fixed offsets):
//   REQUEST  "MTAP" | type 1 | version | 0 0 | nonce (u32)            12 bytes
//   REPLY    "MTAP" | type 2 | version | 0 0 | nonce (u32)
//            | port (u16) | name length (u8) | name (UTF-8, no NUL)   15 + name
// The nonce lets a client match replies to its own request and ignore stale
// ones. `port` is where the host's ENet listens (today the same port).
//
// Why ENet never mistakes these for its own packets (they share the socket,
// and our check runs first, see net_host.cpp): ENet reads the first two bytes
// as its header, big-endian. "MT" = 0x4D54 has the COMPRESSED flag set and
// peer id 0xD54 (3412): a host without a compressor, or with fewer than 3413
// peers, drops it. Ours have no compressor and a handful of peers.

#include <cstddef>
#include <cstdint>

constexpr uint8_t NET_DISCOVERY_VERSION = 1;
constexpr size_t  NET_DISCOVERY_MAX_NAME = 63;   // bytes of UTF-8
constexpr size_t  NET_DISCOVERY_REQUEST_SIZE = 12;
constexpr size_t  NET_DISCOVERY_REPLY_HEADER_SIZE = 15;
constexpr size_t  NET_DISCOVERY_MAX_PACKET = NET_DISCOVERY_REPLY_HEADER_SIZE + NET_DISCOVERY_MAX_NAME;

struct NetDiscoveryReply
{
    uint32_t nonce = 0;
    uint16_t port = 0;
    char     name[NET_DISCOVERY_MAX_NAME + 1] = {};   // NUL-terminated
};

// Each write returns the packet's size, or 0 if `capacity` is too small.
size_t net_discovery_write_request(uint8_t* out, size_t capacity, uint32_t nonce);

// The name is cut by whoever fills it (net_host cuts at a UTF-8 boundary).
size_t net_discovery_write_reply(uint8_t* out, size_t capacity, const NetDiscoveryReply* reply);

// False (silently: anyone can send anything to an open port) when the data
// isn't exactly that packet of our version.
bool net_discovery_read_request(const uint8_t* data, size_t size, uint32_t* nonce);
bool net_discovery_read_reply(const uint8_t* data, size_t size, NetDiscoveryReply* reply);
