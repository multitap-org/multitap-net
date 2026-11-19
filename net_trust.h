#pragma once

// Who we are and whom we trust, on disk.
//
// Identity: this device's static key (Noise), made once and kept in its own
// file, readable only by the user (host_fs_write_private_file):
//   secret = <64 hex digits>
// Losing it means every paired device has to pair again; copying it to
// another machine makes that machine this device.
//
// Trusted devices: the other side of every pairing (on a host: the clients
// allowed in; on a client: the hosts it paired with), one section each:
//   [device:<public key, 64 hex digits>]
//   name = Ana's phone
//   own = true          a device of this machine's owner (headless later)
//   paired = 2026-11-19
// A key is the identity: the name is only what the device called itself
// when it paired (shown, never trusted for anything).

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "net_noise.h"

constexpr size_t NET_DEVICE_NAME_MAX = 63;   // bytes of UTF-8

struct NetTrustedDevice
{
    uint8_t     key[NET_KEY_SIZE] = {};
    std::string name;
    bool        own = false;
    std::string paired;   // "YYYY-MM-DD"
};

struct NetTrust
{
    std::vector<NetTrustedDevice> devices;
};

// Reads the identity at `path`, or makes one and saves it there. False only
// if there's no randomness or it can't be saved (then networking stays off:
// a key that changes every launch would undo every pairing).
bool net_identity_load_or_create(const char* path, NetKeypair* identity);

// A missing file is an empty list. Malformed sections are logged and skipped.
bool net_trust_load(NetTrust* trust, const char* path);
bool net_trust_save(const NetTrust* trust, const char* path);

// Index of the device with this key, or -1.
int32_t net_trust_find(const NetTrust* trust, const uint8_t* key);
// Adds a device (or renames an existing one), dated today. Returns its index.
uint32_t net_trust_add(NetTrust* trust, const uint8_t* key, const char* name);
void net_trust_remove(NetTrust* trust, uint32_t index);

// "6f1c...e2" -> bytes. False unless exactly 2 * size hex digits.
bool net_hex_to_bytes(const char* hex, uint8_t* out, size_t size);
void net_bytes_to_hex(const uint8_t* data, size_t size, char* out, size_t capacity);
