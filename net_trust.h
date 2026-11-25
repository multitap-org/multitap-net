#pragma once

// Who we are and whom we trust, on disk.
//
// Identity: this device's static key (Noise), made once and kept in its own
// file, readable only by the user (host_fs_write_private_file):
//   secret = <64 hex digits>
// Losing it means every paired device has to pair again; copying it to
// another machine makes that machine this device.
//
// Paired devices: the other side of every pairing, one section each, both
// directions in one record (Andrés, 2026-11-25: one record per device):
//   [device:<public key, 64 hex digits>]
//   name = Ana's phone        what the device calls itself (sent at every connection)
//   kind = piccoletto         piccolo, piccoletto or piccolino (shown; never trusted)
//   grants = gamepad,settings what it may use here (NetCaps; empty = nothing)
//   granted = share           what it lets us use there, as it last said (shown only)
//   signed = true             its build was signed by Multitap when it last connected
//   paired = 2026-11-19
// Older lists migrate on load: "access = <level>" (the ladder before
// 2026-11-25) becomes the set of capabilities that level covered, and
// "own = true" (before access existed) becomes every capability.
// A key is the identity: the name is only shown, never trusted for anything.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "net_noise.h"

constexpr size_t NET_DEVICE_NAME_MAX = 63;   // bytes of UTF-8

// What a device may use on another (Andrés, 2026-11-25: independent bits, Q10).
// Each bit is one capability; none implies another. A device offers some
// (what it can serve) and uses some (what it can make use of); what a peer
// gets is the stored grant ∩ what this device offers ∩ what the peer uses.
using NetCaps = uint32_t;
constexpr NetCaps NET_CAP_GAMEPAD = 1u << 0;    // play with its pads (and the game's hotkeys)
constexpr NetCaps NET_CAP_STREAM = 1u << 1;     // receive the game's video and audio (remote play)
constexpr NetCaps NET_CAP_SETTINGS = 1u << 2;   // configure the frontend, browse and load games (was FULL)
constexpr NetCaps NET_CAP_SHARE = 1u << 3;      // read and write files in the shared folders (file transfer)
constexpr NetCaps NET_CAPS_ALL = NET_CAP_GAMEPAD | NET_CAP_STREAM | NET_CAP_SETTINGS | NET_CAP_SHARE;
constexpr uint32_t NET_CAP_COUNT = 4;

// "gamepad,stream,settings,share" (in bit order; "" for none). Unknown bits
// are left out.
std::string net_caps_name(NetCaps caps);
// A comma list of the names above, spaces allowed; "" is nothing. False on
// an unknown name (then *caps is untouched).
bool net_caps_parse(const char* text, NetCaps* caps);
// The set an old ladder level covered (before 2026-11-25): gamepad; stream =
// gamepad + stream; share = gamepad + stream + share; full and owner = all.
bool net_caps_from_level(const char* level, NetCaps* caps);

// What kind of program a device is: shown on screens and used to word them;
// never trusted for anything.
enum class NetAppKind : uint8_t
{
    piccolo = 0,
    piccoletto = 1,
    piccolino = 2,
};
constexpr uint32_t NET_APP_KIND_COUNT = 3;
const char* net_app_kind_name(NetAppKind kind);   // "piccolo", "piccoletto", "piccolino"
bool net_app_kind_parse(const char* name, NetAppKind* kind);

struct NetTrustedDevice
{
    uint8_t       key[NET_KEY_SIZE] = {};
    std::string   name;
    NetAppKind kind = NetAppKind::piccolo;
    NetCaps       grants = 0;          // what it may use here
    NetCaps       granted = 0;         // what it said we may use there (last known)
    bool          signed_build = false;   // last known
    std::string   paired;   // "YYYY-MM-DD"
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

// One file, two writers: the host side (net_access.h) and the client side
// (net_client.h) of the same device each keep a copy of the paired devices,
// on their own threads. A change is made under the file lock on a fresh copy
// (lock, load, change, save, unlock), and every save moves the generation on;
// a side whose copy is older loads it again. (A process-wide lock: the file is
// the process's, and the two sides are separate objects that don't know each
// other.)
void     net_trust_file_lock();
void     net_trust_file_unlock();
uint32_t net_trust_generation();

// Index of the device with this key, or -1.
int32_t net_trust_find(const NetTrust* trust, const uint8_t* key);
// Adds a device (or renames an existing one, keeping its grants), dated
// today. Returns its index.
uint32_t net_trust_add(NetTrust* trust, const uint8_t* key, const char* name);
// The name a device sent when it connected; true if it changed (save then).
bool net_trust_rename(NetTrust* trust, uint32_t index, const char* name);
void net_trust_remove(NetTrust* trust, uint32_t index);

// Before 2026-11-25 a device kept two lists: whom it lets in (devices) and
// whom it goes to (hosts). If the old hosts list at `old_hosts_path` exists,
// its devices join `trust` (those already there keep their record; the rest
// get no grants, and what they grant us is learned at the next connection),
// `trust` is saved to `path` and the old file is renamed to <name>.old.
// False only if saving fails (the old file then stays, to try again).
bool net_trust_merge_old_hosts(NetTrust* trust, const char* path, const char* old_hosts_path);

// "6f1c...e2" -> bytes. False unless exactly 2 * size hex digits.
bool net_hex_to_bytes(const char* hex, uint8_t* out, size_t size);
void net_bytes_to_hex(const uint8_t* data, size_t size, char* out, size_t capacity);
