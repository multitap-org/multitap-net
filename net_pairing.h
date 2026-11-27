#pragma once

// Pairing and access messages, as pure functions. They travel on the control
// channel of a secured connection (net_session.h): already encrypted, with
// both device keys known. net_access.h (the side that was connected to: the
// host) and net_client.h (the side that connected: the client) run the flow.
//
// Every control message starts with a type byte. Types below
// NET_MESSAGE_FIRST_APP belong to this layer; the rest are the application's,
// and the type says the capability it needs (net_message_required_cap):
//   16..63 GAMEPAD, 64..127 STREAM, 128..191 SETTINGS, 192..255 SHARE,
// except the action messages (NET_MESSAGE_FIRST_ACTION..LAST_ACTION, inside
// the GAMEPAD range): any of GAMEPAD, STREAM or SETTINGS lets them through.
// Each range is one capability (independent bits, net_trust.h). The host
// drops what a device's capabilities don't cover; the client is told what it
// has (welcome) only to show it.
//
// Both sides describe themselves once per connection (NetDeviceInfo: name,
// kind, what it offers, what it uses, its build proof):
//   client -> host  hello            my info (first, on every connection)
//   host -> client  welcome          you're a paired device: what you may use here + my info
//   host -> client  pairing_needed   you're not; pairing open?  + my info
//   client -> host  pair_ask         please pair (the host makes and shows a code)
//   client -> host  pair_request     CPace share Ya (the code my user typed)
//   host -> client  pair_response    CPace share Yb, host confirm
//   client -> host  pair_confirm     client confirm
//   host -> client  pair_result      ok / refused
//   either side     grant            what you may use on me (after pairing, and whenever it changes)
//   either side     unpair           I forget you: forget me (then the sender closes)
//
// Unpairing (Andrés, 2026-11-19) starts on either side: if the other side is
// connected now it's told (unpair) and forgets the sender too; if not, the
// sender only forgets it locally. The sender closes the connection (only
// one side may close, net_host.h); the other side just forgets.
//
// Who has the code (Andrés, 2026-11-25): the device that receives the
// pairing request, because it's the one granting. Here that's the host: on
// pair_ask it makes the 9-digit code and shows it with what the client may
// use (net_access.h: pairing_requested), and the client's user types it
// (pair_request). Across the internet the host shows the code first
// (GENERATE PAIRING CODE) and waits on the beacon in its slot; the client
// joins with the typed code. A wrong code: the host makes a new one and
// shows it; the client's user types again on the same connection.
// One pairing sets both directions: the host's grant is stored when pairing
// succeeds (welcome carries it); the client's is the `grant` it sends when
// its user is done (no "give it the same access?" question).
//
// The code (shown by the host, typed on the client) is CPace's password
// (net_cpace.h): all 9 digits. The first 3 are also the slot on the beacon
// (net_beacon.h) where the two meet across the internet; they're public.
// CPace is bound to this exact connection: its session id is the Noise
// handshake hash and its channel id holds both device keys, so a code typed
// into a connection someone sits in the middle of gives that someone nothing.
// The names (from hello and welcome / pairing_needed) are CPace's associated
// data (ADa, ADb): each side's view of them is part of the key.
//
// Confirmations: BLAKE2b keyed with the CPace key over a label naming the
// sender. The host confirms first; the client checks it before answering, so
// a wrong code is seen on both sides and costs the attacker its one guess.

#include <cstddef>
#include <cstdint>

#include "net_cpace.h"
#include "net_noise.h"
#include "net_trust.h"

enum class NetMessage : uint8_t
{
    welcome = 1,
    pairing_needed = 2,
    pair_ask = 3,
    pair_request = 4,
    pair_response = 5,
    pair_confirm = 6,
    pair_result = 7,
    hello = 8,
    unpair = 9,
    grant = 10,
};
constexpr uint8_t NET_MESSAGE_FIRST_APP = 16;
constexpr uint8_t NET_MESSAGE_FIRST_STREAM = 64;
constexpr uint8_t NET_MESSAGE_FIRST_SETTINGS = 128;
constexpr uint8_t NET_MESSAGE_FIRST_SHARE = 192;   // files (net_share)
// The action messages (actions_request, actions_result, action: the frontend
// library numbers them, net_settings.h). Each action needs its own capability
// (save: STREAM, reset: SETTINGS ...), which only the frontend's action table
// knows, so the transport lets them through with any of the three and the
// table decides. Otherwise a device with STREAM or SETTINGS and no GAMEPAD
// would be offered actions whose messages never arrive.
constexpr uint8_t NET_MESSAGE_FIRST_ACTION = 17;
constexpr uint8_t NET_MESSAGE_LAST_ACTION = 19;

// The capabilities an application message type needs: one bit, except the
// action messages (three bits: any of them is enough).
NetCaps net_message_required_cap(uint8_t type);
// True if `have` includes any of the capabilities message `type` needs.
bool net_caps_allow(NetCaps have, uint8_t type);

constexpr size_t NET_PAIR_CODE_DIGITS = 9;
constexpr size_t NET_PAIR_SLOT_DIGITS = 3;   // the code's first digits: its slot on the beacon
constexpr uint32_t NET_PAIRING_MAX_FAILURES = 5;   // wrong codes per connection, then it closes
constexpr size_t NET_PAIR_CONFIRM_SIZE = 32;
constexpr size_t NET_PAIR_CI_SIZE = 15 + 2 * NET_KEY_SIZE;   // "multitap-pair 3" + both keys
constexpr size_t NET_PAIR_SID_SIZE = 32;                     // of the handshake hash

// A build's proof that Multitap released it (net_access.h / net_client.h,
// verify_build): the releases server's signed record for this build and the
// signature text, both opaque here; this layer only carries them. Empty in
// dev and debug builds.
constexpr size_t NET_BUILD_RECORD_MAX = 512;
constexpr size_t NET_BUILD_SIGNATURE_MAX = 256;

// What a device says about itself (hello, welcome, pairing_needed).
struct NetDeviceInfo
{
    char          name[NET_DEVICE_NAME_MAX + 1] = {};
    NetAppKind kind = NetAppKind::piccolo;
    NetCaps       offers = 0;   // what it can serve
    NetCaps       uses = 0;     // what it can make use of
    uint16_t      record_size = 0;
    uint8_t       record[NET_BUILD_RECORD_MAX] = {};
    uint16_t      signature_size = 0;
    uint8_t       signature[NET_BUILD_SIGNATURE_MAX] = {};
};
// name length + name + kind + offers + uses + record length + record + signature length + signature
constexpr size_t NET_DEVICE_INFO_MAX = 1 + NET_DEVICE_NAME_MAX + 1 + 4 + 4 + 2 + NET_BUILD_RECORD_MAX + 2 +
                                       NET_BUILD_SIGNATURE_MAX;
// The largest message here: welcome = type + caps + the largest info.
constexpr size_t NET_PAIR_MAX_MESSAGE = 1 + 4 + NET_DEVICE_INFO_MAX;

// Checks a device's build proof (NetDeviceInfo's record and
// signature) with the releases key; the frontend provides it (multitap-net
// has no keys). Null = every build reads as unsigned.
typedef bool (*NetVerifyBuildFn)(void* user, const NetDeviceInfo* info);


// A uniformly random 9-digit code ("482193706"), NUL-terminated (10 bytes).
bool net_pair_code_generate(char* code);
// Exactly 9 ASCII digits.
bool net_pair_code_valid(const char* code);

// CPace inputs for one connection.
void net_pair_ci(const uint8_t* client_key, const uint8_t* host_key, uint8_t* ci);
void net_pair_confirm(const uint8_t* isk, bool from_host, uint8_t* confirm);

// A name as the messages carry it (cut to NET_DEVICE_NAME_MAX bytes at a
// UTF-8 boundary), as bytes for CPace's associated data. `out` holds
// NET_DEVICE_NAME_MAX bytes. Returns the length.
size_t net_pair_name_bytes(const char* name, uint8_t* out);

// `info->name` set from `name` (cut as the messages cut it, control characters
// replaced: net_name_clean).
void net_device_info_set_name(NetDeviceInfo* info, const char* name);

// Message type of a control payload, or 0 if empty.
uint8_t net_message_type(const uint8_t* data, size_t size);

// Writers return the size (0 if `capacity` is too small); readers are false
// unless the payload is exactly that message (unknown capability bits and
// kinds are refused: a newer device's message isn't half-read).
size_t net_message_write_hello(uint8_t* out, size_t capacity, const NetDeviceInfo* info);
bool   net_message_read_hello(const uint8_t* data, size_t size, NetDeviceInfo* info);
size_t net_message_write_welcome(uint8_t* out, size_t capacity, NetCaps caps, const NetDeviceInfo* host);
bool   net_message_read_welcome(const uint8_t* data, size_t size, NetCaps* caps, NetDeviceInfo* host);
size_t net_message_write_pairing_needed(uint8_t* out, size_t capacity, bool open, const NetDeviceInfo* host);
bool   net_message_read_pairing_needed(const uint8_t* data, size_t size, bool* open, NetDeviceInfo* host);
size_t net_message_write_pair_ask(uint8_t* out, size_t capacity);
bool   net_message_read_pair_ask(const uint8_t* data, size_t size);
size_t net_message_write_pair_request(uint8_t* out, size_t capacity, const uint8_t* share);
bool   net_message_read_pair_request(const uint8_t* data, size_t size, uint8_t* share);
size_t net_message_write_pair_response(uint8_t* out, size_t capacity, const uint8_t* share, const uint8_t* confirm);
bool   net_message_read_pair_response(const uint8_t* data, size_t size, uint8_t* share, uint8_t* confirm);
size_t net_message_write_pair_confirm(uint8_t* out, size_t capacity, const uint8_t* confirm);
bool   net_message_read_pair_confirm(const uint8_t* data, size_t size, uint8_t* confirm);
size_t net_message_write_pair_result(uint8_t* out, size_t capacity, bool ok);
bool   net_message_read_pair_result(const uint8_t* data, size_t size, bool* ok);
size_t net_message_write_grant(uint8_t* out, size_t capacity, NetCaps caps);
bool   net_message_read_grant(const uint8_t* data, size_t size, NetCaps* caps);
size_t net_message_write_unpair(uint8_t* out, size_t capacity);
bool   net_message_read_unpair(const uint8_t* data, size_t size);
