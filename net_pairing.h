#pragma once

// Pairing and access messages, as pure functions. They travel on the control
// channel of a secured connection (net_session.h): already encrypted, with
// both device keys known. net_access.h (host) and net_client.h (client) run
// the flow.
//
// Every control message starts with a type byte. Types below
// NET_MESSAGE_FIRST_APP belong to this layer; the rest are the application's,
// and the type says the access level it needs (net_message_required_access):
//   16..63 gamepad, 64..127 stream, 128..191 full, 192..255 owner.
// The host drops what a device's level doesn't cover; the client is told its
// level (welcome) only to show what it can use.
//
//   host -> client  welcome          you're a paired device       + access + host name
//   client -> host  device_name      what I'm called now (after welcome, every connection)
//   host -> client  pairing_needed   you're not; pairing open?    + host name
//   client -> host  pair_request     CPace share Ya               + client name
//   host -> client  pair_response    CPace share Yb, host confirm + host name
//   client -> host  pair_confirm     client confirm
//   host -> client  pair_result      ok / refused
//   either side     unpair           I forget you: forget me (then the sender closes)
//
// Unpairing (Andrés, 2026-11-19) starts on either side: if the other side is
// connected now it's told (unpair) and forgets the sender too; if not, the
// sender only forgets it locally. The sender closes the connection (only
// one side may close, net_host.h); the other side just forgets.
//
// The 6-digit code (shown by the host, typed on the client) is CPace's
// password (net_cpace.h). CPace is bound to this exact connection: its session
// id is the Noise handshake hash and its channel id holds both device keys,
// so a code typed into a connection someone sits in the middle of gives that
// someone nothing. The names are CPace's associated data (ADa, ADb): each
// side's view of them is part of the key.
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
    pair_request = 3,
    pair_response = 4,
    pair_confirm = 5,
    pair_result = 6,
    device_name = 7,
    unpair = 8,
};
constexpr uint8_t NET_MESSAGE_FIRST_APP = 16;
constexpr uint8_t NET_MESSAGE_FIRST_STREAM = 64;
constexpr uint8_t NET_MESSAGE_FIRST_FULL = 128;
constexpr uint8_t NET_MESSAGE_FIRST_OWNER = 192;   // files (net_share)

// The level an application message type needs.
NetAccessLevel net_message_required_access(uint8_t type);
bool net_access_allows(NetAccessLevel have, NetAccessLevel need);

constexpr size_t NET_PAIR_CODE_DIGITS = 6;
constexpr size_t NET_PAIR_CONFIRM_SIZE = 32;
constexpr size_t NET_PAIR_CI_SIZE = 15 + 2 * NET_KEY_SIZE;   // "multitap-pair 1" + both keys
constexpr size_t NET_PAIR_SID_SIZE = 32;                     // of the handshake hash
// The largest message here: type + share + confirm + name length + name.
constexpr size_t NET_PAIR_MAX_MESSAGE = 1 + NET_CPACE_SHARE_SIZE + NET_PAIR_CONFIRM_SIZE + 1 + NET_DEVICE_NAME_MAX;

// A uniformly random 6-digit code ("042917"), NUL-terminated (7 bytes).
bool net_pair_code_generate(char* code);
// Exactly 6 ASCII digits.
bool net_pair_code_valid(const char* code);

// CPace inputs for one connection.
void net_pair_ci(const uint8_t* client_key, const uint8_t* host_key, uint8_t* ci);
void net_pair_confirm(const uint8_t* isk, bool from_host, uint8_t* confirm);

// A name as the messages carry it (cut to NET_DEVICE_NAME_MAX bytes at a
// UTF-8 boundary), as bytes for CPace's associated data. `out` holds
// NET_DEVICE_NAME_MAX bytes. Returns the length.
size_t net_pair_name_bytes(const char* name, uint8_t* out);

// Message type of a control payload, or 0 if empty.
uint8_t net_message_type(const uint8_t* data, size_t size);

// Writers return the size (0 if `capacity` is too small); readers are false
// unless the payload is exactly that message. Names are cut to
// NET_DEVICE_NAME_MAX bytes; read names are NUL-terminated in `name`
// (NET_DEVICE_NAME_MAX + 1 bytes).
size_t net_message_write_welcome(uint8_t* out, size_t capacity, NetAccessLevel access, const char* host_name);
bool   net_message_read_welcome(const uint8_t* data, size_t size, NetAccessLevel* access, char* host_name);
size_t net_message_write_device_name(uint8_t* out, size_t capacity, const char* name);
bool   net_message_read_device_name(const uint8_t* data, size_t size, char* name);
size_t net_message_write_pairing_needed(uint8_t* out, size_t capacity, bool open, const char* host_name);
bool   net_message_read_pairing_needed(const uint8_t* data, size_t size, bool* open, char* host_name);
size_t net_message_write_pair_request(uint8_t* out, size_t capacity, const uint8_t* share, const char* client_name);
bool   net_message_read_pair_request(const uint8_t* data, size_t size, uint8_t* share, char* client_name);
size_t net_message_write_pair_response(uint8_t* out, size_t capacity, const uint8_t* share, const uint8_t* confirm,
                                       const char* host_name);
bool   net_message_read_pair_response(const uint8_t* data, size_t size, uint8_t* share, uint8_t* confirm,
                                      char* host_name);
size_t net_message_write_pair_confirm(uint8_t* out, size_t capacity, const uint8_t* confirm);
bool   net_message_read_pair_confirm(const uint8_t* data, size_t size, uint8_t* confirm);
size_t net_message_write_unpair(uint8_t* out, size_t capacity);
bool   net_message_read_unpair(const uint8_t* data, size_t size);
size_t net_message_write_pair_result(uint8_t* out, size_t capacity, bool ok);
bool   net_message_read_pair_result(const uint8_t* data, size_t size, bool* ok);
