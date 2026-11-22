#pragma once

// Guest links (design-notes, "Guest links", Andrés 2026-11-22): a piccolo
// streaming a game makes a link anyone can open to join it at once, with no
// pairing and nothing saved on either side. As pure functions: the link, what
// both sides derive from it, the messages that prove it, the card's body.
// net_access.h (host) and net_client.h (guest) run the flow.
//
// The link: https://<beacon>/join/<room>#<token>
// - token: 26 base32 characters (130 random bits), after the '#': browsers
//   never send it, so no server sees it. It is the key.
// - From the token (BLAKE2b; the beacon's PROTOCOL.md "Guest links" has the
//   same, with the same test vectors):
//     card key   = BLAKE2b-256("multitap guest card v1" || token)
//     room       = 13 base32 characters of BLAKE2b-256("multitap guest room v1" || card key)
//     meeting id = BLAKE2b-128("multitap guest v1" || room): UDP MEET and the signaling room
//     signal key = BLAKE2b-256("multitap guest signal v1" || token): seals the signaling blobs
//     mac key    = BLAKE2b-256("multitap guest mac v1" || token): the proofs below
//   The beacon sees the room and, when the card is uploaded, the card key;
//   neither gives a way in.
//
// The handshake (agreed with piccolo-network): the guest connects as any
// client does (Noise XX), with a throwaway key made for this connection. Right
// after the handshake it proves it has the token, bound to this connection:
//   guest -> host  guest_hello    MAC("guest client" || handshake hash) + its app's name
//   host -> guest  guest_welcome  MAC("guest host" || handshake hash) + level
//              or  guest_full     MAC("guest host" || handshake hash): no free seat
//   host -> guest  guest_bye      reason (kicked / ended), then it closes
// The host checks the guest's MAC in constant time before giving it anything;
// a wrong or old token is closed quietly (no reply, no dialog). The guest
// checks the host's MAC before it believes anything: the token is the only
// thing that tells it this is the host the link names. The welcome comes
// again when the host changes the level.
//
// Other forms of the same link (the join page passes them on):
//   piccoletto://join/<room>?t=<token>[&b=<beacon>]     (Android's intent)
//   piccolo://join/<room>#<token>
//   ...#join=<room>.<token>[&b=<beacon>]                (piccoletto web's hash)

#include <cstddef>
#include <cstdint>
#include <vector>

#include "beacon_wire.h"
#include "net_noise.h"

constexpr size_t NET_GUEST_TOKEN_SIZE = 26;      // base32 characters
constexpr size_t NET_GUEST_ROOM_SIZE = 13;       // base32 characters
constexpr size_t NET_GUEST_KEY_SIZE = 32;
constexpr size_t NET_GUEST_MAC_SIZE = 32;
constexpr size_t NET_GUEST_MAX_BEACON = 128;     // a beacon's host name in a link
constexpr size_t NET_GUEST_MAX_TITLE = 64;       // the card's title, bytes of UTF-8
constexpr size_t NET_GUEST_MAX_NAME = 32;        // a guest's app name, as the host shows it
constexpr size_t NET_GUEST_MAX_LINK = 256;
constexpr uint32_t NET_GUEST_MAX_SEATS = 8;      // NET_MAX_PEERS
// The card upload's limits (the beacon refuses more).
constexpr size_t NET_GUEST_CARD_MAX_PNG = 256 * 1024;
constexpr uint32_t NET_GUEST_CARD_MAX_WIDTH = 1280;
constexpr uint32_t NET_GUEST_CARD_MAX_HEIGHT = 960;

enum class NetGuestMessage : uint8_t
{
    hello = 10,
    welcome = 11,
    full = 12,
    bye = 13,
};

// What a guest may do: watch (the stream), or also play (a pad on a free port).
enum class NetGuestLevel : uint8_t
{
    watch = 0,
    play = 1,
};

enum class NetGuestBye : uint8_t
{
    none = 0,
    kicked = 1,
    ended = 2,      // the session ended (END, the game closed, piccolo quit)
};

struct NetGuestLink
{
    char     token[NET_GUEST_TOKEN_SIZE + 1] = {};
    char     room[NET_GUEST_ROOM_SIZE + 1] = {};
    uint8_t  card_key[NET_GUEST_KEY_SIZE] = {};
    BeaconId meeting = {};
    uint8_t  signal_key[NET_GUEST_KEY_SIZE] = {};
    uint8_t  mac_key[NET_GUEST_KEY_SIZE] = {};
};

// A new random link. False if there's no randomness.
bool net_guest_link_make(NetGuestLink* link);
// Everything from a token. False unless it's 26 base32 characters.
bool net_guest_link_from_token(const char* token, NetGuestLink* link);
void net_guest_link_wipe(NetGuestLink* link);

// "https://<beacon>/join/<room>#<token>". Returns the length, 0 if it doesn't fit.
size_t net_guest_link_url(const NetGuestLink* link, const char* beacon, char* out, size_t capacity);

// Any form of the link (above). `beacon` gets the beacon's host name when the
// link names one ("" when it doesn't: the default). False unless the room
// matches the token.
bool net_guest_link_parse(const char* text, NetGuestLink* link, char* beacon, size_t beacon_capacity);

// Whether `text` is a guest link at all (any form), without checking it.
bool net_guest_link_looks_like(const char* text);

// The proof for this connection (`handshake_hash`: NET_HASH_SIZE bytes).
void net_guest_mac(const NetGuestLink* link, bool from_host, const uint8_t* handshake_hash, uint8_t* mac);

// Messages. Writers return the size (0 if it doesn't fit); readers are false
// unless the payload is exactly that message.
size_t net_guest_write_hello(uint8_t* out, size_t capacity, const uint8_t* mac, const char* name);
bool   net_guest_read_hello(const uint8_t* data, size_t size, uint8_t* mac, char* name);
size_t net_guest_write_welcome(uint8_t* out, size_t capacity, const uint8_t* mac, NetGuestLevel level);
bool   net_guest_read_welcome(const uint8_t* data, size_t size, uint8_t* mac, NetGuestLevel* level);
size_t net_guest_write_full(uint8_t* out, size_t capacity, const uint8_t* mac);
bool   net_guest_read_full(const uint8_t* data, size_t size, uint8_t* mac);
size_t net_guest_write_bye(uint8_t* out, size_t capacity, NetGuestBye reason);
bool   net_guest_read_bye(const uint8_t* data, size_t size, NetGuestBye* reason);
constexpr size_t NET_GUEST_MAX_MESSAGE = 1 + NET_GUEST_MAC_SIZE + 1 + NET_GUEST_MAX_NAME;

// host -> guest, an application message in the stream range (a guest gets
// those): the port its pad plays on, or NET_GUEST_NO_PORT (watching: not
// joined yet, or no port free). Sent at join and whenever it changes.
constexpr uint8_t NET_GUEST_PORT_MESSAGE = 78;
constexpr uint8_t NET_GUEST_NO_PORT = 0xff;
size_t net_guest_write_port(uint8_t* out, size_t capacity, uint8_t port);
bool   net_guest_read_port(const uint8_t* data, size_t size, uint8_t* port);

// A game's file name as a card title: "Teenage Mutant Ninja Turtles IV (USA)
// [!]" -> "Teenage Mutant Ninja Turtles IV" (groups in () and [] dropped,
// spaces tidied, cut to NET_GUEST_MAX_TITLE bytes at a UTF-8 boundary, no
// control characters). `out` holds NET_GUEST_MAX_TITLE + 1 bytes.
void net_guest_title_clean(const char* name, char* out);

// The beacon's card upload body: card key, title, PNG (PROTOCOL.md). False if
// the title or the PNG is out of bounds.
bool net_guest_card_body(const NetGuestLink* link, const char* title, const uint8_t* png, size_t png_size,
                         std::vector<uint8_t>* out);
