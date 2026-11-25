#pragma once

// The host side of access control: who may use this device over the
// network. On top of net_session.h (encrypted connections) and net_trust.h
// (the paired devices on disk), running net_pairing.h's flow.
//
// Every client says who it is first (hello). A paired device (its key is in
// the list) is then welcomed with what it may use here and reported
// `authorized`. Any other is told it isn't paired; it may ask to pair
// (pair_ask): this side makes a 9-digit code and reports `pairing_requested`
// with it and the capabilities to grant ticked by default (what the device
// uses ∩ what we offer; FILE TRANSFER and SETTINGS not for an unsigned build).
// The frontend shows the code and the ticks (net_access_set_pairing_grants
// while the user changes them); the other device's user types the code there,
// and success is reported `paired`.
// Across the internet (or to whoever types it on the LAN) the frontend shows
// a code first (net_access_show_code): any device that asks while it's shown
// pairs with that code and its grants, without a request.
// Only authorized peers' messages reach the frontend, and only the ones their
// capabilities cover (net_pairing.h: the message type says the capability it
// needs): the stored grant ∩ what we offer ∩ what the device uses. A paired
// device's name, kind and build follow it at every connection, and it says
// what it grants us (grant), stored as `granted`.
//
// A wrong code (the other side found our confirm wrong) comes back as a new
// pair_ask: a request gets a new code (reported `pairing_requested` again,
// `retry`); a shown code stays. A connection gets NET_PAIRING_MAX_FAILURES
// attempts.
//
// Guest links (net_guest.h): while a link is open (net_access_guest_open), a
// device we don't know may prove it has the link's token instead of pairing
// (guest_hello). It becomes a guest: never saved, at most `seats` at once,
// reported `guest_joined` and its messages with `guest` set and no device.
// A guest may only start / stop the stream and ask for keyframes, plus send
// its pad when the link's level is PLAY; the host only sends it what runs and
// the stream. A wrong or old token is closed without a word.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "net_beacon.h"
#include "net_guest.h"
#include "net_signal.h"
#include "net_pairing.h"
#include "net_session.h"
#include "net_trust.h"

constexpr double   NET_ACCESS_PAIRING_STEP_SECONDS = 30.0;   // a peer may sit in a pairing step this long
constexpr double   NET_ACCESS_REQUEST_SECONDS = 300.0;       // a request or a shown code waits this long (Andrés: 5 min)
constexpr NetCaps  NET_CAPS_UNSIGNED_OFF = NET_CAP_SHARE | NET_CAP_SETTINGS;   // not ticked for an unsigned build
constexpr double   NET_ACCESS_GUEST_HELLO_SECONDS = 10.0;    // a device that can't pair has this long to say guest_hello

enum class NetAccessPeerState
{
    none,
    hello_wait,   // secured, a paired key: waiting for its hello
    unpaired,     // secured, not trusted; may send pair_ask (or guest_hello)
    requested,    // pair_ask taken: our code shown, waiting for pair_request
    pairing,      // pair_response sent, waiting for pair_confirm (or a new pair_ask: wrong code)
    authorized,
    guest,        // proved the guest link's token: a guest (no device)
};

struct NetAccessPeer
{
    NetAccessPeerState state = NetAccessPeerState::none;
    double   since = 0.0;   // net_seconds() when this state began
    uint8_t  key[NET_KEY_SIZE] = {};
    uint8_t  handshake_hash[NET_HASH_SIZE] = {};
    NetDeviceInfo info;                             // what it said in hello
    bool     has_info = false;
    bool     signed_build = false;                  // its build proof checked out (verify_build)
    char     code[NET_PAIR_CODE_DIGITS + 1] = {};   // requested / pairing: the code it must type
    bool     shown_code = false;                    // that code is the shown one (net_access_show_code)
    NetCaps  grants = 0;                            // requested / pairing: what it will get here
    uint32_t failures = 0;                          // wrong codes on this connection
    uint8_t  isk[NET_CPACE_ISK_SIZE] = {};
    int32_t  device = -1;   // index in trust.devices once authorized
    bool     forgotten = false;   // its device was removed while connected: `closed` still reported
    bool     guest_only = false;  // unpaired while pairing is closed: only guest_hello may follow
    char     guest_name[NET_GUEST_MAX_NAME + 1] = {};   // a guest: what its app calls itself (unverified)
    bool     guest_leaving = false;   // kicked or the session ended: closing, no seat, nothing from it
};

enum class NetAccessEventType
{
    none,
    authorized,       // a paired device connected: `peer`, `device`, `caps`, `info`, `signed_build`
    paired,           // a new device paired and is now authorized: `peer`, `device`, `caps`, `info`, `signed_build`
    message,          // from an authorized `peer`, covered by its capabilities: `data`/`size` on `channel`
    closed,           // `peer` left (`device` if it was authorized, else -1: also a request that went)
    pairing_requested,// `peer` asks to pair: show `code`; `info`, `signed_build`, `caps` = the default ticks;
                      // `retry` after a wrong code (a new code)
    pairing_failed,   // `peer`'s attempts ran out (or it broke the protocol): it's closed
    unpaired,         // a connected device unpaired itself: forgotten here too (`info.name`); `closed` follows
    granted,          // a paired device says what we may use on it: `device`, `caps` (stored as granted)
    code_expired,     // the shown code's time ran out (net_access_show_code): it's gone
    guest_joined,     // a guest took a seat: `peer`, `info.name`, `guest_level` (closed, `guest`, when it goes)
    guest_full,       // a guest came with the link but every seat was taken: `info.name` (it's closed)
};

struct NetAccessEvent
{
    NetAccessEventType type = NetAccessEventType::none;
    uint32_t       peer = NET_NO_PEER;
    int32_t        device = -1;
    NetAddress     address;
    NetChannel     channel = NetChannel::control;
    const uint8_t* data = nullptr;   // message: valid until the next poll
    size_t         size = 0;
    NetCaps        caps = 0;   // authorized / paired / message: what it may use here; granted: what it grants us
    NetDeviceInfo  info;       // authorized / paired / pairing_requested; unpaired / guests: only the name
    bool           signed_build = false;
    char           code[NET_PAIR_CODE_DIGITS + 1] = {};   // pairing_requested
    bool           retry = false;                          // pairing_requested: the last code was wrong
    bool           guest = false;                          // message / closed / guest_joined: from a guest
    NetGuestLevel  guest_level = NetGuestLevel::watch;     // guest_joined, a guest's message
};

struct NetAccess
{
    NetSession    session;
    NetTrust      trust;             // our copy of the paired devices (net_trust.h: shared with the client side)
    std::string   trust_path;
    uint32_t      trust_generation = 0;   // of our copy
    NetDeviceInfo info;              // ours: name (as discovery shows it), kind, offers, uses, build proof
    std::string   name;              // info.name
    NetVerifyBuildFn verify_build = nullptr;
    void*         verify_user = nullptr;
    uint8_t       host_key[NET_KEY_SIZE] = {};
    bool          accept_pairing = true;   // false: every unpaired connection is closed at once
    // The shown code (net_access_show_code): it waits on the beacon in its slot's room.
    bool          showing = false;
    char          shown_code[NET_PAIR_CODE_DIGITS + 1] = {};
    NetCaps       shown_grants = 0;
    double        shown_since = 0.0;
    char          invite_slot[NET_PAIR_SLOT_DIGITS + 1] = {};
    std::vector<uint8_t> refused_keys;     // refused this run (NET_KEY_SIZE each): asked no more
    uint32_t      dropped_by_access = 0;   // messages a device's capabilities didn't cover
    NetAccessPeer peers[NET_MAX_PEERS];
    std::vector<uint8_t> out;        // messages we write (sized at creation)
    NetBeaconHost beacon;            // across the internet (off until net_access_set_beacon)
    NetSignal     signal;            // WebRTC signaling, for browsers (off until net_access_set_signal)
    // Guest links (net_guest.h).
    bool          guest_open = false;
    NetGuestLink  guest_link;
    uint32_t      guest_seats = 0;
    NetGuestLevel guest_level = NetGuestLevel::watch;
    std::vector<uint8_t> guest_kicked;   // keys kicked this session (NET_KEY_SIZE each): refused
    uint32_t      guest_failures = 0;    // connections that never got through while a link was open
    uint32_t      guest_full_count = 0;  // guests turned away: no seat
};

// `info`: this device (its name is what discovery shows). `trust_path`: the
// paired devices file (net_trust.h: loaded now; changes saved at once).
bool net_access_create(NetAccess* access, uint16_t port, const NetDeviceInfo* info, const NetKeypair* identity,
                       const char* trust_path);
void net_access_destroy(NetAccess* access);
void net_access_set_verify_build(NetAccess* access, NetVerifyBuildFn verify, void* user);

// One event per call; call until false, once per frame.
bool net_access_poll(NetAccess* access, NetAccessEvent* event);

// What a `pairing_requested` peer will get here (its ticks, as the user
// changes them before the code is typed). Kept to what we offer and it uses.
// False if that peer isn't asking.
bool net_access_set_pairing_grants(NetAccess* access, uint32_t peer, NetCaps grants);
// Refuses a request and closes it; that device isn't asked about again until
// this NetAccess is made again.
void net_access_refuse_pairing(NetAccess* access, uint32_t peer);
// GENERATE PAIRING CODE: makes a code (written to `code`, 10 bytes) and shows
// it until net_access_end_code or NET_ACCESS_REQUEST_SECONDS (code_expired):
// it waits on this network and in its slot's room on the beacon (and the
// signaling server). A device that asks while it's shown pairs with it,
// granted `grants` ∩ what it uses (FILE TRANSFER and SETTINGS off for an
// unsigned build); the code then ends (one code, one device). A new call
// replaces the code.
bool net_access_show_code(NetAccess* access, NetCaps grants, char* code);
void net_access_set_shown_grants(NetAccess* access, NetCaps grants);
void net_access_end_code(NetAccess* access);

// To an authorized peer. A control payload's first byte is its message type,
// NET_MESSAGE_FIRST_APP or above.
bool net_access_send(NetAccess* access, uint32_t peer, NetChannel channel, const uint8_t* data, size_t size);
void net_access_close(NetAccess* access, uint32_t peer);

// Forget a device (saved at once). A connected device is told (unpair: it
// forgets this host too) and its connections are closed; one that isn't
// connected is only forgotten here.
void net_access_remove_device(NetAccess* access, uint32_t device);
// Changes what a device may use here (saved at once); a connected device is
// told (a new welcome).
void net_access_set_grants(NetAccess* access, uint32_t device, NetCaps grants);
// What an authorized peer may use now: grant ∩ our offers ∩ its uses (0 if
// it isn't authorized).
NetCaps net_access_peer_caps(const NetAccess* access, uint32_t peer);
// How the connection to an authorized peer is doing (ping). False if it isn't.
bool net_access_peer_stats(const NetAccess* access, uint32_t peer, NetLinkStats* stats);
// Reliable bytes still on their way to that peer (net_host_peer_pending).
size_t net_access_peer_pending(const NetAccess* access, uint32_t peer);
bool net_access_peer_address(const NetAccess* access, uint32_t peer, NetAddress* address);
// Is this peer connected and authorized as that device?
bool net_access_device_connected(const NetAccess* access, uint32_t device);

// Paired devices may reach this host across the internet through a beacon
// (net_beacon.h): `servers` = its addresses (net_address_resolve), count 0 = off.
void net_access_set_beacon(NetAccess* access, const NetAddress* servers, uint32_t count);
NetBeaconStatus net_access_beacon_status(const NetAccess* access);
// Browsers too (WebRTC): the beacon's signaling `url` (net_signal_url) and its
// STUN (net_signal_stun); "" turns it off. False if this build has no WebRTC.
bool net_access_set_signal(NetAccess* access, const char* url, const char* stun);
NetSignalStatus net_access_signal_status(const NetAccess* access);
// Guest links. Opens `link` (or replaces the open one: the old token stops
// working, connected guests stay) with `seats` (1..NET_GUEST_MAX_SEATS) and
// `level`. Its meeting id and signaling room join the beacon's.
void net_access_guest_open(NetAccess* access, const NetGuestLink* link, uint32_t seats, NetGuestLevel level);
// Fewer seats never drop anyone, they only turn newcomers away.
void net_access_guest_set_seats(NetAccess* access, uint32_t seats);
// Connected guests are told at once (a new welcome).
void net_access_guest_set_level(NetAccess* access, NetGuestLevel level);
// Tells the guest (bye: kicked), closes it, and refuses its key until the
// link is closed.
void net_access_guest_kick(NetAccess* access, uint32_t peer);
// The session ends: every guest is told (bye: ended) and closed, the link and
// its rooms go, the kicked list is forgotten.
void net_access_guest_close(NetAccess* access);
uint32_t net_access_guest_count(const NetAccess* access);
// The open link's room is on the beacon (its signaling answered our JOIN):
// guests coming through WebRTC can find us, and its card can be uploaded.
bool net_access_guest_ready(const NetAccess* access);
// The guest at `peer`, or nullptr.
const NetAccessPeer* net_access_guest(const NetAccess* access, uint32_t peer);

// The two together, for a status line: can paired devices reach us from
// outside? `registered` when the UDP registration holds or the signaling
// socket is in its rooms (a browser has only the latter); `symmetric_nat`
// when UDP found one (WebRTC may not get through it either); otherwise
// whichever says more (waiting, unreachable).
NetBeaconStatus net_access_internet_status(const NetAccess* access);
