#pragma once

// The host side of access control (piccolo): who may use this machine over
// the network. On top of net_session.h (encrypted connections) and
// net_trust.h (the paired devices on disk), running net_pairing.h's flow.
//
// A connection whose device key is in the trusted list is welcomed and
// reported `authorized`. Any other is told it isn't paired; it may then ask to
// pair (pair_request, with the code it shows on its own screen): reported
// `pairing_requested`, held until this host's user types that code and picks
// a level (net_access_answer_pairing) or refuses (net_access_refuse_pairing),
// and reported `paired` when it succeeds.
// Only authorized peers' messages reach the frontend, and only the ones their
// access level covers (net_pairing.h: the message type says the level it
// needs). A paired device sends its name at every connection; the list
// follows it.
//
// The code is the client's (Andrés, 2026-11-22): it makes a new one after a
// mistyped attempt and asks again on the same connection (reported
// `pairing_requested` again, `retry`). A connection gets
// NET_PAIRING_MAX_FAILURES attempts. Across the internet the host waits in the
// pairing room of the code's slot (net_access_invite) while its user types it.
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
constexpr double   NET_ACCESS_REQUEST_SECONDS = 1800.0;      // a request waits this long for the host's user
constexpr double   NET_ACCESS_GUEST_HELLO_SECONDS = 10.0;    // a device that can't pair has this long to say guest_hello

enum class NetAccessPeerState
{
    none,
    unpaired,     // secured, not trusted; may send pair_request
    requested,    // pair_request held: waiting for this host's user (net_access_answer_pairing)
    pairing,      // pair_response sent, waiting for pair_confirm
    authorized,
    guest,        // proved the guest link's token: a guest (no device)
};

struct NetAccessPeer
{
    NetAccessPeerState state = NetAccessPeerState::none;
    double   since = 0.0;   // net_seconds() when this state began
    uint8_t  key[NET_KEY_SIZE] = {};
    uint8_t  handshake_hash[NET_HASH_SIZE] = {};
    char     name[NET_DEVICE_NAME_MAX + 1] = {};   // what it called itself when pairing
    uint8_t  share[NET_CPACE_SHARE_SIZE] = {};     // its CPace share, while requested
    NetAccessLevel want = NetAccessLevel::gamepad;  // the level it asked for
    NetAccessLevel grant = NetAccessLevel::gamepad; // the level this host's user picked
    NetPairKind  kind = NetPairKind::piccolo;
    uint32_t failures = 0;                         // wrong codes on this connection
    bool     just_paired = false;                  // paired on this connection: may grant_back
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
    authorized,       // a paired device connected: `peer`, `device`
    paired,           // a new device paired and is now authorized: `peer`, `device`
    message,          // from an authorized `peer`, covered by its access: `data`/`size` on `channel`
    closed,           // `peer` left (`device` if it was authorized, else -1: also a request that went)
    pairing_requested,// `peer` asks to pair: `name`, `kind`, `access` = the level it wants; `retry` after a wrong code
    pairing_failed,   // `peer`'s attempts ran out (or it broke the protocol): it's closed
    unpaired,         // a connected device unpaired itself: forgotten here too (`name`); `closed` follows
    granted_back,     // the device that just paired lets us come to it at `access` (`peer`, `device`)
    guest_joined,     // a guest took a seat: `peer`, `name`, `guest_level` (closed, `guest`, when it goes)
    guest_full,       // a guest came with the link but every seat was taken: `name` (it's closed)
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
    NetAccessLevel access = NetAccessLevel::gamepad;   // the device's, for authorized / paired / message
    char           name[NET_DEVICE_NAME_MAX + 1] = {};   // unpaired / pairing_requested: the device's name
    NetPairKind  kind = NetPairKind::piccolo;        // pairing_requested
    bool           retry = false;                        // pairing_requested: the last code was wrong
    bool           guest = false;                        // message / closed / guest_joined: from a guest
    NetGuestLevel  guest_level = NetGuestLevel::watch;   // guest_joined, a guest's message
};

struct NetAccess
{
    NetSession    session;
    NetTrust      trust;
    std::string   trust_path;
    std::string   name;              // this host's name, as discovery shows it
    uint8_t       host_key[NET_KEY_SIZE] = {};
    bool          accept_pairing = true;   // false: every unpaired connection is closed at once
    bool          inviting = false;        // waiting in a pairing room on the beacon
    char          invite_slot[NET_PAIR_SLOT_DIGITS + 1] = {};
    std::vector<uint8_t> refused_keys;     // refused this run (NET_KEY_SIZE each): asked no more
    uint32_t      dropped_by_access = 0;   // messages a device's level didn't cover
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

// `trust_path`: the paired devices file (loaded now, saved on every change).
bool net_access_create(NetAccess* access, uint16_t port, const char* name, const NetKeypair* identity,
                       const char* trust_path);
void net_access_destroy(NetAccess* access);

// One event per call; call until false, once per frame.
bool net_access_poll(NetAccess* access, NetAccessEvent* event);

// Answers a `pairing_requested` peer with the code its user typed (as the
// other side shows it) and the level to give it. False if that peer isn't
// waiting or the code isn't 9 digits. Success (`paired`) or a new request
// (`retry`, the code was wrong) follows.
bool net_access_answer_pairing(NetAccess* access, uint32_t peer, const char* code, NetAccessLevel level);
// Refuses a request and closes it; that device isn't asked about again until
// this NetAccess is made again.
void net_access_refuse_pairing(NetAccess* access, uint32_t peer);
// Across the internet: waits in the pairing room of `code`'s slot on the
// beacon (and the signaling server) until net_access_end_invite. The client
// that shows the code comes in as an ordinary `pairing_requested`.
bool net_access_invite(NetAccess* access, const char* code);
void net_access_end_invite(NetAccess* access);
// Adds (or updates) a device at `level` without pairing: a host we just paired
// with as a client, that we let come to us (grant_back). Saved at once.
uint32_t net_access_add_device(NetAccess* access, const uint8_t* key, const char* name, NetAccessLevel level);

// To an authorized peer. A control payload's first byte is its message type,
// NET_MESSAGE_FIRST_APP or above.
bool net_access_send(NetAccess* access, uint32_t peer, NetChannel channel, const uint8_t* data, size_t size);
void net_access_close(NetAccess* access, uint32_t peer);

// Forget a device (saved at once). A connected device is told (unpair: it
// forgets this host too) and its connections are closed; one that isn't
// connected is only forgotten here.
void net_access_remove_device(NetAccess* access, uint32_t device);
// Changes a device's level (saved at once); a connected device is told.
void net_access_set_level(NetAccess* access, uint32_t device, NetAccessLevel level);
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
