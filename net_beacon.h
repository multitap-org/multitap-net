#pragma once

// Connections across the internet between devices that are already paired:
// the beacon (deps/beacon, PROTOCOL.md there) tells each side the other's
// public address, then both punch through their NATs on the same UDP socket
// ENet uses, and the client connects with ENet as on the LAN (Noise XX and the
// paired-key check follow, unchanged). No relay, ever (Andrés): when punching
// fails the client says it couldn't connect.
//
//   host (piccolo)                beacon                  client (piccoletto)
//   REGISTER ids, every 20 s ->   id -> host address
//                                                    <-   MEET id (every 500 ms)
//   <- INTRO (client address)     INTRO (host address) ->
//   PUNCH every 100 ms, 5 s  <------------------------>  PUNCH every 100 ms, 5 s
//                                                         ENet connect (to where the
//                                                         host's PUNCH came from, or
//                                                         the INTRO address after 1 s)
//
// Meeting id: the first 16 bytes of BLAKE2b("multitap beacon v1" ||
// X25519(own secret, other's public key)). Both sides of a pairing compute the
// same id and nobody else can: the beacon never learns who is who.
//
// What's checked: beacon replies must come from a server address we sent to,
// carrying our nonce (COOKIE, REGISTERED, BOUND) or one of our ids (INTRO,
// NOT_FOUND); a PUNCH must carry an id and nonce we're punching for. A PUNCH
// with the right id and nonce from another address than the INTRO said is
// taken as the real one ("peer-reflexive": NATs that change ports, beacons
// that saw a private address). None of it is trusted for more than where to
// send: the Noise handshake authenticates the peer afterwards.
//
// No sockets of its own: everything goes out through net_host_send_datagram
// and comes in as NetEventType::beacon. Polled from the owner's loop (NetAccess
// for the host, NetClient for the client). Nothing allocates while polling
// (the ids list only when the paired devices change).

#include <cstddef>
#include <cstdint>
#include <vector>

#include "beacon_wire.h"
#include "net_host.h"
#include "net_noise.h"

constexpr uint16_t NET_BEACON_DEFAULT_PORT = 55430;   // the secondary (NAT check) is the next one
constexpr const char* NET_BEACON_DEFAULT_SERVER = "beacon.get-piccolo.app";
constexpr uint32_t NET_BEACON_MAX_SERVERS = 2;        // the server's IPv4 and IPv6 addresses
constexpr double NET_BEACON_REGISTER_SECONDS = 20.0;  // the server keeps an entry 60 s
constexpr double NET_BEACON_RETRY_SECONDS = 2.0;      // no answer to a REGISTER: ask again this soon
constexpr double NET_BEACON_SILENT_SECONDS = 10.0;    // no answer this long: the server is unreachable
constexpr double NET_BEACON_MEET_INTERVAL = 0.5;      // the server drops a repeat within 250 ms
constexpr double NET_BEACON_MEET_SECONDS = 5.0;       // no INTRO by then: give up
constexpr double NET_BEACON_PATIENT_INTERVAL = 2.0;   // a pairing client waiting for the host to type its code
constexpr double NET_BEACON_PUNCH_INTERVAL = 0.1;
constexpr double NET_BEACON_PUNCH_SECONDS = 5.0;
constexpr double NET_BEACON_CONNECT_AFTER = 1.0;      // no PUNCH from the host by then: connect to the INTRO address
constexpr uint32_t NET_BEACON_MAX_PUNCHES = 8;        // places punched at once (host: clients x families)

// The id both sides of a pairing compute. False if the shared secret is all
// zeros (a key that can't be used: then the beacon isn't used either).
bool net_beacon_meeting_id(const NetKeypair* own, const uint8_t* other_public_key, BeaconId* id);
// The key that seals signaling blobs between the same two devices (32 bytes:
// BLAKE2b("multitap signal v1" || X25519(own, other)); net_signal.h).
bool net_beacon_signal_key(const NetKeypair* own, const uint8_t* other_public_key, uint8_t* key);

// The pairing room (2026-11-22): where a client that shows a code meets the
// host that types it, across the internet. From the code's slot only (its
// first NET_PAIR_SLOT_DIGITS digits, `slot`): BLAKE2b("multitap pair v2" ||
// slot). Never from the secret digits: a hash of a million values is ground
// in a second. Two pairings on the same slot both get introduced; only the
// code that matches pairs (CPace), the other sees a wrong code.
void net_beacon_pair_id(const char* slot, BeaconId* id);
// The key that seals the pairing room's signaling blobs (32 bytes:
// BLAKE2b("multitap pair signal v2" || slot)). It only keeps the WebRTC offer
// from a casual reader; Noise + CPace protect the pairing itself.
void net_beacon_pair_signal_key(const char* slot, uint8_t* key);

// One server address (a family) as we talk to it.
struct NetBeaconServer
{
    NetAddress address;                 // its primary port
    uint64_t nonce = 0;                 // of the current REGISTER round / BINDs
    uint8_t  cookie[BEACON_COOKIE_SIZE] = {};
    bool     has_cookie = false;
    double   next_register = 0.0;
    double   last_heard = -1.0;         // net_seconds() of the last valid reply, -1 = never
    double   first_sent = -1.0;
    bool     registered = false;        // the last REGISTERED accepted every id
    NetAddress observed;                // BOUND from the primary port: how the server sees us
    NetAddress observed_secondary;      // BOUND from the secondary port
    bool     has_observed = false;
    bool     has_observed_secondary = false;
};

// Punching toward one address for one meeting.
struct NetBeaconPunch
{
    bool       active = false;
    NetAddress to;
    BeaconId   id;
    uint64_t   nonce = 0;   // the MEET's (both sides send it in PUNCH)
    double     until = 0.0;
    double     next = 0.0;
};

enum class NetBeaconStatus
{
    off,            // no server set
    waiting,        // asked, no answer yet
    registered,     // the server has our ids: paired devices can reach us
    symmetric_nat,  // registered, but our NAT gives every destination its own port: punching will likely fail
    unreachable,    // the server doesn't answer
};
const char* net_beacon_status_name(NetBeaconStatus status);   // "off", "waiting", ...

// --- The host (piccolo): registers its paired devices' ids, punches on INTRO.
struct NetBeaconHost
{
    NetBeaconServer servers[NET_BEACON_MAX_SERVERS];
    uint32_t        server_count = 0;
    std::vector<BeaconId> ids;          // one per paired device
    NetBeaconPunch  punches[NET_BEACON_MAX_PUNCHES];
    uint32_t        intros = 0;         // INTROs taken (for tests and logs)
};

// `count` 0 turns it off. Registering starts at the next update.
void net_beacon_host_set_servers(NetBeaconHost* beacon, const NetAddress* servers, uint32_t count);
// The paired devices' ids (registered again at once when they change).
void net_beacon_host_set_ids(NetBeaconHost* beacon, const BeaconId* ids, uint32_t count);
// Timers: REGISTER rounds, BINDs, punches. Call every poll.
void net_beacon_host_update(NetBeaconHost* beacon, NetHost* host, double now);
// A beacon message that arrived; false if it wasn't for us (dropped).
bool net_beacon_host_receive(NetBeaconHost* beacon, NetHost* host, const BeaconMessage* message, NetAddress from,
                             double now);
NetBeaconStatus net_beacon_host_status(const NetBeaconHost* beacon, double now);

// --- The client (piccoletto): MEET, punch, then where to connect.
enum class NetBeaconMeetState
{
    idle,
    meeting,    // MEET sent, waiting for INTRO
    punching,   // INTRO arrived; punching, connect target not chosen yet
    connect,    // target chosen (net_beacon_client_target); still punching until it times out
    failed,     // see `failure`
};

enum class NetBeaconFailure
{
    none,
    unreachable,    // no beacon server answered
    host_offline,   // the server doesn't know the host (not running, internet off, or not registered yet)
};

struct NetBeaconClient
{
    NetBeaconMeetState state = NetBeaconMeetState::idle;
    NetBeaconFailure   failure = NetBeaconFailure::none;
    NetAddress     servers[NET_BEACON_MAX_SERVERS];
    uint32_t       server_count = 0;
    uint32_t       not_found = 0;       // bit per server that answered NOT_FOUND
    BeaconId       id;
    uint64_t       nonce = 0;
    double         started = 0.0;
    double         next_meet = 0.0;
    double         intro_at = 0.0;
    NetAddress     target;
    bool           heard_punch = false; // the host's PUNCH reached us: its NAT lets us in
    bool           patient = false;     // pairing: keep meeting until the host comes (no NOT_FOUND / time limit)
    NetBeaconPunch punches[NET_BEACON_MAX_SERVERS * 2];
};

// Starts meeting the host with `id` through `servers`. False if there's no server.
bool net_beacon_client_start(NetBeaconClient* beacon, const NetAddress* servers, uint32_t count, const BeaconId* id,
                             double now);
void net_beacon_client_stop(NetBeaconClient* beacon);
void net_beacon_client_update(NetBeaconClient* beacon, NetHost* host, double now);
bool net_beacon_client_receive(NetBeaconClient* beacon, NetHost* host, const BeaconMessage* message, NetAddress from,
                               double now);
