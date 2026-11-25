#pragma once

// A frontend's connection to another piccolo, as its client, for
// piccolo-share (net_share_client.h): on its own thread like net_service
// (NetClient polled about every millisecond, so copies aren't paced by the
// frontend's frames), with LAN discovery to find piccolos and pairing for a
// new one (the other side shows a code, our user types it: net_pairing.h). piccolo is a host for phones and other piccolos and
// at the same time, through this, a client of one other piccolo: two
// sockets (its listener and this one's ephemeral port).
//
// Every function locks the link's mutex itself; the thread takes it only for
// its short polls. Nothing here touches SDL or the frontend.

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "net_client.h"
#include "net_share_client.h"
#include "net_share_folders.h"

constexpr uint32_t NET_SHARE_LINK_FOUND_MAX = 16;
constexpr double   NET_SHARE_LINK_DISCOVERY_SECONDS = 3.0;   // how often the LAN is asked
constexpr double   NET_SHARE_LINK_FOUND_SECONDS = 10.0;      // a piccolo not heard from for this long is gone

struct NetShareLinkFound
{
    std::string   name;
    NetAddress    address;
    NetDeviceKind kind = NetDeviceKind::piccolo;
    NetCaps       offers = 0;      // what it serves (discovery v2; 0 from an old device)
    bool          offers_known = false;
    bool          signed_build = false;   // what it says (checked once connected)
    double        seen_at = 0.0;
};

enum class NetShareLinkState : uint8_t
{
    off,          // not started
    idle,         // not connected
    connecting,   // connecting or pairing
    ready,        // connected: `caps` says what we may use there
};

// What the frontend shows (a copy, taken under the lock).
struct NetShareLinkStatus
{
    NetShareLinkState state = NetShareLinkState::off;
    NetClientRefusal  refusal = NetClientRefusal::none;   // why the last try ended
    NetCaps           caps = 0;            // ready: what the host lets us use there
    std::string       host_name;           // ready, or code_needed: the host's name
    NetDeviceKind     host_kind = NetDeviceKind::piccolo;
    bool              host_signed = false;
    bool              code_needed = false; // pairing: show TYPE THE CODE SHOWN ON <host_name> and take the code
    bool              code_retry = false;  // code_needed: the last one was wrong
    bool              checking_code = false;   // pairing: the typed code is being checked
    std::vector<NetShareLinkFound> found;   // piccolos on the LAN, newest first
    std::vector<std::string> paired;        // the devices we paired with (net_share_link_connect_paired's index)
    std::vector<NetTrustedDevice> paired_devices;   // the same, whole records (both directions)
    std::vector<uint8_t>     paired_online; // per `paired`: on the beacon now (1) or not (0); empty = unknown
    bool              newly_paired = false;   // ready: paired on this connection (the DONE screen's ticks follow)
    int32_t           device = -1;            // ready: the host's index in `paired`
    uint8_t           host_key[NET_KEY_SIZE] = {};   // ready: the host's key
};

constexpr double NET_SHARE_LINK_PRESENCE_SECONDS = 20.0;

struct NetShareLink
{
    bool        newly_paired = false;   // the last ready came with newly_paired (cleared on a new connection)
    std::mutex  lock;
    std::thread thread;
    bool        running = false;

    NetClient       client;
    NetHost         discovery;          // its own socket: asks the LAN who's there
    bool            discovery_ready = false;
    double          next_discovery = 0.0;
    NetShareFolders folders;            // ours (the frontend's settings)
    NetShareClient  share;
    std::vector<uint8_t> out;

    // A close is polite (ENet sends what's queued first): a connect asked
    // meanwhile waits until the old connection is gone.
    bool        closing = false;
    bool        connect_pending = false;
    NetAddress  connect_address;
    bool        connect_pair = false;   // the pending LAN connect may pair
    std::string connect_code;
    // Across the internet (through the beacon): the pending connect is to
    // paired host `connect_device`, or pairs (`connect_device` -1) with
    // `connect_code`, typed by our user, in the pairing room of the device
    // showing it (GENERATE PAIRING CODE there).
    bool        code_needed = false;    // the client asked for a code (code_needed), our user hasn't typed it
    bool        code_retry = false;
    bool        connect_beacon = false;
    int32_t     connect_device = -1;
    std::string connect_beacon_name;    // the beacon used for it ("name" or "name:port")
    // Its addresses, looked up by the thread outside the lock (DNS blocks).
    bool        resolve_wanted = false;
    bool        resolved = false;
    NetAddress  servers[NET_BEACON_MAX_SERVERS];
    uint32_t    server_count = 0;
    std::string beacon;                 // the frontend's beacon setting (net_share_link_set_beacon)
    // Presence: the paired hosts online across the internet, asked every
    // NET_SHARE_LINK_PRESENCE_SECONDS through `beacon` (its own lookup).
    std::string presence_name;
    NetAddress  presence_servers[NET_BEACON_MAX_SERVERS];
    uint32_t    presence_count = 0;
    double      presence_next = 0.0;

    NetShareLinkState state = NetShareLinkState::off;
    NetClientRefusal  refusal = NetClientRefusal::none;
    NetShareLinkFound found[NET_SHARE_LINK_FOUND_MAX];
    uint32_t          found_count = 0;
};

// `info`: this device. `devices_path`: the paired devices (net_trust.h, shared
// with this device's NetAccess).
bool net_share_link_start(NetShareLink* link, const NetKeypair* identity, const NetDeviceInfo* info,
                          const char* devices_path);
void net_share_link_stop(NetShareLink* link);
// Started (and not stopped)? Only the frontend's thread starts and stops it,
// so this needs no lock.
bool net_share_link_started(const NetShareLink* link);

// Our shared folders: where gets land and what puts send.
void net_share_link_set_folders(NetShareLink* link, const NetShareFolderPaths* paths);

// To a device found on the LAN (or any address). `pair`: if it doesn't know
// us, ask to pair (it pops up a code; status code_needed, then
// net_share_link_enter_code). Closes a connection first.
bool net_share_link_connect(NetShareLink* link, NetAddress address, bool pair);
// The code our user typed (status code_needed). False if none is wanted.
bool net_share_link_enter_code(NetShareLink* link, const char* code);
// Across the internet, through the beacon (UDP hole punching, then WebRTC
// through its signaling; net_client_connect_beacon): `server` is the
// frontend's beacon setting ("" = none: the calls below fail).
void net_share_link_set_beacon(NetShareLink* link, const char* server);
// To a piccolo we paired with (the index into the status' `paired`).
bool net_share_link_connect_paired(NetShareLink* link, uint32_t device);
// Pairs across the internet with `code`, typed by our user (the other device
// shows it: GENERATE PAIRING CODE, waiting in the code's pairing room on the
// beacon). False if the code isn't 9 digits.
bool net_share_link_pair_beacon(NetShareLink* link, const char* code);
void net_share_link_disconnect(NetShareLink* link);
// What the device at `device` (the status' `paired` index) may use here: the
// DONE screen's ticks right after pairing, or later (net_client_set_grants:
// saved, and told if we're connected to it).
bool net_share_link_set_grants(NetShareLink* link, uint32_t device, NetCaps grants);
// Forgets the host at `device` (the status' `paired` index): net_client_unpair
// (told if we're connected to it now, else only here). Saved at once.
bool net_share_link_forget_host(NetShareLink* link, uint32_t device);

void net_share_link_status(NetShareLink* link, NetShareLinkStatus* status);

// net_share_client.h's calls, under the link's lock.
void     net_share_link_list(NetShareLink* link, const char* path);
bool     net_share_link_listing(NetShareLink* link, std::string* path, NetShareStatus* status,
                                std::vector<NetShareEntry>* entries);
uint32_t net_share_link_copy(NetShareLink* link, bool to_remote, const char* local, const char* remote, uint64_t size,
                             uint64_t mtime, uint8_t flags);
void     net_share_link_cancel(NetShareLink* link);
void     net_share_link_progress(NetShareLink* link, NetShareProgress* progress, NetShareClientCopy* copy,
                                 uint32_t* queued);
// The copies that ended since the last call (moved into `done`).
void     net_share_link_take_done(NetShareLink* link, std::vector<NetShareClientDone>* done);
