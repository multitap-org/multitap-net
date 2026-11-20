#pragma once

// A frontend's connection to another piccolo, as its client, for
// piccolo-share (net_share_client.h): on its own thread like net_service
// (NetClient polled about every millisecond, so copies aren't paced by the
// frontend's frames), with LAN discovery to find piccolos and the 6-digit
// pairing for a new one. piccolo is a host for phones and other piccolos and
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
    std::string name;
    NetAddress  address;
    double      seen_at = 0.0;
};

enum class NetShareLinkState : uint8_t
{
    off,          // not started
    idle,         // not connected
    connecting,   // connecting or pairing
    ready,        // connected: `access` says what we may do there
};

// What the frontend shows (a copy, taken under the lock).
struct NetShareLinkStatus
{
    NetShareLinkState state = NetShareLinkState::off;
    NetClientRefusal  refusal = NetClientRefusal::none;   // why the last try ended
    NetAccessLevel    access = NetAccessLevel::gamepad;
    std::string       host_name;
    std::vector<NetShareLinkFound> found;   // piccolos on the LAN, newest first
};

struct NetShareLink
{
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
    std::string connect_code;

    NetShareLinkState state = NetShareLinkState::off;
    NetClientRefusal  refusal = NetClientRefusal::none;
    NetShareLinkFound found[NET_SHARE_LINK_FOUND_MAX];
    uint32_t          found_count = 0;
};

// `hosts_path`: the piccolos we paired with (net_trust format), loaded now.
bool net_share_link_start(NetShareLink* link, const NetKeypair* identity, const char* name, const char* hosts_path);
void net_share_link_stop(NetShareLink* link);
// Started (and not stopped)? Only the frontend's thread starts and stops it,
// so this needs no lock.
bool net_share_link_started(const NetShareLink* link);

// Our shared folders: where gets land and what puts send.
void net_share_link_set_folders(NetShareLink* link, const std::vector<std::string>* game_paths,
                                const char* saves_path, const char* states_path);

// To a piccolo found on the LAN (or any address): `code` = the 6 digits it
// shows to pair, "" when we're paired already. Closes a connection first.
bool net_share_link_connect(NetShareLink* link, NetAddress address, const char* code);
void net_share_link_disconnect(NetShareLink* link);

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
