#pragma once

// The client's side of piccolo-share (net_share.h): a piccolo with SHARE
// access on another one lists its shared folders and copies files both
// ways. No transport of its own: whoever owns the connection hands it the
// host's share messages (net_share_client_handle) and sends what it gives
// (net_share_client_take: control or files channel). The copy runs with one
// NetShareEngine, one file at a time from a queue.
//
// Local paths are virtual too: this piccolo's own shared folders
// (net_share_folders.h), so a copy only ever writes inside them, whichever
// way it goes.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "net_host.h"
#include "net_share_engine.h"
#include "net_share_folders.h"

struct NetShareClientCopy
{
    uint32_t    id = 0;
    bool        to_remote = true;   // a put (ours -> theirs); false: a get
    std::string local;              // virtual, in our shared folders
    std::string remote;             // virtual, in theirs
    uint8_t     flags = 0;          // NET_SHARE_PUT_REPLACE: an existing file may be replaced (either side)
    uint64_t    size = 0;           // a get: as listed (the host's get_ready must say the same)
    uint64_t    mtime = 0;          // a get: as listed (a file of this size and date here already is `same`)
};

// A copy that ended, for the frontend to show.
struct NetShareClientDone
{
    NetShareClientCopy copy;
    NetShareStatus     status = NetShareStatus::ok;
};

enum class NetShareClientStep : uint8_t
{
    idle,
    asked,     // get_request / put_request sent, waiting for get_ready / put_ready
    copying,   // the engine runs
};

struct NetShareClient
{
    const NetShareFolders* local = nullptr;   // ours (the frontend's settings)
    NetShareEngine         engine;
    bool                   started = false;
    uint32_t               next_id = 1;

    // The listing asked for (one at a time: a new one replaces it).
    std::string                list_path;
    uint32_t                   list_id = 0;
    bool                       list_send = false;   // a list_request (from list_next) is due
    uint32_t                   list_next = 0;
    bool                       list_waiting = false;
    bool                       list_done = false;
    NetShareStatus             list_status = NetShareStatus::ok;
    std::vector<NetShareEntry> list_entries;
    std::vector<NetShareEntry> page;

    // Copies.
    std::vector<NetShareClientCopy> queue;
    NetShareClientCopy              current;
    NetShareClientStep              step = NetShareClientStep::idle;
    bool                            request_due = false;   // current's request not sent yet
    std::string                     part;    // a get: where it goes here
    std::string                     target;
    std::string                     real;    // a put: our file
    uint64_t                        offset = 0;
    uint64_t                        put_size = 0;
    uint64_t                        put_mtime = 0;
    bool                            cancel_due = false;
    std::vector<NetShareClientDone> done;   // drained by the frontend
};

void net_share_client_start(NetShareClient* client, const NetShareFolders* local);
void net_share_client_stop(NetShareClient* client);

// The host's shared folder `path` ("" = the shared folders themselves).
// Pages are asked for until the whole listing is there; then
// net_share_client_listing gives it.
void net_share_client_list(NetShareClient* client, const char* path);
// True once the listing asked for is complete (or failed: `status`).
bool net_share_client_listing(const NetShareClient* client, std::string* path, NetShareStatus* status,
                              std::vector<NetShareEntry>* entries);

// Queues a copy (its id is given here). Runs after the ones before it.
uint32_t net_share_client_copy(NetShareClient* client, bool to_remote, const char* local, const char* remote,
                               uint64_t size, uint64_t mtime, uint8_t flags);
// Stops the copy running and drops the queue.
void net_share_client_cancel(NetShareClient* client);

// A message from the host: true if it was piccolo-share's.
bool net_share_client_handle(NetShareClient* client, const uint8_t* data, size_t size);

// The next message to send (0 = nothing now) and its channel. Chunks only
// with `may_send` (little in flight, nobody streaming). Call until 0.
size_t net_share_client_take(NetShareClient* client, bool may_send, uint8_t* out, size_t capacity,
                             NetChannel* channel);

// The copy running (none: role none) and how many wait after it.
void net_share_client_progress(NetShareClient* client, NetShareProgress* progress, NetShareClientCopy* copy,
                               uint32_t* queued);

// The connection went away: the copy stops (a get keeps its part file), the
// queue and the listing are dropped.
void net_share_client_disconnected(NetShareClient* client);
