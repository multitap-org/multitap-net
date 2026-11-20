#pragma once

// One side of a file copy between piccolos (net_share.h), without the
// network: the side that has the file (sender) and the side that writes it
// (receiver) each run one. The network thread hands it what arrives and
// takes what to send; the disk is read and written on the engine's own
// worker thread, never on the network thread (piccolo-netcode: a slow SD
// card, a disk spinning up or a FUSE mount would stall input and remote play).
//
// Memory: one fixed ring of NET_SHARE_RING_SLOTS chunks, allocated at start;
// nothing is allocated per chunk. The sender's worker reads ahead into it,
// the network thread sends from it; the receiver's network thread copies
// chunks into it, the worker writes them out.
//
// Flow: besides the transport's own pacing (the caller's `may_send`: little
// in flight on the connection, nobody streaming), the sender keeps at most
// NET_SHARE_WINDOW bytes past what the receiver says it has written
// (progress, every NET_SHARE_PROGRESS_STEP bytes). That's what keeps a slow
// disk on the receiving side from overflowing its ring: chunks are reliable
// and can't be dropped.
//
// Hash: BLAKE2b-256 of the whole file, from byte 0. A resumed copy hashes the
// part already there first (sender: reading it without sending; receiver:
// reading its part file), so neither side reads the file twice.
//
// One copy at a time per engine: a client copying many files queues them.
// Threads: the net_share_engine_* calls are for one thread (the network's);
// the engine locks against its worker itself.

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "net_share.h"

constexpr uint32_t NET_SHARE_RING_SLOTS = 16;
constexpr uint64_t NET_SHARE_WINDOW = NET_SHARE_RING_SLOTS * NET_SHARE_CHUNK;   // 256 KiB
constexpr uint64_t NET_SHARE_PROGRESS_STEP = 4 * NET_SHARE_CHUNK;               // 64 KiB

enum class NetShareRole : uint8_t
{
    none,
    sender,
    receiver,
};

struct NetShareSlot
{
    uint64_t offset = 0;
    uint32_t count = 0;
    bool     full = false;   // holds bytes the other thread hasn't taken yet
};

struct NetShareEngine
{
    std::mutex              lock;
    std::condition_variable wake;    // the worker waits on it
    std::thread             worker;
    bool                    quit = false;

    std::vector<uint8_t>      storage;   // NET_SHARE_RING_SLOTS * NET_SHARE_CHUNK
    std::vector<NetShareSlot> slots;
    uint32_t                  fill_index = 0;   // the next slot to fill (sender: worker, receiver: network)
    uint32_t                  take_index = 0;   // the next slot to take (sender: network, receiver: worker)

    // The copy.
    NetShareRole role = NetShareRole::none;
    uint32_t     id = 0;
    std::string  path;     // sender: the file; receiver: the part file
    std::string  target;   // receiver: where it goes once checked
    uint64_t     size = 0;
    uint64_t     mtime = 0;
    uint64_t     start = 0;       // resumed from here
    bool         started = false; // the worker picked the copy up
    bool         worker_busy = false;
    bool         cancelled = false;

    uint64_t disk = 0;       // sender: read into the ring; receiver: written to the part file
    uint64_t moved = 0;      // sender: handed to the network; receiver: accepted from it
    uint64_t acked = 0;      // sender: what the receiver says it wrote
    uint64_t reported = 0;   // receiver: the last progress sent
    uint8_t  hash[NET_SHARE_HASH_SIZE] = {};
    uint8_t  expected[NET_SHARE_HASH_SIZE] = {};
    bool     hashed = false;      // sender: whole file read and hashed
    bool     end_sent = false;
    bool     end_received = false;
    bool     finished = false;    // the copy is over: `status` says how
    bool     result_sent = false;
    NetShareStatus status = NetShareStatus::ok;
};

// The worker thread and the ring. Call once.
void net_share_engine_start(NetShareEngine* engine);
// Cancels what runs and joins the worker.
void net_share_engine_stop(NetShareEngine* engine);

// A copy begins (false while another hasn't been cleared). Sender: `path`
// from `offset` (what the receiver already has). Receiver: into `part`
// (net_share_begin_put), which already holds `offset` bytes, renamed over
// `target` with `mtime` once the whole file is there and its hash matches.
bool net_share_engine_send(NetShareEngine* engine, uint32_t id, const char* path, uint64_t file_size,
                           uint64_t offset);
bool net_share_engine_receive(NetShareEngine* engine, uint32_t id, const char* part, const char* target,
                              uint64_t file_size, uint64_t mtime, uint64_t offset);

// The next message to send, if any (0 = nothing now): the sender's chunks
// (only with `may_send`) and its end; the receiver's progress and result.
// Call until it returns 0.
size_t net_share_engine_take(NetShareEngine* engine, bool may_send, uint8_t* out, size_t capacity);

// What arrived for this copy. False: not this copy's, or the other side
// broke the protocol (a chunk out of order, past the file or the window):
// the copy fails (and the caller sends a cancel).
bool net_share_engine_on_chunk(NetShareEngine* engine, uint32_t id, uint64_t offset, const uint8_t* bytes,
                               size_t count);
bool net_share_engine_on_progress(NetShareEngine* engine, uint32_t id, uint64_t received);
bool net_share_engine_on_end(NetShareEngine* engine, uint32_t id, const uint8_t* hash);
bool net_share_engine_on_result(NetShareEngine* engine, uint32_t id, NetShareStatus status);

// Stops the copy (cancel from the other side, or ours). A receiver keeps its
// part file, so a later try resumes.
void net_share_engine_cancel(NetShareEngine* engine);

struct NetShareProgress
{
    NetShareRole   role = NetShareRole::none;
    uint32_t       id = 0;
    uint64_t       size = 0;
    uint64_t       done = 0;   // bytes the receiver has written (both sides)
    bool           finished = false;
    NetShareStatus status = NetShareStatus::ok;
};

void net_share_engine_progress(NetShareEngine* engine, NetShareProgress* progress);

// Ready for the next copy once this one finished or was cancelled and the
// worker let go of it. False while the worker still closes the file.
bool net_share_engine_clear(NetShareEngine* engine);
