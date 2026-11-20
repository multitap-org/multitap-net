#include "net_share_engine.h"

#include <cstring>

#include "host_fs.h"
#include "host_log.h"
#include "monocypher.h"
#include "net_share_folders.h"

// The ring's slots, then one more chunk the worker uses on its own (hashing
// what a resumed copy already has, while the network may be filling slots).
static uint8_t* slot_data(NetShareEngine* engine, uint32_t slot)
{
    return engine->storage.data() + static_cast<size_t>(slot) * NET_SHARE_CHUNK;
}

static uint8_t* scratch(NetShareEngine* engine)
{
    return slot_data(engine, NET_SHARE_RING_SLOTS);
}

// With the lock held.
static bool should_stop(const NetShareEngine* engine)
{
    return engine->quit || engine->cancelled || engine->finished;
}

static void finish(NetShareEngine* engine, NetShareStatus status)
{
    std::lock_guard<std::mutex> guard(engine->lock);
    if (!engine->finished)
    {
        engine->finished = true;
        engine->status = status;
    }
}

// Hashes the first `count` bytes of `file` (already open at 0) through the
// worker's scratch chunk. False if the file is shorter or can't be read.
static bool hash_prefix(NetShareEngine* engine, HostFsFile* file, uint64_t count, crypto_blake2b_ctx* context)
{
    uint64_t left = count;
    while (left > 0)
    {
        size_t want = left < NET_SHARE_CHUNK ? static_cast<size_t>(left) : NET_SHARE_CHUNK;
        size_t got = 0;
        if (!host_fs_file_read(file, scratch(engine), want, &got) || got != want)
        {
            return false;
        }
        crypto_blake2b_update(context, scratch(engine), got);
        left -= got;
    }
    return true;
}

// ---------------------------------------------------------------------------
// The worker
// ---------------------------------------------------------------------------

// Sender: reads the file into the ring, hashing as it goes.
static void run_sender(NetShareEngine* engine)
{
    std::string path;
    uint64_t size = 0;
    uint64_t position = 0;
    {
        std::lock_guard<std::mutex> guard(engine->lock);
        path = engine->path;
        size = engine->size;
        position = engine->start;
    }
    crypto_blake2b_ctx context;
    crypto_blake2b_init(&context, NET_SHARE_HASH_SIZE);
    HostFsFile* file = host_fs_open_read(path.c_str(), 0);
    if (file == nullptr || !hash_prefix(engine, file, position, &context))
    {
        host_fs_file_close(file);
        finish(engine, NetShareStatus::failed);
        return;
    }
    while (position < size)
    {
        uint32_t slot = 0;
        {
            std::unique_lock<std::mutex> guard(engine->lock);
            while (!should_stop(engine) && engine->slots[engine->fill_index].full)
            {
                engine->wake.wait(guard);
            }
            if (should_stop(engine))
            {
                guard.unlock();
                host_fs_file_close(file);
                return;
            }
            slot = engine->fill_index;
        }
        // The slot isn't full: the network thread won't touch it.
        uint64_t left = size - position;
        size_t want = left < NET_SHARE_CHUNK ? static_cast<size_t>(left) : NET_SHARE_CHUNK;
        size_t got = 0;
        if (!host_fs_file_read(file, slot_data(engine, slot), want, &got) || got != want)
        {
            host_log(LogLevel::error, "Network: share: %s changed while it was sent", path.c_str());
            host_fs_file_close(file);
            finish(engine, NetShareStatus::failed);
            return;
        }
        crypto_blake2b_update(&context, slot_data(engine, slot), got);
        {
            std::lock_guard<std::mutex> guard(engine->lock);
            engine->slots[slot].offset = position;
            engine->slots[slot].count = static_cast<uint32_t>(got);
            engine->slots[slot].full = true;
            engine->fill_index = (slot + 1) % NET_SHARE_RING_SLOTS;
            engine->disk = position + got;
        }
        position += got;
    }
    host_fs_file_close(file);
    std::lock_guard<std::mutex> guard(engine->lock);
    crypto_blake2b_final(&context, engine->hash);
    engine->hashed = true;
}

// Receiver: writes the ring out to the part file, hashing as it goes; once
// the end is there, checks the hash and puts the file in place.
static void run_receiver(NetShareEngine* engine)
{
    std::string part;
    std::string target;
    uint64_t size = 0;
    uint64_t start = 0;
    uint64_t mtime = 0;
    {
        std::lock_guard<std::mutex> guard(engine->lock);
        part = engine->path;
        target = engine->target;
        size = engine->size;
        start = engine->start;
        mtime = engine->mtime;
    }
    crypto_blake2b_ctx context;
    crypto_blake2b_init(&context, NET_SHARE_HASH_SIZE);
    if (start > 0)
    {
        HostFsFile* before = host_fs_open_read(part.c_str(), 0);
        bool ok = before != nullptr && hash_prefix(engine, before, start, &context);
        host_fs_file_close(before);
        if (!ok)
        {
            finish(engine, NetShareStatus::failed);
            return;
        }
    }
    HostFsFile* file = host_fs_open_append(part.c_str());
    if (file == nullptr)
    {
        finish(engine, NetShareStatus::failed);
        return;
    }
    for (;;)
    {
        uint32_t slot = 0;
        {
            std::unique_lock<std::mutex> guard(engine->lock);
            while (!should_stop(engine) && !engine->slots[engine->take_index].full &&
                   !(engine->end_received && engine->disk == size))
            {
                engine->wake.wait(guard);
            }
            if (should_stop(engine))
            {
                guard.unlock();
                host_fs_file_close(file);   // the part stays: a later try resumes
                return;
            }
            if (!engine->slots[engine->take_index].full)
            {
                break;   // everything written and the end is here
            }
            slot = engine->take_index;
        }
        // The slot is full: the network thread won't touch it until it's freed.
        uint32_t count = engine->slots[slot].count;
        if (!host_fs_file_write(file, slot_data(engine, slot), count))
        {
            host_fs_file_close(file);
            finish(engine, NetShareStatus::failed);
            return;
        }
        crypto_blake2b_update(&context, slot_data(engine, slot), count);
        std::lock_guard<std::mutex> guard(engine->lock);
        engine->slots[slot].full = false;
        engine->take_index = (slot + 1) % NET_SHARE_RING_SLOTS;
        engine->disk += count;
    }
    if (!host_fs_file_close(file))
    {
        finish(engine, NetShareStatus::failed);
        return;
    }
    uint8_t hash[NET_SHARE_HASH_SIZE];
    crypto_blake2b_final(&context, hash);
    uint8_t expected[NET_SHARE_HASH_SIZE];
    {
        std::lock_guard<std::mutex> guard(engine->lock);
        std::memcpy(expected, engine->expected, sizeof(expected));
    }
    if (crypto_verify32(hash, expected) != 0)
    {
        host_log(LogLevel::warning, "Network: share: %s arrived different from what was sent, thrown away",
                 target.c_str());
        net_share_discard_put(part.c_str());
        finish(engine, NetShareStatus::mismatch);
        return;
    }
    finish(engine, net_share_finish_put(part.c_str(), target.c_str(), mtime) ? NetShareStatus::ok
                                                                              : NetShareStatus::failed);
}

static void run(NetShareEngine* engine)
{
    std::unique_lock<std::mutex> guard(engine->lock);
    while (!engine->quit)
    {
        bool pending = engine->role != NetShareRole::none && !engine->started && !engine->cancelled &&
                       !engine->finished;
        if (!pending)
        {
            engine->wake.wait(guard);
            continue;
        }
        engine->started = true;
        engine->worker_busy = true;
        NetShareRole role = engine->role;
        guard.unlock();
        if (role == NetShareRole::sender)
        {
            run_sender(engine);
        }
        else
        {
            run_receiver(engine);
        }
        guard.lock();
        engine->worker_busy = false;
    }
}

// ---------------------------------------------------------------------------
// The network thread's side
// ---------------------------------------------------------------------------

void net_share_engine_start(NetShareEngine* engine)
{
    engine->storage.assign(static_cast<size_t>(NET_SHARE_RING_SLOTS + 1) * NET_SHARE_CHUNK, 0);
    engine->slots.assign(NET_SHARE_RING_SLOTS, NetShareSlot());
    engine->quit = false;
    engine->worker = std::thread(run, engine);
}

void net_share_engine_stop(NetShareEngine* engine)
{
    {
        std::lock_guard<std::mutex> guard(engine->lock);
        engine->quit = true;
        engine->cancelled = true;
    }
    engine->wake.notify_all();
    if (engine->worker.joinable())
    {
        engine->worker.join();
    }
}

// With the lock held: ready for a new copy.
static void reset(NetShareEngine* engine)
{
    for (uint32_t i = 0; i < NET_SHARE_RING_SLOTS; i++)
    {
        engine->slots[i] = NetShareSlot();
    }
    engine->fill_index = 0;
    engine->take_index = 0;
    engine->role = NetShareRole::none;
    engine->id = 0;
    engine->path.clear();
    engine->target.clear();
    engine->size = 0;
    engine->mtime = 0;
    engine->start = 0;
    engine->started = false;
    engine->cancelled = false;
    engine->disk = 0;
    engine->moved = 0;
    engine->acked = 0;
    engine->reported = 0;
    std::memset(engine->hash, 0, sizeof(engine->hash));
    std::memset(engine->expected, 0, sizeof(engine->expected));
    engine->hashed = false;
    engine->end_sent = false;
    engine->end_received = false;
    engine->finished = false;
    engine->result_sent = false;
    engine->status = NetShareStatus::ok;
}

static bool begin(NetShareEngine* engine, NetShareRole role, uint32_t id, const char* path, const char* target,
                  uint64_t file_size, uint64_t mtime, uint64_t offset)
{
    {
        std::lock_guard<std::mutex> guard(engine->lock);
        if (engine->role != NetShareRole::none || engine->worker_busy || offset > file_size)
        {
            return false;
        }
        reset(engine);
        engine->role = role;
        engine->id = id;
        engine->path = path;
        engine->target = target;
        engine->size = file_size;
        engine->mtime = mtime;
        engine->start = offset;
        engine->disk = offset;
        engine->moved = offset;
        engine->acked = offset;
        engine->reported = offset;
    }
    engine->wake.notify_all();
    return true;
}

bool net_share_engine_send(NetShareEngine* engine, uint32_t id, const char* path, uint64_t file_size, uint64_t offset)
{
    return begin(engine, NetShareRole::sender, id, path, "", file_size, 0, offset);
}

bool net_share_engine_receive(NetShareEngine* engine, uint32_t id, const char* part, const char* target,
                              uint64_t file_size, uint64_t mtime, uint64_t offset)
{
    return begin(engine, NetShareRole::receiver, id, part, target, file_size, mtime, offset);
}

static size_t take_sender(NetShareEngine* engine, bool may_send, uint8_t* out, size_t capacity)
{
    if (engine->finished)
    {
        if (engine->status != NetShareStatus::ok && !engine->result_sent)
        {
            engine->result_sent = true;   // ours failed (the file couldn't be read): the other side is told
            return net_share_write_cancel(out, capacity, engine->id);
        }
        return 0;
    }
    NetShareSlot* slot = &engine->slots[engine->take_index];
    if (may_send && slot->full && engine->moved + slot->count - engine->acked <= NET_SHARE_WINDOW)
    {
        size_t size = net_share_write_chunk(out, capacity, engine->id, slot->offset,
                                            slot_data(engine, engine->take_index), slot->count);
        if (size == 0)
        {
            return 0;
        }
        engine->moved += slot->count;
        slot->full = false;
        engine->take_index = (engine->take_index + 1) % NET_SHARE_RING_SLOTS;
        engine->wake.notify_all();
        return size;
    }
    if (engine->hashed && engine->moved == engine->size && !engine->end_sent)
    {
        size_t size = net_share_write_end(out, capacity, engine->id, engine->hash);
        engine->end_sent = size > 0;
        return size;
    }
    return 0;
}

static size_t take_receiver(NetShareEngine* engine, uint8_t* out, size_t capacity)
{
    bool all = engine->disk == engine->size && engine->reported < engine->size;
    if (engine->disk - engine->reported >= NET_SHARE_PROGRESS_STEP || all)
    {
        size_t size = net_share_write_progress(out, capacity, engine->id, engine->disk);
        if (size > 0)
        {
            engine->reported = engine->disk;
        }
        return size;
    }
    if (engine->finished && !engine->result_sent)
    {
        engine->result_sent = true;
        if (engine->cancelled)
        {
            return 0;   // cancelled: the cancel says it
        }
        return net_share_write_result(out, capacity, engine->id, engine->status);
    }
    return 0;
}

size_t net_share_engine_take(NetShareEngine* engine, bool may_send, uint8_t* out, size_t capacity)
{
    std::lock_guard<std::mutex> guard(engine->lock);
    if (engine->role == NetShareRole::sender)
    {
        return take_sender(engine, may_send, out, capacity);
    }
    if (engine->role == NetShareRole::receiver)
    {
        return take_receiver(engine, out, capacity);
    }
    return 0;
}

// With the lock held: the other side broke the protocol.
static bool violation(NetShareEngine* engine, const char* what)
{
    host_log(LogLevel::warning, "Network: share: %s, copy %u stopped", what, engine->id);
    if (!engine->finished)
    {
        engine->finished = true;
        engine->status = NetShareStatus::failed;
    }
    engine->wake.notify_all();
    return false;
}

bool net_share_engine_on_chunk(NetShareEngine* engine, uint32_t id, uint64_t offset, const uint8_t* bytes,
                               size_t count)
{
    std::lock_guard<std::mutex> guard(engine->lock);
    if (engine->role != NetShareRole::receiver || engine->id != id || engine->finished)
    {
        return false;
    }
    if (offset != engine->moved || count == 0 || count > NET_SHARE_CHUNK || count > engine->size - engine->moved)
    {
        return violation(engine, "a chunk out of order or past the file");
    }
    NetShareSlot* slot = &engine->slots[engine->fill_index];
    if (slot->full)
    {
        return violation(engine, "a chunk past the window");
    }
    std::memcpy(slot_data(engine, engine->fill_index), bytes, count);
    slot->offset = offset;
    slot->count = static_cast<uint32_t>(count);
    slot->full = true;
    engine->fill_index = (engine->fill_index + 1) % NET_SHARE_RING_SLOTS;
    engine->moved += count;
    engine->wake.notify_all();
    return true;
}

bool net_share_engine_on_progress(NetShareEngine* engine, uint32_t id, uint64_t received)
{
    std::lock_guard<std::mutex> guard(engine->lock);
    if (engine->role != NetShareRole::sender || engine->id != id || engine->finished)
    {
        return false;
    }
    if (received > engine->moved)
    {
        return violation(engine, "progress past what was sent");
    }
    if (received > engine->acked)
    {
        engine->acked = received;
    }
    return true;
}

bool net_share_engine_on_end(NetShareEngine* engine, uint32_t id, const uint8_t* hash)
{
    std::lock_guard<std::mutex> guard(engine->lock);
    if (engine->role != NetShareRole::receiver || engine->id != id || engine->finished)
    {
        return false;
    }
    if (engine->moved != engine->size || engine->end_received)
    {
        return violation(engine, "an end before the whole file");
    }
    std::memcpy(engine->expected, hash, NET_SHARE_HASH_SIZE);
    engine->end_received = true;
    engine->wake.notify_all();
    return true;
}

bool net_share_engine_on_result(NetShareEngine* engine, uint32_t id, NetShareStatus status)
{
    std::lock_guard<std::mutex> guard(engine->lock);
    if (engine->role != NetShareRole::sender || engine->id != id || engine->finished)
    {
        return false;
    }
    engine->finished = true;
    engine->status = status;
    engine->result_sent = true;   // the receiver's answer: nothing to tell it
    if (status == NetShareStatus::ok)
    {
        engine->acked = engine->size;
    }
    engine->wake.notify_all();
    return true;
}

void net_share_engine_cancel(NetShareEngine* engine)
{
    {
        std::lock_guard<std::mutex> guard(engine->lock);
        if (engine->role == NetShareRole::none)
        {
            return;
        }
        engine->cancelled = true;
        engine->result_sent = true;   // the caller sends (or got) the cancel: nothing more from us
        if (!engine->finished)
        {
            engine->finished = true;
            engine->status = NetShareStatus::failed;
        }
    }
    engine->wake.notify_all();
}

void net_share_engine_progress(NetShareEngine* engine, NetShareProgress* progress)
{
    std::lock_guard<std::mutex> guard(engine->lock);
    progress->role = engine->role;
    progress->id = engine->id;
    progress->size = engine->size;
    progress->done = engine->role == NetShareRole::sender ? engine->acked : engine->disk;
    progress->finished = engine->finished;
    progress->status = engine->status;
}

bool net_share_engine_clear(NetShareEngine* engine)
{
    std::lock_guard<std::mutex> guard(engine->lock);
    if (engine->role == NetShareRole::none)
    {
        return true;
    }
    if (!engine->finished || engine->worker_busy)
    {
        return false;
    }
    reset(engine);
    return true;
}
