#pragma once

// Files between piccolos (piccolo-share, 2026-11-20): a paired device with
// SHARE access (net_pairing.h: message types 192..255) browses the host's
// shared folders and copies files both ways: games, saves, states.
//
// Paths are virtual, like net_content.h's: the first part names one shared
// folder, the rest goes down from there with '/'. The shared folders are the
// game folders plus SAVES, STATES and SCREENSHOTS; the root listing ("")
// says which is which by kind, so a client knows where a game's saves and
// states live.
// Archives are plain files here (copied whole, never browsed). The host
// resolves every path without ever leaving the shared folders (the same part
// rules as net_content.h, then host_fs_is_inside); writes go to a hidden
// part file next to the target and are renamed over only once the whole file
// has arrived and its hash matches.
//
// Messages (control channel unless said, little-endian; text = u16 length + UTF-8):
//
//   client -> host  list_request    id u32 | start u32 | path
//   host -> client  list_result     id u32 | status u8 | start u32 | total u32 | count u16 |
//                                   count x { kind u8 | size u64 | mtime u64 | name }
//
//   client -> host  get_request     id u32 | offset u64 | path       (offset > 0: resume)
//   host -> client  get_ready       id u32 | status u8 | size u64 | mtime u64
//   client -> host  put_request     id u32 | size u64 | mtime u64 | flags u8 | path
//   host -> client  put_ready       id u32 | status u8 | offset u64  (bytes already there: resume)
//
// Then the side that has the file (the host for a get, the client for a put)
// sends it from the offset:
//
//   sender          chunk           id u32 | offset u64 | bytes      (files channel; at most
//                                                                    NET_SHARE_CHUNK bytes)
//   receiver        progress        id u32 | received u64            (now and then: the bar, resume)
//   sender          end             id u32 | hash[32]                (all bytes sent; BLAKE2b-256
//                                                                    of the whole file)
//   receiver        result          id u32 | status u8               (ok: checked and in place)
//   either          cancel          id u32
//
// `id` is the client's, one per file, echoed by both sides. The hash is the
// whole file's (from byte 0, the part already there included), computed by
// the sender as it reads and checked by the receiver once it has it all; a
// mismatch throws the part file away (result `mismatch`). mtime: seconds
// since 1970, 0 when unknown; the receiver sets it on the finished file.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

enum class NetShareMessage : uint8_t
{
    list_request = 192,
    list_result = 193,
    get_request = 194,
    get_ready = 195,
    put_request = 196,
    put_ready = 197,
    chunk = 198,
    progress = 199,
    end = 200,
    result = 201,
    cancel = 202,
};

constexpr size_t   NET_SHARE_HASH_SIZE = 32;      // BLAKE2b-256
constexpr size_t   NET_SHARE_CHUNK = 16384;       // bytes of file in one chunk (piccolo-netcode: ENet fragments it)
constexpr size_t   NET_SHARE_CHUNK_HEADER = 13;   // type + id + offset
constexpr uint8_t  NET_SHARE_PUT_REPLACE = 1;     // put_request flags: an existing file may be replaced

enum class NetShareStatus : uint8_t
{
    ok,
    not_found,   // no such path
    refused,     // outside the shared folders, a bad path or name, a folder, an archive's inside
    exists,      // put without NET_SHARE_PUT_REPLACE onto an existing file
    no_space,    // not enough free space for the file
    busy,        // too many transfers at once; ask again later
    mismatch,    // the whole file arrived but its hash doesn't match: thrown away
    failed,      // it couldn't be read or written (see that side's log)
    same,        // put without NET_SHARE_PUT_REPLACE onto a file of the same size and date: nothing to copy
};
constexpr uint8_t NET_SHARE_STATUS_COUNT = 9;

enum class NetShareKind : uint8_t
{
    folder,
    file,
    games,    // root listing: a game folder
    saves,    // root listing: SAVES (<core>/<game>.srm ...)
    states,   // root listing: STATES (<core>/<game>.stateN + .png)
    screenshots,   // root listing: SCREENSHOTS (no save / state lookup)
};
// Kinds this build knows. A list_result with a kind past these (a newer
// build's folder kind) reads it as a plain folder, so new kinds can be added
// without breaking older readers. Builds before SCREENSHOTS refused the whole
// listing instead; none of those were released.
constexpr uint8_t NET_SHARE_KIND_COUNT = 6;

struct NetShareEntry
{
    NetShareKind kind = NetShareKind::file;
    uint64_t     size = 0;    // files
    uint64_t     mtime = 0;   // seconds since 1970, 0 = unknown
    std::string  name;
};

// --- messages ---------------------------------------------------------------
// Writers return the size, 0 if `capacity` is too small. Readers are false
// unless the payload is exactly that message (texts without NUL bytes, at
// most NET_WIRE_TEXT_MAX bytes, statuses known; an unknown kind reads as
// NetShareKind::folder).

size_t net_share_write_list_request(uint8_t* out, size_t capacity, uint32_t id, uint32_t start, const char* path);
bool   net_share_read_list_request(const uint8_t* data, size_t size, uint32_t* id, uint32_t* start,
                                   std::string* path);

// The entries from `start` that fit (none when `status` isn't ok).
size_t net_share_write_list_result(uint8_t* out, size_t capacity, uint32_t id, NetShareStatus status,
                                   const std::vector<NetShareEntry>* entries, uint32_t start);
bool   net_share_read_list_result(const uint8_t* data, size_t size, uint32_t* id, NetShareStatus* status,
                                  uint32_t* start, uint32_t* total, std::vector<NetShareEntry>* entries);

size_t net_share_write_get_request(uint8_t* out, size_t capacity, uint32_t id, uint64_t offset, const char* path);
bool   net_share_read_get_request(const uint8_t* data, size_t size, uint32_t* id, uint64_t* offset,
                                  std::string* path);

size_t net_share_write_get_ready(uint8_t* out, size_t capacity, uint32_t id, NetShareStatus status,
                                 uint64_t file_size, uint64_t mtime);
bool   net_share_read_get_ready(const uint8_t* data, size_t size, uint32_t* id, NetShareStatus* status,
                                uint64_t* file_size, uint64_t* mtime);

size_t net_share_write_put_request(uint8_t* out, size_t capacity, uint32_t id, uint64_t file_size, uint64_t mtime,
                                   uint8_t flags, const char* path);
bool   net_share_read_put_request(const uint8_t* data, size_t size, uint32_t* id, uint64_t* file_size,
                                  uint64_t* mtime, uint8_t* flags, std::string* path);

size_t net_share_write_put_ready(uint8_t* out, size_t capacity, uint32_t id, NetShareStatus status, uint64_t offset);
bool   net_share_read_put_ready(const uint8_t* data, size_t size, uint32_t* id, NetShareStatus* status,
                                uint64_t* offset);

// A chunk: `bytes` (1..NET_SHARE_CHUNK) of the file from `offset`; `out` needs
// NET_SHARE_CHUNK_HEADER + bytes. Reading points `*bytes` into `data` (no copy).
size_t net_share_write_chunk(uint8_t* out, size_t capacity, uint32_t id, uint64_t offset, const uint8_t* bytes,
                             size_t count);
bool   net_share_read_chunk(const uint8_t* data, size_t size, uint32_t* id, uint64_t* offset, const uint8_t** bytes,
                            size_t* count);

size_t net_share_write_progress(uint8_t* out, size_t capacity, uint32_t id, uint64_t received);
bool   net_share_read_progress(const uint8_t* data, size_t size, uint32_t* id, uint64_t* received);

size_t net_share_write_end(uint8_t* out, size_t capacity, uint32_t id, const uint8_t* hash);
bool   net_share_read_end(const uint8_t* data, size_t size, uint32_t* id, uint8_t* hash);

size_t net_share_write_result(uint8_t* out, size_t capacity, uint32_t id, NetShareStatus status);
bool   net_share_read_result(const uint8_t* data, size_t size, uint32_t* id, NetShareStatus* status);

size_t net_share_write_cancel(uint8_t* out, size_t capacity, uint32_t id);
bool   net_share_read_cancel(const uint8_t* data, size_t size, uint32_t* id);
