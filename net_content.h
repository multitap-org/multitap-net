#pragma once

// Games from a client (netcode milestone 5): a paired device with FULL access
// (net_pairing.h: message types 128 and up) browses the host's game folders
// and asks it to start a game with one of its cores.
//
// Paths the client sees are virtual, never the host's own: the first part
// names one game folder (its last folder name: "ROMS"; a second "ROMS"
// becomes "ROMS 2"), the rest goes down from there with '/':
//
//   ""                                 the game folders themselves
//   "ROMS/snes"                        a folder
//   "ROMS/snes/Chrono Trigger.sfc"     a file
//   "ROMS/snes.7z/Chrono Trigger.sfc"  a file inside an archive: archives are
//                                      listed as files of kind `archive` and
//                                      browsed like folders
//
// The host resolves them (net_content_folders.h) and refuses anything that
// isn't inside a game folder once symlinks and ".." are followed: a part
// that is "", "." or "..", or holds '\\', ':' or a control character, is
// refused before the disk is touched, and the result is checked with
// host_fs_is_inside.
//
// Messages (control channel, little-endian; text = u16 length + UTF-8):
//
//   client -> host  cores_request  id u32 | start u32
//   host -> client  cores_result   id u32 | status u8 | start u32 | total u32 | count u16 |
//                                  count x { flags u8 | file | name | version | extensions }
//   client -> host  list_request   id u32 | start u32 | path
//   host -> client  list_result    id u32 | status u8 | start u32 | total u32 | count u16 |
//                                  count x { kind u8 | size u64 | name }
//   client -> host  load_request   id u32 | core file | path ("" = the core without a game)
//   host -> client  load_result    id u32 | status u8
//
// Results are paged: a control message holds NET_LINK_MAX_PAYLOAD bytes and
// a big folder doesn't fit, so a result carries what fits from `start` and
// says how many there are in all; the client asks again from start + count.
// `id` is the client's, echoed in the result. Cores: the host's usable ones
// with their extensions, so the client filters files like LOAD GAME does
// (core first). The core is named by its file name ("snes9x_libretro.so").

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

enum class NetContentMessage : uint8_t
{
    cores_request = 128,
    cores_result = 129,
    list_request = 130,
    list_result = 131,
    load_request = 132,
    load_result = 133,
};

constexpr size_t NET_CONTENT_PATH_MAX = 4096;   // bytes of a virtual path, and of any text field

enum class NetContentStatus : uint8_t
{
    ok,
    not_found,   // no such path, or no such core
    refused,     // outside the game folders, a bad path, or not allowed (a folder to load...)
    failed,      // it exists but couldn't be read or started (see the host's log)
};
constexpr uint8_t NET_CONTENT_STATUS_COUNT = 4;

enum class NetContentKind : uint8_t
{
    folder,
    file,
    archive,   // a zip / 7z on disk: a file that can also be browsed
};
constexpr uint8_t NET_CONTENT_KIND_COUNT = 3;

struct NetContentEntry
{
    NetContentKind kind = NetContentKind::file;
    uint64_t       size = 0;   // files and archives
    std::string    name;
};

constexpr uint8_t NET_CONTENT_CORE_NO_GAME = 1;   // flags: it can start without a game

struct NetContentCore
{
    uint8_t     flags = 0;
    std::string file;         // "snes9x_libretro.so": what load_request names
    std::string name;         // "Snes9x"
    std::string version;
    std::string extensions;   // "smc|sfc|swc|fig", as the core says
};

// --- messages ---------------------------------------------------------------
// Writers return the size, 0 if `capacity` is too small. Readers are false
// unless the payload is exactly that message (texts without NUL bytes, at
// most NET_CONTENT_PATH_MAX bytes, kinds and statuses known).

size_t net_content_write_cores_request(uint8_t* out, size_t capacity, uint32_t id, uint32_t start);
bool   net_content_read_cores_request(const uint8_t* data, size_t size, uint32_t* id, uint32_t* start);

// The cores from `start` that fit (none when `status` isn't ok).
size_t net_content_write_cores_result(uint8_t* out, size_t capacity, uint32_t id, NetContentStatus status,
                                      const std::vector<NetContentCore>* cores, uint32_t start);
bool   net_content_read_cores_result(const uint8_t* data, size_t size, uint32_t* id, NetContentStatus* status,
                                     uint32_t* start, uint32_t* total, std::vector<NetContentCore>* cores);

size_t net_content_write_list_request(uint8_t* out, size_t capacity, uint32_t id, uint32_t start, const char* path);
bool   net_content_read_list_request(const uint8_t* data, size_t size, uint32_t* id, uint32_t* start,
                                     std::string* path);

// The entries from `start` that fit (none when `status` isn't ok).
size_t net_content_write_list_result(uint8_t* out, size_t capacity, uint32_t id, NetContentStatus status,
                                     const std::vector<NetContentEntry>* entries, uint32_t start);
bool   net_content_read_list_result(const uint8_t* data, size_t size, uint32_t* id, NetContentStatus* status,
                                    uint32_t* start, uint32_t* total, std::vector<NetContentEntry>* entries);

size_t net_content_write_load_request(uint8_t* out, size_t capacity, uint32_t id, const char* core_file,
                                      const char* path);
bool   net_content_read_load_request(const uint8_t* data, size_t size, uint32_t* id, std::string* core_file,
                                     std::string* path);

size_t net_content_write_load_result(uint8_t* out, size_t capacity, uint32_t id, NetContentStatus status);
bool   net_content_read_load_result(const uint8_t* data, size_t size, uint32_t* id, NetContentStatus* status);
