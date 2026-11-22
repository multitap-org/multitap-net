#pragma once

// The host's side of net_share.h: its shared folders (the game folders,
// SAVES and STATES) as the virtual paths a SHARE device sees, listed,
// read and written without ever leaving them.
//
// Every path a device sends goes through the same part rules as
// net_content.h ("", ".", "..", '\\', ':' and control characters refused
// before the disk is touched), then host_fs_is_inside on what exists. Names
// starting with '.' are hidden and can't be written: the part files a put
// writes into are hidden ones, ".<name>.piccolo-part" next to the target,
// renamed over it only once the whole file is there and its hash matched
// (net_share_finish_put). Archives are plain files here.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "net_share.h"

struct NetShareRoot
{
    std::string  name;   // what the device sees ("ROMS", "ROMS 2", "SAVES", "STATES")
    std::string  path;   // canonical (host_fs_canonical)
    NetShareKind kind = NetShareKind::games;
};

struct NetShareFolders
{
    std::vector<NetShareRoot> roots;

    // The last folder listed, kept for its next pages.
    std::string                listed_path;
    std::vector<NetShareEntry> listed;
};

// The game folders, then SAVES and STATES ("" = not shared). Folders that
// don't exist now are left out; call again when the settings change. A game
// folder whose name is taken ("saves" can't be "SAVES"... but "SAVES" can)
// gets " 2", " 3".
void net_share_set_folders(NetShareFolders* folders, const std::vector<std::string>* game_paths,
                           const char* saves_path, const char* states_path);

// What's in a virtual folder: "" = the shared folders (kinds games / saves /
// states), otherwise folders first, then files, each sorted ignoring case.
// Hidden entries and symlinks leading out of the shared folders are left out.
NetShareStatus net_share_list(const NetShareFolders* folders, const char* path, std::vector<NetShareEntry>* entries);

// The host's whole answer to a list_request (the first page lists, the next
// ones reuse that listing). Returns its size; 0 if the request isn't one.
size_t net_share_answer_list(NetShareFolders* folders, const uint8_t* request, size_t size, uint8_t* out,
                             size_t capacity);

// A file to send (get): its host path, size and date. Folders are refused.
NetShareStatus net_share_resolve_get(const NetShareFolders* folders, const char* path, std::string* real_path,
                                     uint64_t* file_size, uint64_t* mtime);

// Where a put goes, with everything checked before a byte arrives:
//   - every part safe, the last one not hidden;
//   - missing folders under the shared folder are created (the deepest one
//     that exists must be inside it: a symlink can't lead the new ones out);
//   - an existing target: a folder or symlink is refused, a file needs
//     NET_SHARE_PUT_REPLACE (otherwise `exists`, or `same` when it has
//     `file_size` and `mtime` already: piccolo's copies keep the date, so
//     that's the file copied before);
//   - enough free space for what's still to come (`no_space`).
// `*target` is the file's host path and `*part` the part file the bytes go
// into; `*offset` is how much of it is already there from an earlier try
// (a part longer than the file is thrown away and starts again at 0).
NetShareStatus net_share_begin_put(const NetShareFolders* folders, const char* path, uint64_t file_size,
                                   uint64_t mtime, uint8_t flags, std::string* target, std::string* part, uint64_t* offset);

// The whole file arrived and its hash matched: the part replaces the target
// and takes `mtime` (0 = leave the date it has). False (logged) if the
// rename failed; the part is then left for a later try.
bool net_share_finish_put(const char* part, const char* target, uint64_t mtime);

// A put that won't be finished (mismatch): its part file goes. A cancelled
// put keeps it, so a later try resumes.
void net_share_discard_put(const char* part);

// The part file next to `target`: "/x/Game.sfc" -> "/x/.Game.sfc.piccolo-part".
std::string net_share_part_path(const char* target);
