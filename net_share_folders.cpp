#include "net_share_folders.h"

#include <algorithm>
#include <cstring>

#include "host_fs.h"
#include "host_log.h"
#include "net_content.h"
#include "net_wire.h"

// Kept free on the disk beyond the file itself, so a put never fills it to
// the last byte (other programs, the saves of the game being played).
static constexpr uint64_t FREE_SPACE_MARGIN = 64ull * 1024 * 1024;

static const char* const PART_SUFFIX = ".piccolo-part";

// ---------------------------------------------------------------------------
// Shared folders
// ---------------------------------------------------------------------------

static bool root_named(const NetShareFolders* folders, const std::string* name)
{
    for (size_t i = 0; i < folders->roots.size(); i++)
    {
        if (folders->roots[i].name == *name)
        {
            return true;
        }
    }
    return false;
}

// Adds a root if the folder exists now, named `base` or "base 2", "base 3"...
static void add_root(NetShareFolders* folders, const char* path, const std::string* base, NetShareKind kind)
{
    char canonical[NET_WIRE_TEXT_MAX] = {};
    if (path[0] == '\0')
    {
        return;   // not shared
    }
    if (!host_fs_canonical(path, canonical, sizeof(canonical)) || !host_fs_is_directory(canonical))
    {
        host_log(LogLevel::info, "Network: shared folder %s isn't there now, not offered", path);
        return;
    }
    NetShareRoot root;
    root.path = canonical;
    root.kind = kind;
    root.name = *base;
    for (uint32_t n = 2; root_named(folders, &root.name); n++)
    {
        root.name = *base + " " + std::to_string(n);
    }
    folders->roots.push_back(root);
}

void net_share_set_folders(NetShareFolders* folders, const std::vector<std::string>* game_paths,
                           const char* saves_path, const char* states_path,
                           const char* screenshots_path)
{
    folders->roots.clear();
    folders->listed_path.clear();
    folders->listed.clear();
    // SAVES, STATES and SCREENSHOTS are named first, so a game folder can't
    // take their names; they're listed after the game folders.
    std::string saves_name = "SAVES";
    std::string states_name = "STATES";
    std::string screenshots_name = "SCREENSHOTS";
    add_root(folders, saves_path, &saves_name, NetShareKind::saves);
    add_root(folders, states_path, &states_name, NetShareKind::states);
    add_root(folders, screenshots_path, &screenshots_name, NetShareKind::screenshots);
    size_t fixed = folders->roots.size();
    for (size_t i = 0; i < game_paths->size(); i++)
    {
        std::string base = net_content_folder_name(&(*game_paths)[i]);
        add_root(folders, (*game_paths)[i].c_str(), &base, NetShareKind::games);
    }
    std::rotate(folders->roots.begin(), folders->roots.begin() + static_cast<std::ptrdiff_t>(fixed),
                folders->roots.end());
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

static std::string join(const std::string* folder, const std::string* name)
{
    if (!folder->empty() && folder->back() == '/')
    {
        return *folder + *name;
    }
    return *folder + "/" + *name;
}

// A virtual path split and checked: every part safe, the first naming a
// root. Nothing on disk is touched.
static NetShareStatus split_checked(const NetShareFolders* folders, const char* path, std::vector<std::string>* parts,
                                    const NetShareRoot** root)
{
    if (std::strlen(path) > NET_WIRE_TEXT_MAX)
    {
        return NetShareStatus::refused;
    }
    net_content_split_path(path, parts);
    for (size_t i = 0; i < parts->size(); i++)
    {
        if (!net_content_part_is_safe(&(*parts)[i]))
        {
            host_log(LogLevel::warning, "Network: share: refused path \"%s\"", path);
            return NetShareStatus::refused;
        }
    }
    *root = nullptr;
    for (size_t i = 0; i < folders->roots.size(); i++)
    {
        if (folders->roots[i].name == (*parts)[0])
        {
            *root = &folders->roots[i];
        }
    }
    return *root != nullptr ? NetShareStatus::ok : NetShareStatus::not_found;
}

// An existing path inside the shared folders: its canonical host path.
static NetShareStatus resolve_existing(const NetShareFolders* folders, const char* path, std::string* real_path)
{
    std::vector<std::string> parts;
    const NetShareRoot* root = nullptr;
    NetShareStatus status = split_checked(folders, path, &parts, &root);
    if (status != NetShareStatus::ok)
    {
        return status;
    }
    std::string disk = root->path;
    for (size_t i = 1; i < parts.size(); i++)
    {
        if (parts[i][0] == '.')
        {
            return NetShareStatus::not_found;   // hidden: never listed, never reached
        }
        disk = join(&disk, &parts[i]);
    }
    if (!host_fs_exists(disk.c_str()))
    {
        return NetShareStatus::not_found;
    }
    // The parts were checked, so this is about symlinks.
    if (!host_fs_is_inside(root->path.c_str(), disk.c_str()))
    {
        host_log(LogLevel::warning, "Network: share: refused path \"%s\" (leads out of the shared folders)", path);
        return NetShareStatus::refused;
    }
    char canonical[NET_WIRE_TEXT_MAX] = {};
    if (!host_fs_canonical(disk.c_str(), canonical, sizeof(canonical)))
    {
        return NetShareStatus::not_found;
    }
    *real_path = canonical;
    return NetShareStatus::ok;
}

std::string net_share_part_path(const char* target)
{
    std::string path = target;
    size_t slash = path.rfind('/');
    size_t name_at = slash == std::string::npos ? 0 : slash + 1;
    return path.substr(0, name_at) + "." + path.substr(name_at) + PART_SUFFIX;
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

static char lower_ascii(char c)
{
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}

// Folders first, then by name ignoring ASCII case (then exactly, so the
// order is the same every time).
static bool entry_before(const NetShareEntry& a, const NetShareEntry& b)
{
    bool a_folder = a.kind == NetShareKind::folder;
    bool b_folder = b.kind == NetShareKind::folder;
    if (a_folder != b_folder)
    {
        return a_folder;
    }
    size_t length = a.name.size() < b.name.size() ? a.name.size() : b.name.size();
    for (size_t i = 0; i < length; i++)
    {
        char x = lower_ascii(a.name[i]);
        char y = lower_ascii(b.name[i]);
        if (x != y)
        {
            return static_cast<uint8_t>(x) < static_cast<uint8_t>(y);
        }
    }
    if (a.name.size() != b.name.size())
    {
        return a.name.size() < b.name.size();
    }
    return a.name < b.name;
}

NetShareStatus net_share_list(const NetShareFolders* folders, const char* path, std::vector<NetShareEntry>* entries)
{
    entries->clear();
    if (path[0] == '\0')
    {
        for (size_t i = 0; i < folders->roots.size(); i++)
        {
            NetShareEntry entry;
            entry.kind = folders->roots[i].kind;
            entry.name = folders->roots[i].name;
            entries->push_back(entry);
        }
        return NetShareStatus::ok;   // game folders in the settings' order, then SAVES, STATES
    }
    std::string real_path;
    NetShareStatus status = resolve_existing(folders, path, &real_path);
    if (status != NetShareStatus::ok)
    {
        return status;
    }
    if (!host_fs_is_directory(real_path.c_str()))
    {
        return NetShareStatus::refused;   // not a folder
    }
    // Which root: what a symlink inside may lead to is checked against it.
    std::vector<std::string> parts;
    net_content_split_path(path, &parts);
    const NetShareRoot* root = nullptr;
    for (size_t i = 0; i < folders->roots.size(); i++)
    {
        if (folders->roots[i].name == parts[0])
        {
            root = &folders->roots[i];
        }
    }
    std::vector<HostFsEntry> listed;
    if (root == nullptr || !host_fs_list_directory(real_path.c_str(), &listed))
    {
        return NetShareStatus::failed;
    }
    for (size_t i = 0; i < listed.size(); i++)
    {
        const HostFsEntry* item = &listed[i];
        if (item->name.empty() || item->name[0] == '.')
        {
            continue;   // hidden (part files included)
        }
        if (item->is_symlink)
        {
            std::string item_path = join(&real_path, &item->name);
            if (!host_fs_is_inside(root->path.c_str(), item_path.c_str()))
            {
                continue;   // leads out: left out rather than shown and refused later
            }
        }
        NetShareEntry entry;
        entry.kind = item->is_directory ? NetShareKind::folder : NetShareKind::file;
        entry.size = item->is_directory ? 0 : item->size;
        entry.mtime = item->is_directory ? 0 : item->mtime;
        entry.name = item->name;
        entries->push_back(entry);
    }
    std::sort(entries->begin(), entries->end(), entry_before);
    return NetShareStatus::ok;
}

size_t net_share_answer_list(NetShareFolders* folders, const uint8_t* request, size_t size, uint8_t* out,
                             size_t capacity)
{
    uint32_t id = 0;
    uint32_t start = 0;
    std::string path;
    if (!net_share_read_list_request(request, size, &id, &start, &path))
    {
        return 0;
    }
    NetShareStatus status = NetShareStatus::ok;
    if (start == 0 || path != folders->listed_path)
    {
        status = net_share_list(folders, path.c_str(), &folders->listed);
        folders->listed_path = status == NetShareStatus::ok ? path : std::string();
        if (status != NetShareStatus::ok)
        {
            folders->listed.clear();
        }
    }
    if (status == NetShareStatus::ok && start > folders->listed.size())
    {
        start = static_cast<uint32_t>(folders->listed.size());
    }
    return net_share_write_list_result(out, capacity, id, status, &folders->listed, start);
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

NetShareStatus net_share_resolve_get(const NetShareFolders* folders, const char* path, std::string* real_path,
                                     uint64_t* file_size, uint64_t* mtime)
{
    std::string found;
    NetShareStatus status = resolve_existing(folders, path, &found);
    if (status != NetShareStatus::ok)
    {
        return status;
    }
    if (host_fs_is_directory(found.c_str()))
    {
        return NetShareStatus::refused;   // files only (a folder is its files, one by one)
    }
    if (!host_fs_file_info(found.c_str(), file_size, mtime))
    {
        return NetShareStatus::failed;
    }
    *real_path = found;
    return NetShareStatus::ok;
}

// ---------------------------------------------------------------------------
// Put
// ---------------------------------------------------------------------------

NetShareStatus net_share_begin_put(const NetShareFolders* folders, const char* path, uint64_t file_size,
                                   uint64_t mtime, uint8_t flags, std::string* target, std::string* part, uint64_t* offset)
{
    std::vector<std::string> parts;
    const NetShareRoot* root = nullptr;
    NetShareStatus status = split_checked(folders, path, &parts, &root);
    if (status != NetShareStatus::ok)
    {
        return status;
    }
    if (parts.size() < 2)
    {
        return NetShareStatus::refused;   // a shared folder itself isn't a file
    }
    for (size_t i = 1; i < parts.size(); i++)
    {
        if (parts[i][0] == '.')
        {
            host_log(LogLevel::warning, "Network: share: refused path \"%s\" (hidden name)", path);
            return NetShareStatus::refused;
        }
    }

    // The deepest folder that exists must be inside the root (a symlink in
    // the way would lead the new folders out); the missing ones are made
    // under it.
    std::string folder = root->path;
    size_t existing = 1;
    while (existing < parts.size() - 1)
    {
        std::string next = join(&folder, &parts[existing]);
        if (!host_fs_exists(next.c_str()))
        {
            break;
        }
        if (!host_fs_is_directory(next.c_str()))
        {
            return NetShareStatus::refused;   // a file where a folder should be
        }
        folder = next;
        existing++;
    }
    if (!host_fs_is_inside(root->path.c_str(), folder.c_str()))
    {
        host_log(LogLevel::warning, "Network: share: refused path \"%s\" (leads out of the shared folders)", path);
        return NetShareStatus::refused;
    }
    for (size_t i = existing; i < parts.size() - 1; i++)
    {
        folder = join(&folder, &parts[i]);
    }
    std::string file = join(&folder, &parts.back());

    if (host_fs_exists(file.c_str()) || host_fs_is_symlink(file.c_str()))
    {
        if (host_fs_is_symlink(file.c_str()) || host_fs_is_directory(file.c_str()))
        {
            return NetShareStatus::refused;
        }
        if ((flags & NET_SHARE_PUT_REPLACE) == 0)
        {
            uint64_t there_size = 0;
            uint64_t there_mtime = 0;
            bool same = mtime != 0 && host_fs_file_info(file.c_str(), &there_size, &there_mtime) &&
                        there_size == file_size && there_mtime == mtime;
            return same ? NetShareStatus::same : NetShareStatus::exists;
        }
    }

    // What an earlier try left. A part that isn't a plain file is refused; a
    // part longer than the file can't be from it.
    std::string part_file = net_share_part_path(file.c_str());
    uint64_t already = 0;
    if (host_fs_is_symlink(part_file.c_str()) || host_fs_is_directory(part_file.c_str()))
    {
        return NetShareStatus::refused;
    }
    uint64_t part_size = 0;
    uint64_t part_mtime = 0;
    if (host_fs_file_info(part_file.c_str(), &part_size, &part_mtime))
    {
        if (part_size <= file_size)
        {
            already = part_size;
        }
        else if (!host_fs_remove_file(part_file.c_str()))
        {
            return NetShareStatus::failed;
        }
    }

    if (!host_fs_make_directories(folder.c_str()))
    {
        return NetShareStatus::failed;
    }
    // Made inside the root, from a folder already checked: still inside.
    uint64_t free_bytes = 0;
    if (!host_fs_free_space(folder.c_str(), &free_bytes))
    {
        return NetShareStatus::failed;
    }
    uint64_t needed = file_size - already;
    if (free_bytes < needed || free_bytes - needed < FREE_SPACE_MARGIN)
    {
        return NetShareStatus::no_space;
    }
    *target = file;
    *part = part_file;
    *offset = already;
    return NetShareStatus::ok;
}

bool net_share_finish_put(const char* part, const char* target, uint64_t mtime)
{
    if (!host_fs_rename(part, target))
    {
        return false;
    }
    if (mtime != 0)
    {
        host_fs_set_mtime(target, mtime);   // a date that can't be set isn't worth failing the copy
    }
    return true;
}

void net_share_discard_put(const char* part)
{
    host_fs_remove_file(part);
}
