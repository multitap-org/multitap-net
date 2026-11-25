// Checks net_share_folders.h (the host's shared folders for SHARE devices):
// the roots and their names, listings (hidden and part files left out, links
// leading out left out), gets and puts that never leave the shared folders
// ("..", backslashes, ':', hidden names, symlinks pointing out, a file where
// a folder should be), puts that refuse to overwrite unless asked, resume
// from a part file, and finishing / discarding a put.
//
// Usage: frontend_net_share_folders_test <scratch folder>
// Exit code 0 = all checks passed. Each failure is printed.

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <unistd.h>   // symlink
#endif

#include "host_fs.h"
#include "net_link.h"
#include "net_share_folders.h"

static int g_failures = 0;

static void check(bool condition, const char* what)
{
    if (!condition)
    {
        std::printf("FAIL %s\n", what);
        g_failures++;
    }
}

static void write_text(const std::string* path, const char* text)
{
    host_fs_write_file(path->c_str(), text, std::strlen(text));
}

static bool has_entry(const std::vector<NetShareEntry>* entries, const char* name)
{
    for (size_t i = 0; i < entries->size(); i++)
    {
        if ((*entries)[i].name == name)
        {
            return true;
        }
    }
    return false;
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::printf("FAIL no scratch folder given\n");
        return 1;
    }
    // A folder of its own per run (the links and files of an earlier run stay
    // behind), canonical so paths compare with the roots'.
    std::string run = std::string(argv[1]) + "/run-" + std::to_string(std::time(nullptr)) + "-" +
                      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    char canonical_base[4096] = {};
    if (!host_fs_make_directories(run.c_str()) || !host_fs_canonical(run.c_str(), canonical_base, sizeof(canonical_base)))
    {
        std::printf("FAIL scratch folder\n");
        return 1;
    }
    std::string base = canonical_base;
    std::string roms = base + "/roms";
    std::string roms2 = base + "/other/roms";
    std::string saves = base + "/saves";
    std::string states = base + "/states";
    std::string screenshots = base + "/screenshots";
    std::string outside = base + "/outside";
    host_fs_make_directories((roms + "/gba").c_str());
    host_fs_make_directories(roms2.c_str());
    host_fs_make_directories((saves + "/mGBA").c_str());
    host_fs_make_directories(states.c_str());
    host_fs_make_directories(screenshots.c_str());
    host_fs_make_directories(outside.c_str());
    std::string game = roms + "/gba/Metroid Fusion.gba";
    write_text(&game, "FUSION");
    std::string hidden = roms + "/gba/.hidden";
    write_text(&hidden, "x");
    std::string old_part = roms + "/gba/.Zero Mission.gba.piccolo-part";
    write_text(&old_part, "ZER");
    std::string secret = outside + "/secret.txt";
    write_text(&secret, "SECRET");
    std::string save = saves + "/mGBA/Metroid Fusion.srm";
    write_text(&save, "SRAM");
    host_fs_set_mtime(game.c_str(), 1700000000);
#if !defined(_WIN32)
    std::string link_out = roms + "/out";
    std::string link_file = roms + "/gba/secret.txt";
    std::string link_in = roms + "/same";
    check(symlink(outside.c_str(), link_out.c_str()) == 0, "symlink out made");
    check(symlink(secret.c_str(), link_file.c_str()) == 0, "file symlink out made");
    check(symlink((roms + "/gba").c_str(), link_in.c_str()) == 0, "symlink in made");
#endif

    NetShareFolders folders;
    NetShareFolderPaths paths;
    paths.games.push_back(roms);
    paths.games.push_back(roms2);
    paths.games.push_back(base + "/missing");
    std::string named_saves = base + "/SAVES";
    host_fs_make_directories(named_saves.c_str());
    paths.games.push_back(named_saves);
    paths.saves = saves;
    paths.states = states;
    paths.screenshots = screenshots;
    net_share_set_folders(&folders, &paths);
    check(folders.roots.size() == 6, "missing folders left out");
    check(folders.roots.size() == 6 && folders.roots[0].name == "roms" && folders.roots[1].name == "roms 2" &&
              folders.roots[2].name == "SAVES 2" && folders.roots[3].name == "SAVES" &&
              folders.roots[3].kind == NetShareKind::saves && folders.roots[4].name == "STATES" &&
              folders.roots[4].kind == NetShareKind::states && folders.roots[5].name == "SCREENSHOTS" &&
              folders.roots[5].kind == NetShareKind::screenshots,
          "roots: game folders first, SAVES / STATES / SCREENSHOTS keep their names");

    // Listing.
    std::vector<NetShareEntry> entries;
    check(net_share_list(&folders, "", &entries) == NetShareStatus::ok && entries.size() == 6 &&
              entries[0].kind == NetShareKind::games && entries[3].kind == NetShareKind::saves &&
              entries[5].kind == NetShareKind::screenshots,
          "root listing with kinds");
    check(net_share_list(&folders, "roms/gba", &entries) == NetShareStatus::ok, "folder listed");
    check(has_entry(&entries, "Metroid Fusion.gba") && !has_entry(&entries, ".hidden") &&
              !has_entry(&entries, ".Zero Mission.gba.piccolo-part"),
          "hidden and part files left out");
    for (size_t i = 0; i < entries.size(); i++)
    {
        if (entries[i].name == "Metroid Fusion.gba")
        {
            check(entries[i].size == 6 && entries[i].mtime == 1700000000, "size and date listed");
        }
    }
#if !defined(_WIN32)
    check(!has_entry(&entries, "secret.txt"), "file link leading out left out");
    check(net_share_list(&folders, "roms", &entries) == NetShareStatus::ok && !has_entry(&entries, "out") &&
              has_entry(&entries, "same"),
          "folder link out left out, link inside kept");
    check(net_share_list(&folders, "roms/out", &entries) == NetShareStatus::refused, "listing through a link out refused");
#endif
    check(net_share_list(&folders, "roms/..", &entries) == NetShareStatus::refused, "\"..\" refused");
    check(net_share_list(&folders, "roms/gba/Metroid Fusion.gba", &entries) == NetShareStatus::refused,
          "a file isn't listed");
    check(net_share_list(&folders, "nope", &entries) == NetShareStatus::not_found, "unknown root");

    // Paged answers.
    uint8_t request[256];
    static uint8_t out[NET_LINK_MAX_PAYLOAD];
    size_t size = net_share_write_list_request(request, sizeof(request), 5, 0, "roms/gba");
    size_t answer = net_share_answer_list(&folders, request, size, out, sizeof(out));
    uint32_t id = 0;
    NetShareStatus status = NetShareStatus::failed;
    uint32_t start = 0;
    uint32_t total = 0;
    check(answer > 0 && net_share_read_list_result(out, answer, &id, &status, &start, &total, &entries) && id == 5 &&
              status == NetShareStatus::ok && total == entries.size() && has_entry(&entries, "Metroid Fusion.gba"),
          "list answered");

    // Get.
    std::string real;
    uint64_t file_size = 0;
    uint64_t mtime = 0;
    check(net_share_resolve_get(&folders, "roms/gba/Metroid Fusion.gba", &real, &file_size, &mtime) ==
                  NetShareStatus::ok &&
              file_size == 6 && mtime == 1700000000,
          "get resolved");
    check(net_share_resolve_get(&folders, "roms/gba", &real, &file_size, &mtime) == NetShareStatus::refused,
          "get of a folder refused");
    check(net_share_resolve_get(&folders, "roms/gba/.hidden", &real, &file_size, &mtime) == NetShareStatus::not_found,
          "hidden file can't be got");
    check(net_share_resolve_get(&folders, "roms/gba/../../outside/secret.txt", &real, &file_size, &mtime) ==
              NetShareStatus::refused,
          "get with \"..\" refused");
    check(net_share_resolve_get(&folders, "roms/gba\\..\\x", &real, &file_size, &mtime) == NetShareStatus::refused,
          "backslash refused");
    check(net_share_resolve_get(&folders, "roms/C:x", &real, &file_size, &mtime) == NetShareStatus::refused,
          "':' refused");
#if !defined(_WIN32)
    check(net_share_resolve_get(&folders, "roms/gba/secret.txt", &real, &file_size, &mtime) == NetShareStatus::refused,
          "get through a file link out refused");
    check(net_share_resolve_get(&folders, "roms/out/secret.txt", &real, &file_size, &mtime) == NetShareStatus::refused,
          "get through a folder link out refused");
#endif

    // Put.
    std::string target;
    std::string part;
    uint64_t offset = 99;
    check(net_share_begin_put(&folders, "roms/gba/Metroid Fusion.gba", 10, 0, 0, &target, &part, &offset) ==
              NetShareStatus::exists,
          "existing file not replaced unless asked");
    uint64_t there_size = 0;
    uint64_t there_mtime = 0;
    host_fs_file_info(game.c_str(), &there_size, &there_mtime);
    check(net_share_begin_put(&folders, "roms/gba/Metroid Fusion.gba", there_size, there_mtime, 0, &target, &part,
                              &offset) == NetShareStatus::same,
          "same size and date: nothing to copy");
    check(net_share_begin_put(&folders, "roms/gba/Metroid Fusion.gba", there_size, there_mtime + 1, 0, &target, &part,
                              &offset) == NetShareStatus::exists,
          "another date: exists");
    check(net_share_begin_put(&folders, "roms/gba/Metroid Fusion.gba", there_size, there_mtime, NET_SHARE_PUT_REPLACE,
                              &target, &part, &offset) == NetShareStatus::ok,
          "the same file is still replaced when asked");
    check(net_share_begin_put(&folders, "roms/gba/Metroid Fusion.gba", 10, 0, NET_SHARE_PUT_REPLACE, &target, &part,
                              &offset) == NetShareStatus::ok &&
              offset == 0 && target == game && part == roms + "/gba/.Metroid Fusion.gba.piccolo-part",
          "replace allowed when asked");
    check(net_share_begin_put(&folders, "roms/gba/Zero Mission.gba", 8, 0, 0, &target, &part, &offset) ==
                  NetShareStatus::ok &&
              offset == 3 && part == old_part,
          "resume from the part file");
    check(net_share_begin_put(&folders, "roms/gba/Zero Mission.gba", 2, 0, 0, &target, &part, &offset) ==
                  NetShareStatus::ok &&
              offset == 0 && !host_fs_exists(old_part.c_str()),
          "a part longer than the file starts again");
    check(net_share_begin_put(&folders, "roms/gba", 8, 0, NET_SHARE_PUT_REPLACE, &target, &part, &offset) ==
              NetShareStatus::refused,
          "a folder can't be replaced");
    check(net_share_begin_put(&folders, "roms", 8, 0, NET_SHARE_PUT_REPLACE, &target, &part, &offset) ==
              NetShareStatus::refused,
          "a root can't be written");
    check(net_share_begin_put(&folders, "roms/gba/.evil", 8, 0, 0, &target, &part, &offset) == NetShareStatus::refused,
          "hidden names can't be written");
    check(net_share_begin_put(&folders, "roms/../outside/x", 8, 0, 0, &target, &part, &offset) ==
              NetShareStatus::refused,
          "put with \"..\" refused");
    check(net_share_begin_put(&folders, "roms/gba/Metroid Fusion.gba/x", 8, 0, 0, &target, &part, &offset) ==
              NetShareStatus::refused,
          "a file where a folder should be");
    check(net_share_begin_put(&folders, "SAVES/mGBA/Golden Sun.srm", 8, 0, 0, &target, &part, &offset) ==
              NetShareStatus::ok,
          "put into SAVES");
    check(net_share_begin_put(&folders, "STATES/mGBA/Golden Sun.state1", 8, 0, 0, &target, &part, &offset) ==
                  NetShareStatus::ok &&
              host_fs_is_directory((states + "/mGBA").c_str()),
          "missing core folder made");
    check(net_share_begin_put(&folders, "roms/gba/Huge.gba", UINT64_MAX / 2, 0, 0, &target, &part, &offset) ==
              NetShareStatus::no_space,
          "no space for a huge file");
#if !defined(_WIN32)
    check(net_share_begin_put(&folders, "roms/out/new/file.bin", 8, 0, 0, &target, &part, &offset) ==
                  NetShareStatus::refused &&
              !host_fs_exists((outside + "/new").c_str()),
          "put through a link out refused, nothing made outside");
    check(net_share_begin_put(&folders, "roms/gba/secret.txt", 8, 0, NET_SHARE_PUT_REPLACE, &target, &part, &offset) ==
              NetShareStatus::refused,
          "a link target is never replaced");
    check(net_share_begin_put(&folders, "roms/same/New.gba", 8, 0, 0, &target, &part, &offset) == NetShareStatus::ok,
          "put through a link inside allowed");
#endif

    // Finish and discard.
    check(net_share_begin_put(&folders, "roms/gba/New Game.gba", 4, 0, 0, &target, &part, &offset) == NetShareStatus::ok,
          "new put");
    write_text(&part, "NEW!");
    check(net_share_finish_put(part.c_str(), target.c_str(), 1600000000) && !host_fs_exists(part.c_str()),
          "finished: part renamed");
    check(host_fs_file_info(target.c_str(), &file_size, &mtime) && file_size == 4 && mtime == 1600000000,
          "finished file has its size and date");
    check(net_share_begin_put(&folders, "roms/gba/Bad.gba", 4, 0, 0, &target, &part, &offset) == NetShareStatus::ok,
          "another put");
    write_text(&part, "BAD!");
    net_share_discard_put(part.c_str());
    check(!host_fs_exists(part.c_str()) && !host_fs_exists(target.c_str()), "discarded: nothing left");
    uint8_t* data = nullptr;
    size_t data_size = 0;
    check(host_fs_read_file(secret.c_str(), &data, &data_size) && data_size == 6 && std::memcmp(data, "SECRET", 6) == 0,
          "the outside file is untouched");
    delete[] data;

    // RECORDINGS and CONFIG (2026-11-25). CONFIG never shows what makes a
    // device itself, at any depth, nor the frontend's own names.
    std::string recordings = base + "/recordings";
    std::string config = base + "/config";
    std::string remap = config + "/remaps/mGBA/Metroid Fusion.rmp";
    write_text(&remap, "REMAP");
    std::string identity = config + "/net_identity.cfg";
    write_text(&identity, "secret = x");
    std::string devices = config + "/net_devices.cfg";
    write_text(&devices, "[device:x]");
    std::string cached = config + "/cache/thumbs.bin";
    write_text(&cached, "C");
    std::string nested = config + "/remaps/Net_Devices.CFG";
    write_text(&nested, "N");
    std::string global = config + "/piccolo.cfg";
    write_text(&global, "G");
    host_fs_make_directories(recordings.c_str());
    NetShareFolderPaths more;
    more.recordings = recordings;
    more.config = config;
    more.config_refused.push_back("piccolo.cfg");
    NetShareFolders config_folders;
    net_share_set_folders(&config_folders, &more);
    check(config_folders.roots.size() == 2 && config_folders.roots[0].name == "RECORDINGS" &&
              config_folders.roots[0].kind == NetShareKind::recordings && config_folders.roots[1].name == "CONFIG" &&
              config_folders.roots[1].kind == NetShareKind::config,
          "RECORDINGS and CONFIG roots, with their kinds");
    check(net_share_list(&config_folders, "CONFIG", &entries) == NetShareStatus::ok && entries.size() == 1 &&
              entries[0].name == "remaps",
          "CONFIG lists only what doesn't belong to the device (no identity, devices, cache, frontend file)");
    check(net_share_list(&config_folders, "CONFIG/remaps", &entries) == NetShareStatus::ok &&
              has_entry(&entries, "mGBA") && !has_entry(&entries, "Net_Devices.CFG"),
          "refused names at any depth, ignoring case");
    std::string real_path;
    check(net_share_resolve_get(&config_folders, "CONFIG/net_identity.cfg", &real_path, &file_size, &mtime) ==
              NetShareStatus::not_found,
          "the identity can't be read through CONFIG");
    check(net_share_resolve_get(&config_folders, "CONFIG/remaps/mGBA/Metroid Fusion.rmp", &real_path, &file_size,
                                &mtime) == NetShareStatus::ok,
          "a remap can");
    check(net_share_begin_put(&config_folders, "CONFIG/net_devices.cfg", 1, 0, NET_SHARE_PUT_REPLACE, &target, &part,
                              &offset) == NetShareStatus::not_found,
          "the paired devices can't be written through CONFIG");
    check(net_share_begin_put(&config_folders, "CONFIG/cache/new.bin", 1, 0, 0, &target, &part, &offset) ==
              NetShareStatus::not_found,
          "nor anything in cache/");
    check(net_share_begin_put(&config_folders, "CONFIG/piccolo.cfg", 1, 0, NET_SHARE_PUT_REPLACE, &target, &part,
                              &offset) == NetShareStatus::not_found,
          "nor the frontend's global settings");

    if (g_failures == 0)
    {
        std::printf("net share folders: all checks passed\n");
    }
    return g_failures == 0 ? 0 : 1;
}
