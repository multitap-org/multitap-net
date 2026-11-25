// Checks net_share.h (files between piccolos): every message written and
// read back, damaged messages refused (cut, a byte more, unknown statuses,
// kinds and flags), chunks within their bounds, list results paged so every
// entry arrives once, and every type in SHARE's range.
//
// Usage: frontend_net_share_test
// Exit code 0 = all checks passed. Each failure is printed.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "net_link.h"
#include "net_pairing.h"
#include "net_share.h"

static int g_failures = 0;

static void check(bool condition, const char* what)
{
    if (!condition)
    {
        std::printf("FAIL %s\n", what);
        g_failures++;
    }
}

static void test_types()
{
    for (uint32_t type = static_cast<uint32_t>(NetShareMessage::list_request);
         type <= static_cast<uint32_t>(NetShareMessage::cancel); type++)
    {
        if (net_message_required_access(static_cast<uint8_t>(type)) != NetAccessLevel::share)
        {
            std::printf("FAIL share type %u doesn't need owner\n", type);
            g_failures++;
        }
    }
}

static void test_requests()
{
    uint8_t out[NET_LINK_MAX_PAYLOAD];
    uint32_t id = 0;
    uint32_t start = 0;
    uint64_t offset = 0;
    uint64_t file_size = 0;
    uint64_t mtime = 0;
    uint8_t flags = 0;
    std::string path;

    size_t size = net_share_write_list_request(out, sizeof(out), 7, 40, "SAVES/mgba");
    check(size > 0 && out[0] == 192, "list_request written");
    check(net_share_read_list_request(out, size, &id, &start, &path) && id == 7 && start == 40 && path == "SAVES/mgba",
          "list_request read");
    check(!net_share_read_list_request(out, size - 1, &id, &start, &path), "list_request cut refused");
    out[size] = 0;
    check(!net_share_read_list_request(out, size + 1, &id, &start, &path), "list_request with a byte more refused");

    size = net_share_write_get_request(out, sizeof(out), 9, 1048576, "ROMS/gba/Metroid Fusion.gba");
    check(size > 0 && net_share_read_get_request(out, size, &id, &offset, &path) && id == 9 && offset == 1048576 &&
              path == "ROMS/gba/Metroid Fusion.gba",
          "get_request read");
    check(!net_share_read_list_request(out, size, &id, &start, &path), "a get_request isn't a list_request");

    size = net_share_write_put_request(out, sizeof(out), 11, 8388608, 1795000000, NET_SHARE_PUT_REPLACE,
                                       "STATES/mgba/Metroid Fusion.state1");
    check(size > 0 &&
              net_share_read_put_request(out, size, &id, &file_size, &mtime, &flags, &path) && id == 11 &&
              file_size == 8388608 && mtime == 1795000000 && flags == NET_SHARE_PUT_REPLACE &&
              path == "STATES/mgba/Metroid Fusion.state1",
          "put_request read");
    out[21] = 2;   // flags: type 1 + id 4 + size 8 + mtime 8 = 21
    check(!net_share_read_put_request(out, size, &id, &file_size, &mtime, &flags, &path),
          "put_request with unknown flags refused");

    std::string long_path(5000, 'a');
    check(net_share_write_get_request(out, sizeof(out), 1, 0, long_path.c_str()) == 0,
          "a path over the text limit isn't written");
}

static void test_answers()
{
    uint8_t out[64];
    uint32_t id = 0;
    NetShareStatus status = NetShareStatus::failed;
    uint64_t file_size = 0;
    uint64_t mtime = 0;
    uint64_t offset = 0;

    size_t size = net_share_write_get_ready(out, sizeof(out), 3, NetShareStatus::ok, 4194304, 1700000000);
    check(size == 22 && net_share_read_get_ready(out, size, &id, &status, &file_size, &mtime) && id == 3 &&
              status == NetShareStatus::ok && file_size == 4194304 && mtime == 1700000000,
          "get_ready read");
    out[5] = NET_SHARE_STATUS_COUNT;
    check(!net_share_read_get_ready(out, size, &id, &status, &file_size, &mtime), "unknown status refused");

    size = net_share_write_put_ready(out, sizeof(out), 4, NetShareStatus::ok, 65536);
    check(size == 14 && net_share_read_put_ready(out, size, &id, &status, &offset) && id == 4 && offset == 65536,
          "put_ready read (resume offset)");
    size = net_share_write_put_ready(out, sizeof(out), 4, NetShareStatus::exists, 0);
    check(net_share_read_put_ready(out, size, &id, &status, &offset) && status == NetShareStatus::exists,
          "put_ready exists");

    uint64_t received = 0;
    size = net_share_write_progress(out, sizeof(out), 5, 3145728);
    check(net_share_read_progress(out, size, &id, &received) && id == 5 && received == 3145728, "progress read");

    uint8_t hash[NET_SHARE_HASH_SIZE];
    for (size_t i = 0; i < sizeof(hash); i++)
    {
        hash[i] = static_cast<uint8_t>(i * 7 + 1);
    }
    uint8_t got[NET_SHARE_HASH_SIZE] = {};
    size = net_share_write_end(out, sizeof(out), 6, hash);
    check(size == 5 + NET_SHARE_HASH_SIZE && net_share_read_end(out, size, &id, got) && id == 6 &&
              std::memcmp(hash, got, sizeof(hash)) == 0,
          "end read (hash)");
    check(!net_share_read_end(out, size - 1, &id, got), "end with a short hash refused");
    check(net_share_write_end(out, 20, 6, hash) == 0, "end doesn't fit: not written");

    size = net_share_write_result(out, sizeof(out), 7, NetShareStatus::mismatch);
    check(net_share_read_result(out, size, &id, &status) && id == 7 && status == NetShareStatus::mismatch,
          "result read");
    size = net_share_write_cancel(out, sizeof(out), 8);
    check(size == 5 && net_share_read_cancel(out, size, &id) && id == 8, "cancel read");
    check(!net_share_read_result(out, size, &id, &status), "a cancel isn't a result");
}

static void test_chunks()
{
    static uint8_t file[NET_SHARE_CHUNK + 1];
    for (size_t i = 0; i < sizeof(file); i++)
    {
        file[i] = static_cast<uint8_t>(i * 31);
    }
    static uint8_t out[NET_LINK_MAX_PAYLOAD];
    check(NET_SHARE_CHUNK_HEADER + NET_SHARE_CHUNK <= NET_LINK_MAX_PAYLOAD, "a whole chunk fits one control message");

    size_t size = net_share_write_chunk(out, sizeof(out), 12, 32768, file, NET_SHARE_CHUNK);
    uint32_t id = 0;
    uint64_t offset = 0;
    const uint8_t* bytes = nullptr;
    size_t count = 0;
    check(size == NET_SHARE_CHUNK_HEADER + NET_SHARE_CHUNK && out[0] == 198, "full chunk written");
    check(net_share_read_chunk(out, size, &id, &offset, &bytes, &count) && id == 12 && offset == 32768 &&
              count == NET_SHARE_CHUNK && bytes == out + NET_SHARE_CHUNK_HEADER &&
              std::memcmp(bytes, file, count) == 0,
          "full chunk read in place");

    size = net_share_write_chunk(out, sizeof(out), 12, 0, file, 1);
    check(size == NET_SHARE_CHUNK_HEADER + 1 && net_share_read_chunk(out, size, &id, &offset, &bytes, &count) &&
              count == 1 && bytes[0] == file[0],
          "one-byte chunk");
    check(net_share_write_chunk(out, sizeof(out), 12, 0, file, 0) == 0, "empty chunk not written");
    check(net_share_write_chunk(out, sizeof(out), 12, 0, file, NET_SHARE_CHUNK + 1) == 0, "oversized chunk not written");
    check(net_share_write_chunk(out, NET_SHARE_CHUNK_HEADER + 10, 12, 0, file, 11) == 0,
          "chunk past capacity not written");
    check(!net_share_read_chunk(out, NET_SHARE_CHUNK_HEADER, &id, &offset, &bytes, &count), "chunk without bytes refused");
    check(!net_share_read_chunk(out, NET_SHARE_CHUNK_HEADER - 1, &id, &offset, &bytes, &count), "cut chunk refused");

    // A payload with more bytes than a chunk may carry (written by hand).
    size = net_share_write_chunk(out, sizeof(out), 12, 0, file, NET_SHARE_CHUNK);
    out[size] = 0;
    check(!net_share_read_chunk(out, size + 1, &id, &offset, &bytes, &count), "chunk over NET_SHARE_CHUNK refused");
}

static void test_list_pages()
{
    std::vector<NetShareEntry> entries;
    NetShareEntry games;
    games.kind = NetShareKind::games;
    games.name = "ROMS";
    entries.push_back(games);
    NetShareEntry saves;
    saves.kind = NetShareKind::saves;
    saves.name = "SAVES";
    entries.push_back(saves);
    for (uint32_t i = 0; i < 3000; i++)
    {
        NetShareEntry entry;
        entry.kind = NetShareKind::file;
        entry.size = 1000u + i;
        entry.mtime = 1700000000u + i;
        char name[64];
        std::snprintf(name, sizeof(name), "Game number %04u (World) (Rev %u).sfc", i, i % 3);
        entry.name = name;
        entries.push_back(entry);
    }

    static uint8_t out[NET_LINK_MAX_PAYLOAD];
    std::vector<NetShareEntry> all;
    std::vector<NetShareEntry> page;
    uint32_t start = 0;
    uint32_t pages = 0;
    bool ok = true;
    while (ok && start < entries.size() && pages < 1000)
    {
        size_t size = net_share_write_list_result(out, sizeof(out), 21, NetShareStatus::ok, &entries, start);
        uint32_t id = 0;
        NetShareStatus status = NetShareStatus::failed;
        uint32_t got_start = 0;
        uint32_t total = 0;
        ok = size > 0 && net_share_read_list_result(out, size, &id, &status, &got_start, &total, &page) && id == 21 &&
             status == NetShareStatus::ok && got_start == start && total == entries.size() && !page.empty();
        for (size_t i = 0; ok && i < page.size(); i++)
        {
            all.push_back(page[i]);
        }
        start += static_cast<uint32_t>(page.size());
        pages++;
    }
    check(ok && pages > 1, "list paged");
    bool same = all.size() == entries.size();
    for (size_t i = 0; same && i < all.size(); i++)
    {
        same = all[i].kind == entries[i].kind && all[i].size == entries[i].size && all[i].mtime == entries[i].mtime &&
               all[i].name == entries[i].name;
    }
    check(same, "every entry arrives once, in order, whole");

    size_t size = net_share_write_list_result(out, sizeof(out), 22, NetShareStatus::refused, &entries, 0);
    uint32_t id = 0;
    NetShareStatus status = NetShareStatus::ok;
    uint32_t got_start = 0;
    uint32_t total = 1;
    check(net_share_read_list_result(out, size, &id, &status, &got_start, &total, &page) &&
              status == NetShareStatus::refused && total == 0 && page.empty(),
          "refused list carries no entries");

    std::vector<NetShareEntry> one;
    one.push_back(games);
    size = net_share_write_list_result(out, sizeof(out), 23, NetShareStatus::ok, &one, 0);
    // Header: type 1, id 4, status 1, start 4, total 4, count 2 = 16; the entry's kind is byte 16.
    // A newer build's kind (past the ones we know) is still a folder to go into.
    out[16] = NET_SHARE_KIND_COUNT;
    check(net_share_read_list_result(out, size, &id, &status, &got_start, &total, &page) && page.size() == 1 &&
              page[0].kind == NetShareKind::folder && page[0].name == "ROMS",
          "unknown kind read as a folder");
    one[0].kind = NetShareKind::screenshots;
    one[0].name = "SCREENSHOTS";
    size = net_share_write_list_result(out, sizeof(out), 24, NetShareStatus::ok, &one, 0);
    check(net_share_read_list_result(out, size, &id, &status, &got_start, &total, &page) && page.size() == 1 &&
              page[0].kind == NetShareKind::screenshots,
          "screenshots kind round trip");
}

int main()
{
    test_types();
    test_requests();
    test_answers();
    test_chunks();
    test_list_pages();
    if (g_failures == 0)
    {
        std::printf("net share: all checks passed\n");
    }
    return g_failures == 0 ? 0 : 1;
}
