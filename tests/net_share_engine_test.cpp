// Checks net_share_engine.h (one side of a file copy, disk on its own
// thread): two engines joined by an in-memory wire copy files into a shared
// folder (net_share_folders.h) and the copy is byte for byte the same, with
// its date; the window is never passed (the receiver's ring never overflows);
// nothing is sent while the transport says no; a copy cancelled halfway
// resumes from its part file; a byte changed on the way is caught by the hash
// (the part thrown away, nothing put in place); a file shorter than announced
// fails the sender; chunks out of order are refused; empty files copy.
//
// Usage: frontend_net_share_engine_test <scratch folder>
// Exit code 0 = all checks passed. Each failure is printed.

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <deque>
#include <string>
#include <thread>
#include <vector>

#include "host_fs.h"
#include "net_link.h"
#include "net_share_engine.h"
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

// What travels from one side to the other, in order (a reliable channel).
struct Wire
{
    std::deque<std::vector<uint8_t>> to_receiver;
    std::deque<std::vector<uint8_t>> to_sender;
};

struct Run
{
    uint64_t max_outstanding = 0;    // chunk bytes sent past the receiver's progress
    uint64_t chunk_bytes = 0;        // all chunk bytes sent
    uint64_t receiver_progress = 0;  // the last progress the sender got
    bool     refused_chunk = false;  // the receiver refused a chunk (window or order)
    bool     sender_cancelled = false;
    int32_t  corrupt_chunk = -1;     // this chunk (counting from 0) gets one byte changed on the way
    int32_t  chunks_seen = 0;
};

static void deliver_to_receiver(NetShareEngine* receiver, std::vector<uint8_t>* message, Run* run)
{
    const uint8_t* data = message->data();
    size_t size = message->size();
    uint32_t id = 0;
    if (data[0] == static_cast<uint8_t>(NetShareMessage::chunk))
    {
        uint64_t offset = 0;
        const uint8_t* bytes = nullptr;
        size_t count = 0;
        if (net_share_read_chunk(data, size, &id, &offset, &bytes, &count) &&
            !net_share_engine_on_chunk(receiver, id, offset, bytes, count))
        {
            run->refused_chunk = true;
        }
    }
    else if (data[0] == static_cast<uint8_t>(NetShareMessage::end))
    {
        uint8_t hash[NET_SHARE_HASH_SIZE];
        if (net_share_read_end(data, size, &id, hash))
        {
            net_share_engine_on_end(receiver, id, hash);
        }
    }
    else if (data[0] == static_cast<uint8_t>(NetShareMessage::cancel))
    {
        run->sender_cancelled = true;
        net_share_engine_cancel(receiver);
    }
}

static void deliver_to_sender(NetShareEngine* sender, std::vector<uint8_t>* message, Run* run)
{
    const uint8_t* data = message->data();
    size_t size = message->size();
    uint32_t id = 0;
    if (data[0] == static_cast<uint8_t>(NetShareMessage::progress))
    {
        uint64_t received = 0;
        if (net_share_read_progress(data, size, &id, &received))
        {
            run->receiver_progress = received;
            net_share_engine_on_progress(sender, id, received);
        }
    }
    else if (data[0] == static_cast<uint8_t>(NetShareMessage::result))
    {
        NetShareStatus status = NetShareStatus::failed;
        if (net_share_read_result(data, size, &id, &status))
        {
            net_share_engine_on_result(sender, id, status);
        }
    }
}

// One round: each side sends what it has, then gets what arrived. Up to
// `budget` messages travel each way per round (a slow link holds the rest).
static void pump(NetShareEngine* sender, NetShareEngine* receiver, Wire* wire, Run* run, bool may_send,
                 size_t budget)
{
    static uint8_t out[NET_LINK_MAX_PAYLOAD];
    for (;;)
    {
        size_t size = net_share_engine_take(sender, may_send, out, sizeof(out));
        if (size == 0)
        {
            break;
        }
        std::vector<uint8_t> message(out, out + size);
        if (out[0] == static_cast<uint8_t>(NetShareMessage::chunk))
        {
            uint32_t id = 0;
            uint64_t offset = 0;
            const uint8_t* bytes = nullptr;
            size_t count = 0;
            net_share_read_chunk(out, size, &id, &offset, &bytes, &count);
            run->chunk_bytes += count;
            uint64_t outstanding = offset + count - run->receiver_progress;
            if (outstanding > run->max_outstanding)
            {
                run->max_outstanding = outstanding;
            }
            if (run->chunks_seen == run->corrupt_chunk)
            {
                message[NET_SHARE_CHUNK_HEADER] ^= 0x5A;
            }
            run->chunks_seen++;
        }
        wire->to_receiver.push_back(message);
    }
    for (;;)
    {
        size_t size = net_share_engine_take(receiver, true, out, sizeof(out));
        if (size == 0)
        {
            break;
        }
        wire->to_sender.push_back(std::vector<uint8_t>(out, out + size));
    }
    for (size_t i = 0; i < budget && !wire->to_receiver.empty(); i++)
    {
        deliver_to_receiver(receiver, &wire->to_receiver.front(), run);
        wire->to_receiver.pop_front();
    }
    for (size_t i = 0; i < budget && !wire->to_sender.empty(); i++)
    {
        deliver_to_sender(sender, &wire->to_sender.front(), run);
        wire->to_sender.pop_front();
    }
}

// Pumps until both sides finished (or `rounds` run out, or `stop_at` bytes
// were written on the receiving side when it isn't 0).
static bool pump_until_done(NetShareEngine* sender, NetShareEngine* receiver, Wire* wire, Run* run, size_t budget,
                            uint64_t stop_at)
{
    for (int round = 0; round < 200000; round++)
    {
        pump(sender, receiver, wire, run, true, budget);
        NetShareProgress a;
        NetShareProgress b;
        net_share_engine_progress(sender, &a);
        net_share_engine_progress(receiver, &b);
        if (a.finished && b.finished && wire->to_receiver.empty() && wire->to_sender.empty())
        {
            return true;
        }
        if (stop_at != 0 && b.done >= stop_at)
        {
            return false;
        }
        if (round % 64 == 63)
        {
            std::this_thread::sleep_for(std::chrono::microseconds(200));   // let the workers catch up
        }
    }
    return false;
}

static void make_file(const std::string* path, size_t size, uint32_t seed)
{
    std::vector<uint8_t> data(size);
    uint32_t x = seed;
    for (size_t i = 0; i < size; i++)
    {
        x = x * 1664525u + 1013904223u;
        data[i] = static_cast<uint8_t>(x >> 24);
    }
    host_fs_write_file(path->c_str(), data.data(), data.size());
}

static bool same_files(const std::string* a, const std::string* b)
{
    uint8_t* x = nullptr;
    uint8_t* y = nullptr;
    size_t x_size = 0;
    size_t y_size = 0;
    bool same = host_fs_read_file(a->c_str(), &x, &x_size) && host_fs_read_file(b->c_str(), &y, &y_size) &&
                x_size == y_size && std::memcmp(x, y, x_size) == 0;
    delete[] x;
    delete[] y;
    return same;
}

// Sets both engines up for `virtual_path`, from `source`. False if the put
// wasn't accepted.
static bool begin_copy(NetShareFolders* folders, NetShareEngine* sender, NetShareEngine* receiver, uint32_t id,
                       const std::string* source, uint64_t announced, const char* virtual_path, uint64_t mtime,
                       std::string* target, std::string* part, uint64_t* offset)
{
    if (net_share_begin_put(folders, virtual_path, announced, 0, 0, target, part, offset) != NetShareStatus::ok)
    {
        return false;
    }
    return net_share_engine_receive(receiver, id, part->c_str(), target->c_str(), announced, mtime, *offset) &&
           net_share_engine_send(sender, id, source->c_str(), announced, *offset);
}

static void clear_both(NetShareEngine* sender, NetShareEngine* receiver)
{
    for (int i = 0; i < 2000; i++)
    {
        bool a = net_share_engine_clear(sender);
        bool b = net_share_engine_clear(receiver);
        if (a && b)
        {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    check(false, "engines cleared");
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::printf("FAIL no scratch folder given\n");
        return 1;
    }
    std::string run_folder = std::string(argv[1]) + "/run-" + std::to_string(std::time(nullptr)) + "-" +
                      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    char canonical[4096] = {};
    if (!host_fs_make_directories(run_folder.c_str()) ||
        !host_fs_canonical(run_folder.c_str(), canonical, sizeof(canonical)))
    {
        std::printf("FAIL scratch folder\n");
        return 1;
    }
    std::string base = canonical;
    std::string local = base + "/local";
    std::string games = base + "/games";
    host_fs_make_directories(local.c_str());
    host_fs_make_directories(games.c_str());
    std::string saves = base + "/saves";
    std::string states = base + "/states";
    host_fs_make_directories(saves.c_str());
    host_fs_make_directories(states.c_str());
    NetShareFolders folders;
    std::vector<std::string> game_paths;
    game_paths.push_back(games);
    net_share_set_folders(&folders, &game_paths, saves.c_str(), states.c_str(), "");

    NetShareEngine sender;
    NetShareEngine receiver;
    net_share_engine_start(&sender);
    net_share_engine_start(&receiver);
    std::string target;
    std::string part;
    uint64_t offset = 0;

    // A whole copy over a slow link (a few messages a round).
    {
        std::string source = local + "/big.bin";
        size_t size = 5 * 1024 * 1024 + 12345;
        make_file(&source, size, 1);
        Wire wire;
        Run run;
        check(begin_copy(&folders, &sender, &receiver, 1, &source, size, "games/big.bin", 1600000000, &target, &part,
                         &offset) && offset == 0,
              "copy begins");
        check(pump_until_done(&sender, &receiver, &wire, &run, 3, 0), "copy finishes");
        NetShareProgress a;
        NetShareProgress b;
        net_share_engine_progress(&sender, &a);
        net_share_engine_progress(&receiver, &b);
        check(a.status == NetShareStatus::ok && b.status == NetShareStatus::ok && a.done == size && b.done == size,
              "both sides ok, all bytes");
        check(same_files(&source, &target), "the copy is the same, byte for byte");
        uint64_t got_size = 0;
        uint64_t got_mtime = 0;
        check(host_fs_file_info(target.c_str(), &got_size, &got_mtime) && got_mtime == 1600000000, "with its date");
        check(!host_fs_exists(part.c_str()), "no part file left");
        check(!run.refused_chunk && run.max_outstanding <= NET_SHARE_WINDOW, "the window is never passed");
        check(run.chunk_bytes == size, "every byte sent once");
        clear_both(&sender, &receiver);
    }

    // Nothing while the transport says no.
    {
        std::string source = local + "/held.bin";
        make_file(&source, 100000, 2);
        Wire wire;
        Run run;
        check(begin_copy(&folders, &sender, &receiver, 2, &source, 100000, "games/held.bin", 0, &target, &part,
                         &offset),
              "held copy begins");
        for (int i = 0; i < 200; i++)
        {
            pump(&sender, &receiver, &wire, &run, false, 100);
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        check(run.chunk_bytes == 0, "no chunk while may_send is false");
        check(pump_until_done(&sender, &receiver, &wire, &run, 100, 0) && same_files(&source, &target),
              "and it goes once allowed");
        clear_both(&sender, &receiver);
    }

    // Cancelled halfway, then resumed from the part file.
    {
        std::string source = local + "/resume.bin";
        size_t size = 3 * 1024 * 1024;
        make_file(&source, size, 3);
        Wire wire;
        Run run;
        check(begin_copy(&folders, &sender, &receiver, 3, &source, size, "SAVES/core/resume.bin", 0, &target, &part,
                         &offset),
              "copy into SAVES begins (core folder made)");
        pump_until_done(&sender, &receiver, &wire, &run, 4, size / 2);
        net_share_engine_cancel(&sender);
        net_share_engine_cancel(&receiver);
        clear_both(&sender, &receiver);
        check(host_fs_exists(part.c_str()) && !host_fs_exists(target.c_str()), "cancelled: part kept, nothing in place");

        Wire again;
        Run second;
        check(begin_copy(&folders, &sender, &receiver, 4, &source, size, "SAVES/core/resume.bin", 0, &target, &part,
                         &offset) && offset >= size / 2 && offset < size,
              "resumed from the part file");
        check(pump_until_done(&sender, &receiver, &again, &second, 8, 0) && same_files(&source, &target),
              "resumed copy is whole");
        check(second.chunk_bytes == size - offset, "only the rest was sent");
        clear_both(&sender, &receiver);
    }

    // A byte changed on the way.
    {
        std::string source = local + "/bad.bin";
        make_file(&source, 200000, 4);
        Wire wire;
        Run run;
        run.corrupt_chunk = 5;
        check(begin_copy(&folders, &sender, &receiver, 5, &source, 200000, "games/bad.bin", 0, &target, &part,
                         &offset),
              "corrupted copy begins");
        pump_until_done(&sender, &receiver, &wire, &run, 50, 0);
        NetShareProgress a;
        NetShareProgress b;
        net_share_engine_progress(&sender, &a);
        net_share_engine_progress(&receiver, &b);
        check(b.status == NetShareStatus::mismatch && a.status == NetShareStatus::mismatch, "mismatch on both sides");
        check(!host_fs_exists(target.c_str()) && !host_fs_exists(part.c_str()), "nothing kept");
        clear_both(&sender, &receiver);
    }

    // The file is shorter than announced (it changed meanwhile).
    {
        std::string source = local + "/short.bin";
        make_file(&source, 50000, 5);
        Wire wire;
        Run run;
        check(begin_copy(&folders, &sender, &receiver, 6, &source, 80000, "games/short.bin", 0, &target, &part,
                         &offset),
              "short copy begins");
        pump_until_done(&sender, &receiver, &wire, &run, 50, 0);
        NetShareProgress a;
        net_share_engine_progress(&sender, &a);
        check(a.finished && a.status == NetShareStatus::failed && run.sender_cancelled,
              "sender fails and cancels");
        check(!host_fs_exists(target.c_str()), "nothing put in place");
        clear_both(&sender, &receiver);
        net_share_discard_put(part.c_str());
    }

    // An empty file, and a chunk out of order.
    {
        std::string source = local + "/empty.bin";
        host_fs_write_file(source.c_str(), "", 0);
        Wire wire;
        Run run;
        check(begin_copy(&folders, &sender, &receiver, 7, &source, 0, "games/empty.bin", 0, &target, &part, &offset) &&
                  pump_until_done(&sender, &receiver, &wire, &run, 10, 0) && host_fs_exists(target.c_str()),
              "empty file copied");
        clear_both(&sender, &receiver);

        check(net_share_begin_put(&folders, "games/order.bin", 100, 0, 0, &target, &part, &offset) == NetShareStatus::ok &&
                  net_share_engine_receive(&receiver, 8, part.c_str(), target.c_str(), 100, 0, 0),
              "receiver for the order check");
        uint8_t bytes[10] = {};
        check(!net_share_engine_on_chunk(&receiver, 9, 0, bytes, 10), "another copy's chunk refused");
        check(!net_share_engine_on_chunk(&receiver, 8, 10, bytes, 10), "a chunk out of order refused");
        NetShareProgress b;
        net_share_engine_progress(&receiver, &b);
        check(b.finished && b.status == NetShareStatus::failed, "and the copy fails");
        clear_both(&sender, &receiver);
        net_share_discard_put(part.c_str());
    }

    net_share_engine_stop(&sender);
    net_share_engine_stop(&receiver);
    if (g_failures == 0)
    {
        std::printf("net share engine: all checks passed\n");
    }
    return g_failures == 0 ? 0 : 1;
}
