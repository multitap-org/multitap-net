#pragma once

// Speed test: how much unreliable traffic gets through at a given rate, and
// how much is lost, in either direction. What remote play needs to know
// (which codec, which quality), measured the way it will send: numbered
// packets under the MTU on the unreliable input channel, encrypted like
// everything else, paced by time.
//
//   client -> host  speed_request  id u32 | direction u8 | rate kbit/s u32 | duration ms u32
//   host -> client  speed_report   id u32 | direction u8 | packets u32 | bytes u64 | seconds (text)
//   either way      speed_data     (input channel) type 3 | id u32 | seq u32 | filler
//
// Down (piccolo -> phone): the host sends at the asked rate for the asked
// time, then reports how many packets it sent; the client compares with
// what it got. Up: the client sends, the host counts and reports what it got
// once the time (plus a moment for stragglers) is over. One test at a time
// per host; rate and duration are capped (NET_SPEED_MAX_*). A client finds
// the usable rate by asking for rising rates (5, 10, 20, 50, 100 Mbit/s...)
// until the loss passes a few percent.
//
// speed_request needs STREAM access (it can fill the network); the host
// ignores speed_data from devices below it.

#include <cstddef>
#include <cstdint>
#include <string>

constexpr uint8_t  NET_SPEED_REQUEST = 64;   // control, client -> host
constexpr uint8_t  NET_SPEED_REPORT = 65;    // control, host -> client
constexpr uint8_t  NET_INPUT_TYPE_SPEED = 3; // input channel
constexpr uint32_t NET_SPEED_MAX_KBPS = 200000;      // 200 Mbit/s
constexpr uint32_t NET_SPEED_MAX_MS = 5000;
constexpr size_t   NET_SPEED_PACKET_SIZE = 1200;     // payload: under a 1500-byte MTU with every header
constexpr uint32_t NET_SPEED_MAX_BURST = 512;        // packets one call may send (keeps a frame short)
constexpr double   NET_SPEED_GRACE_SECONDS = 0.5;    // up: how long the host waits for stragglers

enum class NetSpeedDirection : uint8_t
{
    down = 0,   // host -> client
    up = 1,     // client -> host
};

struct NetSpeedReport
{
    uint32_t          id = 0;
    NetSpeedDirection direction = NetSpeedDirection::down;
    uint32_t          packets = 0;   // down: sent; up: received
    uint64_t          bytes = 0;     // the same, payload bytes
    double            seconds = 0.0; // down: sending time; up: first to last received
};

size_t net_speed_write_request(uint8_t* out, size_t capacity, uint32_t id, NetSpeedDirection direction,
                               uint32_t rate_kbps, uint32_t duration_ms);
// Rate and duration come back capped.
bool   net_speed_read_request(const uint8_t* data, size_t size, uint32_t* id, NetSpeedDirection* direction,
                              uint32_t* rate_kbps, uint32_t* duration_ms);
size_t net_speed_write_report(uint8_t* out, size_t capacity, const NetSpeedReport* report);
bool   net_speed_read_report(const uint8_t* data, size_t size, NetSpeedReport* report);

// --- sending ------------------------------------------------------------------

struct NetSpeedSender
{
    bool     active = false;
    uint32_t id = 0;
    uint32_t peer = 0;          // for the caller
    double   start = 0.0;
    double   bytes_per_second = 0.0;
    double   duration = 0.0;
    uint32_t sent = 0;          // packets
    uint64_t sent_bytes = 0;
};

void net_speed_sender_start(NetSpeedSender* sender, uint32_t id, uint32_t peer, uint32_t rate_kbps,
                            uint32_t duration_ms, double now);

// How many packets are due by `now` (at most NET_SPEED_MAX_BURST); the
// caller sends them with net_speed_write_data and counts each with
// net_speed_sender_sent. Done (active false) once the time is over.
uint32_t net_speed_sender_due(NetSpeedSender* sender, double now);
void     net_speed_sender_sent(NetSpeedSender* sender, size_t size);

// The next test packet (seq = sender->sent), NET_SPEED_PACKET_SIZE bytes.
size_t net_speed_write_data(uint8_t* out, size_t capacity, uint32_t id, uint32_t seq);

// --- receiving ----------------------------------------------------------------

struct NetSpeedReceiver
{
    bool     active = false;
    uint32_t id = 0;
    uint32_t peer = 0;          // for the caller
    double   until = 0.0;       // up, on the host: when to report
    uint32_t received = 0;
    uint64_t bytes = 0;
    double   first = 0.0;
    double   last = 0.0;
};

void net_speed_receiver_start(NetSpeedReceiver* receiver, uint32_t id, uint32_t peer, double until);

// A packet from the input channel: counted if it's a test packet of this
// test. True if it was a test packet at all (of any test: not for others).
bool net_speed_receive(NetSpeedReceiver* receiver, const uint8_t* data, size_t size, double now);

// The receiver's count as a report.
void net_speed_receiver_report(const NetSpeedReceiver* receiver, NetSpeedDirection direction, NetSpeedReport* report);
