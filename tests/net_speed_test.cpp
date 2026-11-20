// Checks net_speed.h: messages (and their caps), the sender's pacing by time,
// and the receiver's count, with a made-up clock.
//
// Exit code 0 = all checks passed. Each failure is printed.

#include <cmath>
#include <cstdio>

#include "net_speed.h"

static int g_failures = 0;

static void check(bool condition, const char* what)
{
    if (!condition)
    {
        std::printf("FAIL %s\n", what);
        g_failures++;
    }
}

int main()
{
    uint8_t out[NET_SPEED_PACKET_SIZE];
    uint32_t id = 0;
    NetSpeedDirection direction = NetSpeedDirection::down;
    uint32_t rate = 0;
    uint32_t duration = 0;
    size_t size = net_speed_write_request(out, sizeof(out), 7, NetSpeedDirection::up, 20000, 1000);
    check(net_speed_read_request(out, size, &id, &direction, &rate, &duration) && id == 7 &&
              direction == NetSpeedDirection::up && rate == 20000 && duration == 1000,
          "request read");
    size = net_speed_write_request(out, sizeof(out), 8, NetSpeedDirection::down, 900000, 60000);
    check(net_speed_read_request(out, size, &id, &direction, &rate, &duration) && rate == NET_SPEED_MAX_KBPS &&
              duration == NET_SPEED_MAX_MS,
          "rate and duration capped");
    size = net_speed_write_request(out, sizeof(out), 8, NetSpeedDirection::down, 0, 1000);
    check(!net_speed_read_request(out, size, &id, &direction, &rate, &duration), "rate 0 refused");

    NetSpeedReport report;
    report.id = 7;
    report.direction = NetSpeedDirection::up;
    report.packets = 1234;
    report.bytes = 1234ull * NET_SPEED_PACKET_SIZE;
    report.seconds = 0.987654;
    NetSpeedReport read;
    size = net_speed_write_report(out, sizeof(out), &report);
    check(net_speed_read_report(out, size, &read) && read.id == 7 && read.direction == NetSpeedDirection::up &&
              read.packets == 1234 && read.bytes == report.bytes && std::fabs(read.seconds - 0.987654) < 1e-6,
          "report read");

    NetSpeedResult result;
    result.direction = NetSpeedDirection::up;
    result.asked_kbps = 50000;
    result.got_kbps = 49000;
    result.loss_per_mille = 20;
    NetSpeedResult result_read;
    size = net_speed_write_result(out, sizeof(out), &result);
    check(net_speed_read_result(out, size, &result_read) && result_read.direction == NetSpeedDirection::up &&
              result_read.asked_kbps == 50000 && result_read.got_kbps == 49000 && result_read.loss_per_mille == 20,
          "result read");
    out[size - 2] = 0xFF;   // loss over 1000
    out[size - 1] = 0xFF;
    check(!net_speed_read_result(out, size, &result_read), "a loss over 100% refused");

    // 9.6 Mbit/s = 1000 packets of 1200 bytes a second, for one second,
    // called at 60 Hz: 1000 packets in all, about 16-17 a call.
    NetSpeedSender sender;
    net_speed_sender_start(&sender, 3, 1, 9600, 1000, 100.0);
    NetSpeedReceiver receiver;
    net_speed_receiver_start(&receiver, 3, 1, 0.0);
    uint32_t calls = 0;
    uint32_t largest = 0;
    double now = 100.0;
    while (sender.active && calls < 1000)
    {
        now += 1.0 / 60.0;
        uint32_t due = net_speed_sender_due(&sender, now);
        largest = due > largest ? due : largest;
        for (uint32_t i = 0; i < due; i++)
        {
            size = net_speed_write_data(out, sizeof(out), sender.id, sender.sent);
            net_speed_sender_sent(&sender, size);
            if (sender.sent % 10 != 0)   // every tenth one is "lost"
            {
                check(net_speed_receive(&receiver, out, size, now), "a test packet is one");
            }
        }
        calls++;
    }
    check(sender.sent >= 999 && sender.sent <= 1001, "paced: the asked rate for the asked time");
    check(largest <= 18, "spread over the calls, not all at once");
    check(receiver.received == sender.sent - sender.sent / 10, "the receiver counted what arrived");
    NetSpeedReport got;
    net_speed_receiver_report(&receiver, NetSpeedDirection::down, &got);
    check(got.packets == receiver.received && got.bytes == static_cast<uint64_t>(receiver.received) * NET_SPEED_PACKET_SIZE &&
              got.seconds > 0.9 && got.seconds < 1.1,
          "receiver report");

    // Another test's packets, and other input packets, aren't counted.
    uint32_t before = receiver.received;
    size = net_speed_write_data(out, sizeof(out), 99, 0);
    check(net_speed_receive(&receiver, out, size, now) && receiver.received == before, "another test's packet ignored");
    const uint8_t pad_packet[] = {1, 0, 1};
    check(!net_speed_receive(&receiver, pad_packet, sizeof(pad_packet), now), "a pad packet isn't a test packet");

    // A burst is capped per call (a long stall then catches up gradually).
    NetSpeedSender fast;
    net_speed_sender_start(&fast, 4, 1, NET_SPEED_MAX_KBPS, 1000, 0.0);
    check(net_speed_sender_due(&fast, 0.5) == NET_SPEED_MAX_BURST, "a burst is capped");

    if (g_failures == 0)
    {
        std::printf("net speed: all checks passed\n");
        return 0;
    }
    std::printf("%d check(s) failed\n", g_failures);
    return 1;
}
