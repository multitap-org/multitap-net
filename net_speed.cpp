#include "net_speed.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "net_wire.h"

size_t net_speed_write_request(uint8_t* out, size_t capacity, uint32_t id, NetSpeedDirection direction,
                               uint32_t rate_kbps, uint32_t duration_ms)
{
    NetWriter writer = {out, capacity, 0, true};
    net_wire_put_u8(&writer, NET_SPEED_REQUEST);
    net_wire_put_u32(&writer, id);
    net_wire_put_u8(&writer, static_cast<uint8_t>(direction));
    net_wire_put_u32(&writer, rate_kbps);
    net_wire_put_u32(&writer, duration_ms);
    return writer.ok ? writer.size : 0;
}

bool net_speed_read_request(const uint8_t* data, size_t size, uint32_t* id, NetSpeedDirection* direction,
                            uint32_t* rate_kbps, uint32_t* duration_ms)
{
    NetReader reader;
    reader.data = data;
    reader.size = size;
    if (net_wire_get_u8(&reader) != NET_SPEED_REQUEST)
    {
        return false;
    }
    *id = net_wire_get_u32(&reader);
    uint8_t which = net_wire_get_u8(&reader);
    uint32_t rate = net_wire_get_u32(&reader);
    uint32_t duration = net_wire_get_u32(&reader);
    if (!net_wire_done(&reader) || which > 1 || rate == 0 || duration == 0)
    {
        return false;
    }
    *direction = static_cast<NetSpeedDirection>(which);
    *rate_kbps = rate < NET_SPEED_MAX_KBPS ? rate : NET_SPEED_MAX_KBPS;
    *duration_ms = duration < NET_SPEED_MAX_MS ? duration : NET_SPEED_MAX_MS;
    return true;
}

size_t net_speed_write_report(uint8_t* out, size_t capacity, const NetSpeedReport* report)
{
    char seconds[32];
    std::snprintf(seconds, sizeof(seconds), "%.6f", report->seconds);
    NetWriter writer = {out, capacity, 0, true};
    net_wire_put_u8(&writer, NET_SPEED_REPORT);
    net_wire_put_u32(&writer, report->id);
    net_wire_put_u8(&writer, static_cast<uint8_t>(report->direction));
    net_wire_put_u32(&writer, report->packets);
    net_wire_put_u64(&writer, report->bytes);
    net_wire_put_text(&writer, seconds, std::strlen(seconds));
    return writer.ok ? writer.size : 0;
}

bool net_speed_read_report(const uint8_t* data, size_t size, NetSpeedReport* report)
{
    NetReader reader;
    reader.data = data;
    reader.size = size;
    if (net_wire_get_u8(&reader) != NET_SPEED_REPORT)
    {
        return false;
    }
    report->id = net_wire_get_u32(&reader);
    uint8_t which = net_wire_get_u8(&reader);
    report->packets = net_wire_get_u32(&reader);
    report->bytes = net_wire_get_u64(&reader);
    std::string seconds;
    net_wire_get_text(&reader, &seconds);
    if (!net_wire_done(&reader) || which > 1)
    {
        return false;
    }
    report->direction = static_cast<NetSpeedDirection>(which);
    // Our own text, written with "%.6f" ('.' whatever the locale of the
    // writer; strtod reads it the same unless this program changed its own).
    report->seconds = std::strtod(seconds.c_str(), nullptr);
    return true;
}

// ---------------------------------------------------------------------------

void net_speed_sender_start(NetSpeedSender* sender, uint32_t id, uint32_t peer, uint32_t rate_kbps,
                            uint32_t duration_ms, double now)
{
    *sender = NetSpeedSender{};
    sender->active = true;
    sender->id = id;
    sender->peer = peer;
    sender->start = now;
    sender->bytes_per_second = static_cast<double>(rate_kbps) * 1000.0 / 8.0;
    sender->duration = static_cast<double>(duration_ms) / 1000.0;
}

uint32_t net_speed_sender_due(NetSpeedSender* sender, double now)
{
    if (!sender->active)
    {
        return 0;
    }
    double elapsed = now - sender->start;
    if (elapsed >= sender->duration)
    {
        elapsed = sender->duration;
        sender->active = false;   // what's due up to the end still goes out now
    }
    // Paced by time: the bytes due so far, less what went.
    double due_bytes = sender->bytes_per_second * elapsed - static_cast<double>(sender->sent_bytes);
    if (due_bytes <= 0.0)
    {
        return 0;
    }
    double packets = due_bytes / static_cast<double>(NET_SPEED_PACKET_SIZE);
    uint32_t count = packets >= static_cast<double>(NET_SPEED_MAX_BURST) ? NET_SPEED_MAX_BURST
                                                                          : static_cast<uint32_t>(packets);
    if (count == 0 && !sender->active)
    {
        count = 1;   // the last part of a packet at the end
    }
    return count;
}

void net_speed_sender_sent(NetSpeedSender* sender, size_t size)
{
    sender->sent++;
    sender->sent_bytes += size;
}

size_t net_speed_write_data(uint8_t* out, size_t capacity, uint32_t id, uint32_t seq)
{
    if (capacity < NET_SPEED_PACKET_SIZE)
    {
        return 0;
    }
    out[0] = NET_INPUT_TYPE_SPEED;
    for (uint32_t i = 0; i < 4; i++)
    {
        out[1 + i] = static_cast<uint8_t>(id >> (8 * i));
        out[5 + i] = static_cast<uint8_t>(seq >> (8 * i));
    }
    // Filler that doesn't compress to nothing, should anything on the way try.
    for (size_t i = 9; i < NET_SPEED_PACKET_SIZE; i++)
    {
        out[i] = static_cast<uint8_t>((i * 31u + seq) & 0xFF);
    }
    return NET_SPEED_PACKET_SIZE;
}

// ---------------------------------------------------------------------------

void net_speed_receiver_start(NetSpeedReceiver* receiver, uint32_t id, uint32_t peer, double until)
{
    *receiver = NetSpeedReceiver{};
    receiver->active = true;
    receiver->id = id;
    receiver->peer = peer;
    receiver->until = until;
}

bool net_speed_receive(NetSpeedReceiver* receiver, const uint8_t* data, size_t size, double now)
{
    if (size < 9 || data[0] != NET_INPUT_TYPE_SPEED)
    {
        return false;
    }
    uint32_t id = static_cast<uint32_t>(data[1]) | (static_cast<uint32_t>(data[2]) << 8) |
                  (static_cast<uint32_t>(data[3]) << 16) | (static_cast<uint32_t>(data[4]) << 24);
    if (!receiver->active || id != receiver->id)
    {
        return true;   // a test packet, of another (or no) test: ignored
    }
    if (receiver->received == 0)
    {
        receiver->first = now;
    }
    receiver->last = now;
    receiver->received++;
    receiver->bytes += size;
    return true;
}

void net_speed_receiver_report(const NetSpeedReceiver* receiver, NetSpeedDirection direction, NetSpeedReport* report)
{
    report->id = receiver->id;
    report->direction = direction;
    report->packets = receiver->received;
    report->bytes = receiver->bytes;
    report->seconds = receiver->received > 1 ? receiver->last - receiver->first : 0.0;
}
