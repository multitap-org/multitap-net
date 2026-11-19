#include "net_discovery.h"

#include <cstring>

static constexpr uint8_t MAGIC[4] = {'M', 'T', 'A', 'P'};
static constexpr uint8_t TYPE_REQUEST = 1;
static constexpr uint8_t TYPE_REPLY = 2;

static void write_u16(uint8_t* out, uint16_t value)
{
    out[0] = static_cast<uint8_t>(value & 0xFF);
    out[1] = static_cast<uint8_t>(value >> 8);
}

static void write_u32(uint8_t* out, uint32_t value)
{
    out[0] = static_cast<uint8_t>(value & 0xFF);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[3] = static_cast<uint8_t>(value >> 24);
}

static uint16_t read_u16(const uint8_t* data)
{
    return static_cast<uint16_t>(data[0] | (data[1] << 8));
}

static uint32_t read_u32(const uint8_t* data)
{
    return static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) | (static_cast<uint32_t>(data[3]) << 24);
}

// Magic, type, version, two reserved zero bytes, nonce: the first 12 bytes of
// both packets.
static void write_header(uint8_t* out, uint8_t type, uint32_t nonce)
{
    std::memcpy(out, MAGIC, sizeof(MAGIC));
    out[4] = type;
    out[5] = NET_DISCOVERY_VERSION;
    out[6] = 0;
    out[7] = 0;
    write_u32(out + 8, nonce);
}

static bool read_header(const uint8_t* data, size_t size, uint8_t type, uint32_t* nonce)
{
    if (size < NET_DISCOVERY_REQUEST_SIZE)
    {
        return false;
    }
    if (std::memcmp(data, MAGIC, sizeof(MAGIC)) != 0 || data[4] != type || data[5] != NET_DISCOVERY_VERSION ||
        data[6] != 0 || data[7] != 0)
    {
        return false;
    }
    *nonce = read_u32(data + 8);
    return true;
}

size_t net_discovery_write_request(uint8_t* out, size_t capacity, uint32_t nonce)
{
    if (capacity < NET_DISCOVERY_REQUEST_SIZE)
    {
        return 0;
    }
    write_header(out, TYPE_REQUEST, nonce);
    return NET_DISCOVERY_REQUEST_SIZE;
}

bool net_discovery_read_request(const uint8_t* data, size_t size, uint32_t* nonce)
{
    if (size != NET_DISCOVERY_REQUEST_SIZE)
    {
        return false;
    }
    return read_header(data, size, TYPE_REQUEST, nonce);
}

size_t net_discovery_write_reply(uint8_t* out, size_t capacity, const NetDiscoveryReply* reply)
{
    // At most NET_DISCOVERY_MAX_NAME: that's all `name` holds.
    size_t name_length = std::strlen(reply->name);
    size_t size = NET_DISCOVERY_REPLY_HEADER_SIZE + name_length;
    if (capacity < size)
    {
        return 0;
    }
    write_header(out, TYPE_REPLY, reply->nonce);
    write_u16(out + 12, reply->port);
    out[14] = static_cast<uint8_t>(name_length);
    std::memcpy(out + NET_DISCOVERY_REPLY_HEADER_SIZE, reply->name, name_length);
    return size;
}

bool net_discovery_read_reply(const uint8_t* data, size_t size, NetDiscoveryReply* reply)
{
    if (size < NET_DISCOVERY_REPLY_HEADER_SIZE || size > NET_DISCOVERY_MAX_PACKET)
    {
        return false;
    }
    uint32_t nonce = 0;
    if (!read_header(data, size, TYPE_REPLY, &nonce))
    {
        return false;
    }
    size_t name_length = data[14];
    if (size != NET_DISCOVERY_REPLY_HEADER_SIZE + name_length)
    {
        return false;
    }
    // A NUL inside would cut the name short where we show it: refuse.
    if (std::memchr(data + NET_DISCOVERY_REPLY_HEADER_SIZE, 0, name_length) != nullptr)
    {
        return false;
    }
    *reply = {};
    reply->nonce = nonce;
    reply->port = read_u16(data + 12);
    std::memcpy(reply->name, data + NET_DISCOVERY_REPLY_HEADER_SIZE, name_length);
    reply->name[name_length] = '\0';
    return true;
}
