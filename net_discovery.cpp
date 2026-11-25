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

// `version`: the packet's (any; the caller decides which it reads).
static bool read_header(const uint8_t* data, size_t size, uint8_t type, uint32_t* nonce, uint8_t* version)
{
    if (size < NET_DISCOVERY_REQUEST_SIZE)
    {
        return false;
    }
    if (std::memcmp(data, MAGIC, sizeof(MAGIC)) != 0 || data[4] != type || data[6] != 0 || data[7] != 0)
    {
        return false;
    }
    *nonce = read_u32(data + 8);
    *version = data[5];
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
    uint8_t version = 0;
    return read_header(data, size, TYPE_REQUEST, nonce, &version) && version == NET_DISCOVERY_VERSION;
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
    out[14] = reply->kind;
    write_u32(out + 15, reply->offers);
    out[19] = reply->signed_build ? 1 : 0;
    out[20] = static_cast<uint8_t>(name_length);
    std::memcpy(out + NET_DISCOVERY_REPLY_HEADER_SIZE, reply->name, name_length);
    return size;
}

// The name after `header` bytes: its length byte is at header - 1.
static bool read_reply_name(const uint8_t* data, size_t size, size_t header, NetDiscoveryReply* reply)
{
    size_t name_length = data[header - 1];
    if (name_length > NET_DISCOVERY_MAX_NAME || size != header + name_length)
    {
        return false;
    }
    // A NUL inside would cut the name short where we show it: refuse.
    if (std::memchr(data + header, 0, name_length) != nullptr)
    {
        return false;
    }
    std::memcpy(reply->name, data + header, name_length);
    reply->name[name_length] = '\0';
    return true;
}

bool net_discovery_read_reply(const uint8_t* data, size_t size, NetDiscoveryReply* reply)
{
    if (size > NET_DISCOVERY_MAX_PACKET)
    {
        return false;
    }
    uint32_t nonce = 0;
    uint8_t version = 0;
    if (!read_header(data, size, TYPE_REPLY, &nonce, &version))
    {
        return false;
    }
    NetDiscoveryReply read;
    read.version = version;
    read.nonce = nonce;
    if (version == 1)
    {
        if (size < NET_DISCOVERY_V1_REPLY_HEADER_SIZE)
        {
            return false;
        }
        read.port = read_u16(data + 12);
        if (!read_reply_name(data, size, NET_DISCOVERY_V1_REPLY_HEADER_SIZE, &read))
        {
            return false;
        }
        *reply = read;
        return true;
    }
    if (version != NET_DISCOVERY_VERSION || size < NET_DISCOVERY_REPLY_HEADER_SIZE || data[19] > 1)
    {
        return false;
    }
    read.port = read_u16(data + 12);
    read.kind = data[14];
    read.offers = read_u32(data + 15);
    read.signed_build = data[19] == 1;
    if (!read_reply_name(data, size, NET_DISCOVERY_REPLY_HEADER_SIZE, &read))
    {
        return false;
    }
    *reply = read;
    return true;
}
