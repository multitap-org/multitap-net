#include "net_discovery.h"

#include <cstring>
#include <string>

#include "net_trust.h"

static constexpr uint8_t MAGIC[4] = {'M', 'T', 'A', 'P'};
static constexpr uint8_t TYPE_REQUEST = 1;
static constexpr uint8_t TYPE_REPLY = 2;
static constexpr uint8_t FLAG_SIGNED = 1;
static constexpr uint8_t FLAG_KEY_ID = 2;   // version 3

static_assert(NET_DISCOVERY_KEY_ID_SIZE == NET_KEY_ID_SIZE, "discovery carries what net_trust_has_key_id compares");

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
static void write_header(uint8_t* out, uint8_t type, uint8_t version, uint32_t nonce)
{
    std::memcpy(out, MAGIC, sizeof(MAGIC));
    out[4] = type;
    out[5] = version;
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
    write_header(out, TYPE_REQUEST, NET_DISCOVERY_VERSION, nonce);
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
    bool v3 = reply->version >= 3;
    size_t header = v3 ? NET_DISCOVERY_V3_REPLY_HEADER_SIZE : NET_DISCOVERY_REPLY_HEADER_SIZE;
    // At most NET_DISCOVERY_MAX_NAME: that's all `name` holds.
    size_t name_length = std::strlen(reply->name);
    size_t size = header + name_length;
    if (capacity < size)
    {
        return 0;
    }
    write_header(out, TYPE_REPLY, v3 ? static_cast<uint8_t>(3) : static_cast<uint8_t>(2), reply->nonce);
    write_u16(out + 12, reply->port);
    out[14] = reply->kind;
    write_u32(out + 15, reply->offers);
    uint8_t flags = reply->signed_build ? FLAG_SIGNED : static_cast<uint8_t>(0);
    if (v3)
    {
        if (reply->key_id_known)
        {
            flags = static_cast<uint8_t>(flags | FLAG_KEY_ID);
        }
        std::memcpy(out + 20, reply->key_id, NET_DISCOVERY_KEY_ID_SIZE);
    }
    out[19] = flags;
    out[header - 1] = static_cast<uint8_t>(name_length);
    std::memcpy(out + header, reply->name, name_length);
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
    // Shown by frontends before pairing: whatever the other side put in it.
    std::string cleaned = net_name_clean(std::string(reinterpret_cast<const char*>(data + header), name_length).c_str());
    std::memcpy(reply->name, cleaned.c_str(), cleaned.size() + 1);
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
    if (version == 3)
    {
        if (size < NET_DISCOVERY_V3_REPLY_HEADER_SIZE || (data[19] & ~(FLAG_SIGNED | FLAG_KEY_ID)) != 0)
        {
            return false;
        }
        read.port = read_u16(data + 12);
        read.kind = data[14];
        read.offers = read_u32(data + 15);
        read.signed_build = (data[19] & FLAG_SIGNED) != 0;
        read.key_id_known = (data[19] & FLAG_KEY_ID) != 0;
        std::memcpy(read.key_id, data + 20, NET_DISCOVERY_KEY_ID_SIZE);
        if (!read_reply_name(data, size, NET_DISCOVERY_V3_REPLY_HEADER_SIZE, &read))
        {
            return false;
        }
        *reply = read;
        return true;
    }
    if (version != 2 || size < NET_DISCOVERY_REPLY_HEADER_SIZE || data[19] > 1)
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
