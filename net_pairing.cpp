#include "net_pairing.h"

#include <cstring>

#include "monocypher.h"
#include "net_random.h"

static constexpr uint8_t CI_LABEL[15] = {'m', 'u', 'l', 't', 'i', 't', 'a', 'p', '-', 'p', 'a', 'i', 'r', ' ', '3'};
static constexpr uint8_t CONFIRM_HOST[18] = {'m', 'u', 'l', 't', 'i', 't', 'a', 'p', ' ',
                                             'p', 'a', 'i', 'r', ' ', 'h', 'o', 's', 't'};
static constexpr uint8_t CONFIRM_CLIENT[20] = {'m', 'u', 'l', 't', 'i', 't', 'a', 'p', ' ', 'p',
                                               'a', 'i', 'r', ' ', 'c', 'l', 'i', 'e', 'n', 't'};

bool net_pair_code_generate(char* code)
{
    // All nine digits random (the slot too: a code made only of six left
    // every slot at 000). Rejection sampling keeps every code equally likely:
    // 4000000000 is the largest multiple of 10^9 below 2^32.
    uint32_t value = 0;
    do
    {
        uint8_t bytes[4];
        if (!net_random_bytes(bytes, sizeof(bytes)))
        {
            return false;
        }
        value = static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) |
                (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24);
    } while (value >= 4000000000u);
    value %= 1000000000u;
    for (int32_t i = static_cast<int32_t>(NET_PAIR_CODE_DIGITS) - 1; i >= 0; i--)
    {
        code[i] = static_cast<char>('0' + value % 10);
        value /= 10;
    }
    code[NET_PAIR_CODE_DIGITS] = '\0';
    return true;
}

bool net_pair_code_valid(const char* code)
{
    if (code == nullptr || std::strlen(code) != NET_PAIR_CODE_DIGITS)
    {
        return false;
    }
    for (size_t i = 0; i < NET_PAIR_CODE_DIGITS; i++)
    {
        if (code[i] < '0' || code[i] > '9')
        {
            return false;
        }
    }
    return true;
}

void net_pair_ci(const uint8_t* client_key, const uint8_t* host_key, uint8_t* ci)
{
    // Fixed sizes, so plain concatenation is unambiguous.
    std::memcpy(ci, CI_LABEL, sizeof(CI_LABEL));
    std::memcpy(ci + sizeof(CI_LABEL), client_key, NET_KEY_SIZE);
    std::memcpy(ci + sizeof(CI_LABEL) + NET_KEY_SIZE, host_key, NET_KEY_SIZE);
}

void net_pair_confirm(const uint8_t* isk, bool from_host, uint8_t* confirm)
{
    if (from_host)
    {
        crypto_blake2b_keyed(confirm, NET_PAIR_CONFIRM_SIZE, isk, NET_CPACE_ISK_SIZE, CONFIRM_HOST,
                             sizeof(CONFIRM_HOST));
    }
    else
    {
        crypto_blake2b_keyed(confirm, NET_PAIR_CONFIRM_SIZE, isk, NET_CPACE_ISK_SIZE, CONFIRM_CLIENT,
                             sizeof(CONFIRM_CLIENT));
    }
}

uint8_t net_message_type(const uint8_t* data, size_t size)
{
    return size > 0 ? data[0] : 0;
}

// --- names: length byte + UTF-8, cut at a character boundary ---------------

static size_t name_length(const char* name)
{
    size_t length = std::strlen(name);
    if (length > NET_DEVICE_NAME_MAX)
    {
        length = NET_DEVICE_NAME_MAX;
        while (length > 0 && (static_cast<uint8_t>(name[length]) & 0xC0) == 0x80)
        {
            length--;
        }
    }
    return length;
}

size_t net_pair_name_bytes(const char* name, uint8_t* out)
{
    size_t length = name_length(name);
    for (size_t i = 0; i < length; i++)
    {
        out[i] = static_cast<uint8_t>(name[i]);
    }
    return length;
}

static size_t write_name(uint8_t* out, const char* name)
{
    size_t length = name_length(name);
    out[0] = static_cast<uint8_t>(length);
    std::memcpy(out + 1, name, length);
    return 1 + length;
}

void net_device_info_set_name(NetDeviceInfo* info, const char* name)
{
    size_t length = name_length(name);
    std::memcpy(info->name, name, length);
    info->name[length] = '\0';
}

static void put_u16(uint8_t* out, uint16_t value)
{
    out[0] = static_cast<uint8_t>(value & 0xFF);
    out[1] = static_cast<uint8_t>(value >> 8);
}

static uint16_t get_u16(const uint8_t* data)
{
    return static_cast<uint16_t>(data[0] | (data[1] << 8));
}

static void put_u32(uint8_t* out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; i++)
    {
        out[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
    }
}

static uint32_t get_u32(const uint8_t* data)
{
    return static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) | (static_cast<uint32_t>(data[3]) << 24);
}

static size_t info_size(const NetDeviceInfo* info)
{
    return 1 + name_length(info->name) + 1 + 4 + 4 + 2 + info->record_size + 2 + info->signature_size;
}

static size_t write_info(uint8_t* out, const NetDeviceInfo* info)
{
    size_t at = write_name(out, info->name);
    out[at] = static_cast<uint8_t>(info->kind);
    at += 1;
    put_u32(out + at, info->offers);
    at += 4;
    put_u32(out + at, info->uses);
    at += 4;
    put_u16(out + at, info->record_size);
    at += 2;
    std::memcpy(out + at, info->record, info->record_size);
    at += info->record_size;
    put_u16(out + at, info->signature_size);
    at += 2;
    std::memcpy(out + at, info->signature, info->signature_size);
    at += info->signature_size;
    return at;
}

// The info must fill the rest of the payload exactly.
static bool read_info(const uint8_t* data, size_t size, NetDeviceInfo* info)
{
    *info = NetDeviceInfo{};
    if (size < 1)
    {
        return false;
    }
    size_t name = data[0];
    if (name > NET_DEVICE_NAME_MAX || size < 1 + name + 1 + 4 + 4 + 2 || std::memchr(data + 1, 0, name) != nullptr)
    {
        return false;
    }
    std::memcpy(info->name, data + 1, name);
    info->name[name] = '\0';
    size_t at = 1 + name;
    if (data[at] >= NET_APP_KIND_COUNT)
    {
        return false;
    }
    info->kind = static_cast<NetAppKind>(data[at]);
    at += 1;
    info->offers = get_u32(data + at);
    at += 4;
    info->uses = get_u32(data + at);
    at += 4;
    if ((info->offers & ~NET_CAPS_ALL) != 0 || (info->uses & ~NET_CAPS_ALL) != 0)
    {
        return false;
    }
    info->record_size = get_u16(data + at);
    at += 2;
    if (info->record_size > NET_BUILD_RECORD_MAX || size < at + info->record_size + 2)
    {
        return false;
    }
    std::memcpy(info->record, data + at, info->record_size);
    at += info->record_size;
    info->signature_size = get_u16(data + at);
    at += 2;
    if (info->signature_size > NET_BUILD_SIGNATURE_MAX || size != at + info->signature_size)
    {
        return false;
    }
    std::memcpy(info->signature, data + at, info->signature_size);
    return true;
}

// --- messages ---------------------------------------------------------------

NetCaps net_message_required_cap(uint8_t type)
{
    if (type >= NET_MESSAGE_FIRST_SHARE)
    {
        return NET_CAP_SHARE;
    }
    if (type >= NET_MESSAGE_FIRST_SETTINGS)
    {
        return NET_CAP_SETTINGS;
    }
    if (type >= NET_MESSAGE_FIRST_STREAM)
    {
        return NET_CAP_STREAM;
    }
    return NET_CAP_GAMEPAD;
}

bool net_caps_allow(NetCaps have, uint8_t type)
{
    return (have & net_message_required_cap(type)) != 0;
}

size_t net_message_write_hello(uint8_t* out, size_t capacity, const NetDeviceInfo* info)
{
    if (capacity < 1 + info_size(info))
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetMessage::hello);
    return 1 + write_info(out + 1, info);
}

bool net_message_read_hello(const uint8_t* data, size_t size, NetDeviceInfo* info)
{
    return size >= 1 && data[0] == static_cast<uint8_t>(NetMessage::hello) && read_info(data + 1, size - 1, info);
}

size_t net_message_write_welcome(uint8_t* out, size_t capacity, NetCaps caps, const NetDeviceInfo* host)
{
    if (capacity < 5 + info_size(host))
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetMessage::welcome);
    put_u32(out + 1, caps);
    return 5 + write_info(out + 5, host);
}

bool net_message_read_welcome(const uint8_t* data, size_t size, NetCaps* caps, NetDeviceInfo* host)
{
    if (size < 5 || data[0] != static_cast<uint8_t>(NetMessage::welcome))
    {
        return false;
    }
    uint32_t value = get_u32(data + 1);
    if ((value & ~NET_CAPS_ALL) != 0)
    {
        return false;
    }
    *caps = value;
    return read_info(data + 5, size - 5, host);
}

size_t net_message_write_pairing_needed(uint8_t* out, size_t capacity, bool open, const NetDeviceInfo* host)
{
    if (capacity < 2 + info_size(host))
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetMessage::pairing_needed);
    out[1] = open ? 1 : 0;
    return 2 + write_info(out + 2, host);
}

bool net_message_read_pairing_needed(const uint8_t* data, size_t size, bool* open, NetDeviceInfo* host)
{
    if (size < 2 || data[0] != static_cast<uint8_t>(NetMessage::pairing_needed) || data[1] > 1)
    {
        return false;
    }
    *open = data[1] == 1;
    return read_info(data + 2, size - 2, host);
}

static size_t write_type_only(uint8_t* out, size_t capacity, NetMessage type)
{
    if (capacity < 1)
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(type);
    return 1;
}

size_t net_message_write_pair_ask(uint8_t* out, size_t capacity)
{
    return write_type_only(out, capacity, NetMessage::pair_ask);
}

bool net_message_read_pair_ask(const uint8_t* data, size_t size)
{
    return size == 1 && data[0] == static_cast<uint8_t>(NetMessage::pair_ask);
}

size_t net_message_write_pair_request(uint8_t* out, size_t capacity, const uint8_t* share)
{
    if (capacity < 1 + NET_CPACE_SHARE_SIZE)
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetMessage::pair_request);
    std::memcpy(out + 1, share, NET_CPACE_SHARE_SIZE);
    return 1 + NET_CPACE_SHARE_SIZE;
}

bool net_message_read_pair_request(const uint8_t* data, size_t size, uint8_t* share)
{
    if (size != 1 + NET_CPACE_SHARE_SIZE || data[0] != static_cast<uint8_t>(NetMessage::pair_request))
    {
        return false;
    }
    std::memcpy(share, data + 1, NET_CPACE_SHARE_SIZE);
    return true;
}

size_t net_message_write_pair_response(uint8_t* out, size_t capacity, const uint8_t* share, const uint8_t* confirm)
{
    if (capacity < 1 + NET_CPACE_SHARE_SIZE + NET_PAIR_CONFIRM_SIZE)
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetMessage::pair_response);
    std::memcpy(out + 1, share, NET_CPACE_SHARE_SIZE);
    std::memcpy(out + 1 + NET_CPACE_SHARE_SIZE, confirm, NET_PAIR_CONFIRM_SIZE);
    return 1 + NET_CPACE_SHARE_SIZE + NET_PAIR_CONFIRM_SIZE;
}

bool net_message_read_pair_response(const uint8_t* data, size_t size, uint8_t* share, uint8_t* confirm)
{
    if (size != 1 + NET_CPACE_SHARE_SIZE + NET_PAIR_CONFIRM_SIZE ||
        data[0] != static_cast<uint8_t>(NetMessage::pair_response))
    {
        return false;
    }
    std::memcpy(share, data + 1, NET_CPACE_SHARE_SIZE);
    std::memcpy(confirm, data + 1 + NET_CPACE_SHARE_SIZE, NET_PAIR_CONFIRM_SIZE);
    return true;
}

size_t net_message_write_pair_confirm(uint8_t* out, size_t capacity, const uint8_t* confirm)
{
    if (capacity < 1 + NET_PAIR_CONFIRM_SIZE)
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetMessage::pair_confirm);
    std::memcpy(out + 1, confirm, NET_PAIR_CONFIRM_SIZE);
    return 1 + NET_PAIR_CONFIRM_SIZE;
}

bool net_message_read_pair_confirm(const uint8_t* data, size_t size, uint8_t* confirm)
{
    if (size != 1 + NET_PAIR_CONFIRM_SIZE || data[0] != static_cast<uint8_t>(NetMessage::pair_confirm))
    {
        return false;
    }
    std::memcpy(confirm, data + 1, NET_PAIR_CONFIRM_SIZE);
    return true;
}

size_t net_message_write_pair_result(uint8_t* out, size_t capacity, bool ok)
{
    if (capacity < 2)
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetMessage::pair_result);
    out[1] = ok ? 1 : 0;
    return 2;
}

bool net_message_read_pair_result(const uint8_t* data, size_t size, bool* ok)
{
    if (size != 2 || data[0] != static_cast<uint8_t>(NetMessage::pair_result) || data[1] > 1)
    {
        return false;
    }
    *ok = data[1] == 1;
    return true;
}

size_t net_message_write_grant(uint8_t* out, size_t capacity, NetCaps caps)
{
    if (capacity < 5)
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetMessage::grant);
    put_u32(out + 1, caps);
    return 5;
}

bool net_message_read_grant(const uint8_t* data, size_t size, NetCaps* caps)
{
    if (size != 5 || data[0] != static_cast<uint8_t>(NetMessage::grant))
    {
        return false;
    }
    uint32_t value = get_u32(data + 1);
    if ((value & ~NET_CAPS_ALL) != 0)
    {
        return false;
    }
    *caps = value;
    return true;
}

size_t net_message_write_unpair(uint8_t* out, size_t capacity)
{
    return write_type_only(out, capacity, NetMessage::unpair);
}

bool net_message_read_unpair(const uint8_t* data, size_t size)
{
    return size == 1 && data[0] == static_cast<uint8_t>(NetMessage::unpair);
}
