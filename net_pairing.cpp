#include "net_pairing.h"

#include <cstring>

#include "monocypher.h"
#include "net_random.h"

static constexpr uint8_t CI_LABEL[15] = {'m', 'u', 'l', 't', 'i', 't', 'a', 'p', '-', 'p', 'a', 'i', 'r', ' ', '1'};
static constexpr uint8_t CONFIRM_HOST[18] = {'m', 'u', 'l', 't', 'i', 't', 'a', 'p', ' ',
                                             'p', 'a', 'i', 'r', ' ', 'h', 'o', 's', 't'};
static constexpr uint8_t CONFIRM_CLIENT[20] = {'m', 'u', 'l', 't', 'i', 't', 'a', 'p', ' ', 'p',
                                               'a', 'i', 'r', ' ', 'c', 'l', 'i', 'e', 'n', 't'};

bool net_pair_code_generate(char* code)
{
    // Rejection sampling keeps every code equally likely: 4294000000 is the
    // largest multiple of 10^6 below 2^32.
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
    } while (value >= 4294000000u);
    value %= 1000000u;
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

// The name must fill the rest of the payload exactly.
static bool read_name(const uint8_t* data, size_t size, char* name)
{
    if (size < 1)
    {
        return false;
    }
    size_t length = data[0];
    if (length > NET_DEVICE_NAME_MAX || size != 1 + length || std::memchr(data + 1, 0, length) != nullptr)
    {
        return false;
    }
    std::memcpy(name, data + 1, length);
    name[length] = '\0';
    return true;
}

// --- messages ---------------------------------------------------------------

size_t net_message_write_welcome(uint8_t* out, size_t capacity, const char* host_name)
{
    if (capacity < 2 + name_length(host_name))
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetMessage::welcome);
    return 1 + write_name(out + 1, host_name);
}

bool net_message_read_welcome(const uint8_t* data, size_t size, char* host_name)
{
    return size >= 1 && data[0] == static_cast<uint8_t>(NetMessage::welcome) && read_name(data + 1, size - 1, host_name);
}

size_t net_message_write_pairing_needed(uint8_t* out, size_t capacity, bool open, const char* host_name)
{
    if (capacity < 3 + name_length(host_name))
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetMessage::pairing_needed);
    out[1] = open ? 1 : 0;
    return 2 + write_name(out + 2, host_name);
}

bool net_message_read_pairing_needed(const uint8_t* data, size_t size, bool* open, char* host_name)
{
    if (size < 2 || data[0] != static_cast<uint8_t>(NetMessage::pairing_needed) || data[1] > 1)
    {
        return false;
    }
    *open = data[1] == 1;
    return read_name(data + 2, size - 2, host_name);
}

size_t net_message_write_pair_request(uint8_t* out, size_t capacity, const uint8_t* share, const char* client_name)
{
    if (capacity < 2 + NET_CPACE_SHARE_SIZE + name_length(client_name))
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetMessage::pair_request);
    std::memcpy(out + 1, share, NET_CPACE_SHARE_SIZE);
    return 1 + NET_CPACE_SHARE_SIZE + write_name(out + 1 + NET_CPACE_SHARE_SIZE, client_name);
}

bool net_message_read_pair_request(const uint8_t* data, size_t size, uint8_t* share, char* client_name)
{
    if (size < 1 + NET_CPACE_SHARE_SIZE || data[0] != static_cast<uint8_t>(NetMessage::pair_request))
    {
        return false;
    }
    std::memcpy(share, data + 1, NET_CPACE_SHARE_SIZE);
    return read_name(data + 1 + NET_CPACE_SHARE_SIZE, size - 1 - NET_CPACE_SHARE_SIZE, client_name);
}

size_t net_message_write_pair_response(uint8_t* out, size_t capacity, const uint8_t* share, const uint8_t* confirm,
                                       const char* host_name)
{
    if (capacity < 2 + NET_CPACE_SHARE_SIZE + NET_PAIR_CONFIRM_SIZE + name_length(host_name))
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetMessage::pair_response);
    std::memcpy(out + 1, share, NET_CPACE_SHARE_SIZE);
    std::memcpy(out + 1 + NET_CPACE_SHARE_SIZE, confirm, NET_PAIR_CONFIRM_SIZE);
    return 1 + NET_CPACE_SHARE_SIZE + NET_PAIR_CONFIRM_SIZE +
           write_name(out + 1 + NET_CPACE_SHARE_SIZE + NET_PAIR_CONFIRM_SIZE, host_name);
}

bool net_message_read_pair_response(const uint8_t* data, size_t size, uint8_t* share, uint8_t* confirm,
                                    char* host_name)
{
    size_t fixed = 1 + NET_CPACE_SHARE_SIZE + NET_PAIR_CONFIRM_SIZE;
    if (size < fixed || data[0] != static_cast<uint8_t>(NetMessage::pair_response))
    {
        return false;
    }
    std::memcpy(share, data + 1, NET_CPACE_SHARE_SIZE);
    std::memcpy(confirm, data + 1 + NET_CPACE_SHARE_SIZE, NET_PAIR_CONFIRM_SIZE);
    return read_name(data + fixed, size - fixed, host_name);
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
