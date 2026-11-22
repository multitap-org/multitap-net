#include "net_pair_link.h"

#include <cstring>

#include "net_beacon.h"

static const char ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";

static std::string base32(const uint8_t* data, size_t size)
{
    std::string out;
    uint32_t buffer = 0;
    int bits = 0;
    for (size_t i = 0; i < size; i++)
    {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5)
        {
            out.push_back(ALPHABET[(buffer >> (bits - 5)) & 31u]);
            bits -= 5;
        }
    }
    if (bits > 0)
    {
        out.push_back(ALPHABET[(buffer << (5 - bits)) & 31u]);
    }
    return out;
}

static int base32_value(char c)
{
    if (c >= 'a' && c <= 'z')
    {
        return c - 'a';
    }
    if (c >= 'A' && c <= 'Z')
    {
        return c - 'A';
    }
    if (c >= '2' && c <= '7')
    {
        return c - '2' + 26;
    }
    return -1;
}

// Exactly `size` bytes from `length` characters, the unused low bits zero.
static bool unbase32(const char* text, size_t length, uint8_t* out, size_t size)
{
    if (length != (size * 8 + 4) / 5)
    {
        return false;
    }
    uint32_t buffer = 0;
    int bits = 0;
    size_t written = 0;
    for (size_t i = 0; i < length; i++)
    {
        int value = base32_value(text[i]);
        if (value < 0)
        {
            return false;
        }
        buffer = (buffer << 5) | static_cast<uint32_t>(value);
        bits += 5;
        if (bits >= 8)
        {
            out[written++] = static_cast<uint8_t>(buffer >> (bits - 8));
            bits -= 8;
        }
    }
    return written == size && (buffer & ((1u << bits) - 1u)) == 0;
}

// A beacon name or URL travels as it is: only characters that need no escaping.
static bool beacon_text_ok(const char* text, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        char c = text[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                  c == '-' || c == '_' || c == ':' || c == '/' || c == '[' || c == ']';
        if (!ok)
        {
            return false;
        }
    }
    return length > 0;
}

std::string net_pair_link(const uint8_t* host_key, const char* beacon)
{
    std::string link = NET_PAIR_LINK_BASE;
    link += "k=";
    link += base32(host_key, NET_KEY_SIZE);
    if (beacon != nullptr && beacon[0] != '\0' && std::strcmp(beacon, NET_BEACON_DEFAULT_SERVER) != 0 &&
        beacon_text_ok(beacon, std::strlen(beacon)))
    {
        link += "&b=";
        link += beacon;
    }
    return link;
}

bool net_pair_link_parse(const char* text, uint8_t* host_key, std::string* beacon)
{
    const char* hash = std::strrchr(text, '#');
    const char* fields = hash != nullptr ? hash + 1 : text;
    bool have_key = false;
    beacon->clear();
    while (*fields != '\0')
    {
        const char* end = std::strchr(fields, '&');
        size_t length = end != nullptr ? static_cast<size_t>(end - fields) : std::strlen(fields);
        if (length > 2 && fields[0] == 'k' && fields[1] == '=')
        {
            have_key = unbase32(fields + 2, length - 2, host_key, NET_KEY_SIZE);
            if (!have_key)
            {
                return false;
            }
        }
        else if (length > 2 && fields[0] == 'b' && fields[1] == '=' && beacon_text_ok(fields + 2, length - 2))
        {
            beacon->assign(fields + 2, length - 2);
        }
        if (end == nullptr)
        {
            break;
        }
        fields = end + 1;
    }
    return have_key;
}
