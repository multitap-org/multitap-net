#include "net_guest.h"

#include <cstdio>
#include <cstring>

#include "monocypher.h"
#include "net_random.h"

static const char BASE32[] = "abcdefghijklmnopqrstuvwxyz234567";

static bool is_base32(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
}

static bool all_base32(const char* text, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        if (!is_base32(text[i]))
        {
            return false;
        }
    }
    return true;
}

// The first `count` base32 characters of `data` (which holds at least
// count * 5 / 8 + 2 bytes).
static void base32_chars(const uint8_t* data, size_t count, char* out)
{
    for (size_t i = 0; i < count; i++)
    {
        size_t bit = i * 5;
        size_t byte = bit / 8;
        uint32_t shift = static_cast<uint32_t>(bit % 8);
        uint32_t window = static_cast<uint32_t>(data[byte]) << 8 | data[byte + 1];
        out[i] = BASE32[(window >> (11 - shift)) & 31u];
    }
    out[count] = '\0';
}

// BLAKE2b of a label's ASCII bytes followed by `data`.
static void labeled_hash(uint8_t* out, size_t out_size, const char* label, const uint8_t* data, size_t size)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, out_size);
    crypto_blake2b_update(&ctx, reinterpret_cast<const uint8_t*>(label), std::strlen(label));
    crypto_blake2b_update(&ctx, data, size);
    crypto_blake2b_final(&ctx, out);
}

bool net_guest_link_from_token(const char* token, NetGuestLink* link)
{
    *link = {};
    if (std::strlen(token) != NET_GUEST_TOKEN_SIZE || !all_base32(token, NET_GUEST_TOKEN_SIZE))
    {
        return false;
    }
    std::memcpy(link->token, token, NET_GUEST_TOKEN_SIZE);
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(link->token);
    labeled_hash(link->card_key, sizeof(link->card_key), "multitap guest card v1", bytes, NET_GUEST_TOKEN_SIZE);
    uint8_t room_hash[32];
    labeled_hash(room_hash, sizeof(room_hash), "multitap guest room v1", link->card_key, sizeof(link->card_key));
    base32_chars(room_hash, NET_GUEST_ROOM_SIZE, link->room);
    labeled_hash(link->meeting.bytes, BEACON_ID_SIZE, "multitap guest v1", reinterpret_cast<const uint8_t*>(link->room),
                 NET_GUEST_ROOM_SIZE);
    labeled_hash(link->signal_key, sizeof(link->signal_key), "multitap guest signal v1", bytes, NET_GUEST_TOKEN_SIZE);
    labeled_hash(link->mac_key, sizeof(link->mac_key), "multitap guest mac v1", bytes, NET_GUEST_TOKEN_SIZE);
    return true;
}

bool net_guest_link_make(NetGuestLink* link)
{
    uint8_t random[18];
    if (!net_random_bytes(random, sizeof(random)))
    {
        return false;
    }
    char token[NET_GUEST_TOKEN_SIZE + 1];
    base32_chars(random, NET_GUEST_TOKEN_SIZE, token);
    crypto_wipe(random, sizeof(random));
    bool ok = net_guest_link_from_token(token, link);
    crypto_wipe(token, sizeof(token));
    return ok;
}

void net_guest_link_wipe(NetGuestLink* link)
{
    crypto_wipe(link, sizeof(*link));
    *link = {};
}

size_t net_guest_link_url(const NetGuestLink* link, const char* beacon, char* out, size_t capacity)
{
    int written = std::snprintf(out, capacity, "https://%s/join/%s#%s", beacon, link->room, link->token);
    if (written <= 0 || static_cast<size_t>(written) >= capacity)
    {
        if (capacity > 0)
        {
            out[0] = '\0';
        }
        return 0;
    }
    return static_cast<size_t>(written);
}

// A beacon host name as links carry it: letters, digits, '-', '.', ':' and
// IPv6 brackets.
static bool valid_beacon(const char* text, size_t size)
{
    if (size == 0 || size >= NET_GUEST_MAX_BEACON)
    {
        return false;
    }
    for (size_t i = 0; i < size; i++)
    {
        char c = text[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
                  c == '.' || c == ':' || c == '[' || c == ']';
        if (!ok)
        {
            return false;
        }
    }
    return true;
}

// The value of "b=" among '&'-separated parameters, if any (into `beacon`).
static bool read_beacon_param(const char* params, char* beacon, size_t capacity)
{
    const char* at = params;
    while (at != nullptr && *at != '\0')
    {
        const char* end = std::strchr(at, '&');
        size_t length = end != nullptr ? static_cast<size_t>(end - at) : std::strlen(at);
        if (length > 2 && at[0] == 'b' && at[1] == '=')
        {
            if (!valid_beacon(at + 2, length - 2) || length - 2 >= capacity)
            {
                return false;
            }
            std::memcpy(beacon, at + 2, length - 2);
            beacon[length - 2] = '\0';
            return true;
        }
        at = end != nullptr ? end + 1 : nullptr;
    }
    return true;
}

// room (13) then `separator` then token (26), the token ending the text or
// followed by '&'. `rest` gets what follows the token.
static bool read_room_token(const char* text, char separator, char* room, char* token, const char** rest)
{
    if (std::strlen(text) < NET_GUEST_ROOM_SIZE + 1 + NET_GUEST_TOKEN_SIZE || !all_base32(text, NET_GUEST_ROOM_SIZE) ||
        text[NET_GUEST_ROOM_SIZE] != separator || !all_base32(text + NET_GUEST_ROOM_SIZE + 1, NET_GUEST_TOKEN_SIZE))
    {
        return false;
    }
    const char* after = text + NET_GUEST_ROOM_SIZE + 1 + NET_GUEST_TOKEN_SIZE;
    if (*after != '\0' && *after != '&')
    {
        return false;
    }
    std::memcpy(room, text, NET_GUEST_ROOM_SIZE);
    room[NET_GUEST_ROOM_SIZE] = '\0';
    std::memcpy(token, text + NET_GUEST_ROOM_SIZE + 1, NET_GUEST_TOKEN_SIZE);
    token[NET_GUEST_TOKEN_SIZE] = '\0';
    *rest = *after == '&' ? after + 1 : after;
    return true;
}

bool net_guest_link_looks_like(const char* text)
{
    return std::strstr(text, "/join/") != nullptr || std::strstr(text, "join=") != nullptr ||
           std::strncmp(text, "piccoletto://join", 17) == 0 || std::strncmp(text, "piccolo://join", 14) == 0;
}

bool net_guest_link_parse(const char* text, NetGuestLink* link, char* beacon, size_t beacon_capacity)
{
    *link = {};
    if (beacon_capacity > 0)
    {
        beacon[0] = '\0';
    }
    if (std::strlen(text) > NET_GUEST_MAX_LINK)
    {
        return false;
    }
    char room[NET_GUEST_ROOM_SIZE + 1] = {};
    char token[NET_GUEST_TOKEN_SIZE + 1] = {};
    const char* rest = "";
    bool found = false;
    static const char HTTPS[] = "https://";
    static const char APP_PICCOLETTO[] = "piccoletto://join/";
    static const char APP_PICCOLO[] = "piccolo://join/";
    const char* hash_join = std::strstr(text, "join=");
    if (std::strncmp(text, HTTPS, sizeof(HTTPS) - 1) == 0 && std::strstr(text, "/join/") != nullptr &&
        (hash_join == nullptr || std::strchr(text, '#') < hash_join))
    {
        // https://<beacon>/join/<room>#<token>; a beacon other than the default
        // is the link's own host.
        const char* host = text + sizeof(HTTPS) - 1;
        const char* path = std::strstr(host, "/join/");
        if (!valid_beacon(host, static_cast<size_t>(path - host)) ||
            static_cast<size_t>(path - host) >= beacon_capacity)
        {
            return false;
        }
        const char* room_text = path + 6;
        char joined[NET_GUEST_ROOM_SIZE + 1 + NET_GUEST_TOKEN_SIZE + 1] = {};
        // "<room>#<token>", or "<room>/#<token>".
        if (std::strlen(room_text) > NET_GUEST_ROOM_SIZE && room_text[NET_GUEST_ROOM_SIZE] == '/')
        {
            std::memcpy(joined, room_text, NET_GUEST_ROOM_SIZE);
            std::snprintf(joined + NET_GUEST_ROOM_SIZE, sizeof(joined) - NET_GUEST_ROOM_SIZE, "%s",
                          room_text + NET_GUEST_ROOM_SIZE + 1);
            room_text = joined;
        }
        found = read_room_token(room_text, '#', room, token, &rest) && *rest == '\0';
        if (found)
        {
            std::memcpy(beacon, host, static_cast<size_t>(path - host));
            beacon[path - host] = '\0';
        }
    }
    else if (std::strncmp(text, APP_PICCOLETTO, sizeof(APP_PICCOLETTO) - 1) == 0)
    {
        // piccoletto://join/<room>?t=<token>[&b=<beacon>]
        const char* room_text = text + sizeof(APP_PICCOLETTO) - 1;
        char joined[NET_GUEST_MAX_LINK + 1] = {};
        if (std::strlen(room_text) > NET_GUEST_ROOM_SIZE + 3 &&
            std::strncmp(room_text + NET_GUEST_ROOM_SIZE, "?t=", 3) == 0)
        {
            std::memcpy(joined, room_text, NET_GUEST_ROOM_SIZE);
            joined[NET_GUEST_ROOM_SIZE] = '.';
            std::snprintf(joined + NET_GUEST_ROOM_SIZE + 1, sizeof(joined) - NET_GUEST_ROOM_SIZE - 1, "%s",
                          room_text + NET_GUEST_ROOM_SIZE + 3);
            found = read_room_token(joined, '.', room, token, &rest) &&
                    read_beacon_param(rest, beacon, beacon_capacity);
        }
    }
    else if (std::strncmp(text, APP_PICCOLO, sizeof(APP_PICCOLO) - 1) == 0)
    {
        found = read_room_token(text + sizeof(APP_PICCOLO) - 1, '#', room, token, &rest) && *rest == '\0';
    }
    else if (hash_join != nullptr && (hash_join == text || hash_join[-1] == '#' || hash_join[-1] == '&'))
    {
        // [...#]join=<room>.<token>[&b=<beacon>]
        found = read_room_token(hash_join + 5, '.', room, token, &rest) &&
                read_beacon_param(rest, beacon, beacon_capacity);
    }
    if (!found || !net_guest_link_from_token(token, link))
    {
        crypto_wipe(token, sizeof(token));
        *link = {};
        if (beacon_capacity > 0)
        {
            beacon[0] = '\0';
        }
        return false;
    }
    crypto_wipe(token, sizeof(token));
    if (std::memcmp(room, link->room, NET_GUEST_ROOM_SIZE) != 0)
    {
        // Someone changed one half: no link.
        net_guest_link_wipe(link);
        if (beacon_capacity > 0)
        {
            beacon[0] = '\0';
        }
        return false;
    }
    return true;
}

void net_guest_mac(const NetGuestLink* link, bool from_host, const uint8_t* handshake_hash, uint8_t* mac)
{
    const char* label = from_host ? "guest host" : "guest client";
    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, NET_GUEST_MAC_SIZE, link->mac_key, sizeof(link->mac_key));
    crypto_blake2b_update(&ctx, reinterpret_cast<const uint8_t*>(label), std::strlen(label));
    crypto_blake2b_update(&ctx, handshake_hash, NET_HASH_SIZE);
    crypto_blake2b_final(&ctx, mac);
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

// A name cut to NET_GUEST_MAX_NAME bytes at a UTF-8 boundary, control
// characters dropped.
static size_t name_bytes(const char* name, char* out)
{
    size_t used = 0;
    for (size_t i = 0; name[i] != '\0' && used < NET_GUEST_MAX_NAME; i++)
    {
        uint8_t c = static_cast<uint8_t>(name[i]);
        if (c < 0x20 || c == 0x7f)
        {
            continue;
        }
        out[used++] = name[i];
    }
    // Back off a cut multibyte sequence.
    size_t end = used;
    while (end > 0 && (static_cast<uint8_t>(out[end - 1]) & 0xc0u) == 0x80u)
    {
        end--;
    }
    if (end > 0 && static_cast<uint8_t>(out[end - 1]) >= 0xc0u)
    {
        uint8_t lead = static_cast<uint8_t>(out[end - 1]);
        size_t want = lead >= 0xf0u ? 4 : lead >= 0xe0u ? 3 : 2;
        if (used - (end - 1) < want)
        {
            used = end - 1;
        }
    }
    return used;
}

size_t net_guest_write_hello(uint8_t* out, size_t capacity, const uint8_t* mac, const char* name)
{
    char cut[NET_GUEST_MAX_NAME];
    size_t name_size = name_bytes(name, cut);
    size_t size = 1 + NET_GUEST_MAC_SIZE + 1 + name_size;
    if (capacity < size)
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetGuestMessage::hello);
    std::memcpy(out + 1, mac, NET_GUEST_MAC_SIZE);
    out[1 + NET_GUEST_MAC_SIZE] = static_cast<uint8_t>(name_size);
    std::memcpy(out + 2 + NET_GUEST_MAC_SIZE, cut, name_size);
    return size;
}

bool net_guest_read_hello(const uint8_t* data, size_t size, uint8_t* mac, char* name)
{
    if (size < 2 + NET_GUEST_MAC_SIZE || data[0] != static_cast<uint8_t>(NetGuestMessage::hello))
    {
        return false;
    }
    size_t name_size = data[1 + NET_GUEST_MAC_SIZE];
    if (name_size > NET_GUEST_MAX_NAME || size != 2 + NET_GUEST_MAC_SIZE + name_size)
    {
        return false;
    }
    std::memcpy(mac, data + 1, NET_GUEST_MAC_SIZE);
    // Shown on the host: control characters never get through.
    size_t used = 0;
    for (size_t i = 0; i < name_size; i++)
    {
        char c = static_cast<char>(data[2 + NET_GUEST_MAC_SIZE + i]);
        if (static_cast<uint8_t>(c) >= 0x20 && c != 0x7f)
        {
            name[used++] = c;
        }
    }
    name[used] = '\0';
    return true;
}

size_t net_guest_write_welcome(uint8_t* out, size_t capacity, const uint8_t* mac, NetGuestLevel level)
{
    size_t size = 1 + NET_GUEST_MAC_SIZE + 1;
    if (capacity < size)
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetGuestMessage::welcome);
    std::memcpy(out + 1, mac, NET_GUEST_MAC_SIZE);
    out[1 + NET_GUEST_MAC_SIZE] = static_cast<uint8_t>(level);
    return size;
}

bool net_guest_read_welcome(const uint8_t* data, size_t size, uint8_t* mac, NetGuestLevel* level)
{
    if (size != 2 + NET_GUEST_MAC_SIZE || data[0] != static_cast<uint8_t>(NetGuestMessage::welcome) ||
        data[1 + NET_GUEST_MAC_SIZE] > static_cast<uint8_t>(NetGuestLevel::play))
    {
        return false;
    }
    std::memcpy(mac, data + 1, NET_GUEST_MAC_SIZE);
    *level = static_cast<NetGuestLevel>(data[1 + NET_GUEST_MAC_SIZE]);
    return true;
}

size_t net_guest_write_full(uint8_t* out, size_t capacity, const uint8_t* mac)
{
    if (capacity < 1 + NET_GUEST_MAC_SIZE)
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetGuestMessage::full);
    std::memcpy(out + 1, mac, NET_GUEST_MAC_SIZE);
    return 1 + NET_GUEST_MAC_SIZE;
}

bool net_guest_read_full(const uint8_t* data, size_t size, uint8_t* mac)
{
    if (size != 1 + NET_GUEST_MAC_SIZE || data[0] != static_cast<uint8_t>(NetGuestMessage::full))
    {
        return false;
    }
    std::memcpy(mac, data + 1, NET_GUEST_MAC_SIZE);
    return true;
}

size_t net_guest_write_bye(uint8_t* out, size_t capacity, NetGuestBye reason)
{
    if (capacity < 2)
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(NetGuestMessage::bye);
    out[1] = static_cast<uint8_t>(reason);
    return 2;
}

bool net_guest_read_bye(const uint8_t* data, size_t size, NetGuestBye* reason)
{
    if (size != 2 || data[0] != static_cast<uint8_t>(NetGuestMessage::bye) ||
        data[1] < static_cast<uint8_t>(NetGuestBye::kicked) || data[1] > static_cast<uint8_t>(NetGuestBye::ended))
    {
        return false;
    }
    *reason = static_cast<NetGuestBye>(data[1]);
    return true;
}

size_t net_guest_write_port(uint8_t* out, size_t capacity, uint8_t port)
{
    if (capacity < 2)
    {
        return 0;
    }
    out[0] = NET_GUEST_PORT_MESSAGE;
    out[1] = port;
    return 2;
}

bool net_guest_read_port(const uint8_t* data, size_t size, uint8_t* port)
{
    if (size != 2 || data[0] != NET_GUEST_PORT_MESSAGE)
    {
        return false;
    }
    *port = data[1];
    return true;
}

// ---------------------------------------------------------------------------
// The card
// ---------------------------------------------------------------------------

void net_guest_title_clean(const char* name, char* out)
{
    // Groups dropped, control characters and runs of spaces / '_' as one space.
    std::vector<char> text;
    int32_t depth_round = 0;
    int32_t depth_square = 0;
    for (size_t i = 0; name[i] != '\0'; i++)
    {
        char c = name[i];
        if (c == '(')
        {
            depth_round++;
            continue;
        }
        if (c == '[')
        {
            depth_square++;
            continue;
        }
        if (c == ')' && depth_round > 0)
        {
            depth_round--;
            continue;
        }
        if (c == ']' && depth_square > 0)
        {
            depth_square--;
            continue;
        }
        if (depth_round > 0 || depth_square > 0)
        {
            continue;
        }
        uint8_t byte = static_cast<uint8_t>(c);
        bool space = c == ' ' || c == '_' || c == '\t' || byte < 0x20 || byte == 0x7f;
        if (space)
        {
            if (!text.empty() && text.back() != ' ')
            {
                text.push_back(' ');
            }
            continue;
        }
        text.push_back(c);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '-' || text.back() == ','))
    {
        text.pop_back();
    }
    // Cut at NET_GUEST_MAX_TITLE bytes, at a UTF-8 boundary.
    size_t used = text.size() < NET_GUEST_MAX_TITLE ? text.size() : NET_GUEST_MAX_TITLE;
    if (used < text.size())
    {
        while (used > 0 && (static_cast<uint8_t>(text[used]) & 0xc0u) == 0x80u)
        {
            used--;
        }
    }
    for (size_t i = 0; i < used; i++)
    {
        out[i] = text[i];
    }
    out[used] = '\0';
    // A name that was nothing but groups: keep something.
    if (used == 0)
    {
        std::snprintf(out, NET_GUEST_MAX_TITLE + 1, "%s", "A game");
    }
}

bool net_guest_card_body(const NetGuestLink* link, const char* title, const uint8_t* png, size_t png_size,
                         std::vector<uint8_t>* out)
{
    size_t title_size = std::strlen(title);
    // No PNG is fine: the card then has only its title (the beacon shows
    // white noise for the picture).
    if (title_size == 0 || title_size > NET_GUEST_MAX_TITLE || png_size > NET_GUEST_CARD_MAX_PNG)
    {
        return false;
    }
    out->clear();
    out->reserve(NET_GUEST_KEY_SIZE + 1 + title_size + png_size);
    out->insert(out->end(), link->card_key, link->card_key + NET_GUEST_KEY_SIZE);
    out->push_back(static_cast<uint8_t>(title_size));
    out->insert(out->end(), reinterpret_cast<const uint8_t*>(title), reinterpret_cast<const uint8_t*>(title) + title_size);
    if (png_size > 0)
    {
        out->insert(out->end(), png, png + png_size);
    }
    return true;
}
