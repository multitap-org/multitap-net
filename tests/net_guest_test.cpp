// net_guest: the derivations (the beacon's vectors, computed with Python's
// hashlib.blake2b: deps/beacon tests/http_test.cpp has the same), every form
// of the link, the messages, the title and the card's body.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "net_guest.h"

static int g_failures = 0;

static void check(bool condition, const char* what)
{
    std::printf("%s %s\n", condition ? "ok  " : "FAIL", what);
    if (!condition)
    {
        g_failures++;
    }
}

static std::string hex(const uint8_t* data, size_t size)
{
    std::string text;
    char piece[3];
    for (size_t i = 0; i < size; i++)
    {
        std::snprintf(piece, sizeof(piece), "%02x", data[i]);
        text += piece;
    }
    return text;
}

static const char TOKEN[] = "abcdefghijklmnopqrstuvwxyz";
static const char ROOM[] = "7hqelxhbgx2e3";

static void test_derivations()
{
    NetGuestLink link;
    check(net_guest_link_from_token(TOKEN, &link), "a token");
    check(hex(link.card_key, 32) == "08df115380262124acd5de50e376071f05ef0e65857d278af6e0f52d01b4e1c2",
          "card key (vector)");
    check(std::strcmp(link.room, ROOM) == 0, "room (vector)");
    check(hex(link.meeting.bytes, 16) == "cef90bb0d95aa2ae4643af9cab828945", "meeting id (vector)");
    check(hex(link.signal_key, 32) == "4af31e6521153e7d52a7368b575154eb5117dfd3da83795f454871e2612ad695",
          "signal key (vector)");
    check(!net_guest_link_from_token("abcdefghijklmnopqrstuvwxy", &link), "25 characters: no");
    check(!net_guest_link_from_token("abcdefghijklmnopqrstuvwxy1", &link), "'1' isn't base32");
    check(!net_guest_link_from_token("Abcdefghijklmnopqrstuvwxyz", &link), "upper case: no");

    NetGuestLink a;
    NetGuestLink b;
    check(net_guest_link_make(&a) && net_guest_link_make(&b), "random links");
    check(std::strcmp(a.token, b.token) != 0 && std::strcmp(a.room, b.room) != 0, "two links differ");
    NetGuestLink again;
    check(net_guest_link_from_token(a.token, &again) && std::strcmp(again.room, a.room) == 0, "a link's token gives its room");
}

static void test_links()
{
    NetGuestLink link;
    net_guest_link_from_token(TOKEN, &link);
    char url[NET_GUEST_MAX_LINK];
    check(net_guest_link_url(&link, "beacon.get-piccolo.app", url, sizeof(url)) > 0 &&
              std::string(url) == "https://beacon.get-piccolo.app/join/7hqelxhbgx2e3#abcdefghijklmnopqrstuvwxyz",
          "the link");
    check(net_guest_link_url(&link, "beacon.get-piccolo.app", url, 20) == 0 && url[0] == '\0', "a link that doesn't fit");

    struct Case
    {
        const char* text;
        const char* beacon;
    };
    const Case good[] = {
        {"https://beacon.get-piccolo.app/join/7hqelxhbgx2e3#abcdefghijklmnopqrstuvwxyz", "beacon.get-piccolo.app"},
        {"https://beacon.get-piccolo.app/join/7hqelxhbgx2e3/#abcdefghijklmnopqrstuvwxyz", "beacon.get-piccolo.app"},
        {"https://my.beacon:8443/join/7hqelxhbgx2e3#abcdefghijklmnopqrstuvwxyz", "my.beacon:8443"},
        {"piccoletto://join/7hqelxhbgx2e3?t=abcdefghijklmnopqrstuvwxyz", ""},
        {"piccoletto://join/7hqelxhbgx2e3?t=abcdefghijklmnopqrstuvwxyz&b=my.beacon", "my.beacon"},
        {"piccolo://join/7hqelxhbgx2e3#abcdefghijklmnopqrstuvwxyz", ""},
        {"join=7hqelxhbgx2e3.abcdefghijklmnopqrstuvwxyz", ""},
        {"#join=7hqelxhbgx2e3.abcdefghijklmnopqrstuvwxyz&b=my.beacon", "my.beacon"},
        {"https://get-piccolo.app/play/piccoletto/#join=7hqelxhbgx2e3.abcdefghijklmnopqrstuvwxyz", ""},
    };
    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++)
    {
        NetGuestLink parsed;
        char beacon[NET_GUEST_MAX_BEACON];
        bool ok = net_guest_link_parse(good[i].text, &parsed, beacon, sizeof(beacon));
        if (!ok || std::strcmp(parsed.token, TOKEN) != 0 || std::strcmp(beacon, good[i].beacon) != 0)
        {
            std::printf("     case %s\n", good[i].text);
            check(false, "a good link parses, with its beacon");
        }
        check(net_guest_link_looks_like(good[i].text), "it looks like a guest link");
    }
    const char* bad[] = {
        "https://beacon.get-piccolo.app/join/7hqelxhbgx2e3",                            // no token
        "https://beacon.get-piccolo.app/join/7hqelxhbgx2e4#abcdefghijklmnopqrstuvwxyz", // the room doesn't match
        "https://beacon.get-piccolo.app/join/7hqelxhbgx2e3#abcdefghijklmnopqrstuvwxy",  // short token
        "https://beacon.get-piccolo.app/join/7hqelxhbgx2e3#abcdefghijklmnopqrstuvwxyzz",
        "https://beac<on/join/7hqelxhbgx2e3#abcdefghijklmnopqrstuvwxyz",
        "piccoletto://join/7hqelxhbgx2e3?t=abcdefghijklmnopqrstuvwxyz&b=bad/host",
        "piccoletto://pair?k=abc",
        "xjoin=7hqelxhbgx2e3.abcdefghijklmnopqrstuvwxyz",
        "",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        NetGuestLink parsed;
        char beacon[NET_GUEST_MAX_BEACON];
        if (net_guest_link_parse(bad[i], &parsed, beacon, sizeof(beacon)) || parsed.token[0] != '\0')
        {
            std::printf("     case %s\n", bad[i]);
            check(false, "a bad link doesn't parse");
        }
    }
}

static void test_messages()
{
    NetGuestLink link;
    net_guest_link_from_token(TOKEN, &link);
    uint8_t hash[NET_HASH_SIZE];
    for (size_t i = 0; i < sizeof(hash); i++)
    {
        hash[i] = static_cast<uint8_t>(i);
    }
    uint8_t client_mac[NET_GUEST_MAC_SIZE];
    uint8_t host_mac[NET_GUEST_MAC_SIZE];
    net_guest_mac(&link, false, hash, client_mac);
    net_guest_mac(&link, true, hash, host_mac);
    check(std::memcmp(client_mac, host_mac, NET_GUEST_MAC_SIZE) != 0, "each side's proof differs");
    hash[0] ^= 1;
    uint8_t other[NET_GUEST_MAC_SIZE];
    net_guest_mac(&link, false, hash, other);
    check(std::memcmp(client_mac, other, NET_GUEST_MAC_SIZE) != 0, "another connection, another proof");

    uint8_t out[NET_GUEST_MAX_MESSAGE];
    uint8_t mac[NET_GUEST_MAC_SIZE];
    char name[NET_GUEST_MAX_NAME + 1];
    size_t size = net_guest_write_hello(out, sizeof(out), client_mac, "PIXEL 8");
    check(size == 1 + 32 + 1 + 7 && out[0] == 10 && net_guest_read_hello(out, size, mac, name) &&
              std::memcmp(mac, client_mac, 32) == 0 && std::strcmp(name, "PIXEL 8") == 0,
          "hello");
    check(!net_guest_read_hello(out, size - 1, mac, name), "a hello cut short");
    size = net_guest_write_hello(out, sizeof(out), client_mac, "a\nb\x1b" "c");
    check(net_guest_read_hello(out, size, mac, name) && std::strcmp(name, "abc") == 0, "control characters dropped");
    size = net_guest_write_hello(out, sizeof(out), client_mac, "ÁÁÁÁÁÁÁÁÁÁÁÁÁÁÁÁÁ");   // 34 bytes
    check(net_guest_read_hello(out, size, mac, name) && std::strlen(name) == 32, "a long name cut at a UTF-8 boundary");

    NetGuestLevel level = NetGuestLevel::watch;
    size = net_guest_write_welcome(out, sizeof(out), host_mac, NetGuestLevel::play);
    check(size == 34 && net_guest_read_welcome(out, size, mac, &level) && level == NetGuestLevel::play &&
              std::memcmp(mac, host_mac, 32) == 0,
          "welcome");
    out[33] = 2;
    check(!net_guest_read_welcome(out, size, mac, &level), "an unknown level");
    size = net_guest_write_full(out, sizeof(out), host_mac);
    check(size == 33 && net_guest_read_full(out, size, mac) && !net_guest_read_welcome(out, size, mac, &level), "full");
    NetGuestBye bye = NetGuestBye::none;
    size = net_guest_write_bye(out, sizeof(out), NetGuestBye::kicked);
    check(size == 2 && net_guest_read_bye(out, size, &bye) && bye == NetGuestBye::kicked, "bye");
    out[1] = 0;
    check(!net_guest_read_bye(out, size, &bye), "bye without a reason");
    uint8_t port = 0;
    size = net_guest_write_port(out, sizeof(out), 2);
    check(size == 2 && out[0] == 78 && net_guest_read_port(out, size, &port) && port == 2, "port");
}

static void test_titles()
{
    struct Case
    {
        const char* name;
        const char* title;
    };
    const Case cases[] = {
        {"Teenage Mutant Ninja Turtles IV - Turtles in Time (USA)", "Teenage Mutant Ninja Turtles IV - Turtles in Time"},
        {"Tetris [!] (World)", "Tetris"},
        {"Legend of Zelda, The - Link's Awakening DX (USA, Europe) (Rev 2) (SGB Enhanced) (GB Compatible)",
         "Legend of Zelda, The - Link's Awakening DX"},
        {"Super_Mario_World", "Super Mario World"},
        {"(USA)", "A game"},
        {"  Kirby   (Japan)  [b1]  ", "Kirby"},
        {"ゼルダの伝説 (Japan)", "ゼルダの伝説"},
        {"Pokemon - Edicion Roja (Spain) (SGB Enhanced)", "Pokemon - Edicion Roja"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        char title[NET_GUEST_MAX_TITLE + 1];
        net_guest_title_clean(cases[i].name, title);
        if (std::strcmp(title, cases[i].title) != 0)
        {
            std::printf("     \"%s\" -> \"%s\"\n", cases[i].name, title);
            check(false, "a title cleaned");
        }
    }
    std::string long_name;
    for (int i = 0; i < 30; i++)
    {
        long_name += "ä";
    }
    char title[NET_GUEST_MAX_TITLE + 1];
    net_guest_title_clean(long_name.c_str(), title);
    check(std::strlen(title) == 60, "a long title cut at a UTF-8 boundary");
    net_guest_title_clean((long_name + "ab").c_str(), title);
    check(std::strlen(title) == 62, "and up to 64 bytes");
    net_guest_title_clean((long_name + "abcä").c_str(), title);
    check(std::strlen(title) == 63, "never through a character");
}

static void test_card()
{
    NetGuestLink link;
    net_guest_link_from_token(TOKEN, &link);
    std::vector<uint8_t> png(100, 7);
    std::vector<uint8_t> body;
    check(net_guest_card_body(&link, "Zelda", png.data(), png.size(), &body), "a card body");
    check(body.size() == 32 + 1 + 5 + 100 && std::memcmp(body.data(), link.card_key, 32) == 0 && body[32] == 5 &&
              std::memcmp(body.data() + 33, "Zelda", 5) == 0 && body[38] == 7,
          "card key, title, PNG");
    check(!net_guest_card_body(&link, "", png.data(), png.size(), &body), "no title");
    std::vector<uint8_t> big(NET_GUEST_CARD_MAX_PNG + 1, 0);
    check(!net_guest_card_body(&link, "Zelda", big.data(), big.size(), &body), "a PNG too big");
}

int main()
{
    test_derivations();
    test_links();
    test_messages();
    test_titles();
    test_card();
    if (g_failures == 0)
    {
        std::printf("net guest: all checks passed\n");
    }
    return g_failures == 0 ? 0 : 1;
}
