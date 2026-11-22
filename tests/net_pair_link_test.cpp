// Checks net_pair_link.h: a link round trip (key, default and other
// beacons), the bare fragment, and links that aren't one.
//
// Exit code 0 = all checks passed. Each failure is printed.

#include <cstdio>
#include <cstring>
#include <string>

#include "net_pair_link.h"

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
    NetKeypair key;
    net_keypair_generate(&key);

    std::string link = net_pair_link(key.public_key, nullptr);
    uint8_t read_key[NET_KEY_SIZE] = {};
    std::string beacon = "x";
    check(link.rfind(NET_PAIR_LINK_BASE, 0) == 0, "the link starts with the site's address");
    check(net_pair_link_parse(link.c_str(), read_key, &beacon) &&
              std::memcmp(read_key, key.public_key, NET_KEY_SIZE) == 0 && beacon.empty(),
          "round trip with the default beacon");

    link = net_pair_link(key.public_key, "beacon.example.org:55430");
    std::memset(read_key, 0, sizeof(read_key));
    check(net_pair_link_parse(link.c_str(), read_key, &beacon) &&
              std::memcmp(read_key, key.public_key, NET_KEY_SIZE) == 0 && beacon == "beacon.example.org:55430",
          "round trip with another beacon");

    std::string fragment = link.substr(link.find('#') + 1);
    check(net_pair_link_parse(fragment.c_str(), read_key, &beacon), "the part after '#' alone");

    check(!net_pair_link_parse("https://get-piccolo.app/pair/#k=nope", read_key, &beacon), "a bad key is refused");
    check(!net_pair_link_parse("", read_key, &beacon), "an empty text is refused");

    net_keypair_wipe(&key);
    if (g_failures == 0)
    {
        std::printf("net pair link: all checks passed\n");
        return 0;
    }
    return 1;
}
