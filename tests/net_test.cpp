// Checks the network layer:
//   - discovery packets (net_discovery): round trips, malformed packets
//     refused;
//   - net_host over loopback: a listener on a free port answers a client's
//     discovery request with its name (a long UTF-8 name cut cleanly) and port, ignores garbage on the same
//     socket, accepts an ENet connection and gets a message on each channel.
// Broadcast isn't checked here (whether 255.255.255.255 reaches loopback
// depends on the machine); tools/net_probe.cpp checks it on a real LAN.
//
// Exit code 0 = all checks passed. Each failure is printed.

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include <enet.h>

#include "net_discovery.h"
#include "net_host.h"
#include "net_memory.h"
#include "net_access.h"
#include "net_client.h"
#include "net_session.h"
#include "net_trust.h"
#include "host_fs.h"

static int g_failures = 0;

static void check(bool condition, const char* what)
{
    if (!condition)
    {
        std::printf("FAIL %s\n", what);
        g_failures++;
    }
}

// The levels, the message ranges and the names in the device list.
// Pairing codes: nine digits, all of them random (the first three are the
// beacon slot: always 000 would put every pairing in one room).
static void test_pair_codes()
{
    bool valid = true;
    bool slots_vary = false;
    char first_slot[NET_PAIR_SLOT_DIGITS + 1] = {};
    for (int32_t i = 0; i < 64; i++)
    {
        char code[NET_PAIR_CODE_DIGITS + 1];
        valid = valid && net_pair_code_generate(code) && net_pair_code_valid(code);
        if (i == 0)
        {
            std::memcpy(first_slot, code, NET_PAIR_SLOT_DIGITS);
        }
        else if (std::memcmp(first_slot, code, NET_PAIR_SLOT_DIGITS) != 0)
        {
            slots_vary = true;
        }
    }
    check(valid, "codes are 9 digits");
    check(slots_vary, "the slot digits are random too");
}

static NetDeviceInfo make_info(const char* name, NetAppKind kind, NetCaps offers, NetCaps uses)
{
    NetDeviceInfo info;
    net_device_info_set_name(&info, name);
    info.kind = kind;
    info.offers = offers;
    info.uses = uses;
    return info;
}

// Capabilities: independent bits, the message ranges, their names, the old
// ladder's migration, and the messages that carry them.
static void test_caps()
{
    check(net_message_required_cap(16) == NET_CAP_GAMEPAD && net_message_required_cap(63) == NET_CAP_GAMEPAD,
          "16..63 need GAMEPAD");
    check(net_message_required_cap(64) == NET_CAP_STREAM && net_message_required_cap(127) == NET_CAP_STREAM,
          "64..127 need STREAM");
    check(net_message_required_cap(128) == NET_CAP_SETTINGS && net_message_required_cap(191) == NET_CAP_SETTINGS,
          "128..191 need SETTINGS");
    check(net_message_required_cap(NET_MESSAGE_FIRST_SHARE) == NET_CAP_SHARE && net_message_required_cap(255) == NET_CAP_SHARE,
          "192..255 need SHARE");
    check(!net_caps_allow(NET_CAP_STREAM, 16), "STREAM doesn't imply GAMEPAD (independent bits)");
    check(net_caps_allow(NET_CAP_GAMEPAD, NET_MESSAGE_FIRST_ACTION) && net_caps_allow(NET_CAP_STREAM, 18) &&
              net_caps_allow(NET_CAP_SETTINGS, NET_MESSAGE_LAST_ACTION),
          "the action messages (17..19) pass with any of GAMEPAD, STREAM or SETTINGS");
    check(!net_caps_allow(NET_CAP_SHARE, NET_MESSAGE_FIRST_ACTION) && !net_caps_allow(0, 18) &&
              !net_caps_allow(NET_CAP_STREAM, NET_MESSAGE_FIRST_ACTION - 1) &&
              !net_caps_allow(NET_CAP_STREAM, NET_MESSAGE_LAST_ACTION + 1),
          "SHARE or nothing doesn't pass them, and 16 and 20 still need GAMEPAD");
    check(!net_caps_allow(NET_CAP_SETTINGS, NET_MESSAGE_FIRST_SHARE), "SETTINGS doesn't include SHARE");
    check(net_caps_allow(NET_CAP_GAMEPAD | NET_CAP_SHARE, 200) && !net_caps_allow(NET_CAP_GAMEPAD | NET_CAP_SHARE, 130),
          "a set allows exactly its bits");
    check(net_caps_allow(NET_CAPS_ALL, 16) && net_caps_allow(NET_CAPS_ALL, 70) && net_caps_allow(NET_CAPS_ALL, 130) &&
              net_caps_allow(NET_CAPS_ALL, 250),
          "all four allow every range");

    check(net_caps_name(NET_CAP_SHARE | NET_CAP_SETTINGS) == "settings,share", "names in bit order");
    check(net_caps_name(0).empty(), "nothing is an empty list");
    NetCaps parsed = 0;
    check(net_caps_parse("share, gamepad", &parsed) && parsed == (NET_CAP_SHARE | NET_CAP_GAMEPAD), "a list parses");
    check(net_caps_parse("", &parsed) && parsed == 0, "an empty list is nothing");
    parsed = NET_CAP_STREAM;
    check(!net_caps_parse("gamepad,boss", &parsed) && parsed == NET_CAP_STREAM, "an unknown name refuses the list");
    NetCaps old = 0;
    check(net_caps_from_level("gamepad", &old) && old == NET_CAP_GAMEPAD, "old gamepad: GAMEPAD");
    check(net_caps_from_level("stream", &old) && old == (NET_CAP_GAMEPAD | NET_CAP_STREAM), "old stream: + GAMEPAD");
    check(net_caps_from_level("share", &old) && old == (NET_CAP_GAMEPAD | NET_CAP_STREAM | NET_CAP_SHARE),
          "old share: the levels below it + SHARE (not SETTINGS)");
    check(net_caps_from_level("full", &old) && old == NET_CAPS_ALL, "old full: everything");
    check(net_caps_from_level("owner", &old) && old == NET_CAPS_ALL, "old owner: everything");
    check(!net_caps_from_level("boss", &old), "an unknown level isn't one");
    NetAppKind kind = NetAppKind::piccolo;
    check(net_app_kind_parse("piccolino", &kind) && kind == NetAppKind::piccolino &&
              std::strcmp(net_app_kind_name(NetAppKind::piccoletto), "piccoletto") == 0,
          "kinds by name");

    NetDeviceInfo host = make_info("HOST", NetAppKind::piccolino, NET_CAP_SHARE | NET_CAP_SETTINGS, 0);
    const char* record = "app=piccolino\nversion=0.4.0\n";
    std::memcpy(host.record, record, std::strlen(record));
    host.record_size = static_cast<uint16_t>(std::strlen(record));
    host.signature_size = 3;
    std::memcpy(host.signature, "sig", 3);
    uint8_t message[NET_PAIR_MAX_MESSAGE] = {};
    size_t size = net_message_write_welcome(message, sizeof(message), NET_CAP_SHARE, &host);
    NetCaps told = 0;
    NetDeviceInfo read;
    check(size > 0 && net_message_read_welcome(message, size, &told, &read) && told == NET_CAP_SHARE &&
              std::strcmp(read.name, "HOST") == 0 && read.kind == NetAppKind::piccolino &&
              read.offers == (NET_CAP_SHARE | NET_CAP_SETTINGS) && read.record_size == host.record_size &&
              std::memcmp(read.record, record, host.record_size) == 0 && read.signature_size == 3,
          "welcome carries the caps and the host's info (build proof included)");
    message[1] = 0x10;   // a bit past the four
    check(!net_message_read_welcome(message, size, &told, &read), "welcome with an unknown bit refused");
    size = net_message_write_hello(message, sizeof(message), &host);
    check(size > 0 && net_message_read_hello(message, size, &read) && std::strcmp(read.name, "HOST") == 0, "hello round trip");
    check(!net_message_read_hello(message, size - 1, &read), "hello cut short refused");
    message[1 + 1 + 4] = 9;   // the kind byte, after the name
    check(!net_message_read_hello(message, size, &read), "hello with an unknown kind refused");
    // A name with a line break and a control byte (written raw, as a hostile
    // device would) reads clean; UTF-8 stays.
    std::snprintf(host.name, sizeof(host.name), "Bad\nName\x01" "end \xC3\xA9");
    size = net_message_write_hello(message, sizeof(message), &host);
    check(size > 0 && net_message_read_hello(message, size, &read) && std::strcmp(read.name, "Bad_Name_end \xC3\xA9") == 0,
          "hello name: line break and control byte replaced, UTF-8 kept");
    check(net_name_clean("a\r\nb").compare("a__b") == 0, "net_name_clean: CR LF");
    NetTrust key_trust;
    uint8_t key_a[NET_KEY_SIZE] = {};
    uint8_t key_b[NET_KEY_SIZE] = {};
    key_a[0] = 1;
    key_b[0] = 2;
    net_trust_add(&key_trust, key_a, "A");
    check(net_trust_has_key_id(&key_trust, key_a) && !net_trust_has_key_id(&key_trust, key_b),
          "net_trust_has_key_id: a trusted key's first bytes");
    size = net_message_write_grant(message, sizeof(message), NET_CAP_GAMEPAD | NET_CAP_STREAM);
    check(size == 5 && net_message_read_grant(message, size, &told) && told == (NET_CAP_GAMEPAD | NET_CAP_STREAM),
          "grant round trip");
    check(net_message_write_pair_ask(message, sizeof(message)) == 1 && net_message_read_pair_ask(message, 1), "pair_ask");
}

static void test_discovery_packets()
{
    uint8_t packet[NET_DISCOVERY_MAX_PACKET];
    uint32_t nonce = 0;

    size_t size = net_discovery_write_request(packet, sizeof(packet), 0xA1B2C3D4u);
    check(size == NET_DISCOVERY_REQUEST_SIZE, "request size");
    check(net_discovery_read_request(packet, size, &nonce) && nonce == 0xA1B2C3D4u, "request round trip");
    check(!net_discovery_read_request(packet, size - 1, &nonce), "short request refused");
    check(net_discovery_write_request(packet, NET_DISCOVERY_REQUEST_SIZE - 1, 1) == 0, "request: small buffer");

    packet[5] = NET_DISCOVERY_VERSION + 1;
    check(!net_discovery_read_request(packet, size, &nonce), "other version refused");
    packet[5] = 1;
    check(!net_discovery_read_request(packet, size, &nonce), "an old request isn't answered");
    net_discovery_write_request(packet, sizeof(packet), 7);
    packet[0] = 'X';
    check(!net_discovery_read_request(packet, size, &nonce), "bad magic refused");

    NetDiscoveryReply reply;
    reply.nonce = 42;
    reply.port = 55420;
    reply.kind = static_cast<uint8_t>(NetAppKind::piccolino);
    reply.offers = NET_CAP_SHARE | NET_CAP_SETTINGS;
    reply.signed_build = true;
    std::snprintf(reply.name, sizeof(reply.name), "Living room PC");
    // Version 3: carries the first 8 bytes of the key.
    for (uint32_t i = 0; i < NET_DISCOVERY_KEY_ID_SIZE; i++)
    {
        reply.key_id[i] = static_cast<uint8_t>(0xA0 + i);
    }
    reply.key_id_known = true;
    size = net_discovery_write_reply(packet, sizeof(packet), &reply);
    NetDiscoveryReply read;
    check(size == NET_DISCOVERY_V3_REPLY_HEADER_SIZE + std::strlen("Living room PC"), "reply size");
    check(net_discovery_read_reply(packet, size, &read), "reply round trip");
    check(read.nonce == 42 && read.port == 55420 && std::strcmp(read.name, "Living room PC") == 0, "reply fields");
    check(read.version == 3 && read.kind == static_cast<uint8_t>(NetAppKind::piccolino) &&
              read.offers == (NET_CAP_SHARE | NET_CAP_SETTINGS) && read.signed_build,
          "v3 reply: kind, offers, signed");
    check(read.key_id_known && std::memcmp(read.key_id, reply.key_id, NET_DISCOVERY_KEY_ID_SIZE) == 0,
          "v3 reply: the key id round trips");
    reply.key_id_known = false;
    size_t unknown_size = net_discovery_write_reply(packet, sizeof(packet), &reply);
    check(net_discovery_read_reply(packet, unknown_size, &read) && !read.key_id_known, "v3 without a key: not known");
    reply.key_id_known = true;
    uint8_t v3_packet[NET_DISCOVERY_MAX_PACKET];
    size_t v3_size = net_discovery_write_reply(v3_packet, sizeof(v3_packet), &reply);

    // A version 2 reply (the previous version), written and read: everything
    // but the key id, which it never has.
    reply.version = 2;
    size = net_discovery_write_reply(packet, sizeof(packet), &reply);
    check(size == NET_DISCOVERY_REPLY_HEADER_SIZE + std::strlen("Living room PC"), "v2 reply size");
    read = NetDiscoveryReply{};
    check(net_discovery_read_reply(packet, size, &read), "v2 reply read by the new reader");
    check(read.version == 2 && read.port == 55420 && std::strcmp(read.name, "Living room PC") == 0 &&
              read.kind == static_cast<uint8_t>(NetAppKind::piccolino) &&
              read.offers == (NET_CAP_SHARE | NET_CAP_SETTINGS) && read.signed_build && !read.key_id_known,
          "v2 reply: kind, offers, signed, no key id");
    // The v3 packet read "as far as v2": the same name, kind and offers.
    check(net_discovery_read_reply(v3_packet, v3_size, &read) && read.port == 55420 &&
              std::strcmp(read.name, "Living room PC") == 0 && read.kind == static_cast<uint8_t>(NetAppKind::piccolino) &&
              read.offers == (NET_CAP_SHARE | NET_CAP_SETTINGS),
          "v3 reply: the v2 fields are the same");
    // A version 1 reply (an older device): port and name only, still read.
    uint8_t old[NET_DISCOVERY_MAX_PACKET];
    std::memcpy(old, packet, 12);
    old[5] = 1;
    old[12] = 0x7C;
    old[13] = 0xD8;   // 55420
    old[14] = 3;
    std::memcpy(old + 15, "Old", 3);
    check(net_discovery_read_reply(old, 18, &read) && read.version == 1 && read.port == 55420 &&
              std::strcmp(read.name, "Old") == 0 && read.offers == 0 && !read.key_id_known,
          "v1 reply still read (no offers)");
    packet[19] = 2;
    check(!net_discovery_read_reply(packet, size, &read), "v2 reply with unknown flags refused");
    packet[19] = 1;
    v3_packet[19] = 4;
    check(!net_discovery_read_reply(v3_packet, v3_size, &read), "v3 reply with unknown flags refused");
    v3_packet[19] = 3;
    check(!net_discovery_read_reply(v3_packet, v3_size - 1, &read), "v3 reply with a wrong length refused");
    // A request stays version 2: the hosts of the previous version still answer it.
    uint8_t request[NET_DISCOVERY_REQUEST_SIZE];
    net_discovery_write_request(request, sizeof(request), 9);
    check(request[5] == 2, "requests are written as version 2");
    check(!net_discovery_read_request(packet, size, &nonce), "a reply is not a request");
    check(!net_discovery_read_reply(packet, size + 1, &read), "reply with a wrong length refused");
    packet[NET_DISCOVERY_REPLY_HEADER_SIZE + 3] = 0;
    check(!net_discovery_read_reply(packet, size, &read), "reply with a NUL in the name refused");

    // Names come off the wire clean: a line break and a control byte become '_'.
    NetDiscoveryReply dirty;
    std::snprintf(dirty.name, sizeof(dirty.name), "Bad\nName\x01!");
    size = net_discovery_write_reply(packet, sizeof(packet), &dirty);
    check(net_discovery_read_reply(packet, size, &read) && std::strcmp(read.name, "Bad_Name_!") == 0,
          "discovery name: line break and control byte replaced");

}

// Polls both hosts until `done` says so or two seconds pass.
struct Loopback
{
    NetHost listener;
    NetHost client;
    bool discovered = false;
    NetDiscoveryReply reply;
    bool client_connected = false;
    bool listener_connected = false;
    uint32_t listener_peer = NET_NO_PEER;
    bool got_control = false;
    bool got_input = false;
    bool client_disconnected = false;
    uint32_t unexpected = 0;
};

static void pump(Loopback* loop)
{
    NetEvent event;
    while (net_host_poll(&loop->listener, &event))
    {
        if (event.type == NetEventType::connected)
        {
            loop->listener_connected = true;
            loop->listener_peer = event.peer;
        }
        else if (event.type == NetEventType::received)
        {
            if (event.channel == NetChannel::control && event.size == 5 && std::memcmp(event.data, "hello", 5) == 0)
            {
                loop->got_control = true;
            }
            else if (event.channel == NetChannel::input && event.size == 3 && std::memcmp(event.data, "abc", 3) == 0)
            {
                loop->got_input = true;
            }
            else
            {
                loop->unexpected++;
            }
        }
        else if (event.type != NetEventType::disconnected)
        {
            loop->unexpected++;
        }
    }
    while (net_host_poll(&loop->client, &event))
    {
        if (event.type == NetEventType::discovered)
        {
            loop->discovered = true;
            loop->reply = event.discovered;
        }
        else if (event.type == NetEventType::connected)
        {
            loop->client_connected = true;
        }
        else if (event.type == NetEventType::disconnected)
        {
            loop->client_disconnected = true;
        }
        else
        {
            loop->unexpected++;
        }
    }
}

static bool pump_until(Loopback* loop, const bool* flag)
{
    for (int i = 0; i < 200 && !*flag; i++)
    {
        pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return *flag;
}

static void test_loopback()
{
    // 62 ASCII bytes, then "é" (2 bytes) and more: a cut at 63 bytes would
    // split the "é", so the name must stop at 62.
    char long_name[80];
    std::memset(long_name, 'a', 62);
    long_name[62] = static_cast<char>(0xC3);
    long_name[63] = static_cast<char>(0xA9);
    long_name[64] = 'b';
    long_name[65] = '\0';
    char cut_name[80];
    std::memcpy(cut_name, long_name, 62);
    cut_name[62] = '\0';

    Loopback loop;
    if (!net_host_create_listener(&loop.listener, 0, long_name))
    {
        check(false, "listener created");
        return;
    }
    check(net_host_create_client(&loop.client), "client created");
    uint16_t port = net_host_port(&loop.listener);
    check(port != 0, "listener has a port");

    NetAddress address;
    check(net_address_from_text("127.0.0.1", port, &address), "address from text");
    char text[64];
    net_address_to_text(address, text, sizeof(text));
    char expected[64];
    std::snprintf(expected, sizeof(expected), "127.0.0.1:%u", static_cast<unsigned>(port));
    check(std::strcmp(text, expected) == 0, "address to text");

    // Garbage and a reply nobody asked for, on the listener's socket: both
    // must be ignored (no event, no crash).
    ENetAddress to = {};
    std::memcpy(&to.host, address.ip, sizeof(address.ip));
    to.port = port;
    uint8_t garbage[] = {'M', 'T', 'A', 'P', 9, 9, 9};
    ENetBuffer buffer = {};
    buffer.data = garbage;
    buffer.dataLength = sizeof(garbage);
    enet_socket_send(loop.client.enet->socket, &to, &buffer, 1);
    uint8_t stray[NET_DISCOVERY_MAX_PACKET];
    NetDiscoveryReply stray_reply;
    stray_reply.nonce = 1;
    buffer.data = stray;
    buffer.dataLength = net_discovery_write_reply(stray, sizeof(stray), &stray_reply);
    enet_socket_send(loop.client.enet->socket, &to, &buffer, 1);

    check(net_host_discover_at(&loop.client, address), "discovery request sent");
    check(pump_until(&loop, &loop.discovered), "discovery reply received");
    check(std::strcmp(loop.reply.name, cut_name) == 0, "reply carries the name, cut before the UTF-8 sequence");
    check(loop.reply.port == port, "reply carries the port");
    check(loop.listener.discovery_requests_answered == 1, "listener answered once");

    uint32_t peer = NET_NO_PEER;
    check(net_host_connect(&loop.client, address, &peer), "connect started");
    check(pump_until(&loop, &loop.client_connected), "client connected");
    check(pump_until(&loop, &loop.listener_connected), "listener saw the connection");

    const uint8_t hello[] = {'h', 'e', 'l', 'l', 'o'};
    const uint8_t abc[] = {'a', 'b', 'c'};
    check(net_host_send(&loop.client, peer, NetChannel::control, hello, sizeof(hello)), "send on control");
    check(net_host_send(&loop.client, peer, NetChannel::input, abc, sizeof(abc)), "send on input");
    check(pump_until(&loop, &loop.got_control), "control message arrived");
    check(pump_until(&loop, &loop.got_input), "input message arrived");

    net_host_disconnect(&loop.listener, loop.listener_peer);
    check(pump_until(&loop, &loop.client_disconnected), "client saw the disconnect");
    check(loop.unexpected == 0, "no unexpected events");

    net_host_destroy(&loop.client);
    net_host_destroy(&loop.listener);
}

// IPv6: the text forms, and a connection over ::1 to the same dual-stack
// listener that IPv4 peers reach (zpl-c's ENet).
static void test_ipv6()
{
    NetAddress address;
    char text[64];
    check(net_address_from_text("2001:db8::5", 55420, &address), "IPv6 from text");
    net_address_to_text(address, text, sizeof(text));
    check(std::strcmp(text, "[2001:db8::5]:55420") == 0, "IPv6 to text, in brackets");
    check(!net_address_is_ipv4(address), "IPv6 isn't IPv4");
    NetAddress bracketed;
    check(net_address_from_text("[2001:db8::5]", 55420, &bracketed), "IPv6 in brackets from text");
    check(net_address_equal(address, bracketed), "brackets make no difference");
    check(net_address_from_text("192.168.1.20", 7, &address), "IPv4 from text");
    check(net_address_is_ipv4(address), "IPv4 is kept IPv4-mapped");
    net_address_to_text(address, text, sizeof(text));
    check(std::strcmp(text, "192.168.1.20:7") == 0, "IPv4 to text, plain");
    check(!net_address_from_text("[2001:db8::5", 1, &address), "a lone bracket is refused");

    Loopback loop;
    if (!net_host_create_listener(&loop.listener, 0, "V6"))
    {
        check(false, "listener created");
        return;
    }
    check(net_host_create_client(&loop.client), "client created");
    uint16_t port = net_host_port(&loop.listener);
    check(net_address_from_text("::1", port, &address), "::1 from text");
    check(net_host_discover_at(&loop.client, address), "discovery over IPv6 sent");
    check(pump_until(&loop, &loop.discovered), "discovery reply over IPv6");
    uint32_t peer = NET_NO_PEER;
    check(net_host_connect(&loop.client, address, &peer), "connect over IPv6 started");
    check(pump_until(&loop, &loop.client_connected), "client connected over IPv6");
    check(pump_until(&loop, &loop.listener_connected), "listener saw the IPv6 connection");
    NetAddress seen;
    check(net_host_peer_address(&loop.listener, loop.listener_peer, &seen), "listener knows the peer's address");
    net_address_to_text(seen, text, sizeof(text));
    check(std::strncmp(text, "[::1]:", 6) == 0, "the peer's address is ::1");
    const uint8_t hello[] = {'h', 'e', 'l', 'l', 'o'};
    check(net_host_send(&loop.client, peer, NetChannel::control, hello, sizeof(hello)), "send over IPv6");
    check(pump_until(&loop, &loop.got_control), "message arrived over IPv6");
    check(loop.unexpected == 0, "no unexpected events over IPv6");
    net_host_destroy(&loop.client);
    net_host_destroy(&loop.listener);
}

struct SessionLoop
{
    NetSession listener;
    NetSession client;
    NetKeypair listener_key;
    NetKeypair client_key;
    bool listener_secured = false;
    bool client_secured = false;
    uint32_t listener_peer = NET_NO_PEER;
    uint8_t listener_saw_key[NET_KEY_SIZE] = {};
    uint8_t client_saw_key[NET_KEY_SIZE] = {};
    uint8_t listener_hash[NET_HASH_SIZE] = {};
    uint8_t client_hash[NET_HASH_SIZE] = {};
    bool listener_got_control = false;
    bool listener_got_input = false;
    uint32_t listener_files_bytes = 0;   // file chunks received (all 0xF1)
    bool client_got_control = false;
    bool client_closed = false;
    bool listener_closed_unsecured = false;
};

static void session_pump(SessionLoop* loop)
{
    NetSessionEvent event;
    while (net_session_poll(&loop->listener, &event))
    {
        if (event.type == NetSessionEventType::secured)
        {
            loop->listener_secured = true;
            loop->listener_peer = event.peer;
            std::memcpy(loop->listener_saw_key, event.remote_key, NET_KEY_SIZE);
            std::memcpy(loop->listener_hash, event.handshake_hash, NET_HASH_SIZE);
        }
        else if (event.type == NetSessionEventType::message)
        {
            if (event.channel == NetChannel::control && event.size == 4 && std::memcmp(event.data, "ping", 4) == 0)
            {
                loop->listener_got_control = true;
                const uint8_t pong[] = {'p', 'o', 'n', 'g'};
                net_session_send(&loop->listener, event.peer, NetChannel::control, pong, sizeof(pong));
            }
            else if (event.channel == NetChannel::input && event.size == 2 && event.data[0] == 7)
            {
                loop->listener_got_input = true;
            }
            else if (event.channel == NetChannel::files && event.size > 0 && event.data[0] == 0xF1)
            {
                loop->listener_files_bytes += static_cast<uint32_t>(event.size);
            }
        }
        else if (event.type == NetSessionEventType::closed && !event.was_secured)
        {
            loop->listener_closed_unsecured = true;
        }
    }
    while (net_session_poll(&loop->client, &event))
    {
        if (event.type == NetSessionEventType::secured)
        {
            loop->client_secured = true;
            std::memcpy(loop->client_saw_key, event.remote_key, NET_KEY_SIZE);
            std::memcpy(loop->client_hash, event.handshake_hash, NET_HASH_SIZE);
        }
        else if (event.type == NetSessionEventType::message && event.channel == NetChannel::control &&
                 event.size == 4 && std::memcmp(event.data, "pong", 4) == 0)
        {
            loop->client_got_control = true;
        }
        else if (event.type == NetSessionEventType::closed)
        {
            loop->client_closed = true;
        }
    }
}

static bool session_pump_until(SessionLoop* loop, const bool* flag)
{
    for (int i = 0; i < 300 && !*flag; i++)
    {
        session_pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return *flag;
}

static void test_session()
{
    SessionLoop* loop = new SessionLoop();
    net_keypair_generate(&loop->listener_key);
    net_keypair_generate(&loop->client_key);
    loop->listener.handshake_seconds = 0.5;
    check(net_session_create_listener(&loop->listener, 0, "session test", &loop->listener_key), "session listener");
    check(net_session_create_client(&loop->client, &loop->client_key), "session client");
    NetAddress address;
    net_address_from_text("127.0.0.1", net_host_port(&loop->listener.host), &address);

    uint32_t peer = NET_NO_PEER;
    check(net_session_connect(&loop->client, address, &peer), "session connect");
    check(session_pump_until(loop, &loop->client_secured), "client secured");
    check(session_pump_until(loop, &loop->listener_secured), "listener secured");
    check(std::memcmp(loop->client_saw_key, loop->listener_key.public_key, NET_KEY_SIZE) == 0,
          "client learned the listener's device key");
    check(std::memcmp(loop->listener_saw_key, loop->client_key.public_key, NET_KEY_SIZE) == 0,
          "listener learned the client's device key");
    check(std::memcmp(loop->client_hash, loop->listener_hash, NET_HASH_SIZE) == 0, "same handshake hash");

    const uint8_t ping[] = {'p', 'i', 'n', 'g'};
    const uint8_t input[] = {7, 1};
    check(net_session_send(&loop->client, peer, NetChannel::control, ping, sizeof(ping)), "send ping");
    check(net_session_send(&loop->client, peer, NetChannel::input, input, sizeof(input)), "send input");
    check(session_pump_until(loop, &loop->listener_got_control), "ping arrived (decrypted)");
    check(session_pump_until(loop, &loop->listener_got_input), "input arrived (decrypted)");
    check(session_pump_until(loop, &loop->client_got_control), "pong came back");

    // The files channel: reliable, its own nonces. 8 chunks of 16 KiB: what
    // ENet still has for that peer shows in net_host_peer_pending, and goes
    // back to 0 once everything is acknowledged.
    static uint8_t chunk[16 * 1024];
    std::memset(chunk, 0xF1, sizeof(chunk));
    bool files_sent = true;
    for (int i = 0; i < 8; i++)
    {
        files_sent = files_sent && net_session_send(&loop->client, peer, NetChannel::files, chunk, sizeof(chunk));
    }
    check(files_sent, "chunks sent on files");
    check(net_host_peer_pending(&loop->client.host, peer) >= 8 * sizeof(chunk), "pending counts what's queued");
    bool files_done = false;
    for (int i = 0; i < 400 && !files_done; i++)
    {
        session_pump(loop);
        files_done = loop->listener_files_bytes == 8 * sizeof(chunk) && net_host_peer_pending(&loop->client.host, peer) == 0;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    check(loop->listener_files_bytes == 8 * sizeof(chunk), "every chunk arrived (decrypted, in order)");
    check(net_host_peer_pending(&loop->client.host, peer) == 0, "pending back to 0 once acknowledged");

    // The frame loop must not allocate: like a game sending input every frame,
    // both ways. Warmed up, a round of 1000 packets each way takes nothing from
    // the system. On a busy machine (or under ASan) more packets can be in
    // flight at once in a later round than in the first, which takes a block
    // more, once: so rounds go on (up to 5) until one takes none.
    uint8_t frame_input[48] = {7, 1};
    uint64_t taken = 1;
    int rounds = 0;
    for (int round = 0; round < 5 && taken > 0; round++)
    {
        uint64_t before = net_memory_stats().system_allocations;
        for (int frame = 0; frame < 1000; frame++)
        {
            net_session_send(&loop->client, peer, NetChannel::input, frame_input, sizeof(frame_input));
            net_session_send(&loop->listener, loop->listener_peer, NetChannel::input, frame_input, sizeof(frame_input));
            session_pump(loop);
        }
        for (int i = 0; i < 20; i++)
        {
            session_pump(loop);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        taken = round == 0 ? 1 : net_memory_stats().system_allocations - before;   // the first only warms up
        rounds = round + 1;
    }
    char what[128];
    std::snprintf(what, sizeof(what),
                  "warmed up: a round of 1000 input packets each way takes no blocks from the system (%d rounds)",
                  rounds);
    check(taken == 0, what);
    check(net_memory_stats().reused > 4000, "ENet's memory is being reused");

    // A plain ENet client (no handshake) and one that sends garbage as its
    // first handshake message: the listener closes both, never secured.
    NetHost raw;
    net_host_create_client(&raw);
    uint32_t raw_peer = NET_NO_PEER;
    net_host_connect(&raw, address, &raw_peer);
    bool raw_closed = false;
    bool raw_connected = false;
    for (int i = 0; i < 300 && !raw_closed; i++)
    {
        session_pump(loop);
        NetEvent event;
        while (net_host_poll(&raw, &event))
        {
            if (event.type == NetEventType::connected)
            {
                raw_connected = true;
            }
            else if (event.type == NetEventType::disconnected)
            {
                raw_closed = true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    check(raw_connected && raw_closed, "a peer without a handshake is closed after the deadline");
    check(session_pump_until(loop, &loop->listener_closed_unsecured), "listener reported it closed, never secured");

    loop->listener_closed_unsecured = false;
    net_host_connect(&raw, address, &raw_peer);
    raw_closed = false;
    bool sent_garbage = false;
    for (int i = 0; i < 300 && !raw_closed; i++)
    {
        session_pump(loop);
        NetEvent event;
        while (net_host_poll(&raw, &event))
        {
            if (event.type == NetEventType::connected && !sent_garbage)
            {
                uint8_t garbage[40] = {1, 2, 3};
                net_host_send(&raw, event.peer, NetChannel::control, garbage, 10);   // too short for "e"
                sent_garbage = true;
            }
            else if (event.type == NetEventType::disconnected)
            {
                raw_closed = true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    check(sent_garbage && raw_closed, "a peer sending a bad handshake is closed");
    net_host_destroy(&raw);

    net_session_close(&loop->client, peer);
    check(session_pump_until(loop, &loop->client_closed), "client closed");
    net_session_destroy(&loop->client);
    net_session_destroy(&loop->listener);
    delete loop;
}

struct PairLoop
{
    NetAccess host;
    NetClient client;
    NetClientEvent client_event;   // the last outcome (ready / refused)
    bool client_got = false;
    NetAccessEventType host_last = NetAccessEventType::none;
    uint32_t host_events = 0;
    bool host_got_message = false;
    bool host_got_stream_message = false;
    uint8_t host_last_key[NET_KEY_SIZE] = {};   // the key of the last pad packet's event
    bool host_got_pad_packet = false;   // an input-channel packet of 2 bytes {5, 'p'} reached the frontend
    bool client_got_message = false;
    bool client_got_caps = false;
    bool client_closed = false;
    bool client_unpaired = false;
    bool host_unpaired = false;
    std::string host_unpaired_name;
    bool host_paired = false;
    bool host_got_granted = false;
    NetCaps host_granted = 0;
    bool host_code_expired = false;
    // The host's user, played by the test: sees each request's code (and may
    // change the ticks, or refuse).
    bool host_refuses = false;
    bool host_sets_grants = false;
    NetCaps host_grants = 0;
    uint32_t host_requests = 0;
    uint32_t host_retries = 0;
    NetAccessEvent host_request;     // the last pairing_requested
    bool host_request_fresh = false; // its code not typed yet
    // The client's user: types the code the host shows (the request's, or the
    // shown one), mistyping the first `client_mistypes`; or doesn't type.
    bool client_types = true;
    uint32_t client_mistypes = 0;
    uint32_t client_code_needed = 0;
    uint32_t client_retries = 0;
    NetClientEvent client_code_event;
};

static void wrong_code(const char* code, char* out)
{
    std::snprintf(out, NET_PAIR_CODE_DIGITS + 1, "%s", code);
    out[8] = out[8] == '9' ? '0' : static_cast<char>(out[8] + 1);   // the last digit: the slot stays
}

static void pair_pump(PairLoop* loop)
{
    NetAccessEvent host_event;
    while (net_access_poll(&loop->host, &host_event))
    {
        loop->host_last = host_event.type;
        loop->host_events++;
        if (host_event.type == NetAccessEventType::pairing_requested)
        {
            loop->host_requests++;
            loop->host_retries += host_event.retry ? 1 : 0;
            loop->host_request = host_event;
            loop->host_request_fresh = true;
            if (loop->host_refuses)
            {
                net_access_refuse_pairing(&loop->host, host_event.peer);
            }
            else if (loop->host_sets_grants)
            {
                net_access_set_pairing_grants(&loop->host, host_event.peer, loop->host_grants);
            }
        }
        if (host_event.type == NetAccessEventType::paired)
        {
            loop->host_paired = true;
        }
        if (host_event.type == NetAccessEventType::granted)
        {
            loop->host_got_granted = true;
            loop->host_granted = host_event.caps;
        }
        if (host_event.type == NetAccessEventType::code_expired)
        {
            loop->host_code_expired = true;
        }
        if (host_event.type == NetAccessEventType::unpaired)
        {
            loop->host_unpaired = true;
            loop->host_unpaired_name = host_event.info.name;
        }
        if (host_event.type == NetAccessEventType::message && host_event.channel == NetChannel::input &&
            host_event.size == 2 && host_event.data[0] == 5 && host_event.data[1] == 'p')
        {
            loop->host_got_pad_packet = true;
            std::memcpy(loop->host_last_key, host_event.key, NET_KEY_SIZE);
        }
        if (host_event.type == NetAccessEventType::message && host_event.channel == NetChannel::control &&
            host_event.size == 2 && host_event.data[0] == NET_MESSAGE_FIRST_STREAM)
        {
            loop->host_got_stream_message = true;
        }
        if (host_event.type == NetAccessEventType::message && host_event.channel == NetChannel::control &&
            host_event.size == 2 && host_event.data[0] == NET_MESSAGE_FIRST_APP && host_event.data[1] == 'x')
        {
            loop->host_got_message = true;
            const uint8_t reply[] = {9, 9, 9};
            net_access_send(&loop->host, host_event.peer, NetChannel::input, reply, sizeof(reply));
        }
    }
    NetClientEvent event;
    while (net_client_poll(&loop->client, &event))
    {
        if (event.type == NetClientEventType::message && event.channel == NetChannel::input && event.size == 3)
        {
            loop->client_got_message = true;
        }
        else if (event.type == NetClientEventType::closed)
        {
            loop->client_closed = true;
        }
        else if (event.type == NetClientEventType::caps)
        {
            loop->client_got_caps = true;
        }
        else if (event.type == NetClientEventType::unpaired)
        {
            loop->client_unpaired = true;
        }
        else if (event.type == NetClientEventType::code_needed)
        {
            loop->client_code_needed++;
            loop->client_retries += event.retry ? 1 : 0;
            loop->client_code_event = event;
        }
        else
        {
            loop->client_event = event;
            loop->client_got = true;
        }
    }
    // The client's user types what the host's screen shows, once it's asked.
    // (Like a person, only a code that's on the screen now: after a wrong one,
    // the request's new code.)
    if (loop->client_types && loop->client.state == NetClientState::code_wait &&
        (loop->host.showing || loop->host_request_fresh))
    {
        const char* shown = loop->host.showing ? loop->host.shown_code : loop->host_request.code;
        loop->host_request_fresh = false;
        if (net_pair_code_valid(shown))
        {
            char typed[NET_PAIR_CODE_DIGITS + 1];
            std::snprintf(typed, sizeof(typed), "%s", shown);
            if (loop->client_mistypes > 0)
            {
                wrong_code(shown, typed);
                loop->client_mistypes--;
            }
            net_client_enter_code(&loop->client, typed);
        }
    }
}

// Connects and waits for the client's outcome.
static NetClientEvent pair_attempt(PairLoop* loop, NetAddress address, bool pair)
{
    loop->client_got = false;
    loop->client_event = {};
    loop->host_request = {};
    loop->host_request_fresh = false;
    if (!net_client_connect(&loop->client, address, pair))
    {
        check(false, "client connect started");
        return loop->client_event;
    }
    for (int i = 0; i < 300 && !loop->client_got; i++)
    {
        pair_pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return loop->client_event;
}

static void pump_for(PairLoop* loop, int milliseconds)
{
    for (int i = 0; i < milliseconds / 10; i++)
    {
        pair_pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// Closes the client's connection and waits until both sides saw it close (a
// new connection right away can meet the old one still closing).
static void close_and_wait(PairLoop* loop)
{
    loop->client_closed = false;
    loop->host_last = NetAccessEventType::none;
    net_client_close(&loop->client);
    for (int i = 0; i < 300 && !(loop->client_closed && loop->host_last == NetAccessEventType::closed); i++)
    {
        pair_pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    pump_for(loop, 100);
}

static void pump_while(PairLoop* loop, const bool* flag, bool want)
{
    for (int i = 0; i < 200 && *flag != want; i++)
    {
        pair_pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// The build check the frontend provides: a record reading "signed" passes.
static bool test_verify_build(void* user, const NetDeviceInfo* info)
{
    (void)user;
    return info->record_size == 6 && std::memcmp(info->record, "signed", 6) == 0;
}

static NetTrustedDevice* host_record(PairLoop* loop, uint32_t index)
{
    return index < loop->host.trust.devices.size() ? &loop->host.trust.devices[index] : nullptr;
}

static void test_trust_files(const char* folder)
{
    // Old lists migrate: the ladder's names become the sets they covered.
    std::string old_list = std::string(folder) + "/old_devices.cfg";
    const char* old_text = "[device:0101010101010101010101010101010101010101010101010101010101010101]\nname = A\nown = true\n"
                           "[device:0202020202020202020202020202020202020202020202020202020202020202]\nname = B\n"
                           "[device:0303030303030303030303030303030303030303030303030303030303030303]\nname = C\naccess = share\n"
                           "[device:0404040404040404040404040404040404040404040404040404040404040404]\nname = D\naccess = stream\n";
    host_fs_write_file(old_list.c_str(), old_text, std::strlen(old_text));
    NetTrust old_trust;
    net_trust_load(&old_trust, old_list.c_str());
    check(old_trust.devices.size() == 4 && old_trust.devices[0].grants == NET_CAPS_ALL &&
              old_trust.devices[1].grants == 0 &&
              old_trust.devices[2].grants == (NET_CAP_GAMEPAD | NET_CAP_STREAM | NET_CAP_SHARE) &&
              old_trust.devices[3].grants == (NET_CAP_GAMEPAD | NET_CAP_STREAM),
          "old lists migrate: own -> all, nothing -> nothing, share and stream -> what they covered");
    check(net_trust_save(&old_trust, old_list.c_str()), "a migrated list saves");
    NetTrust saved;
    net_trust_load(&saved, old_list.c_str());
    check(saved.devices.size() == 4 && saved.devices[2].grants == (NET_CAP_GAMEPAD | NET_CAP_STREAM | NET_CAP_SHARE),
          "and reads back as grants");
    std::string text;
    uint8_t* bytes = nullptr;
    size_t byte_count = 0;
    if (host_fs_read_file(old_list.c_str(), &bytes, &byte_count))
    {
        text.assign(reinterpret_cast<const char*>(bytes), byte_count);
        delete[] bytes;
    }
    check(text.find("access") == std::string::npos && text.find("grants = gamepad,stream,share") != std::string::npos,
          "saved with grants, no access key");

    // One record per device: the old hosts list merges in, then is renamed.
    std::string devices = std::string(folder) + "/merge_devices.cfg";
    std::string hosts = std::string(folder) + "/merge_hosts.cfg";
    const char* devices_text = "[device:0101010101010101010101010101010101010101010101010101010101010101]\nname = A\n"
                               "grants = gamepad\n";
    const char* hosts_text = "[device:0101010101010101010101010101010101010101010101010101010101010101]\nname = A\n"
                             "access = gamepad\n"
                             "[device:0505050505050505050505050505050505050505050505050505050505050505]\nname = E\n"
                             "access = gamepad\n";
    host_fs_write_file(devices.c_str(), devices_text, std::strlen(devices_text));
    host_fs_write_file(hosts.c_str(), hosts_text, std::strlen(hosts_text));
    std::remove((hosts + ".old").c_str());
    NetTrust merged;
    net_trust_load(&merged, devices.c_str());
    check(net_trust_merge_old_hosts(&merged, devices.c_str(), hosts.c_str()), "the old hosts list merges");
    check(merged.devices.size() == 2 && merged.devices[0].grants == NET_CAP_GAMEPAD && merged.devices[1].name == "E" &&
              merged.devices[1].grants == 0,
          "a device in both keeps its record; a host only we went to may use nothing here");
    check(!host_fs_exists(hosts.c_str()) && host_fs_exists((hosts + ".old").c_str()), "the old file is renamed .old");
    net_trust_load(&saved, devices.c_str());
    check(saved.devices.size() == 2, "the merged list is saved");
}

static void test_pairing(const char* folder)
{
    std::string host_trust = std::string(folder) + "/host_devices.cfg";
    std::string client_trust = std::string(folder) + "/client_devices.cfg";
    std::string identity_path = std::string(folder) + "/identity.cfg";
    std::remove(host_trust.c_str());
    std::remove(client_trust.c_str());
    std::remove(identity_path.c_str());

    NetKeypair host_key;
    NetKeypair client_key;
    check(net_identity_load_or_create(identity_path.c_str(), &host_key), "identity created");
    NetKeypair again;
    check(net_identity_load_or_create(identity_path.c_str(), &again), "identity loaded");
    check(std::memcmp(host_key.public_key, again.public_key, NET_KEY_SIZE) == 0, "the same identity comes back");
    net_keypair_generate(&client_key);

    // A piccolo (offers everything, uses FILE TRANSFER and SETTINGS) and a
    // piccoletto (offers nothing, uses GAMEPAD, STREAM and SETTINGS).
    NetDeviceInfo host_info = make_info("Living room", NetAppKind::piccolo, NET_CAPS_ALL,
                                        NET_CAP_SHARE | NET_CAP_SETTINGS);
    NetDeviceInfo client_info = make_info("Ana's phone", NetAppKind::piccoletto, 0,
                                          NET_CAP_GAMEPAD | NET_CAP_STREAM | NET_CAP_SETTINGS);
    PairLoop* loop = new PairLoop();
    check(net_access_create(&loop->host, 0, &host_info, &host_key, host_trust.c_str()), "access host created");
    check(net_client_create(&loop->client, &client_key, &client_info, client_trust.c_str()), "client created");
    net_access_set_verify_build(&loop->host, test_verify_build, nullptr);
    net_client_set_verify_build(&loop->client, test_verify_build, nullptr);
    NetAddress address;
    net_address_from_text("127.0.0.1", net_host_port(&loop->host.session.host), &address);

    NetClientEvent result = pair_attempt(loop, address, false);
    check(result.type == NetClientEventType::refused && result.refusal == NetClientRefusal::not_paired,
          "not paired, not asking: refused (not_paired)");

    // The host's user refuses: refused, and that device isn't asked about again.
    loop->host_refuses = true;
    result = pair_attempt(loop, address, true);
    check(result.type == NetClientEventType::refused && result.refusal == NetClientRefusal::refused,
          "the host refuses: refused (refused)");
    check(loop->host_requests == 1 && std::strcmp(loop->host_request.info.name, "Ana's phone") == 0 &&
              loop->host_request.info.kind == NetAppKind::piccoletto && net_pair_code_valid(loop->host_request.code),
          "the host saw the request: the device's name and kind, and a code of its own to show");
    result = pair_attempt(loop, address, true);
    check(result.type == NetClientEventType::refused && result.refusal == NetClientRefusal::pairing_closed &&
              loop->host_requests == 1,
          "refused once: not asked again (pairing_closed)");
    loop->host_refuses = false;
    loop->host.refused_keys.clear();   // as a new NetAccess (restart) would be

    // Nobody types: the request waits, with the default ticks; going away closes it.
    loop->client_types = false;
    loop->client_got = false;
    loop->client_code_needed = 0;
    check(net_client_connect(&loop->client, address, true), "connect to pair");
    pump_for(loop, 400);
    check(!loop->client_got && loop->client_code_needed == 1 &&
              std::strcmp(loop->client_code_event.host.name, "Living room") == 0,
          "the client is asked for the code, with the host's name to show");
    check(loop->host_request.caps == (NET_CAP_GAMEPAD | NET_CAP_STREAM),
          "default ticks: what it uses and we offer, without SETTINGS for an unsigned build");
    check(!loop->host_request.signed_build, "an unsigned build is reported unsigned");
    net_client_close(&loop->client);
    pump_for(loop, 200);
    check(loop->host_last == NetAccessEventType::closed, "a request that goes: closed (the dialog closes)");
    loop->client_types = true;

    // Mistyped twice, then right: the host makes a new code each time; the
    // same connection pairs, with the ticks the host's user set.
    loop->client_mistypes = 2;
    loop->host_requests = 0;
    loop->host_retries = 0;
    loop->client_retries = 0;
    loop->host_sets_grants = true;
    loop->host_grants = NET_CAP_GAMEPAD | NET_CAP_SETTINGS | NET_CAP_SHARE;   // SHARE: not something it uses
    result = pair_attempt(loop, address, true);
    check(result.type == NetClientEventType::ready && result.newly_paired, "right code at the third try: paired");
    check(loop->host_retries == 2 && loop->host_requests == 3 && loop->client_retries == 2,
          "two wrong codes: two new codes on the host, the client asked twice more");
    check(result.caps == (NET_CAP_GAMEPAD | NET_CAP_SETTINGS) && loop->client.caps == result.caps,
          "the client may use what the host's user ticked, kept to what it uses");
    check(std::strcmp(result.host.name, "Living room") == 0 && result.host.kind == NetAppKind::piccolo &&
              result.host.offers == NET_CAPS_ALL,
          "the client knows the host's name, kind and offers");
    pump_for(loop, 100);
    check(loop->host_paired, "host reported the new device");
    NetTrustedDevice* record = host_record(loop, 0);
    check(loop->host.trust.devices.size() == 1 && record != nullptr && record->name == "Ana's phone" &&
              record->kind == NetAppKind::piccoletto && record->grants == (NET_CAP_GAMEPAD | NET_CAP_SETTINGS),
          "host keeps the device: name, kind, grants");
    check(record != nullptr && std::memcmp(record->key, client_key.public_key, NET_KEY_SIZE) == 0,
          "host trusts the client's key");
    check(loop->client.trust.devices.size() == 1 && loop->client.trust.devices[0].name == "Living room" &&
              loop->client.trust.devices[0].granted == (NET_CAP_GAMEPAD | NET_CAP_SETTINGS) &&
              loop->client.trust.devices[0].grants == 0,
          "client keeps the host: what it was granted, nothing granted back yet");
    loop->host_sets_grants = false;

    // The client's last screen: what the host may use on it, told at once.
    net_client_set_grants(&loop->client, 0, NET_CAP_SHARE);
    pump_while(loop, &loop->host_got_granted, true);
    check(loop->host_got_granted && loop->host_granted == NET_CAP_SHARE, "the host is told what it may use there");
    check(host_record(loop, 0) != nullptr && host_record(loop, 0)->granted == NET_CAP_SHARE,
          "and keeps it in the same record");
    NetTrust saved;
    net_trust_load(&saved, host_trust.c_str());
    check(saved.devices.size() == 1 && saved.devices[0].granted == NET_CAP_SHARE &&
              saved.devices[0].grants == (NET_CAP_GAMEPAD | NET_CAP_SETTINGS),
          "both directions on disk, one record");

    const uint8_t hello[] = {NET_MESSAGE_FIRST_APP, 'x'};
    check(net_client_send(&loop->client, NetChannel::control, hello, sizeof(hello)), "app message sent");
    pump_while(loop, &loop->client_got_message, true);
    check(loop->host_got_message && loop->client_got_message, "app messages both ways");
    const uint8_t sneaky[] = {static_cast<uint8_t>(NetMessage::welcome), 0};
    check(!net_client_send(&loop->client, NetChannel::control, sneaky, sizeof(sneaky)),
          "the app can't send pairing messages");

    // Reconnecting under a new name: the host's record follows it.
    net_client_close(&loop->client);
    pump_for(loop, 200);
    net_device_info_set_name(&loop->client.info, "ANA'S NEW PHONE");
    loop->host_got_granted = false;
    result = pair_attempt(loop, address, false);
    check(result.type == NetClientEventType::ready && !result.newly_paired, "paired device welcomed without pairing");
    check(result.caps == (NET_CAP_GAMEPAD | NET_CAP_SETTINGS), "welcomed with what it was given");
    pump_for(loop, 100);
    check(host_record(loop, 0) != nullptr && host_record(loop, 0)->name == "ANA'S NEW PHONE",
          "the device's new name replaces the old one");
    check(loop->host_got_granted && loop->host_granted == NET_CAP_SHARE, "its grant comes again at every connection");

    // A STREAM message without STREAM is dropped; given it, it goes through.
    const uint8_t stream_message[] = {NET_MESSAGE_FIRST_STREAM, 's'};
    check(net_client_send(&loop->client, NetChannel::control, stream_message, sizeof(stream_message)),
          "stream message sent");
    pump_for(loop, 200);
    check(!loop->host_got_stream_message && loop->host.dropped_by_access == 1, "no STREAM: stream message dropped");
    loop->client_got_caps = false;
    net_access_set_grants(&loop->host, 0, NET_CAPS_ALL);
    pump_while(loop, &loop->client_got_caps, true);
    check(loop->client_got_caps && loop->client.caps == (NET_CAP_GAMEPAD | NET_CAP_STREAM | NET_CAP_SETTINGS),
          "the client is told: everything granted, kept to what it uses (no SHARE)");
    net_client_send(&loop->client, NetChannel::control, stream_message, sizeof(stream_message));
    pump_while(loop, &loop->host_got_stream_message, true);
    check(loop->host_got_stream_message, "with STREAM: stream message delivered");
    net_trust_load(&saved, host_trust.c_str());
    check(saved.devices.size() == 1 && saved.devices[0].grants == NET_CAPS_ALL, "grants saved");

    // The input channel needs GAMEPAD too: a pad packet from a device granted
    // no GAMEPAD is dropped and counted; granted it, it goes through. The
    // message carries the device's key (the index may change under a reader).
    uint32_t dropped_before = loop->host.dropped_by_access;
    loop->client_got_caps = false;
    net_access_set_grants(&loop->host, 0, NET_CAP_SETTINGS | NET_CAP_STREAM);
    pump_while(loop, &loop->client_got_caps, true);
    const uint8_t pad_packet[] = {5, 'p'};
    loop->host_got_pad_packet = false;
    check(net_client_send(&loop->client, NetChannel::input, pad_packet, sizeof(pad_packet)), "pad packet sent");
    pump_for(loop, 200);
    check(!loop->host_got_pad_packet && loop->host.dropped_by_access == dropped_before + 1,
          "no GAMEPAD: pad packet dropped and counted");
    loop->client_got_caps = false;
    net_access_set_grants(&loop->host, 0, NET_CAPS_ALL);
    pump_while(loop, &loop->client_got_caps, true);
    net_client_send(&loop->client, NetChannel::input, pad_packet, sizeof(pad_packet));
    pump_while(loop, &loop->host_got_pad_packet, true);
    check(loop->host_got_pad_packet, "with GAMEPAD: pad packet delivered");
    check(std::memcmp(loop->host_last_key, client_key.public_key, NET_KEY_SIZE) == 0,
          "the message event carries the device's key");

    loop->client_closed = false;
    net_access_remove_device(&loop->host, 0);
    pump_while(loop, &loop->client_closed, true);
    check(loop->client_closed, "removing the device closes its connection");
    check(loop->client_unpaired && loop->client.trust.devices.empty(),
          "a connected device is told: it forgets the host too");
    pump_for(loop, 100);
    check(loop->host_last == NetAccessEventType::closed, "and the host reports it closed (its pads can go)");
    result = pair_attempt(loop, address, false);
    check(result.type == NetClientEventType::refused && result.refusal == NetClientRefusal::not_paired,
          "a removed device is refused");

    // A host that knows our key but whose key we don't know (an impostor
    // that copied the list, say): refused even though it welcomes us.
    NetTrust impostor;
    net_trust_add(&impostor, client_key.public_key, "Ana's phone");
    impostor.devices[0].grants = NET_CAP_GAMEPAD;
    net_trust_save(&impostor, host_trust.c_str());
    result = pair_attempt(loop, address, false);
    check(result.type == NetClientEventType::refused && result.refusal == NetClientRefusal::unknown_host,
          "unknown host refused");
    // Its connection closes first (the client closes it): both sides closing
    // at once leaves ENet peers stuck until they time out.
    pump_for(loop, 300);
    impostor.devices.clear();
    net_trust_save(&impostor, host_trust.c_str());
    pump_for(loop, 50);

    // GENERATE PAIRING CODE: the host shows a code first; the client types it
    // and pairs with no request, granted the shown ticks ∩ what it uses.
    char shown[NET_PAIR_CODE_DIGITS + 1];
    check(net_access_show_code(&loop->host, NET_CAPS_ALL, shown) && net_pair_code_valid(shown), "a code is shown");
    loop->host_requests = 0;
    result = pair_attempt(loop, address, true);
    check(result.type == NetClientEventType::ready && result.newly_paired, "the shown code pairs");
    check(loop->host_requests == 0, "no request dialog: the user already sees the code");
    check(!loop->host.showing, "one code, one device: it ends once a device paired with it");
    check(result.caps == (NET_CAP_GAMEPAD | NET_CAP_STREAM),
          "shown ticks ∩ what it uses, FILE TRANSFER and SETTINGS off for an unsigned build");
    close_and_wait(loop);

    // Unpairing from the client, connected: the host forgets it too.
    result = pair_attempt(loop, address, false);
    check(result.type == NetClientEventType::ready, "reconnected");
    pump_for(loop, 100);
    check(loop->host.trust.devices.size() == 1 && loop->client.trust.devices.size() == 1, "both lists have it");
    loop->client_closed = false;
    loop->host_unpaired = false;
    check(net_client_unpair(&loop->client, 0), "client unpairs");
    check(loop->client.trust.devices.empty(), "the client forgot the host at once");
    for (int i = 0; i < 200 && !(loop->host_unpaired && loop->host_last == NetAccessEventType::closed); i++)
    {
        pair_pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    check(loop->host_unpaired && loop->host_unpaired_name == "ANA'S NEW PHONE", "the host is told who unpaired");
    check(loop->host.trust.devices.empty(), "and forgets it");
    net_trust_load(&saved, host_trust.c_str());
    check(saved.devices.empty(), "the host's list on disk too");

    // A signed build: SETTINGS is ticked by default (only FILE TRANSFER is
    // what it doesn't use).
    const char* proof = "signed";
    std::memcpy(loop->client.info.record, proof, 6);
    loop->client.info.record_size = 6;
    loop->client_types = false;
    loop->host_request = {};
    check(net_client_connect(&loop->client, address, true), "a signed build asks");
    pump_for(loop, 300);
    check(loop->host_request.signed_build && loop->host_request.caps == (NET_CAP_GAMEPAD | NET_CAP_STREAM | NET_CAP_SETTINGS),
          "a signed build: reported signed, SETTINGS ticked by default");
    net_client_close(&loop->client);
    pump_for(loop, 200);
    loop->client_types = true;
    loop->client.info.record_size = 0;

    // Five wrong codes on one connection: refused (wrong_code).
    loop->client_mistypes = NET_PAIRING_MAX_FAILURES;
    result = pair_attempt(loop, address, true);
    check(result.type == NetClientEventType::refused && result.refusal == NetClientRefusal::wrong_code,
          "five wrong codes: refused (wrong_code)");
    loop->client_mistypes = 0;
    pump_for(loop, 200);

    // The shown code's time runs out (5 minutes): it's gone.
    loop->host_code_expired = false;
    check(net_access_show_code(&loop->host, NET_CAP_GAMEPAD, shown), "another code shown");
    loop->host.shown_since -= NET_ACCESS_REQUEST_SECONDS + 1.0;
    pump_while(loop, &loop->host_code_expired, true);
    check(loop->host_code_expired && !loop->host.showing, "the shown code expires after 5 minutes");
    check(NET_ACCESS_REQUEST_SECONDS == 300.0, "requests and shown codes wait 5 minutes");

    net_client_destroy(&loop->client);
    net_access_destroy(&loop->host);
    delete loop;
}

int main(int argc, char** argv)
{
    test_caps();
    test_discovery_packets();
    if (!net_init())
    {
        std::printf("FAIL net_init\n");
        return 1;
    }
    test_pair_codes();
    test_loopback();
    test_ipv6();
    test_session();
    if (argc > 1)
    {
        host_fs_make_directories(argv[1]);
        test_trust_files(argv[1]);
        test_pairing(argv[1]);
    }
    else
    {
        std::printf("FAIL no scratch folder given (pairing not checked)\n");
        g_failures++;
    }
    net_shutdown();
    if (g_failures == 0)
    {
        std::printf("all net checks passed\n");
    }
    return g_failures == 0 ? 0 : 1;
}
