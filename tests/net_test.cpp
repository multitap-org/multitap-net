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

#include <enet/enet.h>

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
    net_discovery_write_request(packet, sizeof(packet), 7);
    packet[0] = 'X';
    check(!net_discovery_read_request(packet, size, &nonce), "bad magic refused");

    NetDiscoveryReply reply;
    reply.nonce = 42;
    reply.port = 55420;
    std::snprintf(reply.name, sizeof(reply.name), "Living room PC");
    size = net_discovery_write_reply(packet, sizeof(packet), &reply);
    NetDiscoveryReply read;
    check(size == NET_DISCOVERY_REPLY_HEADER_SIZE + std::strlen("Living room PC"), "reply size");
    check(net_discovery_read_reply(packet, size, &read), "reply round trip");
    check(read.nonce == 42 && read.port == 55420 && std::strcmp(read.name, "Living room PC") == 0, "reply fields");
    check(!net_discovery_read_request(packet, size, &nonce), "a reply is not a request");
    check(!net_discovery_read_reply(packet, size + 1, &read), "reply with a wrong length refused");
    packet[NET_DISCOVERY_REPLY_HEADER_SIZE + 3] = 0;
    check(!net_discovery_read_reply(packet, size, &read), "reply with a NUL in the name refused");

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
    to.host = address.host;
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
    NetClientEvent client_event;   // the last interesting one
    bool client_got = false;
    NetAccessEventType host_last = NetAccessEventType::none;
    uint32_t host_events = 0;
    bool host_got_message = false;
    bool host_got_stream_message = false;
    bool client_got_message = false;
    bool client_got_access = false;
    bool client_closed = false;
    bool client_unpaired = false;
    bool host_unpaired = false;
    std::string host_unpaired_name;
};

static void pair_pump(PairLoop* loop)
{
    NetAccessEvent host_event;
    while (net_access_poll(&loop->host, &host_event))
    {
        loop->host_last = host_event.type;
        loop->host_events++;
        if (host_event.type == NetAccessEventType::unpaired)
        {
            loop->host_unpaired = true;
            loop->host_unpaired_name = host_event.name;
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
        else if (event.type == NetClientEventType::access)
        {
            loop->client_got_access = true;
        }
        else if (event.type == NetClientEventType::unpaired)
        {
            loop->client_unpaired = true;
        }
        else
        {
            loop->client_event = event;
            loop->client_got = true;
        }
    }
}

// Connects (with `code` or none) and waits for the client's outcome.
static NetClientEvent pair_attempt(PairLoop* loop, NetAddress address, const char* code)
{
    loop->client_got = false;
    loop->client_event = {};
    if (!net_client_connect(&loop->client, address, code))
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

static void wrong_code(const char* code, char* out)
{
    std::snprintf(out, NET_PAIR_CODE_DIGITS + 1, "%s", code);
    out[0] = out[0] == '9' ? '0' : static_cast<char>(out[0] + 1);
}

static void test_pairing(const char* folder)
{
    std::string host_trust = std::string(folder) + "/host_devices.cfg";
    std::string client_trust = std::string(folder) + "/client_hosts.cfg";
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

    PairLoop* loop = new PairLoop();
    check(net_access_create(&loop->host, 0, "Living room", &host_key, host_trust.c_str()), "access host created");
    check(net_client_create(&loop->client, &client_key, "Ana's phone", client_trust.c_str()), "client created");
    NetAddress address;
    net_address_from_text("127.0.0.1", net_host_port(&loop->host.session.host), &address);

    NetClientEvent result = pair_attempt(loop, address, nullptr);
    check(result.type == NetClientEventType::refused && result.refusal == NetClientRefusal::not_paired,
          "not paired, no code: refused (not_paired)");
    result = pair_attempt(loop, address, "123456");
    check(result.type == NetClientEventType::refused && result.refusal == NetClientRefusal::pairing_closed,
          "pairing closed: refused (pairing_closed)");

    check(net_access_open_pairing(&loop->host), "pairing opened");
    char code[NET_PAIR_CODE_DIGITS + 1];
    std::snprintf(code, sizeof(code), "%s", loop->host.code);
    check(net_pair_code_valid(code), "the code is 6 digits");
    char bad[NET_PAIR_CODE_DIGITS + 1];
    wrong_code(code, bad);
    result = pair_attempt(loop, address, bad);
    check(result.type == NetClientEventType::refused && result.refusal == NetClientRefusal::wrong_code,
          "wrong code: refused (wrong_code)");
    pump_for(loop, 200);
    check(loop->host_last == NetAccessEventType::pairing_failed, "host saw the failed attempt");
    check(std::strcmp(code, loop->host.code) != 0, "the code changed after the failure");
    check(loop->host.pairing_open, "pairing still open after one failure");

    std::snprintf(code, sizeof(code), "%s", loop->host.code);
    result = pair_attempt(loop, address, code);
    check(result.type == NetClientEventType::ready && result.newly_paired, "right code: paired");
    pump_for(loop, 100);
    check(loop->host_last == NetAccessEventType::paired, "host reported the new device");
    check(!loop->host.pairing_open, "pairing closes after a success");
    check(loop->host.trust.devices.size() == 1 && loop->host.trust.devices[0].name == "Ana's phone",
          "host trusts the client by name");
    check(std::memcmp(loop->host.trust.devices[0].key, client_key.public_key, NET_KEY_SIZE) == 0,
          "host trusts the client's key");
    check(loop->client.trust.devices.size() == 1 && loop->client.trust.devices[0].name == "Living room",
          "client trusts the host");
    NetTrust saved;
    net_trust_load(&saved, host_trust.c_str());
    check(saved.devices.size() == 1 && std::memcmp(saved.devices[0].key, client_key.public_key, NET_KEY_SIZE) == 0,
          "the host's list is on disk");

    const uint8_t hello[] = {NET_MESSAGE_FIRST_APP, 'x'};
    check(net_client_send(&loop->client, NetChannel::control, hello, sizeof(hello)), "app message sent");
    for (int i = 0; i < 200 && !loop->client_got_message; i++)
    {
        pair_pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    check(loop->host_got_message && loop->client_got_message, "app messages both ways");
    const uint8_t sneaky[] = {static_cast<uint8_t>(NetMessage::welcome), 0};
    check(!net_client_send(&loop->client, NetChannel::control, sneaky, sizeof(sneaky)),
          "the app can't send pairing messages");

    // Reconnecting under a new name: the host's list follows it.
    net_client_close(&loop->client);
    pump_for(loop, 200);
    loop->client.name = "ANA'S NEW PHONE";
    result = pair_attempt(loop, address, nullptr);
    check(result.type == NetClientEventType::ready && !result.newly_paired, "paired device welcomed without a code");
    check(result.access == NetAccessLevel::gamepad, "a new device starts at gamepad (and is told)");
    pump_for(loop, 100);
    check(loop->host.trust.devices[0].name == "ANA'S NEW PHONE", "the device's new name replaces the old one");
    net_trust_load(&saved, host_trust.c_str());
    check(saved.devices.size() == 1 && saved.devices[0].name == "ANA'S NEW PHONE", "and is saved");

    // Access: a stream-level message from a gamepad-level device is dropped.
    const uint8_t stream_message[] = {NET_MESSAGE_FIRST_STREAM, 's'};
    check(net_client_send(&loop->client, NetChannel::control, stream_message, sizeof(stream_message)),
          "stream message sent");
    pump_for(loop, 200);
    check(!loop->host_got_stream_message && loop->host.dropped_by_access == 1, "gamepad level: stream message dropped");

    net_access_set_level(&loop->host, 0, NetAccessLevel::full);
    for (int i = 0; i < 200 && !loop->client_got_access; i++)
    {
        pair_pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    check(loop->client_got_access && loop->client.access == NetAccessLevel::full, "the client is told its new level");
    net_client_send(&loop->client, NetChannel::control, stream_message, sizeof(stream_message));
    for (int i = 0; i < 200 && !loop->host_got_stream_message; i++)
    {
        pair_pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    check(loop->host_got_stream_message, "full level: stream message delivered");
    net_trust_load(&saved, host_trust.c_str());
    check(saved.devices.size() == 1 && saved.devices[0].access == NetAccessLevel::full, "access level saved");

    // A list from before access: own = true reads as full, nothing as gamepad.
    std::string old_list = std::string(folder) + "/old_devices.cfg";
    const char* old_text = "[device:0101010101010101010101010101010101010101010101010101010101010101]\nname = A\nown = true\n"
                           "[device:0202020202020202020202020202020202020202020202020202020202020202]\nname = B\n";
    host_fs_write_file(old_list.c_str(), old_text, std::strlen(old_text));
    NetTrust old_trust;
    net_trust_load(&old_trust, old_list.c_str());
    check(old_trust.devices.size() == 2 && old_trust.devices[0].access == NetAccessLevel::full &&
              old_trust.devices[1].access == NetAccessLevel::gamepad,
          "old lists migrate: own = true -> full");

    loop->client_closed = false;   // set by the close above
    net_access_remove_device(&loop->host, 0);
    for (int i = 0; i < 200 && !loop->client_closed; i++)
    {
        pair_pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    check(loop->client_closed, "removing the device closes its connection");
    check(loop->client_unpaired && loop->client.trust.devices.empty(),
          "a connected device is told: it forgets the host too");
    pump_for(loop, 100);
    check(loop->host_last == NetAccessEventType::closed, "and the host reports it closed (its pads can go)");
    result = pair_attempt(loop, address, nullptr);
    check(result.type == NetClientEventType::refused && result.refusal == NetClientRefusal::not_paired,
          "a removed device is refused");

    // A host that knows our key but whose key we don't know (an impostor
    // that copied the list, say): refused even though it welcomes us.
    loop->client.trust.devices.clear();
    net_trust_add(&loop->host.trust, client_key.public_key, "Ana's phone");
    result = pair_attempt(loop, address, nullptr);
    check(result.type == NetClientEventType::refused && result.refusal == NetClientRefusal::unknown_host,
          "unknown host refused");
    net_trust_remove(&loop->host.trust, 0);

    // Unpairing from the client, connected: the host forgets it too.
    net_access_open_pairing(&loop->host);
    result = pair_attempt(loop, address, loop->host.code);
    check(result.type == NetClientEventType::ready && result.newly_paired, "paired again");
    pump_for(loop, 100);
    check(loop->host.trust.devices.size() == 1 && loop->client.trust.devices.size() == 1, "both lists have it");
    loop->client_closed = false;
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
    check(loop->host_last == NetAccessEventType::closed, "the connection closed (the client closes it)");

    // Unpairing from the client, not connected: only its own list.
    net_access_open_pairing(&loop->host);
    result = pair_attempt(loop, address, loop->host.code);
    check(result.type == NetClientEventType::ready, "paired once more");
    net_client_close(&loop->client);
    pump_for(loop, 200);
    loop->host_unpaired = false;
    check(net_client_unpair(&loop->client, 0) && loop->client.trust.devices.empty(), "offline: forgotten here");
    pump_for(loop, 100);
    check(!loop->host_unpaired && loop->host.trust.devices.size() == 1, "offline: the host still has it");
    check(!net_client_unpair(&loop->client, 0), "no such host: false");
    net_trust_remove(&loop->host.trust, 0);

    // Five failures close pairing.
    net_access_open_pairing(&loop->host);
    for (uint32_t i = 0; i < NET_PAIRING_MAX_FAILURES && loop->host.pairing_open; i++)
    {
        wrong_code(loop->host.code, bad);
        pair_attempt(loop, address, bad);
        pump_for(loop, 150);
    }
    check(!loop->host.pairing_open, "pairing closes after five failures");

    net_client_destroy(&loop->client);
    net_access_destroy(&loop->host);
    delete loop;
}

int main(int argc, char** argv)
{
    test_discovery_packets();
    if (!net_init())
    {
        std::printf("FAIL net_init\n");
        return 1;
    }
    test_loopback();
    test_session();
    if (argc > 1)
    {
        host_fs_make_directories(argv[1]);
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
