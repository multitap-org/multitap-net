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
#include <thread>

#include <enet/enet.h>

#include "net_discovery.h"
#include "net_host.h"

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

int main()
{
    test_discovery_packets();
    if (!net_init())
    {
        std::printf("FAIL net_init\n");
        return 1;
    }
    test_loopback();
    net_shutdown();
    if (g_failures == 0)
    {
        std::printf("all net checks passed\n");
    }
    return g_failures == 0 ? 0 : 1;
}
