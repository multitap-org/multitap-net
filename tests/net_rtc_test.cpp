// WebRTC data channels (net_rtc_datachannel.cpp) under NetSession, in one
// process: a host and a client hand each other their signal blobs directly
// (the beacon's job in real use), the data channels open, the Noise handshake
// runs on them as it does over ENet, and messages pass on all four channels.
// Then the client closes and the host sees it. Host candidates only (no
// STUN): loopback.

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

#include "net_session.h"

static int g_failures = 0;

static void check(bool condition, const char* what)
{
    std::printf("%s %s\n", condition ? "ok  " : "FAIL", what);
    if (!condition)
    {
        g_failures++;
    }
}

struct RtcLoop
{
    NetSession host;
    NetSession client;
    uint32_t   host_peer = NET_NO_PEER;
    uint32_t   client_peer = NET_NO_PEER;
    bool       host_secured = false;
    bool       client_secured = false;
    uint8_t    host_saw_key[NET_KEY_SIZE] = {};
    bool       got[NET_CHANNEL_COUNT] = {};
    bool       host_closed = false;
    uint32_t   signals = 0;
};

static void pump(RtcLoop* loop)
{
    NetSessionEvent event;
    while (net_session_poll(&loop->client, &event))
    {
        if (event.type == NetSessionEventType::signal)
        {
            loop->signals++;
            // The first blob is the offer: the host takes it as a new peer.
            if (loop->host_peer == NET_NO_PEER)
            {
                check(net_session_rtc_accept(&loop->host, &loop->host_peer), "host accepts the offer");
            }
            check(net_session_rtc_signal(&loop->host, loop->host_peer, event.data, event.size), "client blob taken");
        }
        else if (event.type == NetSessionEventType::secured)
        {
            loop->client_secured = true;
        }
    }
    while (net_session_poll(&loop->host, &event))
    {
        if (event.type == NetSessionEventType::signal)
        {
            loop->signals++;
            check(net_session_rtc_signal(&loop->client, loop->client_peer, event.data, event.size), "host blob taken");
        }
        else if (event.type == NetSessionEventType::secured)
        {
            loop->host_secured = true;
            std::memcpy(loop->host_saw_key, event.remote_key, NET_KEY_SIZE);
        }
        else if (event.type == NetSessionEventType::message && event.size == 3 &&
                 std::memcmp(event.data, "abc", 3) == 0)
        {
            loop->got[static_cast<uint32_t>(event.channel)] = true;
        }
        else if (event.type == NetSessionEventType::closed)
        {
            loop->host_closed = true;
        }
    }
}

static bool pump_until(RtcLoop* loop, const bool* flag, int milliseconds)
{
    for (int i = 0; i < milliseconds / 5 && !*flag; i++)
    {
        pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return *flag;
}

int main()
{
    if (!net_init())
    {
        std::printf("FAIL net_init\n");
        return 1;
    }
    RtcLoop* loop = new RtcLoop();
    NetKeypair host_key;
    NetKeypair client_key;
    net_keypair_generate(&host_key);
    net_keypair_generate(&client_key);
    check(net_session_create_listener(&loop->host, 0, "RTC HOST", &host_key), "host session");
    check(net_session_create_client(&loop->client, &client_key), "client session");
    check(net_session_enable_rtc(&loop->host, nullptr) && net_session_enable_rtc(&loop->client, nullptr),
          "WebRTC enabled on both");
    check(net_session_rtc_connect(&loop->client, &loop->client_peer), "client offers");
    check(net_host_peer_transport(&loop->client.host, loop->client_peer) == NetTransport::rtc, "the peer is WebRTC");

    check(pump_until(loop, &loop->client_secured, 15000), "client secured over data channels");
    check(pump_until(loop, &loop->host_secured, 3000), "host secured");
    check(std::memcmp(loop->host_saw_key, client_key.public_key, NET_KEY_SIZE) == 0, "host sees the client's key");
    check(loop->signals >= 2, "offer and answer went through signaling");

    const uint8_t abc[] = {'a', 'b', 'c'};
    // Unreliable channels may drop on a busy machine: a few tries each.
    for (int attempt = 0; attempt < 20 && !(loop->got[0] && loop->got[1] && loop->got[2] && loop->got[3]); attempt++)
    {
        for (uint32_t c = 0; c < NET_CHANNEL_COUNT; c++)
        {
            if (!loop->got[c])
            {
                net_session_send(&loop->client, loop->client_peer, static_cast<NetChannel>(c), abc, sizeof(abc));
            }
        }
        for (int i = 0; i < 10; i++)
        {
            pump(loop);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    check(loop->got[0], "control message arrived");
    check(loop->got[1], "input message arrived");
    check(loop->got[2], "stream message arrived");
    check(loop->got[3], "files message arrived");

    // NetHost's pings give WebRTC peers a round trip (ENet's own on UDP).
    for (int i = 0; i < 300 && loop->client.host.slots[loop->client_peer].pongs == 0; i++)
    {
        pump(loop);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    NetLinkStats stats;
    check(net_host_peer_stats(&loop->client.host, loop->client_peer, &stats), "stats of a WebRTC peer");
    check(loop->client.host.slots[loop->client_peer].pongs > 0, "a pong came back (round trip known)");
    check(stats.round_trip_ms < 1000 && stats.loss == 0.0f, "a sane round trip, no loss on loopback");

    // A clean close is seen at once through NetHost's bye (libdatachannel's
    // own teardown reaches a browser only after its ~15 s timeouts).
    net_session_close(&loop->client, loop->client_peer);
    check(pump_until(loop, &loop->host_closed, 1000), "host saw the client leave within a second");
    check(loop->host.host.rtc_byes_received >= 1, "... through the client's bye (sent twice: one or both)");

    net_session_destroy(&loop->client);
    net_session_destroy(&loop->host);
    delete loop;
    net_shutdown();
    if (g_failures == 0)
    {
        std::printf("net rtc: all checks passed\n");
    }
    return g_failures == 0 ? 0 : 1;
}
