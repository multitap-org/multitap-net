// WebRTC in the browser (net_rtc_emscripten.cpp + net_webrtc.js), in one page.
// Built only for Emscripten, with MULTITAP_WEB_TESTS=ON (tests/web/README.md
// says how to serve and open it). main() runs on a pthread
// (PROXY_TO_PTHREAD), like the network thread in a frontend, so every
// command really crosses to the page's main thread.
//
// 1. Two NetRtc in the same page: one offers, one answers, the signal blobs
//    are handed over directly; all four channels carry a message; closing
//    one side reports `disconnected` on both.
// 2. With a beacon (argv[1] = its signaling URL, ws://127.0.0.1:<port>/signal;
//    the real server, run natively): the whole flow as in net_signal_test,
//    NetAccess with signaling only and NetClient through
//    net_client_connect_beacon, until both are ready over WebRTC.
//
// 3. Mixed (by hand, argv[2]): "host" runs a NetAccess with a fixed key,
//    "client" a NetClient with the matching fixed key. Either side may be
//    the page or the native build (frontend_net_web_host: libdatachannel),
//    so both directions are checked:
//      - native host, page client: a browser meets a native piccolo (the
//        phone <-> browser case);
//      - page host, native client: a native piccolo meets a browser one
//        (NetClient tries UDP through the beacon first, the browser only
//        signals: it must fall back to WebRTC).
//    argv[3] is the folder for the trust files. A native client also takes
//    the beacon's UDP address (argv[4], 127.0.0.1:47430) and tries UDP
//    first, as piccolo does; the page has no UDP.
//
// The result goes to the console and the page title ("PASS" / "FAIL", from
// the exit status).

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "host_fs.h"
#include "net_access.h"
#include "net_beacon.h"
#include "net_client.h"
#include "net_rtc.h"

// The names each side shows (the logs, the other side's trust file).
#ifdef __EMSCRIPTEN__
constexpr const char* FIXED_HOST_NAME = "BROWSER HOST";
constexpr const char* FIXED_CLIENT_NAME = "BROWSER CLIENT";
constexpr const char* FIXED_DIR_DEFAULT = "/tmp/net_web";
#else
constexpr const char* FIXED_HOST_NAME = "NATIVE HOST";
constexpr const char* FIXED_CLIENT_NAME = "NATIVE CLIENT";
constexpr const char* FIXED_DIR_DEFAULT = "net_web";
#endif

static int g_failures = 0;

static void check(bool condition, const char* what)
{
    std::printf("%s %s\n", condition ? "ok  " : "FAIL", what);
    if (!condition)
    {
        g_failures++;
    }
}

static void sleep_ms(int milliseconds)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

struct RtcSide
{
    NetRtc*  rtc = nullptr;
    uint32_t index = 0;
    bool     connected = false;
    bool     disconnected = false;
    bool     received[NET_CHANNEL_COUNT] = {};
    uint32_t received_size[NET_CHANNEL_COUNT] = {};
    bool     big_ok = false;
};

// Polls one side; signals go straight to the other.
static void pump_rtc(RtcSide* side, RtcSide* other, double now)
{
    NetRtcEvent event;
    while (net_rtc_poll(side->rtc, &event, now))
    {
        switch (event.type)
        {
        case NetRtcEventType::signal:
            net_rtc_signal(other->rtc, other->index, event.data, event.size);
            break;
        case NetRtcEventType::connected:
            side->connected = true;
            break;
        case NetRtcEventType::disconnected:
            side->disconnected = true;
            break;
        case NetRtcEventType::received:
        {
            uint32_t channel = static_cast<uint32_t>(event.channel);
            side->received[channel] = true;
            side->received_size[channel] = static_cast<uint32_t>(event.size);
            if (event.size == 60000)
            {
                bool same = true;
                for (size_t i = 0; i < event.size && same; i++)
                {
                    same = event.data[i] == static_cast<uint8_t>(i * 7);
                }
                side->big_ok = same;
            }
            break;
        }
        case NetRtcEventType::none:
            break;
        }
    }
}

static bool pump_both(RtcSide* a, RtcSide* b, const bool* flag, int milliseconds)
{
    for (int i = 0; i < milliseconds / 5 && !*flag; i++)
    {
        double now = net_seconds();
        pump_rtc(a, b, now);
        pump_rtc(b, a, now);
        sleep_ms(5);
    }
    return *flag;
}

static void test_rtc()
{
    check(net_rtc_available(), "WebRTC available");
    RtcSide* client = new RtcSide();
    RtcSide* host = new RtcSide();
    client->rtc = net_rtc_create(nullptr);
    host->rtc = net_rtc_create(nullptr);
    check(client->rtc != nullptr && host->rtc != nullptr, "two instances");
    // The host's peer exists before the offer arrives (as net_signal does it).
    check(net_rtc_accept(host->rtc, &host->index), "host waits for an offer");
    check(net_rtc_connect(client->rtc, &client->index), "client offers");
    check(pump_both(client, host, &client->connected, 15000), "client connected");
    check(pump_both(client, host, &host->connected, 3000), "host connected");
    check(net_rtc_connected(client->rtc, client->index), "net_rtc_connected");

    const uint8_t hello[] = {'h', 'e', 'l', 'l', 'o'};
    for (uint32_t c = 0; c < NET_CHANNEL_COUNT; c++)
    {
        check(net_rtc_send(client->rtc, client->index, static_cast<NetChannel>(c), hello, sizeof(hello)),
              "sent on a channel");
    }
    bool all = false;
    for (int i = 0; i < 600 && !all; i++)
    {
        double now = net_seconds();
        pump_rtc(client, host, now);
        pump_rtc(host, client, now);
        all = host->received[0] && host->received[1] && host->received[2] && host->received[3];
        sleep_ms(5);
    }
    check(all, "all four channels arrived");
    check(host->received_size[0] == sizeof(hello), "same size");

    // A large reliable message (a control message's worth), and the other way.
    static uint8_t big[60000];
    for (size_t i = 0; i < sizeof(big); i++)
    {
        big[i] = static_cast<uint8_t>(i * 7);
    }
    check(net_rtc_send(host->rtc, host->index, NetChannel::control, big, sizeof(big)), "60 KB sent");
    check(pump_both(client, host, &client->big_ok, 5000), "60 KB arrived intact");
    check(net_rtc_buffered(host->rtc, host->index, NetChannel::control) < sizeof(big) * 2, "buffered is sane");

    net_rtc_close(client->rtc, client->index);
    check(pump_both(client, host, &client->disconnected, 3000), "closed: disconnected here");
    check(pump_both(client, host, &host->disconnected, 15000), "and on the other side");
    check(!net_rtc_connected(client->rtc, client->index), "no longer connected");

    // Instances are reused once released.
    net_rtc_destroy(client->rtc);
    net_rtc_destroy(host->rtc);
    sleep_ms(200);
    NetRtc* again = net_rtc_create(nullptr);
    check(again != nullptr, "an instance again after destroy");
    net_rtc_destroy(again);
    delete client;
    delete host;
}

static void test_flow(const char* url)
{
    host_fs_make_directories("/tmp/net_web");
    NetKeypair host_key;
    NetKeypair client_key;
    net_keypair_generate(&host_key);
    net_keypair_generate(&client_key);
    NetTrust trust;
    net_trust_add(&trust, client_key.public_key, "PHONE");
    net_trust_save(&trust, "/tmp/net_web/host_devices.cfg");
    NetTrust hosts;
    net_trust_add(&hosts, host_key.public_key, "LIVING ROOM");
    net_trust_save(&hosts, "/tmp/net_web/client_hosts.cfg");

    NetAccess* access = new NetAccess();
    NetClient* phone = new NetClient();
    check(net_access_create(access, 0, "LIVING ROOM", &host_key, "/tmp/net_web/host_devices.cfg"), "access created");
    check(net_access_set_signal(access, url, nullptr), "access signals");
    check(net_client_create(phone, &client_key, "PHONE", "/tmp/net_web/client_hosts.cfg"), "client created");
    net_client_set_signal(phone, url, nullptr);
    bool access_ready = false;
    for (int i = 0; i < 1000 && !access_ready; i++)
    {
        NetAccessEvent ignored;
        while (net_access_poll(access, &ignored))
        {
        }
        access_ready = net_access_signal_status(access) == NetSignalStatus::ready;
        sleep_ms(5);
    }
    check(access_ready, "access in its rooms (WebSocket open)");
    sleep_ms(100);
    check(net_client_connect_beacon(phone, nullptr, 0, 0), "client meets through signaling");
    bool phone_ready = false;
    bool access_authorized = false;
    for (int i = 0; i < 3000 && !(phone_ready && access_authorized); i++)
    {
        NetAccessEvent access_event;
        while (net_access_poll(access, &access_event))
        {
            access_authorized = access_authorized || access_event.type == NetAccessEventType::authorized;
        }
        NetClientEvent phone_event;
        while (net_client_poll(phone, &phone_event))
        {
            phone_ready = phone_ready || phone_event.type == NetClientEventType::ready;
            if (phone_event.type == NetClientEventType::refused)
            {
                std::printf("refused %d\n", static_cast<int>(phone_event.refusal));
            }
        }
        sleep_ms(5);
    }
    check(phone_ready, "client ready (Noise over the browser's data channels)");
    check(access_authorized, "host authorized the paired device");
    check(net_host_peer_transport(&phone->session.host, phone->peer) == NetTransport::rtc, "over WebRTC");

    // Pairing from the browser (2026-11-22): the tablet shows a code and waits
    // in its slot's room; the host's user types it in INVITE.
    NetTrust empty;
    net_trust_save(&empty, "/tmp/net_web/tablet_hosts.cfg");
    NetKeypair tablet_key;
    net_keypair_generate(&tablet_key);
    NetClient* tablet = new NetClient();
    check(net_client_create(tablet, &tablet_key, "TABLET", "/tmp/net_web/tablet_hosts.cfg"), "tablet created");
    net_client_set_signal(tablet, url, nullptr);
    char code[NET_PAIR_CODE_DIGITS + 1];
    net_pair_code_generate(code);
    check(net_client_pair_beacon(tablet, nullptr, 0, code), "tablet waits in its room");
    check(net_access_invite(access, code), "host's user types the code");
    bool tablet_ready = false;
    bool host_paired = false;
    for (int i = 0; i < 3000 && !(tablet_ready && host_paired); i++)
    {
        NetAccessEvent access_event;
        while (net_access_poll(access, &access_event))
        {
            host_paired = host_paired || access_event.type == NetAccessEventType::paired;
            if (access_event.type == NetAccessEventType::pairing_requested)
            {
                net_access_answer_pairing(access, access_event.peer, code, NetAccessLevel::gamepad);
            }
        }
        NetClientEvent tablet_event;
        while (net_client_poll(tablet, &tablet_event))
        {
            tablet_ready = tablet_ready || (tablet_event.type == NetClientEventType::ready && tablet_event.newly_paired);
        }
        sleep_ms(5);
    }
    check(tablet_ready && host_paired, "paired from the browser");
    net_client_destroy(tablet);
    delete tablet;

    net_client_destroy(phone);
    net_access_destroy(access);
    delete phone;
    delete access;
}

// Fixed keys for the mixed run (test only: anyone can derive them).
static void fixed_keys(NetKeypair* host_key, NetKeypair* client_key)
{
    uint8_t secret[NET_KEY_SIZE];
    std::memset(secret, 0x11, sizeof(secret));
    net_keypair_from_secret(host_key, secret);
    std::memset(secret, 0x22, sizeof(secret));
    net_keypair_from_secret(client_key, secret);
}

static int run_fixed_host(const char* url, const char* dir)
{
    NetKeypair host_key;
    NetKeypair client_key;
    fixed_keys(&host_key, &client_key);
    host_fs_make_directories(dir);
    std::string devices = std::string(dir) + "/host_devices.cfg";
    NetTrust trust;
    net_trust_add(&trust, client_key.public_key, "FIXED CLIENT");
    net_trust_save(&trust, devices.c_str());
    NetAccess* access = new NetAccess();
    check(net_access_create(access, 0, FIXED_HOST_NAME, &host_key, devices.c_str()), "fixed host created");
    check(net_access_set_signal(access, url, nullptr), "fixed host signals");
    bool authorized = false;
    for (int i = 0; i < 60000 / 5 && !authorized; i++)
    {
        NetAccessEvent event;
        while (net_access_poll(access, &event))
        {
            authorized = authorized || event.type == NetAccessEventType::authorized;
        }
        sleep_ms(5);
    }
    check(authorized, "the fixed client connected and was authorized");
    for (int i = 0; i < 200; i++)   // a moment for the client to see ready
    {
        NetAccessEvent event;
        while (net_access_poll(access, &event))
        {
        }
        sleep_ms(5);
    }
    net_access_destroy(access);
    delete access;
    return g_failures == 0 ? 0 : 1;
}

// `wait_close`: after ready, stay until the connection is reported closed
// (the host killed by hand: how long it takes to notice).
static void run_fixed_client(const char* url, const char* dir, const char* udp_server, bool wait_close)
{
    NetKeypair host_key;
    NetKeypair client_key;
    fixed_keys(&host_key, &client_key);
    host_fs_make_directories(dir);
    std::string hosts_file = std::string(dir) + "/fixed_hosts.cfg";
    NetTrust hosts;
    net_trust_add(&hosts, host_key.public_key, "FIXED HOST");
    net_trust_save(&hosts, hosts_file.c_str());
    NetClient* client = new NetClient();
    check(net_client_create(client, &client_key, FIXED_CLIENT_NAME, hosts_file.c_str()), "fixed client created");
    net_client_set_signal(client, url, nullptr);
    NetAddress servers[4];
    uint32_t count = 0;
    if (udp_server != nullptr && udp_server[0] != '\0')
    {
        count = net_address_resolve(udp_server, NET_BEACON_DEFAULT_PORT, servers);
        check(count > 0, "the beacon's UDP address resolved");
    }
    check(net_client_connect_beacon(client, servers, count, 0), "fixed client looks for the fixed host");
    bool ready = false;
    bool refused = false;
    for (int i = 0; i < 4000 && !ready && !refused; i++)
    {
        NetClientEvent event;
        while (net_client_poll(client, &event))
        {
            ready = ready || event.type == NetClientEventType::ready;
            if (event.type == NetClientEventType::refused)
            {
                refused = true;
                std::printf("refused %d\n", static_cast<int>(event.refusal));
            }
        }
        sleep_ms(5);
    }
    check(ready, "fixed client ready with the fixed host");
    if (ready && wait_close)
    {
        std::printf("ready: now kill the host (60 s at most)\n");
        double start = net_seconds();
        bool closed = false;
        for (int i = 0; i < 12000 && !closed; i++)
        {
            NetClientEvent event;
            while (net_client_poll(client, &event))
            {
                closed = closed || event.type == NetClientEventType::closed;
            }
            sleep_ms(5);
        }
        std::printf("closed after %.1f s\n", net_seconds() - start);
        check(closed, "a host that vanished is noticed");
    }
    net_client_destroy(client);
    delete client;
}

int main(int argc, char** argv)
{
    net_init();
    const char* url = argc > 1 ? argv[1] : "";
    const char* mode = argc > 2 ? argv[2] : "";
    if (std::strcmp(mode, "host") == 0)
    {
        int status = run_fixed_host(url, argc > 3 ? argv[3] : FIXED_DIR_DEFAULT);
        net_shutdown();
        std::printf(status == 0 ? "net web host: all checks passed\n" : "net web host: failed\n");
        return status;
    }
    if (std::strcmp(mode, "client") == 0 || std::strcmp(mode, "client-wait") == 0)
    {
        run_fixed_client(url, argc > 3 ? argv[3] : FIXED_DIR_DEFAULT, argc > 4 ? argv[4] : nullptr,
                         std::strcmp(mode, "client-wait") == 0);
    }
    else
    {
        test_rtc();
        if (url[0] != '\0')
        {
            test_flow(url);
        }
        else
        {
            std::printf("note: no beacon URL given, the signaling flow was skipped\n");
        }
    }
    net_shutdown();
    if (g_failures == 0)
    {
        std::printf("net web: all checks passed\n");
    }
    return g_failures == 0 ? 0 : 1;
}
