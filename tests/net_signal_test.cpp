// WebRTC through the beacon's signaling, end to end on loopback: the real
// `beacon` binary (argv[1], built from deps/beacon) is started with its
// WebSocket listener; a host joins its paired device's room, the client joins
// it, offers, and the encrypted blobs go through the beacon; the data
// channels connect and the Noise handshake runs on them (each side sees the
// other's device key). Then a client whose host isn't there (host_offline)
// and one pointed at no beacon at all (unreachable). Last, the whole flow
// with NetAccess and NetClient: a host with only signaling (like a browser),
// net_client_connect_beacon with no UDP servers, ready on both sides.

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include "host_fs.h"
#include "net_access.h"
#include "net_client.h"
#include "net_session.h"
#include "net_signal.h"

extern char** environ;

static int g_failures = 0;

static void check(bool condition, const char* what)
{
    std::printf("%s %s\n", condition ? "ok  " : "FAIL", what);
    if (!condition)
    {
        g_failures++;
    }
}

struct Side
{
    NetSession session;
    NetSignal  signal;
    bool       secured = false;
    uint8_t    saw_key[NET_KEY_SIZE] = {};
    bool       got_message = false;
};

static void pump_side(Side* side, double now)
{
    net_signal_update(&side->signal, &side->session, now);
    NetSessionEvent event;
    while (net_session_poll(&side->session, &event))
    {
        if (event.type == NetSessionEventType::signal)
        {
            net_signal_outgoing(&side->signal, event.peer, event.data, event.size);
        }
        else if (event.type == NetSessionEventType::secured)
        {
            side->secured = true;
            std::memcpy(side->saw_key, event.remote_key, NET_KEY_SIZE);
        }
        else if (event.type == NetSessionEventType::message && event.size == 2 && std::memcmp(event.data, "hi", 2) == 0)
        {
            side->got_message = true;
        }
        else if (event.type == NetSessionEventType::closed)
        {
            net_signal_peer_gone(&side->signal, event.peer);
        }
    }
}

static bool pump_until(Side* host, Side* client, const bool* flag, int milliseconds)
{
    for (int i = 0; i < milliseconds / 5 && !*flag; i++)
    {
        double now = net_seconds();
        pump_side(host, now);
        pump_side(client, now);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return *flag;
}

static bool pump_until_failure(Side* host, Side* client, int milliseconds)
{
    for (int i = 0; i < milliseconds / 5 && client->signal.failure == NetSignalFailure::none; i++)
    {
        double now = net_seconds();
        pump_side(host, now);
        pump_side(client, now);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return client->signal.failure != NetSignalFailure::none;
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        std::printf("FAIL usage: net_signal_test <beacon binary> <scratch folder>\n");
        return 1;
    }
    std::string dir = argv[2];
    host_fs_make_directories(argv[2]);
    check(net_signal_url("beacon.get-piccolo.app") == "wss://beacon.get-piccolo.app/signal", "signaling URL from a name");
    check(net_signal_url("beacon.example.org:55430") == "wss://beacon.example.org/signal", "the UDP port isn't kept");
    check(net_signal_stun("beacon.get-piccolo.app") == "stun:beacon.get-piccolo.app:55430", "STUN URL from a name");

    // The beacon, on ports of its own for this run.
    uint16_t port = static_cast<uint16_t>(42000 + (getpid() % 4000) * 2);
    uint16_t signal_port = static_cast<uint16_t>(port + 1);
    std::string port_text = std::to_string(port);
    std::string signal_text = std::to_string(signal_port);
    const char* beacon_argv[] = {argv[1], "--bind", "127.0.0.1", "--port", port_text.c_str(), "--secondary-port", "0",
                                 "--signal-port", signal_text.c_str(), "--stats-interval", "0", "--log-level",
                                 "warning", nullptr};
    pid_t beacon = 0;
    if (posix_spawn(&beacon, argv[1], nullptr, nullptr, const_cast<char**>(beacon_argv), environ) != 0)
    {
        std::printf("FAIL could not start %s\n", argv[1]);
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    std::string url = "ws://127.0.0.1:" + signal_text + "/signal";

    net_init();
    Side* host = new Side();
    Side* client = new Side();
    NetKeypair host_key;
    NetKeypair client_key;
    net_keypair_generate(&host_key);
    net_keypair_generate(&client_key);
    check(net_session_create_listener(&host->session, 0, "SIGNAL HOST", &host_key), "host session");
    check(net_session_create_client(&client->session, &client_key), "client session");
    check(net_session_enable_rtc(&host->session, nullptr) && net_session_enable_rtc(&client->session, nullptr),
          "WebRTC on both");

    // The host joins its room (one paired device: the client).
    net_signal_host_start(&host->signal, url.c_str());
    uint8_t devices[1][NET_KEY_SIZE];
    std::memcpy(devices[0], client_key.public_key, NET_KEY_SIZE);
    net_signal_host_set_rooms(&host->signal, &host_key, devices, 1, false);
    bool host_ready = false;
    for (int i = 0; i < 400 && !host_ready; i++)
    {
        pump_side(host, net_seconds());
        host_ready = net_signal_status(&host->signal, net_seconds()) == NetSignalStatus::ready;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    check(host_ready, "host's signaling socket open, room joined");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));   // its JOIN reaches the beacon
    pump_side(host, net_seconds());

    check(net_signal_client_start(&client->signal, url.c_str(), &client_key, host_key.public_key, net_seconds()),
          "client meets its host's room");
    check(pump_until(host, client, &client->secured, 15000), "client secured over WebRTC (signaled by the beacon)");
    check(pump_until(host, client, &host->secured, 3000), "host secured");
    check(std::memcmp(client->saw_key, host_key.public_key, NET_KEY_SIZE) == 0, "client sees the host's key");
    check(std::memcmp(host->saw_key, client_key.public_key, NET_KEY_SIZE) == 0, "host sees the client's key");
    uint32_t peer = net_signal_client_peer(&client->signal);
    const uint8_t hi[] = {'h', 'i'};
    check(net_session_send(&client->session, peer, NetChannel::control, hi, sizeof(hi)), "message sent");
    check(pump_until(host, client, &host->got_message, 3000), "message arrived over the data channel");
    net_session_close(&client->session, peer);
    net_signal_stop(&client->signal);

    // A host that isn't in its room: host_offline.
    NetKeypair stranger;
    net_keypair_generate(&stranger);
    check(net_signal_client_start(&client->signal, url.c_str(), &client_key, stranger.public_key, net_seconds()),
          "client meets a host that isn't there");
    check(pump_until_failure(host, client, 5000) && client->signal.failure == NetSignalFailure::host_offline,
          "host_offline");
    net_signal_stop(&client->signal);

    // No beacon at all: unreachable.
    std::string nowhere = "ws://127.0.0.1:" + std::to_string(signal_port + 2) + "/signal";
    check(net_signal_client_start(&client->signal, nowhere.c_str(), &client_key, host_key.public_key, net_seconds()),
          "client meets through a missing beacon");
    check(pump_until_failure(host, client, 12000) && client->signal.failure == NetSignalFailure::unreachable,
          "unreachable");
    net_signal_stop(&client->signal);

    net_signal_stop(&host->signal);
    net_session_destroy(&client->session);
    net_session_destroy(&host->session);
    delete client;
    delete host;

    // The whole flow: NetAccess (signaling only) and NetClient.
    std::string host_devices = dir + "/host_devices.cfg";
    std::string client_hosts = dir + "/client_hosts.cfg";
    NetTrust trust;
    net_trust_add(&trust, client_key.public_key, "PHONE");
    net_trust_save(&trust, host_devices.c_str());
    NetTrust hosts;
    net_trust_add(&hosts, host_key.public_key, "LIVING ROOM");
    net_trust_save(&hosts, client_hosts.c_str());
    NetAccess* access = new NetAccess();
    NetClient* phone = new NetClient();
    check(net_access_create(access, 0, "LIVING ROOM", &host_key, host_devices.c_str()), "access created");
    check(net_access_set_signal(access, url.c_str(), nullptr), "access signals");
    check(net_client_create(phone, &client_key, "PHONE", client_hosts.c_str()), "client created");
    net_client_set_signal(phone, url.c_str(), nullptr);
    bool access_ready = false;
    for (int i = 0; i < 400 && !access_ready; i++)
    {
        NetAccessEvent ignored;
        while (net_access_poll(access, &ignored))
        {
        }
        access_ready = net_access_signal_status(access) == NetSignalStatus::ready;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    check(access_ready, "access in its rooms");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    check(net_client_connect_beacon(phone, nullptr, 0, 0), "client meets through signaling only");
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
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    check(phone_ready, "client ready (WebRTC, the paired host)");
    check(access_authorized, "host authorized the paired device");
    check(net_host_peer_transport(&phone->session.host, phone->peer) == NetTransport::rtc, "over WebRTC");

    // UDP first, then WebRTC: the beacon's UDP side doesn't know this host
    // (it only signals), so MEET gets NOT_FOUND and the client goes on to
    // signaling by itself. One flow, whatever the transport.
    net_client_close(phone);
    bool phone_closed = false;
    for (int i = 0; i < 2000 && !phone_closed; i++)
    {
        NetAccessEvent ignored;
        while (net_access_poll(access, &ignored))
        {
        }
        NetClientEvent phone_event;
        while (net_client_poll(phone, &phone_event))
        {
            phone_closed = phone_closed || phone_event.type == NetClientEventType::closed;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    check(phone_closed, "client closed");
    NetAddress udp;
    net_address_from_text("127.0.0.1", port, &udp);
    check(net_client_connect_beacon(phone, &udp, 1, 0), "client meets through UDP first");
    phone_ready = false;
    bool refused = false;
    for (int i = 0; i < 4000 && !phone_ready && !refused; i++)
    {
        NetAccessEvent ignored;
        while (net_access_poll(access, &ignored))
        {
        }
        NetClientEvent phone_event;
        while (net_client_poll(phone, &phone_event))
        {
            phone_ready = phone_ready || phone_event.type == NetClientEventType::ready;
            refused = refused || phone_event.type == NetClientEventType::refused;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    check(phone_ready && phone->via_signal, "UDP didn't find it; WebRTC did (ready)");

    // Pairing through signaling (a browser with the pair link): the host's
    // pairing room, the code, CPace over the data channels.
    std::string tablet_hosts = dir + "/tablet_hosts.cfg";
    NetTrust empty;
    net_trust_save(&empty, tablet_hosts.c_str());
    NetKeypair tablet_key;
    net_keypair_generate(&tablet_key);
    NetClient* tablet = new NetClient();
    check(net_client_create(tablet, &tablet_key, "TABLET", tablet_hosts.c_str()), "tablet created");
    net_client_set_signal(tablet, url.c_str(), nullptr);
    check(net_access_open_pairing(access), "host opens pairing");
    for (int i = 0; i < 40; i++)   // the pairing room's JOIN reaches the beacon
    {
        NetAccessEvent ignored;
        while (net_access_poll(access, &ignored))
        {
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    check(net_client_pair_beacon(tablet, nullptr, 0, host_key.public_key, access->code), "tablet pairs by signaling");
    bool tablet_ready = false;
    bool tablet_new = false;
    bool host_paired = false;
    for (int i = 0; i < 3000 && !(tablet_ready && host_paired); i++)
    {
        NetAccessEvent access_event;
        while (net_access_poll(access, &access_event))
        {
            host_paired = host_paired || access_event.type == NetAccessEventType::paired;
        }
        NetClientEvent tablet_event;
        while (net_client_poll(tablet, &tablet_event))
        {
            if (tablet_event.type == NetClientEventType::ready)
            {
                tablet_ready = true;
                tablet_new = tablet_event.newly_paired;
            }
            if (tablet_event.type == NetClientEventType::refused)
            {
                std::printf("refused %d\n", static_cast<int>(tablet_event.refusal));
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    check(tablet_ready && tablet_new, "tablet paired over WebRTC");
    check(host_paired, "host saw it pair");
    net_client_destroy(tablet);
    delete tablet;

    net_client_destroy(phone);
    net_access_destroy(access);
    delete phone;
    delete access;
    net_shutdown();

    kill(beacon, SIGTERM);
    int status = 0;
    waitpid(beacon, &status, 0);
    if (g_failures == 0)
    {
        std::printf("net signal: all checks passed\n");
    }
    return g_failures == 0 ? 0 : 1;
}
