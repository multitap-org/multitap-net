// net_beacon end to end over loopback, against the real beacon server
// (deps/beacon's server code, run in this process): a host registers its
// paired device, the client meets it through the beacon, punches and connects
// (Noise and the paired-key check as on the LAN). Then the failures: a host
// the beacon doesn't know, and no beacon at all. Plus the client taking the
// host's PUNCH source over a wrong INTRO address (peer-reflexive).
//
// No NAT on loopback: what's checked is the protocol and the plumbing; real
// NATs need two networks (net_probe --beacon).

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "beacon_net.h"
#include "beacon_server.h"
#include "host_fs.h"
#include "net_access.h"
#include "net_beacon.h"
#include "net_client.h"

static int g_failures = 0;

static void check(bool condition, const char* what)
{
    std::printf("%s %s\n", condition ? "ok  " : "FAIL", what);
    if (!condition)
    {
        g_failures++;
    }
}

struct World
{
    BeaconServer server;
    BeaconNet    net;
    NetAccess*   host = nullptr;
    NetClient*   client = nullptr;
    NetAddress   beacon_address;
    bool         host_authorized = false;
    bool         client_ready = false;
    bool         client_refused = false;
    NetClientRefusal refusal = NetClientRefusal::none;
};

static void pump(World* world)
{
    uint64_t now = beacon_now_ms();
    beacon_net_drain(&world->net, &world->server, now, BeaconSocket::PRIMARY, 64);
    beacon_net_drain(&world->net, &world->server, now, BeaconSocket::SECONDARY, 64);
    beacon_server_tick(&world->server, now);
    NetAccessEvent host_event;
    while (net_access_poll(world->host, &host_event))
    {
        if (host_event.type == NetAccessEventType::authorized)
        {
            world->host_authorized = true;
        }
    }
    if (world->client != nullptr)
    {
        NetClientEvent client_event;
        while (net_client_poll(world->client, &client_event))
        {
            if (client_event.type == NetClientEventType::ready)
            {
                world->client_ready = true;
            }
            else if (client_event.type == NetClientEventType::refused)
            {
                world->client_refused = true;
                world->refusal = client_event.refusal;
            }
        }
    }
}

static bool pump_until(World* world, const bool* flag, int milliseconds)
{
    for (int i = 0; i < milliseconds / 5 && !*flag; i++)
    {
        pump(world);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return *flag;
}

static bool open_beacon(World* world)
{
    BeaconServerConfig config;
    if (!beacon_server_create(&world->server, &config, beacon_now_ms()))
    {
        return false;
    }
    // net_beacon finds the secondary port at primary + 1: try a few pairs.
    for (uint16_t attempt = 0; attempt < 20; attempt++)
    {
        uint16_t port = static_cast<uint16_t>(41000 + (beacon_now_ms() % 9000) + attempt * 2);
        if (beacon_net_open(&world->net, "::", port, port + 1, -1))
        {
            return net_address_from_text("127.0.0.1", port, &world->beacon_address);
        }
    }
    return false;
}

static void test_peer_reflexive()
{
    NetHost host;
    check(net_host_create_client(&host), "client socket");
    NetAddress server;
    net_address_from_text("127.0.0.1", 9, &server);
    BeaconId id;
    id.bytes[0] = 7;
    NetBeaconClient beacon;
    check(net_beacon_client_start(&beacon, &server, 1, &id, 0.0), "meeting starts");
    net_beacon_client_update(&beacon, &host, 0.0);

    BeaconMessage intro;
    intro.type = BeaconType::INTRO;
    intro.nonce = beacon.nonce;
    intro.ids[0] = id;
    NetAddress wrong;
    net_address_from_text("192.0.2.1", 5000, &wrong);   // where the beacon thought the host was
    std::memcpy(intro.address.ip, wrong.ip, sizeof(wrong.ip));
    intro.address.port = wrong.port;
    check(net_beacon_client_receive(&beacon, &host, &intro, server, 0.1), "INTRO taken");
    check(beacon.state == NetBeaconMeetState::punching, "punching after INTRO");

    BeaconMessage stranger = intro;
    stranger.type = BeaconType::INTRO;
    NetAddress elsewhere;
    net_address_from_text("127.0.0.1", 10, &elsewhere);
    check(!net_beacon_client_receive(&beacon, &host, &stranger, elsewhere, 0.1), "INTRO from a non-server dropped");

    BeaconMessage punch;
    punch.type = BeaconType::PUNCH;
    punch.nonce = beacon.nonce + 1;
    punch.ids[0] = id;
    NetAddress real;
    net_address_from_text("198.51.100.7", 6000, &real);
    check(!net_beacon_client_receive(&beacon, &host, &punch, real, 0.2), "PUNCH with another nonce dropped");
    punch.nonce = beacon.nonce;
    check(net_beacon_client_receive(&beacon, &host, &punch, real, 0.2), "PUNCH taken");
    check(beacon.state == NetBeaconMeetState::connect && net_address_equal(beacon.target, real),
          "connects where the host's PUNCH came from, not the INTRO address");
    net_host_destroy(&host);
}

static void test_end_to_end(const std::string& dir)
{
    World world;
    if (!open_beacon(&world))
    {
        check(false, "beacon server opened");
        return;
    }
    NetKeypair host_key;
    NetKeypair client_key;
    net_keypair_generate(&host_key);
    net_keypair_generate(&client_key);
    std::string host_trust = dir + "/host_devices.cfg";
    std::string client_trust = dir + "/client_hosts.cfg";
    NetTrust trust;
    net_trust_add(&trust, client_key.public_key, "PHONE");
    net_trust_save(&trust, host_trust.c_str());
    NetTrust hosts;
    net_trust_add(&hosts, host_key.public_key, "LIVING ROOM");
    net_trust_save(&hosts, client_trust.c_str());

    world.host = new NetAccess();
    check(net_access_create(world.host, 0, "LIVING ROOM", &host_key, host_trust.c_str()), "host created");
    check(net_access_beacon_status(world.host) == NetBeaconStatus::off, "beacon off until set");
    net_access_set_beacon(world.host, &world.beacon_address, 1);
    bool registered = false;
    for (int i = 0; i < 400 && !registered; i++)
    {
        pump(&world);
        registered = net_access_beacon_status(world.host) == NetBeaconStatus::registered;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    check(registered, "host registered with the beacon (not symmetric on loopback)");
    check(world.server.stats.ids_accepted >= 1, "the beacon holds the id");

    world.client = new NetClient();
    check(net_client_create(world.client, &client_key, "PHONE", client_trust.c_str()), "client created");
    check(net_client_connect_beacon(world.client, &world.beacon_address, 1, 0), "meeting through the beacon");
    check(pump_until(&world, &world.client_ready, 8000), "client ready through the beacon");
    check(pump_until(&world, &world.host_authorized, 2000), "host saw the paired device");
    check(world.host->beacon.intros >= 1, "the host got an INTRO");
    check(!world.client_refused, "no refusal");
    net_client_destroy(world.client);
    delete world.client;

    // A host the beacon doesn't know (another key): host_offline.
    NetKeypair stranger_key;
    net_keypair_generate(&stranger_key);
    std::string stranger_trust = dir + "/stranger_hosts.cfg";
    NetTrust stranger_hosts;
    net_trust_add(&stranger_hosts, stranger_key.public_key, "NOBODY");
    net_trust_save(&stranger_hosts, stranger_trust.c_str());
    world.client = new NetClient();
    world.client_refused = false;
    net_client_create(world.client, &client_key, "PHONE", stranger_trust.c_str());
    check(net_client_connect_beacon(world.client, &world.beacon_address, 1, 0), "meeting an unknown host");
    check(pump_until(&world, &world.client_refused, 3000), "refused");
    check(world.refusal == NetClientRefusal::host_offline, "as host_offline");
    net_client_destroy(world.client);
    delete world.client;

    // No beacon there: beacon_unreachable after the meeting time.
    world.client = new NetClient();
    world.client_refused = false;
    net_client_create(world.client, &client_key, "PHONE", client_trust.c_str());
    NetAddress nowhere = world.beacon_address;
    nowhere.port = static_cast<uint16_t>(nowhere.port + 2);
    check(net_client_connect_beacon(world.client, &nowhere, 1, 0), "meeting through a missing beacon");
    check(pump_until(&world, &world.client_refused, 8000), "refused");
    check(world.refusal == NetClientRefusal::beacon_unreachable, "as beacon_unreachable");
    net_client_destroy(world.client);
    delete world.client;
    world.client = nullptr;

    net_access_destroy(world.host);
    delete world.host;
    beacon_net_close(&world.net);
    beacon_server_destroy(&world.server);
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::printf("FAIL no scratch folder given\n");
        return 1;
    }
    host_fs_make_directories(argv[1]);
    if (!net_init())
    {
        std::printf("FAIL net_init\n");
        return 1;
    }
    test_peer_reflexive();
    test_end_to_end(argv[1]);
    net_shutdown();
    if (g_failures == 0)
    {
        std::printf("net beacon: all checks passed\n");
    }
    return g_failures == 0 ? 0 : 1;
}
