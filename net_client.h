#pragma once

// The client side (piccoletto, another piccolo, net_probe): connect to a host,
// pair with the code we show (the host's user types it), or be welcomed as a
// device it already paired.
// On top of net_session.h and net_trust.h (the hosts this client paired
// with), running net_pairing.h's flow.
//
// A host we connect to without a code must be one we paired with: its device
// key is checked against our list, so a machine pretending to be it (with any
// other key) is refused even if it welcomes us. With a code we pair, and the
// host's key is added to the list when the host confirms.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "net_beacon.h"
#include "net_pairing.h"
#include "net_signal.h"
#include "net_session.h"
#include "net_trust.h"

enum class NetClientState
{
    idle,
    meeting,      // across the internet: asking the beacon, punching (net_beacon.h)
    connecting,   // ENet + Noise handshake
    waiting,      // secured, waiting for welcome / pairing_needed
    pairing,      // pair_request sent
    confirming,   // pair_confirm sent, waiting for the result
    ready,        // authorized: messages flow
};

enum class NetClientRefusal
{
    none,
    not_paired,       // the host doesn't know us and we have no code
    pairing_closed,   // the host isn't pairing now
    wrong_code,       // the host typed our codes wrong NET_PAIRING_MAX_FAILURES times
    refused,          // the host's user refused us
    unknown_host,     // it welcomed us but its key isn't one we paired with
    connection,       // the connection failed or dropped
    beacon_unreachable,   // across the internet: no beacon server answered
    host_offline,     // across the internet: the beacon doesn't know the host (not running, internet off there)
    no_route,         // across the internet: the beacon introduced us, but no path got through the NATs
};

enum class NetClientEventType
{
    none,
    ready,     // authorized (`newly_paired` if it just happened); `device` in our list; `access`
    access,    // the host changed our level (`access`)
    refused,   // `refusal`; the connection is closed
    message,   // from the host: `data`/`size` on `channel`
    closed,    // the host went away after ready
    unpaired,  // the host unpaired us: it's gone from our list too (`closed` follows when it closes)
    code_changed,   // the host typed our code wrong: show the new one (client->code); still pairing
};

struct NetClientEvent
{
    NetClientEventType type = NetClientEventType::none;
    NetClientRefusal   refusal = NetClientRefusal::none;
    bool           newly_paired = false;
    int32_t        device = -1;
    NetAccessLevel access = NetAccessLevel::gamepad;   // what the host lets us do (to show; it enforces)
    NetChannel     channel = NetChannel::control;
    const uint8_t* data = nullptr;   // message: valid until the next poll
    size_t         size = 0;
};

struct NetClient
{
    NetSession     session;
    NetTrust       trust;
    std::string    trust_path;
    std::string    name;                 // ours, as the host will show it
    uint8_t        our_key[NET_KEY_SIZE] = {};
    NetClientState state = NetClientState::idle;
    uint32_t       peer = NET_NO_PEER;
    bool           has_code = false;
    uint32_t       failures = 0;         // codes the host typed wrong on this connection
    NetAccessLevel want = NetAccessLevel::gamepad;   // the level we ask for (net_client_set_pairing)
    NetPairKind  kind = NetPairKind::piccolo;
    bool           just_paired = false;  // may grant_back on this connection
    bool           welcome_pending = false;   // paired (pair_result ok): `ready` waits for the welcome with our level
    char           code[NET_PAIR_CODE_DIGITS + 1] = {};
    uint8_t        host_key[NET_KEY_SIZE] = {};
    uint8_t        handshake_hash[NET_HASH_SIZE] = {};
    char           host_name[NET_DEVICE_NAME_MAX + 1] = {};
    NetCpace       cpace;                // between pair_request and pair_response
    uint8_t        isk[NET_CPACE_ISK_SIZE] = {};
    int32_t        device = -1;
    NetAccessLevel access = NetAccessLevel::gamepad;
    std::vector<uint8_t> out;
    NetBeaconClient beacon;
    bool           via_beacon = false;   // this connection went through the beacon
    // WebRTC through the beacon's signaling (net_signal.h): the hosts that
    // are browsers, or when UDP didn't get through.
    NetSignal      signal;
    std::string    signal_url;           // "" = no signaling (net_client_set_signal)
    std::string    signal_stun;
    bool           via_signal = false;   // this connection is WebRTC, signaled by the beacon
    bool           udp_host_offline = false;   // the beacon said so over UDP before WebRTC was tried
    uint8_t        meet_key[NET_KEY_SIZE] = {};   // the host being met through the beacon
    bool           meet_pairing = false; // met in its pairing room (net_client_pair_beacon)
    bool           expect_key = false;   // the host must turn out to have meet_key
};

bool net_client_create(NetClient* client, const NetKeypair* identity, const char* name, const char* trust_path);
void net_client_destroy(NetClient* client);

// `code` = the 9 digits we show (net_pair_code_generate), or nullptr to
// connect as an already paired device. With a code we ask to pair at once and
// wait (as long as it takes) for the host's user to type it; if it's typed
// wrong we make a new one (code_changed) and ask again.
bool net_client_connect(NetClient* client, NetAddress address, const char* code);
// What a pair_request asks for (the host's user decides).
void net_client_set_pairing(NetClient* client, NetAccessLevel want, NetPairKind kind);
// Right after pairing (ready with newly_paired), on that connection: lets the
// host come to us at `level` (it adds us as a host it may connect to). The
// caller adds the host to its own NetAccess (net_access_add_device).
bool net_client_grant_back(NetClient* client, NetAccessLevel level);
// Across the internet: to the host at `device` in our paired list, through a
// beacon (`servers`: its addresses, net_address_resolve). `ready` or `refused`
// follows as with net_client_connect; pairing needs the LAN.
// The same flow whatever the transport (Andrés): UDP first (hole punching);
// if that fails (or `count` is 0, as in a browser) and signaling is set,
// WebRTC through the beacon's signaling. The refusals are the same either way.
bool net_client_connect_beacon(NetClient* client, const NetAddress* servers, uint32_t count, uint32_t device);
// Pairs across the internet with the host whose user types our `code` in its
// INVITE: we wait in the pairing room of the code's slot on the beacon
// (patient: no time limit) until the host joins it, then pair as on the LAN.
// UDP when `count` > 0, else WebRTC through the signaling (a browser).
bool net_client_pair_beacon(NetClient* client, const NetAddress* servers, uint32_t count, const char* code);
// The beacon's signaling (net_signal_url / net_signal_stun); "" = none.
void net_client_set_signal(NetClient* client, const char* url, const char* stun);
bool net_client_poll(NetClient* client, NetClientEvent* event);
// Only when ready. A control payload starts with its type (NET_MESSAGE_FIRST_APP or above).
bool net_client_send(NetClient* client, NetChannel channel, const uint8_t* data, size_t size);
void net_client_close(NetClient* client);

// How the connection to the host is doing (ping). False unless ready.
bool net_client_stats(const NetClient* client, NetLinkStats* stats);
// Reliable bytes still on their way to the host (net_host_peer_pending); 0 unless ready.
size_t net_client_pending(const NetClient* client);

// Unpairs from the host at `device` in our list (saved at once). If we're
// connected to it now it's told (it forgets us too) and the connection
// closes; if not, it's only forgotten here. False if there's no such host.
bool net_client_unpair(NetClient* client, uint32_t device);
