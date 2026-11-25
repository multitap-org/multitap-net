#pragma once

// The client side: connect to another device (the host here), pair by
// typing the code it shows, or be welcomed as a device it already paired.
// On top of net_session.h and net_trust.h (the paired devices, shared with
// this device's host side), running net_pairing.h's flow.
//
// We say who we are first (hello). A host we connect to without pairing must
// be one we paired with: its device key is checked against our list, so a
// machine pretending to be it (with any other key) is refused even if it
// welcomes us. To pair, we ask (pair_ask) and the host shows a code; our user
// types it (net_client_enter_code, after `code_needed`), and the host's key is
// added to the list when the host confirms. What the host lets us use comes
// with its welcome (stored as `granted`); what we let it use here we send
// (grant) at every connection and whenever it changes (net_client_set_grants).
//
// As a guest (net_guest.h, net_client_join_guest) there's no list: the link's
// token is what proves the host is the one it names. For that connection the
// session uses a throwaway key (made once per run, never saved) instead of
// ours, so the host can't tie a guest to this device, and a host that kicked
// us refuses the same key if we come back.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "net_beacon.h"
#include "net_guest.h"
#include "net_pairing.h"
#include "net_signal.h"
#include "net_session.h"
#include "net_trust.h"

enum class NetClientState
{
    idle,
    meeting,      // across the internet: asking the beacon, punching (net_beacon.h)
    connecting,   // ENet + Noise handshake
    waiting,      // secured, hello sent, waiting for welcome / pairing_needed
    code_wait,    // pair_ask sent: waiting for our user's code (net_client_enter_code)
    pairing,      // pair_request sent
    confirming,   // pair_confirm sent, waiting for the result
    ready,        // authorized: messages flow
};

enum class NetClientRefusal
{
    none,
    not_paired,       // the host doesn't know us and we didn't ask to pair
    pairing_closed,   // the host isn't pairing now
    wrong_code,       // our user typed the code wrong NET_PAIRING_MAX_FAILURES times
    refused,          // the host's user refused us
    unknown_host,     // it welcomed us but its key isn't one we paired with
    connection,       // the connection failed or dropped
    beacon_unreachable,   // across the internet: no beacon server answered
    host_offline,     // across the internet: the beacon doesn't know the host (not running, internet off there)
    no_route,         // across the internet: the beacon introduced us, but no path got through the NATs
    guest_full,       // guest: every seat is taken
    guest_link,       // guest: the link doesn't work any more (the session ended, or the host made a new one)
    guest_kicked,     // guest: the host kicked us (and refuses us for the rest of its session)
};

enum class NetClientEventType
{
    none,
    ready,        // authorized (`newly_paired` if it just happened); `device` in our list; `caps`, `host`, `host_signed`
    caps,         // the host changed what we may use there (`caps`)
    code_needed,  // pairing: show TYPE THE CODE SHOWN ON <host.name> (`retry`: the last one was wrong)
    refused,      // `refusal`; the connection is closed
    message,      // from the host: `data`/`size` on `channel`
    closed,       // the host went away after ready
    unpaired,     // the host unpaired us: it's gone from our list too (`closed` follows when it closes)
};
// (A guest's `ready` and `caps` carry `guest` and `guest_level`; its `closed`
// says why in `guest_bye` when the host said.)

struct NetClientEvent
{
    NetClientEventType type = NetClientEventType::none;
    NetClientRefusal   refusal = NetClientRefusal::none;
    bool           newly_paired = false;
    bool           retry = false;    // code_needed
    int32_t        device = -1;
    NetCaps        caps = 0;         // what the host lets us use (to show; it enforces)
    NetDeviceInfo  host;             // ready / code_needed: what the host said about itself
    bool           host_signed = false;
    NetChannel     channel = NetChannel::control;
    const uint8_t* data = nullptr;   // message: valid until the next poll
    size_t         size = 0;
    bool           guest = false;
    NetGuestLevel  guest_level = NetGuestLevel::watch;
    NetGuestBye    guest_bye = NetGuestBye::none;
};

struct NetClient
{
    NetSession     session;
    NetTrust       trust;                // our copy of the paired devices (net_trust.h: shared with the host side)
    std::string    trust_path;
    uint32_t       trust_generation = 0;
    NetDeviceInfo  info;                 // ours: name (as the host will show it), kind, offers, uses, build proof
    std::string    name;                 // info.name
    NetVerifyBuildFn verify_build = nullptr;
    void*          verify_user = nullptr;
    uint8_t        our_key[NET_KEY_SIZE] = {};
    NetClientState state = NetClientState::idle;
    uint32_t       peer = NET_NO_PEER;
    bool           pair = false;         // this connection may pair (net_client_connect / net_client_pair_beacon)
    bool           has_code = false;     // a code typed before connecting (net_client_pair_beacon)
    uint32_t       failures = 0;         // codes our user typed wrong on this connection
    // Presence (net_client_ask_presence): per host in our list, registered on
    // the beacon at the last answer (1) or not (0); empty = never asked.
    std::vector<uint8_t> online;
    std::vector<uint8_t> online_pending;   // this round's answers, OR'ed over the servers
    uint64_t       presence_base = 0;     // the round's first nonce (one per 8 hosts)
    bool           presence_answered = false;   // a beacon answered once (an old one never does: unknown)
    bool           welcome_pending = false;   // paired (pair_result ok): `ready` waits for the welcome
    char           code[NET_PAIR_CODE_DIGITS + 1] = {};
    uint8_t        host_key[NET_KEY_SIZE] = {};
    uint8_t        handshake_hash[NET_HASH_SIZE] = {};
    NetDeviceInfo  host;                 // what the host said (welcome / pairing_needed)
    bool           host_signed = false;
    NetCpace       cpace;                // between pair_request and pair_response
    uint8_t        isk[NET_CPACE_ISK_SIZE] = {};
    int32_t        device = -1;
    NetCaps        caps = 0;             // what the host lets us use
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
    // Guest links.
    bool           guest = false;        // this connection is a guest link's
    NetGuestLink   guest_link;
    NetKeypair     guest_identity;       // throwaway, made at the first guest join of this run
    bool           has_guest_identity = false;
    NetKeypair     home_identity;        // ours, put back when the guest connection ends
    NetGuestLevel  guest_level = NetGuestLevel::watch;
    NetGuestBye    guest_bye = NetGuestBye::none;   // what the host said before closing
};

// `info`: this device (its name is what the host shows). `trust_path`: the
// paired devices file (net_trust.h).
bool net_client_create(NetClient* client, const NetKeypair* identity, const NetDeviceInfo* info,
                       const char* trust_path);
void net_client_destroy(NetClient* client);
void net_client_set_verify_build(NetClient* client, NetVerifyBuildFn verify, void* user);

// Connects to the host at `address`. `pair` false: it must know us (`ready`
// or `refused` not_paired). `pair` true: if it doesn't know us we ask, and
// `code_needed` says to show where the code is; then net_client_enter_code.
bool net_client_connect(NetClient* client, NetAddress address, bool pair);
// The code our user typed (as the host shows it). False unless we're
// waiting for one or it isn't 9 digits. `ready` (newly_paired) or a new
// `code_needed` (retry: it was wrong; the host shows a new one) follows.
bool net_client_enter_code(NetClient* client, const char* code);
// What the device at `device` in our list may use here (saved at once; told
// at once if we're connected to it, else at the next connection).
void net_client_set_grants(NetClient* client, uint32_t device, NetCaps grants);
// Across the internet: to the host at `device` in our paired list, through a
// beacon (`servers`: its addresses, net_address_resolve). `ready` or `refused`
// follows as with net_client_connect.
// The same flow whatever the transport (Andrés): UDP first (hole punching);
// if that fails (or `count` is 0, as in a browser) and signaling is set,
// WebRTC through the beacon's signaling. The refusals are the same either way.
bool net_client_connect_beacon(NetClient* client, const NetAddress* servers, uint32_t count, uint32_t device);
// Pairs across the internet with the host showing `code` (GENERATE PAIRING
// CODE there): we meet it in the pairing room of the code's slot on the
// beacon, then pair with that code. UDP when `count` > 0, else WebRTC through
// the signaling (a browser). A wrong code: `code_needed` (retry).
bool net_client_pair_beacon(NetClient* client, const NetAddress* servers, uint32_t count, const char* code);
// Joins the session of a guest link (net_guest_link_parse) through a beacon:
// UDP first, else WebRTC through the signaling (net_client_set_signal), as
// net_client_connect_beacon. `ready` (guest) or `refused` follows.
bool net_client_join_guest(NetClient* client, const NetGuestLink* link, const NetAddress* servers, uint32_t count);

// Asks the beacon which of our paired hosts are registered now (online
// across the internet): `online` follows as the answers come in (polled with
// net_client_poll). Any time, connected or not.
void net_client_ask_presence(NetClient* client, const NetAddress* servers, uint32_t count);

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
