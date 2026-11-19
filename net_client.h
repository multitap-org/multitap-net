#pragma once

// The client side (piccoletto, another piccolo, net_probe): connect to a host,
// pair with the code it shows, or be welcomed as a device it already paired.
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

#include "net_pairing.h"
#include "net_session.h"
#include "net_trust.h"

enum class NetClientState
{
    idle,
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
    wrong_code,       // the code didn't match (or the pairing was refused)
    unknown_host,     // it welcomed us but its key isn't one we paired with
    connection,       // the connection failed or dropped
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
    char           code[NET_PAIR_CODE_DIGITS + 1] = {};
    uint8_t        host_key[NET_KEY_SIZE] = {};
    uint8_t        handshake_hash[NET_HASH_SIZE] = {};
    char           host_name[NET_DEVICE_NAME_MAX + 1] = {};
    NetCpace       cpace;                // between pair_request and pair_response
    uint8_t        isk[NET_CPACE_ISK_SIZE] = {};
    int32_t        device = -1;
    NetAccessLevel access = NetAccessLevel::gamepad;
    std::vector<uint8_t> out;
};

bool net_client_create(NetClient* client, const NetKeypair* identity, const char* name, const char* trust_path);
void net_client_destroy(NetClient* client);

// `code` = the 6 digits the host shows, or nullptr to connect as an already
// paired device.
bool net_client_connect(NetClient* client, NetAddress address, const char* code);
bool net_client_poll(NetClient* client, NetClientEvent* event);
// Only when ready. A control payload starts with its type (NET_MESSAGE_FIRST_APP or above).
bool net_client_send(NetClient* client, NetChannel channel, const uint8_t* data, size_t size);
void net_client_close(NetClient* client);

// Unpairs from the host at `device` in our list (saved at once). If we're
// connected to it now it's told (it forgets us too) and the connection
// closes; if not, it's only forgotten here. False if there's no such host.
bool net_client_unpair(NetClient* client, uint32_t device);
