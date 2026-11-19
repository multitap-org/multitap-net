#pragma once

// The host side of access control (piccolo): who may use this machine over
// the network. On top of net_session.h (encrypted connections) and
// net_trust.h (the paired devices on disk), running net_pairing.h's flow.
//
// A connection whose device key is in the trusted list is welcomed and
// reported `authorized`. Any other is told whether pairing is open: if it
// isn't, it's closed right away; if it is, the device may pair with the code
// on screen (net_access_open_pairing) and is reported `paired` when it does.
// Only authorized peers' messages reach the frontend.
//
// The code: 6 digits, new each time pairing opens, and replaced after every
// attempt that doesn't succeed (wrong code, dropped connection): an attacker
// gets one guess per code shown. After NET_PAIRING_MAX_FAILURES failed
// attempts, or NET_PAIRING_OPEN_SECONDS, pairing closes on its own. One
// pairing runs at a time.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "net_pairing.h"
#include "net_session.h"
#include "net_trust.h"

constexpr double   NET_PAIRING_OPEN_SECONDS = 300.0;
constexpr uint32_t NET_PAIRING_MAX_FAILURES = 5;
constexpr double   NET_ACCESS_PAIRING_STEP_SECONDS = 30.0;   // a peer may sit in a pairing step this long

enum class NetAccessPeerState
{
    none,
    unpaired,     // secured, not trusted; may send pair_request while pairing is open
    pairing,      // pair_response sent, waiting for pair_confirm
    authorized,
};

struct NetAccessPeer
{
    NetAccessPeerState state = NetAccessPeerState::none;
    double   since = 0.0;   // net_seconds() when this state began
    uint8_t  key[NET_KEY_SIZE] = {};
    uint8_t  handshake_hash[NET_HASH_SIZE] = {};
    char     name[NET_DEVICE_NAME_MAX + 1] = {};   // what it called itself when pairing
    uint8_t  isk[NET_CPACE_ISK_SIZE] = {};
    int32_t  device = -1;   // index in trust.devices once authorized
    bool     forgotten = false;   // its device was removed while connected: `closed` still reported
};

enum class NetAccessEventType
{
    none,
    authorized,       // a paired device connected: `peer`, `device`
    paired,           // a new device paired and is now authorized: `peer`, `device`
    message,          // from an authorized `peer`: `data`/`size` on `channel`
    closed,           // `peer` left (`device` if it was authorized, else -1)
    pairing_failed,   // an attempt failed; the code changed (or pairing closed)
    pairing_closed,   // pairing closed on its own (time or failures)
};

struct NetAccessEvent
{
    NetAccessEventType type = NetAccessEventType::none;
    uint32_t       peer = NET_NO_PEER;
    int32_t        device = -1;
    NetAddress     address;
    NetChannel     channel = NetChannel::control;
    const uint8_t* data = nullptr;   // message: valid until the next poll
    size_t         size = 0;
};

struct NetAccess
{
    NetSession    session;
    NetTrust      trust;
    std::string   trust_path;
    std::string   name;              // this host's name, as discovery shows it
    uint8_t       host_key[NET_KEY_SIZE] = {};
    bool          pairing_open = false;
    char          code[NET_PAIR_CODE_DIGITS + 1] = {};
    double        pairing_opened_at = 0.0;
    uint32_t      pairing_failures = 0;
    NetAccessPeer peers[NET_MAX_PEERS];
    std::vector<uint8_t> out;        // messages we write (sized at creation)
};

// `trust_path`: the paired devices file (loaded now, saved on every change).
bool net_access_create(NetAccess* access, uint16_t port, const char* name, const NetKeypair* identity,
                       const char* trust_path);
void net_access_destroy(NetAccess* access);

// One event per call; call until false, once per frame.
bool net_access_poll(NetAccess* access, NetAccessEvent* event);

// Opens pairing with a new code (`code`), or makes a new one if already open.
bool net_access_open_pairing(NetAccess* access);
void net_access_close_pairing(NetAccess* access);
double net_access_pairing_seconds_left(const NetAccess* access);

// To an authorized peer. A control payload's first byte is its message type,
// NET_MESSAGE_FIRST_APP or above.
bool net_access_send(NetAccess* access, uint32_t peer, NetChannel channel, const uint8_t* data, size_t size);
void net_access_close(NetAccess* access, uint32_t peer);

// Forget a device (saved at once); its connections are closed.
void net_access_remove_device(NetAccess* access, uint32_t device);
void net_access_set_own(NetAccess* access, uint32_t device, bool own);
// Is this peer connected and authorized as that device?
bool net_access_device_connected(const NetAccess* access, uint32_t device);
