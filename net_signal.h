#pragma once

// WebRTC signaling through the beacon's WebSocket (deps/beacon, PROTOCOL.md
// "Signaling"): how two paired devices exchange the WebRTC offer, answer and
// ICE candidates (net_rtc.h's blobs) when one of them is a browser. The
// beacon only passes them along; the data channels then connect directly
// (ICE, with the beacon as STUN server), and Noise XX runs on them as over
// ENet. No relay: if ICE fails the client says it couldn't connect.
//
// Rooms are the same meeting ids as UDP (net_beacon_meeting_id): one per
// pairing. The host joins one room per paired device (role host) and re-joins
// every 20 s (the server's keepalive); the client joins its host's room (role
// client) and offers once the host is there. Blobs are encrypted end to end
// (the beacon sees no SDP, so no IPs): XChaCha20-Poly1305 with a random nonce,
// the direction in the associated data, a key both sides derive from their
// pairing (net_beacon_signal_key).
//
// Polled from the owner's loop with the NetSession whose WebRTC peers it
// starts (NetAccess for the host, NetClient for the client). Nothing
// allocates while polling (the rooms only when the paired devices change).

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "beacon_wire.h"
#include "net_rtc.h"
#include "net_session.h"

constexpr double NET_SIGNAL_JOIN_SECONDS = 20.0;     // the host's keepalive (the server drops idle sockets at 60 s)
constexpr double NET_SIGNAL_RETRY_SECONDS = 5.0;     // a closed socket: open a new one this long after
constexpr double NET_SIGNAL_CLIENT_SECONDS = 8.0;    // the client: no JOINED by then = the beacon doesn't answer
constexpr uint32_t NET_SIGNAL_MAX_ROOMS = 64;        // the server's limit per socket
constexpr size_t NET_SIGNAL_KEY_SIZE = 32;
constexpr size_t NET_SIGNAL_OVERHEAD = 24 + 16;      // nonce + MAC on every blob

// The default signaling URL for a beacon name ("beacon.get-piccolo.app" ->
// "wss://beacon.get-piccolo.app/signal"); a text with "://" is taken as it is.
std::string net_signal_url(const char* beacon);
// The default STUN URL for a beacon name ("stun:beacon.get-piccolo.app:55430").
std::string net_signal_stun(const char* beacon);

struct NetSignalRoom
{
    BeaconId room;
    uint8_t  key[NET_SIGNAL_KEY_SIZE] = {};
    uint32_t peer = NET_NO_PEER;   // the WebRTC peer this room's signals belong to
    bool     joined = false;       // the beacon answered our JOIN (JOINED) on the socket open now
};

enum class NetSignalRole
{
    host,
    client,
};

enum class NetSignalStatus
{
    off,
    connecting,    // the socket isn't open yet (or is being opened again)
    ready,         // open (its rooms may still be joining: net_signal_rooms_joined)
    unreachable,   // the socket failed or the beacon didn't answer
};

enum class NetSignalFailure
{
    none,
    unreachable,    // client: no answer from the beacon
    host_offline,   // client: the host isn't in its room
};

struct NetSignal
{
    NetSignalRole role = NetSignalRole::host;
    std::string   url;                 // "" = off
    NetRtcSocket* socket = nullptr;
    bool          open = false;
    bool          joined = false;      // the client's JOINED came
    double        started = -1.0;      // when this socket was opened
    double        next_join = 0.0;
    double        retry_at = 0.0;
    bool          failed_once = false; // the last socket closed without ever opening
    std::vector<NetSignalRoom> rooms;
    NetSignalFailure failure = NetSignalFailure::none;
    uint8_t       out[BEACON_SIGNALING_MAX_SIZE] = {};
    uint8_t       plain[BEACON_SIGNALING_MAX_BLOB] = {};
};

// The host: `url` "" stops. The rooms: one per paired device, from our key
// and theirs, plus the pairing room while pairing is open (`pairing`; the
// room comes from our public key, net_beacon_pair_id). Call again when the
// list changes or pairing opens / closes; rooms that stay keep their peer.
void net_signal_host_start(NetSignal* signal, const char* url);
void net_signal_host_set_rooms(NetSignal* signal, const NetKeypair* own, const uint8_t (*device_keys)[NET_KEY_SIZE],
                               uint32_t count, bool pairing);

// The client: meets the host whose key is `host_key`. False if the keys
// can't be used or there's no WebRTC in this build.
bool net_signal_client_start(NetSignal* signal, const char* url, const NetKeypair* own, const uint8_t* host_key,
                             double now);
// The client that pairs: meets the host whose key is `host_key` in its
// pairing room (open only while the host shows its code).
bool net_signal_client_start_pair(NetSignal* signal, const char* url, const uint8_t* host_key, double now);

void net_signal_stop(NetSignal* signal);

// Every poll: the socket, the beacon's messages (starting WebRTC peers in
// `session`), the host's keepalive JOINs, the client's deadline.
void net_signal_update(NetSignal* signal, NetSession* session, double now);
// A `signal` event from the session (a blob for the other side of `peer`).
void net_signal_outgoing(NetSignal* signal, uint32_t peer, const uint8_t* blob, size_t size);
// The session closed `peer`: its room no longer points to it.
void net_signal_peer_gone(NetSignal* signal, uint32_t peer);

NetSignalStatus net_signal_status(const NetSignal* signal, double now);
// Open, and the beacon has answered the JOIN of every room (a room added
// a moment ago may not be there yet: a client arriving before it would be
// told its host is offline).
bool net_signal_rooms_joined(const NetSignal* signal);
// The client's WebRTC peer, once it offered (NET_NO_PEER before).
uint32_t net_signal_client_peer(const NetSignal* signal);
