#pragma once

// NetHost's WebRTC backend (net_host.h owns it; nothing else includes this).
// Peers connected through WebRTC data channels instead of ENet: the same
// three channels (control reliable and ordered; input and stream unordered,
// no retransmits, which net_link turns into "sequenced" like ENet's), the
// same bytes on them, so net_session / net_link / everything above can't tell
// the difference.
//
// One implementation per platform, chosen by CMake (never both in one build):
//   net_rtc_datachannel.cpp  libdatachannel (desktop, Android)
//   net_rtc_none.cpp         no WebRTC: every call fails, nothing is reported
//   (Emscripten: the browser's RTCPeerConnection, through net_webrtc.js; later)
//
// Signaling is the caller's: connecting gives "signal" blobs (our own SDP and
// ICE candidates) to deliver to the other side however it can (the beacon's
// WebSocket, net_beacon.h), and what the other side sent comes back in
// through net_rtc_signal. Blob format (opaque to whoever carries it):
//   'd' | type ("offer" / "answer") | 0 | sdp
//   'c' | mid | 0 | candidate

#include <cstddef>
#include <cstdint>

#include "net_host.h"

struct NetRtc;   // the backend's state (allocated by net_rtc_create)

constexpr uint32_t NET_RTC_MAX_PEERS = NET_MAX_PEERS;
constexpr size_t NET_RTC_MAX_SIGNAL = 4096;           // one blob (an SDP is about 1 KiB)
constexpr size_t NET_RTC_MAX_MESSAGE = 70 * 1024;     // a control message (64 KiB + the link's overhead)
constexpr double NET_RTC_CONNECT_SECONDS = 15.0;      // ICE + DTLS + channels, or it gave up

enum class NetRtcEventType
{
    none,
    connected,      // every channel of `index` is open
    disconnected,   // `index` failed, closed or timed out (it's free again)
    received,       // `data`/`size` on `channel` from `index`
    signal,         // a blob for the other side of `index` (`data`/`size`)
};

struct NetRtcEvent
{
    NetRtcEventType type = NetRtcEventType::none;
    uint32_t       index = 0;
    NetChannel     channel = NetChannel::control;
    const uint8_t* data = nullptr;   // valid until the next net_rtc_poll
    size_t         size = 0;
};

// Whether this build has WebRTC at all.
bool net_rtc_available();

// `stun` = "stun:host:port" or nullptr (host candidates only: same LAN).
NetRtc* net_rtc_create(const char* stun);
void net_rtc_destroy(NetRtc* rtc);

// Starts a connection as the side that offers (the client): the offer comes
// out as a `signal` event. `index` is the backend's peer number.
bool net_rtc_connect(NetRtc* rtc, uint32_t* index);
// Starts a connection as the side that answers (the host), for an offer
// that arrived by signaling: feed it with net_rtc_signal right after.
bool net_rtc_accept(NetRtc* rtc, uint32_t* index);
// A blob from the other side of `index` (an offer, an answer, a candidate).
bool net_rtc_signal(NetRtc* rtc, uint32_t index, const uint8_t* data, size_t size);

// One event per call; never blocks.
bool net_rtc_poll(NetRtc* rtc, NetRtcEvent* event, double now);
bool net_rtc_send(NetRtc* rtc, uint32_t index, NetChannel channel, const uint8_t* data, size_t size);
bool net_rtc_connected(const NetRtc* rtc, uint32_t index);
// Closes it; `disconnected` follows.
void net_rtc_close(NetRtc* rtc, uint32_t index);
// Bytes still queued to send on that channel (pacing; 0 if unknown).
size_t net_rtc_buffered(const NetRtc* rtc, uint32_t index, NetChannel channel);

// --- The beacon's signaling socket (a WebSocket; net_signal.h) -------------
// "wss://beacon.example.org/signal" (or ws:// for tests), subprotocol
// multitap-beacon.1, binary messages only. Polled like the rest.

struct NetRtcSocket;

enum class NetRtcSocketEvent
{
    none,
    open,      // connected: messages can go
    message,   // `data`/`size`: one binary message (valid until the next poll)
    closed,    // closed or failed (net_rtc_socket_close it; open a new one to retry)
};

NetRtcSocket* net_rtc_socket_open(const char* url);
void net_rtc_socket_close(NetRtcSocket* socket);
NetRtcSocketEvent net_rtc_socket_poll(NetRtcSocket* socket, const uint8_t** data, size_t* size);
bool net_rtc_socket_send(NetRtcSocket* socket, const uint8_t* data, size_t size);
