// net_rtc.h with libdatachannel (deps/libdatachannel, MPL-2.0), its C API.
//
// Threads: libdatachannel calls back on its own threads for what happens to
// a connection (our SDP and candidates, channels opening, the connection
// failing). Those callbacks only copy into a small fixed queue under a mutex;
// net_rtc_poll (the caller's network thread) drains it. Messages are not
// taken in callbacks at all: no message callback is set, so libdatachannel
// keeps them and net_rtc_poll reads them with rtcReceiveMessage into one
// buffer (nothing allocated per message on our side).
//
// Every peer slot has a generation: a callback that was already queued when
// a slot was torn down (and maybe reused) is recognized and dropped.

#include "net_rtc.h"

#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include <rtc/rtc.h>

#include "beacon_wire.h"
#include "host_log.h"

constexpr uint32_t QUEUE_SIZE = 64;

enum class Queued : uint8_t
{
    signal,
    channel_open,
    failed,
};

struct QueuedEvent
{
    Queued   kind = Queued::signal;
    uint32_t index = 0;
    uint32_t generation = 0;
    uint32_t size = 0;
    uint8_t  data[NET_RTC_MAX_SIGNAL] = {};
};

struct NetRtcPeer
{
    NetRtc*  owner = nullptr;
    uint32_t index = 0;
    uint32_t generation = 0;
    bool     used = false;
    bool     answering = false;       // accepted an offer (vs. made one)
    bool     open_reported = false;
    uint32_t channels_open = 0;
    double   started = -1.0;          // net_rtc_poll's clock, set at its first look
    int      pc = -1;
    int      dc[NET_CHANNEL_COUNT] = {};   // -1 = none (set by open_peer / teardown)
};

struct NetRtc
{
    std::string stun;
    NetRtcPeer  peers[NET_RTC_MAX_PEERS];
    std::mutex  lock;                  // guards the queue
    QueuedEvent queue[QUEUE_SIZE];
    uint32_t    head = 0;
    uint32_t    count = 0;
    uint32_t    dropped = 0;           // callbacks lost to a full queue
    QueuedEvent current;               // the event net_rtc_poll gave last (its data stays valid)
    std::vector<uint8_t> receive;      // the message net_rtc_poll gave last
    uint32_t    receive_cursor = 0;    // round robin over peers x channels
};

static void push(NetRtcPeer* peer, Queued kind, const uint8_t* first, size_t first_size, const char* second)
{
    NetRtc* rtc = peer->owner;
    size_t second_size = second != nullptr ? std::strlen(second) : 0;
    rtc->lock.lock();
    if (rtc->count == QUEUE_SIZE || first_size + second_size > NET_RTC_MAX_SIGNAL)
    {
        rtc->dropped++;
        rtc->lock.unlock();
        return;
    }
    QueuedEvent* event = &rtc->queue[(rtc->head + rtc->count) % QUEUE_SIZE];
    rtc->count++;
    event->kind = kind;
    event->index = peer->index;
    event->generation = peer->generation;
    if (first_size > 0)
    {
        std::memcpy(event->data, first, first_size);
    }
    if (second_size > 0)
    {
        std::memcpy(event->data + first_size, second, second_size);
    }
    event->size = static_cast<uint32_t>(first_size + second_size);
    rtc->lock.unlock();
}

// A blob: tag, a short text, a zero, a long text ('d' type sdp / 'c' mid candidate).
static void push_signal(NetRtcPeer* peer, char tag, const char* short_text, const char* long_text)
{
    uint8_t head[64];
    size_t short_size = short_text != nullptr ? std::strlen(short_text) : 0;
    if (short_size + 2 > sizeof(head))
    {
        return;
    }
    head[0] = static_cast<uint8_t>(tag);
    if (short_size > 0)
    {
        std::memcpy(head + 1, short_text, short_size);
    }
    head[1 + short_size] = 0;
    push(peer, Queued::signal, head, short_size + 2, long_text);
}

static void RTC_API on_description(int pc, const char* sdp, const char* type, void* user)
{
    (void)pc;
    push_signal(static_cast<NetRtcPeer*>(user), 'd', type, sdp);
}

static void RTC_API on_candidate(int pc, const char* candidate, const char* mid, void* user)
{
    (void)pc;
    push_signal(static_cast<NetRtcPeer*>(user), 'c', mid, candidate);
}

static void RTC_API on_state(int pc, rtcState state, void* user)
{
    (void)pc;
    if (state == RTC_FAILED || state == RTC_CLOSED || state == RTC_DISCONNECTED)
    {
        push(static_cast<NetRtcPeer*>(user), Queued::failed, nullptr, 0, nullptr);
    }
}

static void RTC_API on_open(int dc, void* user)
{
    (void)dc;
    push(static_cast<NetRtcPeer*>(user), Queued::channel_open, nullptr, 0, nullptr);
}

static void RTC_API on_closed(int dc, void* user)
{
    (void)dc;
    push(static_cast<NetRtcPeer*>(user), Queued::failed, nullptr, 0, nullptr);
}

static void RTC_API on_log(rtcLogLevel level, const char* message)
{
    host_log(level <= RTC_LOG_ERROR ? LogLevel::error : LogLevel::warning, "WebRTC: %s", message);
}

bool net_rtc_only()
{
    return false;
}

bool net_rtc_available()
{
    return true;
}

NetRtc* net_rtc_create(const char* stun)
{
    static bool logger = false;
    if (!logger)
    {
        rtcInitLogger(RTC_LOG_WARNING, on_log);
        logger = true;
    }
    NetRtc* rtc = new NetRtc();
    rtc->stun = stun != nullptr ? stun : "";
    rtc->receive.resize(NET_RTC_MAX_MESSAGE);
    for (uint32_t i = 0; i < NET_RTC_MAX_PEERS; i++)
    {
        rtc->peers[i].owner = rtc;
        rtc->peers[i].index = i;
        for (uint32_t c = 0; c < NET_CHANNEL_COUNT; c++)
        {
            rtc->peers[i].dc[c] = -1;
        }
    }
    return rtc;
}

// Deleting a peer connection waits for its callbacks to finish, and none
// come after: the slot can be reused (with a new generation).
static void teardown(NetRtc* rtc, NetRtcPeer* peer)
{
    for (uint32_t c = 0; c < NET_CHANNEL_COUNT; c++)
    {
        if (peer->dc[c] >= 0)
        {
            rtcDeleteDataChannel(peer->dc[c]);
            peer->dc[c] = -1;
        }
    }
    if (peer->pc >= 0)
    {
        rtcDeletePeerConnection(peer->pc);
        peer->pc = -1;
    }
    rtc->lock.lock();
    peer->used = false;
    peer->generation++;
    peer->open_reported = false;
    peer->channels_open = 0;
    peer->started = -1.0;
    rtc->lock.unlock();
}

void net_rtc_destroy(NetRtc* rtc)
{
    if (rtc == nullptr)
    {
        return;
    }
    for (uint32_t i = 0; i < NET_RTC_MAX_PEERS; i++)
    {
        if (rtc->peers[i].used)
        {
            teardown(rtc, &rtc->peers[i]);
        }
    }
    delete rtc;
}

// The three channels, negotiated out of band with fixed stream ids (both
// sides make the same ones; nothing is announced in band).
static bool open_peer(NetRtc* rtc, bool answering, uint32_t* index)
{
    NetRtcPeer* peer = nullptr;
    for (uint32_t i = 0; i < NET_RTC_MAX_PEERS && peer == nullptr; i++)
    {
        if (!rtc->peers[i].used)
        {
            peer = &rtc->peers[i];
        }
    }
    if (peer == nullptr)
    {
        return false;
    }
    rtcConfiguration config = {};
    const char* servers[1] = {rtc->stun.c_str()};
    if (!rtc->stun.empty())
    {
        config.iceServers = servers;
        config.iceServersCount = 1;
    }
    config.disableAutoNegotiation = true;   // the offer / answer go out when we say
    config.maxMessageSize = 256 * 1024;     // what browsers take; our largest is ~64 KiB
    peer->pc = rtcCreatePeerConnection(&config);
    if (peer->pc < 0)
    {
        peer->pc = -1;
        return false;
    }
    rtc->lock.lock();
    peer->used = true;
    rtc->lock.unlock();
    peer->answering = answering;
    peer->open_reported = false;
    peer->channels_open = 0;
    peer->started = -1.0;
    rtcSetUserPointer(peer->pc, peer);
    rtcSetLocalDescriptionCallback(peer->pc, on_description);
    rtcSetLocalCandidateCallback(peer->pc, on_candidate);
    rtcSetStateChangeCallback(peer->pc, on_state);
    static const char* LABELS[NET_CHANNEL_COUNT] = {"control", "input", "stream", "files"};
    for (uint32_t c = 0; c < NET_CHANNEL_COUNT; c++)
    {
        peer->dc[c] = -1;
    }
    for (uint32_t c = 0; c < NET_CHANNEL_COUNT; c++)
    {
        rtcDataChannelInit init = {};
        // control, files: reliable, ordered. input, stream: unordered, never
        // sent again (net_link drops anything older than what it already took).
        bool reliable = c == static_cast<uint32_t>(NetChannel::control) || c == static_cast<uint32_t>(NetChannel::files);
        init.reliability.unordered = !reliable;
        init.reliability.unreliable = !reliable;
        init.reliability.maxRetransmits = 0;
        init.negotiated = true;
        init.manualStream = true;
        init.stream = static_cast<uint16_t>(c);
        peer->dc[c] = rtcCreateDataChannelEx(peer->pc, LABELS[c], &init);
        if (peer->dc[c] < 0)
        {
            peer->dc[c] = -1;
            teardown(rtc, peer);
            return false;
        }
        rtcSetUserPointer(peer->dc[c], peer);
        rtcSetOpenCallback(peer->dc[c], on_open);
        rtcSetClosedCallback(peer->dc[c], on_closed);
    }
    *index = peer->index;
    return true;
}

bool net_rtc_connect(NetRtc* rtc, uint32_t* index)
{
    if (!open_peer(rtc, false, index))
    {
        return false;
    }
    if (rtcSetLocalDescription(rtc->peers[*index].pc, "offer") < 0)
    {
        teardown(rtc, &rtc->peers[*index]);
        return false;
    }
    return true;
}

bool net_rtc_accept(NetRtc* rtc, uint32_t* index)
{
    return open_peer(rtc, true, index);
}

bool net_rtc_signal(NetRtc* rtc, uint32_t index, const uint8_t* data, size_t size)
{
    if (index >= NET_RTC_MAX_PEERS || !rtc->peers[index].used || size < 3 || size > NET_RTC_MAX_SIGNAL)
    {
        return false;
    }
    NetRtcPeer* peer = &rtc->peers[index];
    // Copied into a terminated buffer: the two texts, split at the zero.
    char text[NET_RTC_MAX_SIGNAL + 1];
    std::memcpy(text, data + 1, size - 1);
    text[size - 1] = '\0';
    size_t short_size = std::strlen(text);
    if (short_size + 1 >= size)
    {
        return false;   // no zero inside: malformed
    }
    const char* short_text = text;
    const char* long_text = text + short_size + 1;
    if (data[0] == 'd')
    {
        bool offer = std::strcmp(short_text, "offer") == 0;
        bool answer = std::strcmp(short_text, "answer") == 0;
        if ((offer && !peer->answering) || (answer && peer->answering) || (!offer && !answer))
        {
            return false;
        }
        if (rtcSetRemoteDescription(peer->pc, long_text, short_text) < 0)
        {
            return false;
        }
        if (offer && rtcSetLocalDescription(peer->pc, "answer") < 0)
        {
            return false;
        }
        return true;
    }
    if (data[0] == 'c')
    {
        return rtcAddRemoteCandidate(peer->pc, long_text, short_text[0] != '\0' ? short_text : nullptr) >= 0;
    }
    return false;
}

static bool take_queued(NetRtc* rtc, QueuedEvent* out)
{
    rtc->lock.lock();
    if (rtc->count == 0)
    {
        rtc->lock.unlock();
        return false;
    }
    QueuedEvent* event = &rtc->queue[rtc->head];
    out->kind = event->kind;
    out->index = event->index;
    out->generation = event->generation;
    out->size = event->size;
    std::memcpy(out->data, event->data, event->size);
    rtc->head = (rtc->head + 1) % QUEUE_SIZE;
    rtc->count--;
    rtc->lock.unlock();
    return true;
}

bool net_rtc_poll(NetRtc* rtc, NetRtcEvent* event, double now)
{
    *event = {};
    // What the callbacks queued.
    while (take_queued(rtc, &rtc->current))
    {
        QueuedEvent* queued = &rtc->current;
        NetRtcPeer* peer = &rtc->peers[queued->index];
        if (!peer->used || peer->generation != queued->generation)
        {
            continue;   // from a connection that's gone
        }
        event->index = queued->index;
        switch (queued->kind)
        {
        case Queued::signal:
            event->type = NetRtcEventType::signal;
            event->data = queued->data;
            event->size = queued->size;
            return true;
        case Queued::channel_open:
            peer->channels_open++;
            if (peer->channels_open == NET_CHANNEL_COUNT && !peer->open_reported)
            {
                peer->open_reported = true;
                event->type = NetRtcEventType::connected;
                return true;
            }
            break;
        case Queued::failed:
            teardown(rtc, peer);
            event->type = NetRtcEventType::disconnected;
            return true;
        }
    }
    // Connections that never came up.
    for (uint32_t i = 0; i < NET_RTC_MAX_PEERS; i++)
    {
        NetRtcPeer* peer = &rtc->peers[i];
        if (!peer->used || peer->open_reported)
        {
            continue;
        }
        if (peer->started < 0.0)
        {
            peer->started = now;
        }
        else if (now - peer->started > NET_RTC_CONNECT_SECONDS)
        {
            teardown(rtc, peer);
            event->type = NetRtcEventType::disconnected;
            event->index = i;
            return true;
        }
    }
    // Messages, one per call, round robin so one busy channel can't starve the others.
    uint32_t slots = NET_RTC_MAX_PEERS * NET_CHANNEL_COUNT;
    for (uint32_t step = 0; step < slots; step++)
    {
        uint32_t slot = (rtc->receive_cursor + step) % slots;
        NetRtcPeer* peer = &rtc->peers[slot / NET_CHANNEL_COUNT];
        uint32_t channel = slot % NET_CHANNEL_COUNT;
        if (!peer->used || !peer->open_reported || peer->dc[channel] < 0)
        {
            continue;
        }
        int size = static_cast<int>(rtc->receive.size());
        int result = rtcReceiveMessage(peer->dc[channel], reinterpret_cast<char*>(rtc->receive.data()), &size);
        if (result != RTC_ERR_SUCCESS)
        {
            continue;   // nothing waiting (or a message larger than ours: dropped by the link anyway)
        }
        rtc->receive_cursor = slot + 1;
        if (size <= 0)
        {
            continue;   // a text message: never ours
        }
        event->type = NetRtcEventType::received;
        event->index = peer->index;
        event->channel = static_cast<NetChannel>(channel);
        event->data = rtc->receive.data();
        event->size = static_cast<size_t>(size);
        return true;
    }
    return false;
}

bool net_rtc_send(NetRtc* rtc, uint32_t index, NetChannel channel, const uint8_t* data, size_t size)
{
    if (index >= NET_RTC_MAX_PEERS || !rtc->peers[index].open_reported || size > NET_RTC_MAX_MESSAGE)
    {
        return false;
    }
    int dc = rtc->peers[index].dc[static_cast<uint32_t>(channel)];
    return dc >= 0 && rtcSendMessage(dc, reinterpret_cast<const char*>(data), static_cast<int>(size)) >= 0;
}

bool net_rtc_connected(const NetRtc* rtc, uint32_t index)
{
    return index < NET_RTC_MAX_PEERS && rtc->peers[index].used && rtc->peers[index].open_reported;
}

void net_rtc_close(NetRtc* rtc, uint32_t index)
{
    if (index < NET_RTC_MAX_PEERS && rtc->peers[index].used && rtc->peers[index].pc >= 0)
    {
        // The state callback reports it (failed / closed), then poll tears it down.
        rtcClosePeerConnection(rtc->peers[index].pc);
    }
}

size_t net_rtc_buffered(const NetRtc* rtc, uint32_t index, NetChannel channel)
{
    if (index >= NET_RTC_MAX_PEERS || !rtc->peers[index].used)
    {
        return 0;
    }
    int dc = rtc->peers[index].dc[static_cast<uint32_t>(channel)];
    int amount = dc >= 0 ? rtcGetBufferedAmount(dc) : 0;
    return amount > 0 ? static_cast<size_t>(amount) : 0;
}

// --- The signaling WebSocket ----------------------------------------------
// The same split as the peers: open / closed come through callbacks (two
// flags under a mutex), messages are read with rtcReceiveMessage.

struct NetRtcSocket
{
    int        ws = -1;
    std::mutex lock;
    bool       opened = false;          // set by the callback
    bool       closed = false;          // set by the callback
    bool       open_reported = false;
    bool       closed_reported = false;
    std::vector<uint8_t> receive;
};

static void RTC_API on_socket_open(int ws, void* user)
{
    (void)ws;
    NetRtcSocket* socket = static_cast<NetRtcSocket*>(user);
    socket->lock.lock();
    socket->opened = true;
    socket->lock.unlock();
}

static void RTC_API on_socket_closed(int ws, void* user)
{
    (void)ws;
    NetRtcSocket* socket = static_cast<NetRtcSocket*>(user);
    socket->lock.lock();
    socket->closed = true;
    socket->lock.unlock();
}

static void RTC_API on_socket_error(int ws, const char* error, void* user)
{
    (void)ws;
    host_log(LogLevel::warning, "Network: signaling socket: %s", error);
    on_socket_closed(ws, user);
}

NetRtcSocket* net_rtc_socket_open(const char* url)
{
    NetRtcSocket* socket = new NetRtcSocket();
    socket->receive.resize(BEACON_SIGNALING_MAX_SIZE);
    rtcWsConfiguration config = {};
    const char* protocols[1] = {"multitap-beacon.1"};
    config.protocols = protocols;
    config.protocolsCount = 1;
    config.connectionTimeoutMs = 8000;
    config.maxMessageSize = static_cast<int>(BEACON_SIGNALING_MAX_SIZE);
#if MULTITAP_NET_RTC_MBEDTLS
    // With Mbed TLS (Android) libdatachannel checks a wss certificate only
    // against a CA bundle handed to it, which its C API can't take, and
    // Android's own store isn't one: without this every wss fails. Andrés,
    // 2026-11-21: no check on Android. What crosses this socket is sealed end
    // to end with the pairing keys and the beacon is untrusted by design;
    // someone in the middle sees room ids and can drop messages, no more.
    config.disableTlsVerification = true;
#endif
    socket->ws = rtcCreateWebSocketEx(url, &config);
    if (socket->ws < 0)
    {
        host_log(LogLevel::warning, "Network: can't open the signaling socket to %s", url);
        delete socket;
        return nullptr;
    }
    rtcSetUserPointer(socket->ws, socket);
    rtcSetOpenCallback(socket->ws, on_socket_open);
    rtcSetClosedCallback(socket->ws, on_socket_closed);
    rtcSetErrorCallback(socket->ws, on_socket_error);
    return socket;
}

void net_rtc_socket_close(NetRtcSocket* socket)
{
    if (socket == nullptr)
    {
        return;
    }
    if (socket->ws >= 0)
    {
        rtcDeleteWebSocket(socket->ws);   // no callbacks after it returns
    }
    delete socket;
}

NetRtcSocketEvent net_rtc_socket_poll(NetRtcSocket* socket, const uint8_t** data, size_t* size)
{
    *data = nullptr;
    *size = 0;
    socket->lock.lock();
    bool opened = socket->opened;
    bool closed = socket->closed;
    socket->lock.unlock();
    if (opened && !socket->open_reported)
    {
        socket->open_reported = true;
        return NetRtcSocketEvent::open;
    }
    if (socket->open_reported && !socket->closed_reported)
    {
        int length = static_cast<int>(socket->receive.size());
        while (rtcReceiveMessage(socket->ws, reinterpret_cast<char*>(socket->receive.data()), &length) ==
               RTC_ERR_SUCCESS)
        {
            if (length > 0)
            {
                *data = socket->receive.data();
                *size = static_cast<size_t>(length);
                return NetRtcSocketEvent::message;
            }
            length = static_cast<int>(socket->receive.size());   // a text message: never ours, skipped
        }
    }
    if (closed && !socket->closed_reported)
    {
        socket->closed_reported = true;
        return NetRtcSocketEvent::closed;
    }
    return NetRtcSocketEvent::none;
}

bool net_rtc_socket_send(NetRtcSocket* socket, const uint8_t* data, size_t size)
{
    return socket->open_reported && !socket->closed_reported &&
           rtcSendMessage(socket->ws, reinterpret_cast<const char*>(data), static_cast<int>(size)) >= 0;
}
