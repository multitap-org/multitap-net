// net_rtc.h in the browser (Emscripten): the browser's own RTCPeerConnection,
// RTCDataChannel and WebSocket, driven by net_webrtc.js (linked with
// --js-library; frontend_net adds it to whatever links it).
//
// Threads: those browser objects only exist on the page's main thread, and
// the network runs on its own thread (net_service, a pthread). So nothing
// here calls into JS and waits. Both sides talk through rings in wasm memory
// (a SharedArrayBuffer with pthreads), each with one writer and one reader:
//
//   commands  C++ -> JS   one ring for the whole program (writers take a
//                         mutex); after writing, JS is woken with
//                         net_webrtc_kick (proxied to the main thread, async,
//                         and only when it isn't already woken)
//   events    JS -> C++   one ring per NetRtc and per socket; net_rtc_poll /
//                         net_rtc_socket_poll read them (zero copy: an event's
//                         bytes stay in the ring until the next poll)
//
// Without pthreads the same code works: net_webrtc_kick runs right away.
//
// Ring layout (net_webrtc.js reads the same offsets; keep both in step):
//   +0 head (bytes written, free running)   +4 tail (bytes read)
//   +8 size (data bytes, a power of two)    +12 dropped (records that didn't fit)
//   +16 released (JS sets 1 when it will never write to this ring again)
//   +32 data
// A record: u32 length (with header and padding, a multiple of 4), u8 kind,
// u8 channel, u8 owner, u8 index, u32 size, then `size` bytes. A length of
// 0xFFFFFFFF means "the rest of the ring is empty: go on from its start".
//
// Memory: the rings are allocated the first time their slot is used and
// never freed (a fixed handful for the program's life), because the main
// thread may still be writing to a ring when C++ is done with it; a slot is
// reused only once JS has marked its ring released.

#include "net_rtc.h"

#include <atomic>
#include <cstring>
#include <mutex>
#include <new>

#include "host_log.h"

// net_webrtc.js: drains the command ring on the main thread.
extern "C" void net_webrtc_kick(void* ring, void* kick_pending);

static_assert(sizeof(void*) == 4, "the rings carry 32-bit pointers (wasm32)");
static_assert(sizeof(std::atomic<uint32_t>) == 4 && std::atomic<uint32_t>::is_always_lock_free,
              "JS reads these words with Atomics");

constexpr uint32_t RING_HEADER = 32;
constexpr uint32_t RECORD_HEADER = 12;
constexpr uint32_t RECORD_WRAP = 0xFFFFFFFFu;
constexpr uint32_t COMMAND_RING_SIZE = 2u * 1024 * 1024;
constexpr uint32_t PEER_RING_SIZE = 2u * 1024 * 1024;     // a stream burst while the network thread sleeps
constexpr uint32_t SOCKET_RING_SIZE = 64u * 1024;         // signaling messages (4 KiB at most each)
constexpr uint32_t MAX_INSTANCES = 4;
constexpr uint32_t MAX_SOCKETS = 8;
constexpr uint32_t SLOTS = NET_RTC_MAX_PEERS * NET_CHANNEL_COUNT;

static_assert(NET_RTC_MAX_PEERS <= 255, "a peer index is one byte in a record");

// Commands (C++ -> JS).
enum class Command : uint8_t
{
    instance_open = 1,   // payload: u32 ring, u32 buffered, u32 queued, the STUN URL
    instance_close = 2,
    peer_open = 3,       // channel: 1 = offers, 0 = answers
    peer_signal = 4,     // payload: a blob
    peer_send = 5,       // channel, payload: the message
    peer_close = 6,
    socket_open = 7,     // payload: u32 ring, the URL
    socket_send = 8,
    socket_close = 9,
};

// Events (JS -> C++).
enum class Event : uint8_t
{
    connected = 1,
    disconnected = 2,    // JS has forgotten the peer: its index is free
    received = 3,
    signal = 4,
    socket_open = 6,
    socket_message = 7,
    socket_closed = 8,
};

struct Ring
{
    std::atomic<uint32_t> head;
    std::atomic<uint32_t> tail;
    uint32_t              size;
    std::atomic<uint32_t> dropped;
    std::atomic<uint32_t> released;
    uint32_t              unused[3];
};

static_assert(sizeof(Ring) == RING_HEADER, "the ring header is 32 bytes");

struct RecordHeader
{
    uint32_t length;
    uint8_t  kind;
    uint8_t  channel;
    uint8_t  owner;
    uint8_t  index;
    uint32_t size;
};

static_assert(sizeof(RecordHeader) == RECORD_HEADER, "a record header is 12 bytes");

static Ring* ring_allocate(uint32_t size)
{
    uint32_t* words = new uint32_t[(RING_HEADER + size) / 4];
    Ring* ring = new (words) Ring();
    ring->head.store(0);
    ring->tail.store(0);
    ring->size = size;
    ring->dropped.store(0);
    ring->released.store(0);
    return ring;
}

static uint8_t* ring_data(Ring* ring)
{
    return reinterpret_cast<uint8_t*>(ring) + RING_HEADER;
}

static uint32_t round_up4(size_t size)
{
    return static_cast<uint32_t>((size + 3) & ~static_cast<size_t>(3));
}

// The writer's side (C++ writes only the command ring; JS writes the others).
static bool ring_write(Ring* ring, Command kind, uint8_t channel, uint8_t owner, uint8_t index, const uint8_t* first,
                       size_t first_size, const uint8_t* second, size_t second_size)
{
    size_t size = first_size + second_size;
    uint32_t need = RECORD_HEADER + round_up4(size);
    if (need > ring->size)
    {
        return false;
    }
    uint32_t head = ring->head.load(std::memory_order_relaxed);
    uint32_t tail = ring->tail.load(std::memory_order_acquire);
    uint32_t position = head & (ring->size - 1);
    uint32_t contiguous = ring->size - position;
    uint32_t total = need > contiguous ? contiguous + need : need;
    if ((head - tail) + total > ring->size)
    {
        ring->dropped.fetch_add(1);
        return false;
    }
    uint8_t* data = ring_data(ring);
    if (need > contiguous)
    {
        std::memcpy(data + position, &RECORD_WRAP, 4);
        head += contiguous;
        position = 0;
    }
    RecordHeader header;
    header.length = need;
    header.kind = static_cast<uint8_t>(kind);
    header.channel = channel;
    header.owner = owner;
    header.index = index;
    header.size = static_cast<uint32_t>(size);
    std::memcpy(data + position, &header, RECORD_HEADER);
    if (first_size > 0)
    {
        std::memcpy(data + position + RECORD_HEADER, first, first_size);
    }
    if (second_size > 0)
    {
        std::memcpy(data + position + RECORD_HEADER + first_size, second, second_size);
    }
    ring->head.store(head + need, std::memory_order_release);
    return true;
}

// The reader's side: the oldest record, or nullptr. It stays in place until
// ring_release.
static const RecordHeader* ring_peek(Ring* ring)
{
    for (;;)
    {
        uint32_t tail = ring->tail.load(std::memory_order_relaxed);
        uint32_t head = ring->head.load(std::memory_order_acquire);
        if (head == tail)
        {
            return nullptr;
        }
        uint32_t position = tail & (ring->size - 1);
        const uint8_t* at = ring_data(ring) + position;
        uint32_t length = 0;
        std::memcpy(&length, at, 4);
        if (length == RECORD_WRAP)
        {
            ring->tail.store(tail + (ring->size - position), std::memory_order_release);
            continue;
        }
        return reinterpret_cast<const RecordHeader*>(at);
    }
}

static void ring_release(Ring* ring, uint32_t length)
{
    ring->tail.store(ring->tail.load(std::memory_order_relaxed) + length, std::memory_order_release);
}

static const uint8_t* record_payload(const RecordHeader* record)
{
    return reinterpret_cast<const uint8_t*>(record) + RECORD_HEADER;
}

// --- The command ring --------------------------------------------------------

struct Commands
{
    std::mutex            lock;
    Ring*                 ring = nullptr;
    std::atomic<uint32_t> kick_pending{0};
};

static Commands g_commands;

static bool send_command(Command kind, uint8_t channel, uint8_t owner, uint8_t index, const uint8_t* first,
                         size_t first_size, const uint8_t* second, size_t second_size)
{
    g_commands.lock.lock();
    if (g_commands.ring == nullptr)
    {
        g_commands.ring = ring_allocate(COMMAND_RING_SIZE);
    }
    bool written = ring_write(g_commands.ring, kind, channel, owner, index, first, first_size, second, second_size);
    g_commands.lock.unlock();
    if (!written)
    {
        return false;
    }
    // JS clears the flag before it reads the ring: whatever it doesn't see
    // was written after, and that writer wakes it again.
    if (g_commands.kick_pending.exchange(1) == 0)
    {
        net_webrtc_kick(g_commands.ring, &g_commands.kick_pending);
    }
    return true;
}

static void put_u32(uint8_t* out, uint32_t value)
{
    std::memcpy(out, &value, 4);
}

static uint32_t address_of(const void* pointer)
{
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pointer));
}

// --- Peers -------------------------------------------------------------------

enum class PeerState : uint8_t
{
    free,
    connecting,
    connected,
    closing,      // asked JS to close it; free once its `disconnected` comes back
};

struct RtcPeer
{
    PeerState state = PeerState::free;
    bool      reported = false;   // `disconnected` already given to the caller (a timeout)
    double    started = -1.0;
};

enum class SlotState : uint8_t
{
    free,
    open,
    closing,      // waiting for JS to release the ring
};

struct NetRtc
{
    uint8_t   id = 0;
    SlotState state = SlotState::free;
    bool      close_sent = false;
    Ring*     ring = nullptr;
    uint32_t  release = 0;                          // the record the last poll handed out
    std::atomic<uint32_t> buffered[SLOTS] = {};     // JS: each channel's bufferedAmount
    std::atomic<uint32_t> queued[SLOTS] = {};       // C++ adds what it sends, JS takes it off when sent
    RtcPeer   peers[NET_RTC_MAX_PEERS];
};

static std::mutex g_slots_lock;   // the two tables below (create / destroy / open / close)
static NetRtc g_instances[MAX_INSTANCES];

bool net_rtc_only()
{
    return true;
}

bool net_rtc_available()
{
    return true;
}

static bool try_reclaim(Ring* ring, SlotState* state)
{
    if (*state == SlotState::free)
    {
        return true;
    }
    if (*state == SlotState::closing && ring->released.load() == 1)
    {
        ring->head.store(0);
        ring->tail.store(0);
        ring->released.store(0);
        *state = SlotState::free;
        return true;
    }
    return false;
}

NetRtc* net_rtc_create(const char* stun)
{
    std::lock_guard<std::mutex> guard(g_slots_lock);
    NetRtc* rtc = nullptr;
    for (uint32_t i = 0; i < MAX_INSTANCES && rtc == nullptr; i++)
    {
        NetRtc* candidate = &g_instances[i];
        if (candidate->state == SlotState::closing && !candidate->close_sent)
        {
            candidate->close_sent = send_command(Command::instance_close, 0, static_cast<uint8_t>(i), 0, nullptr, 0,
                                                 nullptr, 0);
        }
        if (candidate->ring == nullptr || try_reclaim(candidate->ring, &candidate->state))
        {
            rtc = candidate;
            rtc->id = static_cast<uint8_t>(i);
        }
    }
    if (rtc == nullptr)
    {
        host_log(LogLevel::warning, "Network: no free WebRTC instance (%u in use)", MAX_INSTANCES);
        return nullptr;
    }
    if (rtc->ring == nullptr)
    {
        rtc->ring = ring_allocate(PEER_RING_SIZE);
    }
    rtc->release = 0;
    rtc->close_sent = false;
    for (uint32_t i = 0; i < SLOTS; i++)
    {
        rtc->buffered[i].store(0);
        rtc->queued[i].store(0);
    }
    for (uint32_t i = 0; i < NET_RTC_MAX_PEERS; i++)
    {
        rtc->peers[i] = RtcPeer();
    }
    uint8_t head[12];
    put_u32(head, address_of(rtc->ring));
    put_u32(head + 4, address_of(rtc->buffered));
    put_u32(head + 8, address_of(rtc->queued));
    size_t stun_size = stun != nullptr ? std::strlen(stun) : 0;
    if (!send_command(Command::instance_open, 0, rtc->id, 0, head, sizeof(head),
                      reinterpret_cast<const uint8_t*>(stun), stun_size))
    {
        return nullptr;
    }
    rtc->state = SlotState::open;
    return rtc;
}

void net_rtc_destroy(NetRtc* rtc)
{
    if (rtc == nullptr)
    {
        return;
    }
    std::lock_guard<std::mutex> guard(g_slots_lock);
    rtc->state = SlotState::closing;
    rtc->close_sent = send_command(Command::instance_close, 0, rtc->id, 0, nullptr, 0, nullptr, 0);
}

static bool open_peer(NetRtc* rtc, bool offers, uint32_t* index)
{
    for (uint32_t i = 0; i < NET_RTC_MAX_PEERS; i++)
    {
        RtcPeer* peer = &rtc->peers[i];
        if (peer->state != PeerState::free)
        {
            continue;
        }
        if (!send_command(Command::peer_open, offers ? 1 : 0, rtc->id, static_cast<uint8_t>(i), nullptr, 0, nullptr,
                          0))
        {
            return false;
        }
        *peer = RtcPeer();
        peer->state = PeerState::connecting;
        *index = i;
        return true;
    }
    return false;
}

bool net_rtc_connect(NetRtc* rtc, uint32_t* index)
{
    return rtc != nullptr && open_peer(rtc, true, index);
}

bool net_rtc_accept(NetRtc* rtc, uint32_t* index)
{
    return rtc != nullptr && open_peer(rtc, false, index);
}

static bool peer_live(const NetRtc* rtc, uint32_t index)
{
    return index < NET_RTC_MAX_PEERS &&
           (rtc->peers[index].state == PeerState::connecting || rtc->peers[index].state == PeerState::connected);
}

bool net_rtc_signal(NetRtc* rtc, uint32_t index, const uint8_t* data, size_t size)
{
    if (!peer_live(rtc, index) || size < 3 || size > NET_RTC_MAX_SIGNAL)
    {
        return false;
    }
    return send_command(Command::peer_signal, 0, rtc->id, static_cast<uint8_t>(index), data, size, nullptr, 0);
}

static void close_peer(NetRtc* rtc, uint32_t index, bool reported)
{
    rtc->peers[index].state = PeerState::closing;
    rtc->peers[index].reported = reported;
    send_command(Command::peer_close, 0, rtc->id, static_cast<uint8_t>(index), nullptr, 0, nullptr, 0);
}

bool net_rtc_poll(NetRtc* rtc, NetRtcEvent* event, double now)
{
    *event = {};
    if (rtc->release != 0)
    {
        ring_release(rtc->ring, rtc->release);
        rtc->release = 0;
    }
    for (;;)
    {
        const RecordHeader* record = ring_peek(rtc->ring);
        if (record == nullptr)
        {
            break;
        }
        bool give = false;
        if (record->index < NET_RTC_MAX_PEERS)
        {
            RtcPeer* peer = &rtc->peers[record->index];
            event->index = record->index;
            switch (static_cast<Event>(record->kind))
            {
            case Event::connected:
                if (peer->state == PeerState::connecting)
                {
                    peer->state = PeerState::connected;
                    event->type = NetRtcEventType::connected;
                    give = true;
                }
                break;
            case Event::disconnected:
                if (peer->state != PeerState::free)
                {
                    give = !peer->reported;
                    *peer = RtcPeer();
                    event->type = NetRtcEventType::disconnected;
                }
                break;
            case Event::received:
                if (peer->state == PeerState::connected && record->channel < NET_CHANNEL_COUNT)
                {
                    event->type = NetRtcEventType::received;
                    event->channel = static_cast<NetChannel>(record->channel);
                    event->data = record_payload(record);
                    event->size = record->size;
                    give = true;
                }
                break;
            case Event::signal:
                if (peer->state == PeerState::connecting || peer->state == PeerState::connected)
                {
                    event->type = NetRtcEventType::signal;
                    event->data = record_payload(record);
                    event->size = record->size;
                    give = true;
                }
                break;
            case Event::socket_open:
            case Event::socket_message:
            case Event::socket_closed:
                break;
            }
        }
        if (give)
        {
            rtc->release = record->length;   // its bytes stay valid until the next poll
            return true;
        }
        ring_release(rtc->ring, record->length);
        *event = {};
    }
    // Connections that never came up.
    for (uint32_t i = 0; i < NET_RTC_MAX_PEERS; i++)
    {
        RtcPeer* peer = &rtc->peers[i];
        if (peer->state != PeerState::connecting)
        {
            continue;
        }
        if (peer->started < 0.0)
        {
            peer->started = now;
        }
        else if (now - peer->started > NET_RTC_CONNECT_SECONDS)
        {
            close_peer(rtc, i, true);
            event->type = NetRtcEventType::disconnected;
            event->index = i;
            return true;
        }
    }
    return false;
}

bool net_rtc_send(NetRtc* rtc, uint32_t index, NetChannel channel, const uint8_t* data, size_t size)
{
    if (index >= NET_RTC_MAX_PEERS || rtc->peers[index].state != PeerState::connected || size > NET_RTC_MAX_MESSAGE)
    {
        return false;
    }
    uint32_t slot = index * NET_CHANNEL_COUNT + static_cast<uint32_t>(channel);
    rtc->queued[slot].fetch_add(static_cast<uint32_t>(size));
    if (!send_command(Command::peer_send, static_cast<uint8_t>(channel), rtc->id, static_cast<uint8_t>(index), data,
                      size, nullptr, 0))
    {
        rtc->queued[slot].fetch_sub(static_cast<uint32_t>(size));
        return false;
    }
    return true;
}

bool net_rtc_connected(const NetRtc* rtc, uint32_t index)
{
    return index < NET_RTC_MAX_PEERS && rtc->peers[index].state == PeerState::connected;
}

void net_rtc_close(NetRtc* rtc, uint32_t index)
{
    if (peer_live(rtc, index))
    {
        close_peer(rtc, index, false);   // `disconnected` comes when JS has closed it
    }
}

size_t net_rtc_buffered(const NetRtc* rtc, uint32_t index, NetChannel channel)
{
    if (!peer_live(rtc, index))
    {
        return 0;
    }
    uint32_t slot = index * NET_CHANNEL_COUNT + static_cast<uint32_t>(channel);
    return static_cast<size_t>(rtc->queued[slot].load()) + rtc->buffered[slot].load();
}

// --- The signaling WebSocket -------------------------------------------------

struct NetRtcSocket
{
    uint8_t   id = 0;
    SlotState state = SlotState::free;
    bool      close_sent = false;
    bool      opened = false;
    bool      closed = false;
    Ring*     ring = nullptr;
    uint32_t  release = 0;
};

static NetRtcSocket g_sockets[MAX_SOCKETS];

NetRtcSocket* net_rtc_socket_open(const char* url)
{
    std::lock_guard<std::mutex> guard(g_slots_lock);
    NetRtcSocket* socket = nullptr;
    for (uint32_t i = 0; i < MAX_SOCKETS && socket == nullptr; i++)
    {
        NetRtcSocket* candidate = &g_sockets[i];
        if (candidate->state == SlotState::closing && !candidate->close_sent)
        {
            candidate->close_sent = send_command(Command::socket_close, 0, static_cast<uint8_t>(i), 0, nullptr, 0,
                                                 nullptr, 0);
        }
        if (candidate->ring == nullptr || try_reclaim(candidate->ring, &candidate->state))
        {
            socket = candidate;
            socket->id = static_cast<uint8_t>(i);
        }
    }
    if (socket == nullptr)
    {
        host_log(LogLevel::warning, "Network: no free signaling socket (%u in use)", MAX_SOCKETS);
        return nullptr;
    }
    if (socket->ring == nullptr)
    {
        socket->ring = ring_allocate(SOCKET_RING_SIZE);
    }
    socket->release = 0;
    socket->close_sent = false;
    socket->opened = false;
    socket->closed = false;
    uint8_t head[4];
    put_u32(head, address_of(socket->ring));
    if (!send_command(Command::socket_open, 0, socket->id, 0, head, sizeof(head), reinterpret_cast<const uint8_t*>(url),
                      std::strlen(url)))
    {
        return nullptr;
    }
    socket->state = SlotState::open;
    return socket;
}

void net_rtc_socket_close(NetRtcSocket* socket)
{
    if (socket == nullptr)
    {
        return;
    }
    std::lock_guard<std::mutex> guard(g_slots_lock);
    socket->state = SlotState::closing;
    socket->close_sent = send_command(Command::socket_close, 0, socket->id, 0, nullptr, 0, nullptr, 0);
}

NetRtcSocketEvent net_rtc_socket_poll(NetRtcSocket* socket, const uint8_t** data, size_t* size)
{
    *data = nullptr;
    *size = 0;
    if (socket->release != 0)
    {
        ring_release(socket->ring, socket->release);
        socket->release = 0;
    }
    for (;;)
    {
        const RecordHeader* record = ring_peek(socket->ring);
        if (record == nullptr || socket->closed)
        {
            return NetRtcSocketEvent::none;
        }
        Event kind = static_cast<Event>(record->kind);
        if (kind == Event::socket_open && !socket->opened)
        {
            socket->opened = true;
            ring_release(socket->ring, record->length);
            return NetRtcSocketEvent::open;
        }
        if (kind == Event::socket_message && socket->opened)
        {
            *data = record_payload(record);
            *size = record->size;
            socket->release = record->length;
            return NetRtcSocketEvent::message;
        }
        ring_release(socket->ring, record->length);
        if (kind == Event::socket_closed)
        {
            socket->closed = true;
            return NetRtcSocketEvent::closed;
        }
    }
}

bool net_rtc_socket_send(NetRtcSocket* socket, const uint8_t* data, size_t size)
{
    return socket->opened && !socket->closed &&
           send_command(Command::socket_send, 0, socket->id, 0, data, size, nullptr, 0);
}
