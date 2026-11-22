#include "net_signal.h"

#include <cstring>

#include <monocypher.h>

#include "host_log.h"
#include "net_beacon.h"
#include "net_random.h"

// Who sealed a blob, in its associated data: a blob can't be sent back to
// the side that made it.
static const uint8_t FROM_HOST = 1;
static const uint8_t FROM_CLIENT = 2;

std::string net_signal_url(const char* beacon)
{
    if (std::strstr(beacon, "://") != nullptr)
    {
        return beacon;
    }
    // A port given for UDP ("name:55430") isn't the signaling one: the name only.
    std::string name = beacon;
    if (!name.empty() && name[0] != '[')
    {
        size_t colon = name.find(':');
        if (colon != std::string::npos && name.find(':', colon + 1) == std::string::npos)
        {
            name.resize(colon);
        }
    }
    return "wss://" + name + "/signal";
}

std::string net_signal_stun(const char* beacon)
{
    std::string name = beacon;
    size_t scheme = name.find("://");
    if (scheme != std::string::npos)
    {
        name = name.substr(scheme + 3);
        size_t slash = name.find('/');
        if (slash != std::string::npos)
        {
            name.resize(slash);
        }
    }
    if (!name.empty() && name[0] != '[')
    {
        size_t colon = name.find(':');
        if (colon != std::string::npos && name.find(':', colon + 1) == std::string::npos)
        {
            name.resize(colon);
        }
    }
    return "stun:" + name + ":55430";
}

static void close_socket(NetSignal* signal)
{
    net_rtc_socket_close(signal->socket);
    signal->socket = nullptr;
    signal->open = false;
    signal->joined = false;
}

void net_signal_stop(NetSignal* signal)
{
    close_socket(signal);
    signal->url.clear();
    signal->rooms.clear();
    signal->failure = NetSignalFailure::none;
    signal->patient = false;
}

void net_signal_host_start(NetSignal* signal, const char* url)
{
    if (signal->role == NetSignalRole::host && signal->url == (url != nullptr ? url : ""))
    {
        return;
    }
    close_socket(signal);
    signal->role = NetSignalRole::host;
    signal->url = url != nullptr ? url : "";
    signal->retry_at = 0.0;
    signal->failed_once = false;
}

static void keep_peer(const NetSignal* signal, NetSignalRoom* room)
{
    for (size_t j = 0; j < signal->rooms.size(); j++)
    {
        if (beacon_id_equal(&signal->rooms[j].room, &room->room))
        {
            room->peer = signal->rooms[j].peer;   // a room that stays keeps its connection
        }
    }
}

void net_signal_host_set_rooms(NetSignal* signal, const NetKeypair* own, const uint8_t (*device_keys)[NET_KEY_SIZE],
                               uint32_t count, const char* pair_slot)
{
    std::vector<NetSignalRoom> rooms;
    if (pair_slot != nullptr)
    {
        NetSignalRoom room;
        net_beacon_pair_id(pair_slot, &room.room);
        net_beacon_pair_signal_key(pair_slot, room.key);
        keep_peer(signal, &room);
        rooms.push_back(room);
    }
    for (uint32_t i = 0; i < count && rooms.size() < NET_SIGNAL_MAX_ROOMS; i++)
    {
        NetSignalRoom room;
        if (!net_beacon_meeting_id(own, device_keys[i], &room.room) ||
            !net_beacon_signal_key(own, device_keys[i], room.key))
        {
            continue;
        }
        keep_peer(signal, &room);
        rooms.push_back(room);
    }
    for (size_t j = 0; j < signal->rooms.size(); j++)
    {
        crypto_wipe(signal->rooms[j].key, sizeof(signal->rooms[j].key));
    }
    signal->rooms = rooms;
    signal->next_join = 0.0;   // joined again at the next update (new rooms at once)
}

bool net_signal_client_start(NetSignal* signal, const char* url, const NetKeypair* own, const uint8_t* host_key,
                             double now)
{
    net_signal_stop(signal);
    NetSignalRoom room;
    if (!net_beacon_meeting_id(own, host_key, &room.room) || !net_beacon_signal_key(own, host_key, room.key))
    {
        return false;
    }
    signal->role = NetSignalRole::client;
    signal->url = url;
    signal->rooms.push_back(room);
    signal->socket = net_rtc_socket_open(url);
    signal->started = now;
    signal->failure = NetSignalFailure::none;
    return signal->socket != nullptr;
}

bool net_signal_client_start_pair(NetSignal* signal, const char* url, const char* slot, double now)
{
    net_signal_stop(signal);
    NetSignalRoom room;
    net_beacon_pair_id(slot, &room.room);
    net_beacon_pair_signal_key(slot, room.key);
    signal->role = NetSignalRole::client;
    signal->patient = true;
    signal->url = url;
    signal->rooms.push_back(room);
    signal->socket = net_rtc_socket_open(url);
    signal->started = now;
    signal->failure = NetSignalFailure::none;
    return signal->socket != nullptr;
}

static bool send_message(NetSignal* signal, const BeaconSignalingMessage* message)
{
    uint32_t size = beacon_signaling_encode(message, signal->out, sizeof(signal->out));
    return size > 0 && net_rtc_socket_send(signal->socket, signal->out, size);
}

static void join_all(NetSignal* signal)
{
    for (size_t i = 0; i < signal->rooms.size(); i++)
    {
        BeaconSignalingMessage join;
        join.type = BeaconSignalingType::JOIN;
        join.room = signal->rooms[i].room;
        join.role = signal->role == NetSignalRole::host ? BeaconRole::HOST : BeaconRole::CLIENT;
        send_message(signal, &join);
    }
}

static NetSignalRoom* room_of(NetSignal* signal, const BeaconId* id)
{
    for (size_t i = 0; i < signal->rooms.size(); i++)
    {
        if (beacon_id_equal(&signal->rooms[i].room, id))
        {
            return &signal->rooms[i];
        }
    }
    return nullptr;
}

// Seals `size` bytes of `blob` for the other side of `room` and sends it.
static void send_blob(NetSignal* signal, NetSignalRoom* room, const uint8_t* blob, size_t size)
{
    if (!signal->open || size == 0 || size + NET_SIGNAL_OVERHEAD > BEACON_SIGNALING_MAX_BLOB)
    {
        return;
    }
    uint8_t* sealed = signal->plain;   // nonce | mac | cipher, built in place
    if (!net_random_bytes(sealed, 24))
    {
        return;
    }
    uint8_t from = signal->role == NetSignalRole::host ? FROM_HOST : FROM_CLIENT;
    crypto_aead_lock(sealed + 40, sealed + 24, room->key, sealed, &from, 1, blob, size);
    BeaconSignalingMessage message;
    message.type = BeaconSignalingType::SIGNAL;
    message.room = room->room;
    message.blob = sealed;
    message.blob_size = static_cast<uint32_t>(size + NET_SIGNAL_OVERHEAD);
    send_message(signal, &message);
}

void net_signal_outgoing(NetSignal* signal, uint32_t peer, const uint8_t* blob, size_t size)
{
    for (size_t i = 0; i < signal->rooms.size(); i++)
    {
        if (signal->rooms[i].peer == peer)
        {
            send_blob(signal, &signal->rooms[i], blob, size);
            return;
        }
    }
}

void net_signal_peer_gone(NetSignal* signal, uint32_t peer)
{
    for (size_t i = 0; i < signal->rooms.size(); i++)
    {
        if (signal->rooms[i].peer == peer)
        {
            signal->rooms[i].peer = NET_NO_PEER;
        }
    }
}

// An offer starts a new connection on the host (a client that came back
// offers again: the old peer, if any, times out on its own).
static bool is_offer(const uint8_t* blob, size_t size)
{
    return size > 7 && blob[0] == 'd' && std::memcmp(blob + 1, "offer", 6) == 0;
}

static void on_signal(NetSignal* signal, NetSession* session, NetSignalRoom* room, const uint8_t* sealed, size_t size)
{
    if (size <= NET_SIGNAL_OVERHEAD)
    {
        return;
    }
    size_t plain_size = size - NET_SIGNAL_OVERHEAD;
    uint8_t from = signal->role == NetSignalRole::host ? FROM_CLIENT : FROM_HOST;
    if (crypto_aead_unlock(signal->plain, sealed + 24, room->key, sealed, &from, 1, sealed + 40, plain_size) != 0)
    {
        return;   // not from the other side of this pairing: dropped
    }
    if (signal->role == NetSignalRole::host && is_offer(signal->plain, plain_size))
    {
        uint32_t peer = NET_NO_PEER;
        if (!net_session_rtc_accept(session, &peer))
        {
            host_log(LogLevel::warning, "Network: a WebRTC offer came, but there's no free peer slot");
            return;
        }
        room->peer = peer;
    }
    if (room->peer != NET_NO_PEER)
    {
        net_session_rtc_signal(session, room->peer, signal->plain, plain_size);
    }
}

static void on_message(NetSignal* signal, NetSession* session, const uint8_t* data, size_t size)
{
    BeaconSignalingMessage message;
    if (!beacon_signaling_decode(data, size, &message))
    {
        return;
    }
    NetSignalRoom* room = room_of(signal, &message.room);
    if (room == nullptr)
    {
        return;
    }
    bool client = signal->role == NetSignalRole::client;
    switch (message.type)
    {
    case BeaconSignalingType::JOINED:
        if (client)
        {
            signal->joined = true;
            if (message.peer_present == 0 && !signal->patient)
            {
                signal->failure = NetSignalFailure::host_offline;
            }
            else if (room->peer == NET_NO_PEER && !net_session_rtc_connect(session, &room->peer))
            {
                room->peer = NET_NO_PEER;
            }
        }
        break;
    case BeaconSignalingType::PEER_JOINED:
        // The host arrived after us (client: offer now); or a client came
        // back (host: its new offer will start a new peer).
        if (client && room->peer == NET_NO_PEER && signal->failure == NetSignalFailure::none &&
            !net_session_rtc_connect(session, &room->peer))
        {
            room->peer = NET_NO_PEER;
        }
        break;
    case BeaconSignalingType::NOT_FOUND:
        if (client && !signal->patient && net_signal_client_peer(signal) == NET_NO_PEER)
        {
            signal->failure = NetSignalFailure::host_offline;
        }
        break;
    case BeaconSignalingType::SIGNAL:
        on_signal(signal, session, room, message.blob, message.blob_size);
        break;
    case BeaconSignalingType::REFUSED:
        host_log(LogLevel::warning, "Network: the beacon refused a signaling room (its limit)");
        break;
    case BeaconSignalingType::LEFT:
    case BeaconSignalingType::JOIN:
    case BeaconSignalingType::LEAVE:
        break;
    }
}

void net_signal_update(NetSignal* signal, NetSession* session, double now)
{
    if (signal->url.empty())
    {
        return;
    }
    // The host keeps a socket open, opening a new one after a failure.
    if (signal->socket == nullptr)
    {
        if (signal->role != NetSignalRole::host || now < signal->retry_at)
        {
            return;
        }
        signal->socket = net_rtc_socket_open(signal->url.c_str());
        signal->started = now;
        if (signal->socket == nullptr)
        {
            signal->retry_at = now + NET_SIGNAL_RETRY_SECONDS;
            signal->failed_once = true;
            return;
        }
    }
    const uint8_t* data = nullptr;
    size_t size = 0;
    for (;;)
    {
        NetRtcSocketEvent event = net_rtc_socket_poll(signal->socket, &data, &size);
        if (event == NetRtcSocketEvent::none)
        {
            break;
        }
        if (event == NetRtcSocketEvent::open)
        {
            signal->open = true;
            signal->failed_once = false;
            join_all(signal);
            signal->next_join = now + NET_SIGNAL_JOIN_SECONDS;
        }
        else if (event == NetRtcSocketEvent::message)
        {
            on_message(signal, session, data, size);
        }
        else
        {
            bool was_open = signal->open;
            close_socket(signal);
            signal->failed_once = !was_open;
            signal->retry_at = now + NET_SIGNAL_RETRY_SECONDS;
            if (signal->role == NetSignalRole::client && net_signal_client_peer(signal) == NET_NO_PEER &&
                signal->failure == NetSignalFailure::none)
            {
                signal->failure = NetSignalFailure::unreachable;
            }
            return;
        }
    }
    if ((signal->role == NetSignalRole::host || signal->patient) && signal->open && now >= signal->next_join)
    {
        join_all(signal);
        signal->next_join = now + NET_SIGNAL_JOIN_SECONDS;
    }
    if (signal->role == NetSignalRole::client && !signal->joined && signal->failure == NetSignalFailure::none &&
        now - signal->started > NET_SIGNAL_CLIENT_SECONDS)
    {
        signal->failure = NetSignalFailure::unreachable;
    }
}

NetSignalStatus net_signal_status(const NetSignal* signal, double now)
{
    (void)now;
    if (signal->url.empty())
    {
        return NetSignalStatus::off;
    }
    if (signal->open)
    {
        return NetSignalStatus::ready;
    }
    return signal->failed_once ? NetSignalStatus::unreachable : NetSignalStatus::connecting;
}

uint32_t net_signal_client_peer(const NetSignal* signal)
{
    return signal->rooms.empty() ? NET_NO_PEER : signal->rooms[0].peer;
}
