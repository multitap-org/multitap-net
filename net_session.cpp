#include "net_session.h"

#include <chrono>
#include <cstdio>
#include <cstring>

#include "host_log.h"
#include "monocypher.h"

double net_seconds()
{
    std::chrono::steady_clock::duration since = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration<double>(since).count();
}

static void buffers_create(NetSession* session)
{
    // Sized once: the largest Noise message either way.
    session->wire.resize(NET_NOISE_MAX_MESSAGE);
    session->payload.resize(NET_NOISE_MAX_MESSAGE);
}

bool net_session_create_listener(NetSession* session, uint16_t port, const char* name, const NetKeypair* identity)
{
    // (handshake_seconds is kept: a test may have set it before creating.)
    session->identity = *identity;
    buffers_create(session);
    return net_host_create_listener(&session->host, port, name);
}

bool net_session_create_client(NetSession* session, const NetKeypair* identity)
{
    session->identity = *identity;
    buffers_create(session);
    return net_host_create_client(&session->host);
}

void net_session_destroy(NetSession* session)
{
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        net_link_wipe(&session->peers[i].link);
        session->peers[i] = {};
    }
    net_keypair_wipe(&session->identity);
    net_host_destroy(&session->host);
}

static NetSessionPeer* peer_get(NetSession* session, uint32_t peer)
{
    if (peer >= NET_MAX_PEERS)
    {
        return nullptr;
    }
    return &session->peers[peer];
}

// The link is dead: drop the connection (ENet's `disconnected` reports it).
static void peer_fail(NetSession* session, uint32_t index, const char* why)
{
    host_log(LogLevel::info, "Network: peer %u closed: %s", static_cast<unsigned>(index), why);
    net_link_wipe(&session->peers[index].link);
    net_host_disconnect(&session->host, index);
}

static void on_connected(NetSession* session, const NetEvent* net)
{
    NetSessionPeer* peer = peer_get(session, net->peer);
    if (peer == nullptr)
    {
        return;
    }
    bool initiator = peer->initiator;   // set by net_session_connect
    *peer = {};
    peer->connected = true;
    peer->initiator = initiator;
    peer->connected_at = net_seconds();
    net_link_init(&peer->link, initiator ? NetNoiseRole::initiator : NetNoiseRole::responder, &session->identity);
    if (initiator)
    {
        size_t size = 0;
        if (!net_link_start(&peer->link, session->wire.data(), session->wire.size(), &size) ||
            !net_host_send(&session->host, net->peer, NetChannel::control, session->wire.data(), size))
        {
            peer_fail(session, net->peer, "handshake could not start");
        }
    }
}

// Returns true when `event` was filled (secured or message).
static bool on_received(NetSession* session, const NetEvent* net, NetSessionEvent* event)
{
    NetSessionPeer* peer = peer_get(session, net->peer);
    // Not connected, or already failed and waiting for ENet's disconnect.
    if (peer == nullptr || !peer->connected || peer->link.state == NetLinkState::failed)
    {
        return false;
    }
    size_t payload_size = 0;
    if (net->channel == NetChannel::input)
    {
        if (!net_link_open_input(&peer->link, net->data, net->size, session->payload.data(), session->payload.size(),
                                 &payload_size))
        {
            return false;   // dropped (counted in the link)
        }
        event->type = NetSessionEventType::message;
        event->peer = net->peer;
        event->address = net->address;
        event->channel = NetChannel::input;
        event->data = session->payload.data();
        event->size = payload_size;
        return true;
    }

    size_t reply_size = 0;
    NetLinkReceive result =
        net_link_receive_control(&peer->link, net->data, net->size, session->wire.data(), session->wire.size(),
                                 &reply_size, session->payload.data(), session->payload.size(), &payload_size);
    if (result == NetLinkReceive::failed)
    {
        peer_fail(session, net->peer, peer->secured_reported ? "a control message didn't authenticate"
                                                             : "handshake failed");
        return false;
    }
    if (result == NetLinkReceive::message)
    {
        event->type = NetSessionEventType::message;
        event->peer = net->peer;
        event->address = net->address;
        event->channel = NetChannel::control;
        event->data = session->payload.data();
        event->size = payload_size;
        return true;
    }
    if (reply_size > 0 && !net_host_send(&session->host, net->peer, NetChannel::control, session->wire.data(), reply_size))
    {
        peer_fail(session, net->peer, "handshake reply could not be sent");
        return false;
    }
    if (peer->link.state == NetLinkState::ready && !peer->secured_reported)
    {
        peer->secured_reported = true;
        event->type = NetSessionEventType::secured;
        event->peer = net->peer;
        event->address = net->address;
        std::memcpy(event->remote_key, peer->link.remote_key, NET_KEY_SIZE);
        std::memcpy(event->handshake_hash, peer->link.handshake_hash, NET_HASH_SIZE);
        return true;
    }
    return false;
}

// Handshakes that take too long are given up: a peer that connects and never
// answers would hold a slot until ENet's own (much longer) timeout.
static void check_deadlines(NetSession* session)
{
    double now = net_seconds();
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        NetSessionPeer* peer = &session->peers[i];
        if (peer->connected && peer->link.state == NetLinkState::handshaking &&
            now - peer->connected_at > session->handshake_seconds)
        {
            peer_fail(session, i, "handshake timed out");
        }
    }
}

bool net_session_poll(NetSession* session, NetSessionEvent* event)
{
    *event = {};
    check_deadlines(session);
    NetEvent net;
    while (net_host_poll(&session->host, &net))
    {
        switch (net.type)
        {
        case NetEventType::none:
            break;
        case NetEventType::discovered:
            event->type = NetSessionEventType::discovered;
            event->address = net.address;
            event->discovered = net.discovered;
            return true;
        case NetEventType::connected:
            on_connected(session, &net);
            break;
        case NetEventType::received:
            if (on_received(session, &net, event))
            {
                return true;
            }
            break;
        case NetEventType::disconnected:
        {
            NetSessionPeer* peer = peer_get(session, net.peer);
            if (peer != nullptr && (peer->connected || peer->initiator))
            {
                event->type = NetSessionEventType::closed;
                event->peer = net.peer;
                event->address = net.address;
                event->was_secured = peer->secured_reported;
                net_link_wipe(&peer->link);
                *peer = {};
                return true;
            }
            break;
        }
        }
    }
    return false;
}

bool net_session_discover(NetSession* session, uint16_t port)
{
    return net_host_discover(&session->host, port);
}

bool net_session_discover_at(NetSession* session, NetAddress address)
{
    return net_host_discover_at(&session->host, address);
}

bool net_session_connect(NetSession* session, NetAddress address, uint32_t* peer)
{
    if (!net_host_connect(&session->host, address, peer))
    {
        return false;
    }
    NetSessionPeer* slot = peer_get(session, *peer);
    if (slot == nullptr)
    {
        return false;
    }
    *slot = {};
    slot->initiator = true;   // on_connected starts the handshake
    return true;
}

bool net_session_send(NetSession* session, uint32_t peer, NetChannel channel, const uint8_t* data, size_t size)
{
    NetSessionPeer* slot = peer_get(session, peer);
    if (slot == nullptr || !slot->connected || slot->link.state != NetLinkState::ready)
    {
        return false;
    }
    size_t sealed = 0;
    if (!net_link_seal(&slot->link, channel, data, size, session->wire.data(), session->wire.size(), &sealed))
    {
        return false;
    }
    return net_host_send(&session->host, peer, channel, session->wire.data(), sealed);
}

void net_session_close(NetSession* session, uint32_t peer)
{
    net_host_disconnect(&session->host, peer);
}

void net_key_fingerprint(const uint8_t* key, char* out, size_t capacity)
{
    uint8_t hash[8];
    crypto_blake2b(hash, sizeof(hash), key, NET_KEY_SIZE);
    std::snprintf(out, capacity, "%02x%02x-%02x%02x-%02x%02x-%02x%02x", hash[0], hash[1], hash[2], hash[3], hash[4],
                  hash[5], hash[6], hash[7]);
}
