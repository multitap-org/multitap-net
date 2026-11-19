#include "net_access.h"

#include <cstring>

#include "host_log.h"
#include "monocypher.h"

bool net_access_create(NetAccess* access, uint16_t port, const char* name, const NetKeypair* identity,
                       const char* trust_path)
{
    access->trust_path = trust_path;
    access->name = name;
    std::memcpy(access->host_key, identity->public_key, NET_KEY_SIZE);
    access->out.resize(NET_PAIR_MAX_MESSAGE);
    net_trust_load(&access->trust, trust_path);
    return net_session_create_listener(&access->session, port, name, identity);
}

static void peer_reset(NetAccessPeer* peer)
{
    crypto_wipe(peer->isk, sizeof(peer->isk));
    *peer = {};
}

void net_access_destroy(NetAccess* access)
{
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        peer_reset(&access->peers[i]);
    }
    net_access_close_pairing(access);
    net_session_destroy(&access->session);
}

static void save_trust(NetAccess* access)
{
    if (!net_trust_save(&access->trust, access->trust_path.c_str()))
    {
        host_log(LogLevel::error, "Network: could not save the paired devices to %s", access->trust_path.c_str());
    }
}

static void send_control(NetAccess* access, uint32_t peer, size_t size)
{
    if (size > 0)
    {
        net_session_send(&access->session, peer, NetChannel::control, access->out.data(), size);
    }
}

bool net_access_open_pairing(NetAccess* access)
{
    if (!net_pair_code_generate(access->code))
    {
        return false;
    }
    if (!access->pairing_open)
    {
        access->pairing_open = true;
        access->pairing_opened_at = net_seconds();
        access->pairing_failures = 0;
    }
    return true;
}

void net_access_close_pairing(NetAccess* access)
{
    access->pairing_open = false;
    crypto_wipe(access->code, sizeof(access->code));
}

double net_access_pairing_seconds_left(const NetAccess* access)
{
    if (!access->pairing_open)
    {
        return 0.0;
    }
    double left = NET_PAIRING_OPEN_SECONDS - (net_seconds() - access->pairing_opened_at);
    return left > 0.0 ? left : 0.0;
}

// An attempt didn't succeed: the code it may have learned something about is
// replaced, and too many failures close pairing. Fills `event`.
static void pairing_failed(NetAccess* access, NetAccessEvent* event)
{
    event->type = NetAccessEventType::pairing_failed;
    if (!access->pairing_open)
    {
        return;
    }
    access->pairing_failures++;
    if (access->pairing_failures >= NET_PAIRING_MAX_FAILURES)
    {
        host_log(LogLevel::warning, "Network: %u failed pairing attempts, pairing closed",
                 static_cast<unsigned>(access->pairing_failures));
        net_access_close_pairing(access);
        return;
    }
    if (!net_pair_code_generate(access->code))
    {
        net_access_close_pairing(access);
    }
}

static bool someone_pairing(const NetAccess* access)
{
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        if (access->peers[i].state == NetAccessPeerState::pairing)
        {
            return true;
        }
    }
    return false;
}

static void on_secured(NetAccess* access, const NetSessionEvent* session_event, NetAccessEvent* event, bool* filled)
{
    uint32_t index = session_event->peer;
    if (index >= NET_MAX_PEERS)
    {
        return;
    }
    NetAccessPeer* peer = &access->peers[index];
    peer_reset(peer);
    std::memcpy(peer->key, session_event->remote_key, NET_KEY_SIZE);
    std::memcpy(peer->handshake_hash, session_event->handshake_hash, NET_HASH_SIZE);
    peer->since = net_seconds();

    int32_t device = net_trust_find(&access->trust, peer->key);
    if (device >= 0)
    {
        peer->state = NetAccessPeerState::authorized;
        peer->device = device;
        send_control(access, index, net_message_write_welcome(access->out.data(), access->out.size(), access->name.c_str()));
        event->type = NetAccessEventType::authorized;
        event->peer = index;
        event->device = device;
        event->address = session_event->address;
        *filled = true;
        return;
    }
    peer->state = NetAccessPeerState::unpaired;
    send_control(access, index,
                 net_message_write_pairing_needed(access->out.data(), access->out.size(), access->pairing_open,
                                                  access->name.c_str()));
    if (!access->pairing_open)
    {
        // Sent first: ENet delivers queued messages before disconnecting.
        // (A client without a code closes on its own; one with a code waits
        // for this.)
        net_session_close(&access->session, index);
    }
}

static void refuse_pairing(NetAccess* access, uint32_t index)
{
    send_control(access, index, net_message_write_pair_result(access->out.data(), access->out.size(), false));
    net_session_close(&access->session, index);
}

static void on_pair_request(NetAccess* access, uint32_t index, const uint8_t* data, size_t size, NetAccessEvent* event,
                            bool* filled)
{
    NetAccessPeer* peer = &access->peers[index];
    uint8_t their_share[NET_CPACE_SHARE_SIZE];
    if (!access->pairing_open || someone_pairing(access) ||
        !net_message_read_pair_request(data, size, their_share, peer->name))
    {
        refuse_pairing(access, index);
        return;
    }
    uint8_t ci[NET_PAIR_CI_SIZE];
    net_pair_ci(peer->key, access->host_key, ci);
    NetCpace cpace;
    uint8_t prs[NET_PAIR_CODE_DIGITS];
    for (size_t i = 0; i < NET_PAIR_CODE_DIGITS; i++)
    {
        prs[i] = static_cast<uint8_t>(access->code[i]);
    }
    bool started = net_cpace_start(&cpace, prs, sizeof(prs), ci, sizeof(ci), peer->handshake_hash, NET_PAIR_SID_SIZE);
    crypto_wipe(prs, sizeof(prs));
    uint8_t our_share[NET_CPACE_SHARE_SIZE];
    std::memcpy(our_share, cpace.share, sizeof(our_share));
    // ADa = the client's name as it sent it, ADb = ours as we send it.
    uint8_t ad_a[NET_DEVICE_NAME_MAX];
    uint8_t ad_b[NET_DEVICE_NAME_MAX];
    size_t ad_a_size = net_pair_name_bytes(peer->name, ad_a);
    size_t ad_b_size = net_pair_name_bytes(access->name.c_str(), ad_b);
    bool finished = started && net_cpace_finish(&cpace, false, their_share, ad_a, ad_a_size, ad_b, ad_b_size,
                                                peer->handshake_hash, NET_PAIR_SID_SIZE, peer->isk);
    net_cpace_wipe(&cpace);
    if (!finished)
    {
        // A low-order share: not an honest client.
        refuse_pairing(access, index);
        pairing_failed(access, event);
        *filled = true;
        return;
    }
    uint8_t confirm[NET_PAIR_CONFIRM_SIZE];
    net_pair_confirm(peer->isk, true, confirm);
    send_control(access, index,
                 net_message_write_pair_response(access->out.data(), access->out.size(), our_share, confirm,
                                                 access->name.c_str()));
    peer->state = NetAccessPeerState::pairing;
    peer->since = net_seconds();
}

static void on_pair_confirm(NetAccess* access, uint32_t index, const uint8_t* data, size_t size, NetAccessEvent* event,
                            bool* filled)
{
    NetAccessPeer* peer = &access->peers[index];
    uint8_t received[NET_PAIR_CONFIRM_SIZE];
    uint8_t expected[NET_PAIR_CONFIRM_SIZE];
    net_pair_confirm(peer->isk, false, expected);
    bool ok = net_message_read_pair_confirm(data, size, received) && crypto_verify32(received, expected) == 0;
    crypto_wipe(peer->isk, sizeof(peer->isk));
    if (!ok)
    {
        peer->state = NetAccessPeerState::unpaired;
        refuse_pairing(access, index);
        pairing_failed(access, event);
        *filled = true;
        return;
    }
    uint32_t device = net_trust_add(&access->trust, peer->key, peer->name);
    save_trust(access);
    send_control(access, index, net_message_write_pair_result(access->out.data(), access->out.size(), true));
    peer->state = NetAccessPeerState::authorized;
    peer->device = static_cast<int32_t>(device);
    net_access_close_pairing(access);   // one device per code shown
    char fingerprint[32];
    net_key_fingerprint(peer->key, fingerprint, sizeof(fingerprint));
    host_log(LogLevel::info, "Network: paired with \"%s\" (%s)", access->trust.devices[device].name.c_str(), fingerprint);
    event->type = NetAccessEventType::paired;
    event->peer = index;
    event->device = static_cast<int32_t>(device);
    *filled = true;
}

static bool on_message(NetAccess* access, const NetSessionEvent* session_event, NetAccessEvent* event)
{
    uint32_t index = session_event->peer;
    if (index >= NET_MAX_PEERS)
    {
        return false;
    }
    NetAccessPeer* peer = &access->peers[index];
    bool filled = false;
    if (peer->state == NetAccessPeerState::authorized)
    {
        // Control messages of this layer aren't the application's.
        if (session_event->channel == NetChannel::control &&
            net_message_type(session_event->data, session_event->size) < NET_MESSAGE_FIRST_APP)
        {
            return false;
        }
        event->type = NetAccessEventType::message;
        event->peer = index;
        event->device = peer->device;
        event->address = session_event->address;
        event->channel = session_event->channel;
        event->data = session_event->data;
        event->size = session_event->size;
        return true;
    }
    if (session_event->channel != NetChannel::control)
    {
        return false;   // input from someone not authorized: ignored
    }
    uint8_t type = net_message_type(session_event->data, session_event->size);
    if (peer->state == NetAccessPeerState::unpaired && type == static_cast<uint8_t>(NetMessage::pair_request))
    {
        on_pair_request(access, index, session_event->data, session_event->size, event, &filled);
    }
    else if (peer->state == NetAccessPeerState::pairing && type == static_cast<uint8_t>(NetMessage::pair_confirm))
    {
        on_pair_confirm(access, index, session_event->data, session_event->size, event, &filled);
    }
    else
    {
        // Anything else before authorization is a protocol error.
        bool was_pairing = peer->state == NetAccessPeerState::pairing;
        refuse_pairing(access, index);
        if (was_pairing)
        {
            pairing_failed(access, event);
            filled = true;
        }
    }
    if (filled)
    {
        event->peer = index;
        event->address = session_event->address;
    }
    return filled;
}

// Pairing's own clock, and peers stuck in a step.
static bool check_timers(NetAccess* access, NetAccessEvent* event)
{
    if (access->pairing_open && net_access_pairing_seconds_left(access) <= 0.0)
    {
        net_access_close_pairing(access);
        event->type = NetAccessEventType::pairing_closed;
        return true;
    }
    double now = net_seconds();
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        NetAccessPeer* peer = &access->peers[i];
        bool waiting = peer->state == NetAccessPeerState::unpaired || peer->state == NetAccessPeerState::pairing;
        if (waiting && now - peer->since > NET_ACCESS_PAIRING_STEP_SECONDS)
        {
            net_session_close(&access->session, i);
            peer->since = now;   // closing takes a moment; don't repeat every frame
        }
    }
    return false;
}

bool net_access_poll(NetAccess* access, NetAccessEvent* event)
{
    *event = {};
    if (check_timers(access, event))
    {
        return true;
    }
    NetSessionEvent session_event;
    while (net_session_poll(&access->session, &session_event))
    {
        bool filled = false;
        switch (session_event.type)
        {
        case NetSessionEventType::none:
        case NetSessionEventType::discovered:
            break;
        case NetSessionEventType::secured:
            on_secured(access, &session_event, event, &filled);
            break;
        case NetSessionEventType::message:
            filled = on_message(access, &session_event, event);
            break;
        case NetSessionEventType::closed:
        {
            if (session_event.peer >= NET_MAX_PEERS)
            {
                break;
            }
            NetAccessPeer* peer = &access->peers[session_event.peer];
            NetAccessPeerState state = peer->state;
            int32_t device = peer->device;
            peer_reset(peer);
            if (state == NetAccessPeerState::pairing)
            {
                // Gone in the middle of pairing (a client that saw a wrong
                // confirmation closes): counts as a failed attempt.
                pairing_failed(access, event);
                event->peer = session_event.peer;
                filled = true;
            }
            else if (state == NetAccessPeerState::authorized)
            {
                event->type = NetAccessEventType::closed;
                event->peer = session_event.peer;
                event->device = device;
                event->address = session_event.address;
                filled = true;
            }
            break;
        }
        }
        if (filled)
        {
            return true;
        }
    }
    return false;
}

bool net_access_send(NetAccess* access, uint32_t peer, NetChannel channel, const uint8_t* data, size_t size)
{
    if (peer >= NET_MAX_PEERS || access->peers[peer].state != NetAccessPeerState::authorized)
    {
        return false;
    }
    if (channel == NetChannel::control && net_message_type(data, size) < NET_MESSAGE_FIRST_APP)
    {
        return false;
    }
    return net_session_send(&access->session, peer, channel, data, size);
}

void net_access_close(NetAccess* access, uint32_t peer)
{
    net_session_close(&access->session, peer);
}

void net_access_remove_device(NetAccess* access, uint32_t device)
{
    if (device >= access->trust.devices.size())
    {
        return;
    }
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        NetAccessPeer* peer = &access->peers[i];
        if (peer->state == NetAccessPeerState::authorized)
        {
            if (peer->device == static_cast<int32_t>(device))
            {
                net_session_close(&access->session, i);
                peer->state = NetAccessPeerState::none;   // nothing more from it reaches the frontend
                peer->device = -1;
            }
            else if (peer->device > static_cast<int32_t>(device))
            {
                peer->device--;   // indexes after it move down
            }
        }
    }
    net_trust_remove(&access->trust, device);
    save_trust(access);
}

void net_access_set_own(NetAccess* access, uint32_t device, bool own)
{
    if (device < access->trust.devices.size())
    {
        access->trust.devices[device].own = own;
        save_trust(access);
    }
}

bool net_access_device_connected(const NetAccess* access, uint32_t device)
{
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        if (access->peers[i].state == NetAccessPeerState::authorized &&
            access->peers[i].device == static_cast<int32_t>(device))
        {
            return true;
        }
    }
    return false;
}
