#include "net_access.h"

#include <cstdio>

#include <cstring>

#include "host_log.h"
#include "monocypher.h"

static void beacon_refresh_ids(NetAccess* access);

bool net_access_create(NetAccess* access, uint16_t port, const char* name, const NetKeypair* identity,
                       const char* trust_path)
{
    access->trust_path = trust_path;
    access->name = name;
    std::memcpy(access->host_key, identity->public_key, NET_KEY_SIZE);
    access->out.resize(NET_PAIR_MAX_MESSAGE);
    net_trust_load(&access->trust, trust_path);
    if (!net_session_create_listener(&access->session, port, name, identity))
    {
        return false;
    }
    beacon_refresh_ids(access);
    return true;
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
    net_access_end_invite(access);
    net_guest_link_wipe(&access->guest_link);
    net_signal_stop(&access->signal);
    net_session_destroy(&access->session);
}

// The beacon registers one meeting id per paired device; computed again when
// the list changes (only then: a level change leaves the ids alone).
static void beacon_refresh_ids(NetAccess* access)
{
    std::vector<BeaconId> ids;
    ids.reserve(access->trust.devices.size() + 1);
    for (size_t i = 0; i < access->trust.devices.size(); i++)
    {
        BeaconId id;
        if (net_beacon_meeting_id(&access->session.identity, access->trust.devices[i].key, &id))
        {
            ids.push_back(id);
        }
    }
    if (access->inviting)
    {
        // The pairing room of the code our user typed: the client waits there.
        BeaconId id;
        net_beacon_pair_id(access->invite_slot, &id);
        ids.push_back(id);
    }
    if (access->guest_open)
    {
        ids.push_back(access->guest_link.meeting);   // the guest link's guests meet us there
    }
    bool same = ids.size() == access->beacon.ids.size();
    for (size_t i = 0; same && i < ids.size(); i++)
    {
        same = beacon_id_equal(&ids[i], &access->beacon.ids[i]);
    }
    if (!same)
    {
        net_beacon_host_set_ids(&access->beacon, ids.data(), static_cast<uint32_t>(ids.size()));
        // The same pairings as signaling rooms (WebRTC: browsers).
        std::vector<uint8_t> keys(access->trust.devices.size() * NET_KEY_SIZE);
        for (size_t i = 0; i < access->trust.devices.size(); i++)
        {
            std::memcpy(&keys[i * NET_KEY_SIZE], access->trust.devices[i].key, NET_KEY_SIZE);
        }
        net_signal_host_set_rooms(&access->signal, &access->session.identity,
                                  reinterpret_cast<const uint8_t(*)[NET_KEY_SIZE]>(keys.data()),
                                  static_cast<uint32_t>(access->trust.devices.size()),
                                  access->inviting ? access->invite_slot : nullptr);
    }
}

static void save_trust(NetAccess* access)
{
    beacon_refresh_ids(access);
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

bool net_access_invite(NetAccess* access, const char* code)
{
    if (!net_pair_code_valid(code))
    {
        return false;
    }
    std::memcpy(access->invite_slot, code, NET_PAIR_SLOT_DIGITS);
    access->invite_slot[NET_PAIR_SLOT_DIGITS] = '\0';
    access->inviting = true;
    beacon_refresh_ids(access);   // the pairing room joins
    return true;
}

void net_access_end_invite(NetAccess* access)
{
    bool was = access->inviting;
    access->inviting = false;
    std::memset(access->invite_slot, 0, sizeof(access->invite_slot));
    if (was)
    {
        beacon_refresh_ids(access);   // and leaves
    }
}

static bool refused_before(const NetAccess* access, const uint8_t* key)
{
    for (size_t i = 0; i + NET_KEY_SIZE <= access->refused_keys.size(); i += NET_KEY_SIZE)
    {
        if (std::memcmp(&access->refused_keys[i], key, NET_KEY_SIZE) == 0)
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
        NetAccessLevel level = access->trust.devices[static_cast<size_t>(device)].access;
        send_control(access, index,
                     net_message_write_welcome(access->out.data(), access->out.size(), level, access->name.c_str()));
        event->type = NetAccessEventType::authorized;
        event->peer = index;
        event->device = device;
        event->access = level;
        event->address = session_event->address;
        *filled = true;
        return;
    }
    peer->state = NetAccessPeerState::unpaired;
    bool open = access->accept_pairing && !refused_before(access, peer->key);
    send_control(access, index,
                 net_message_write_pairing_needed(access->out.data(), access->out.size(), open, access->name.c_str()));
    if (!open && access->guest_open)
    {
        // It may be a guest (guest_hello follows at once); a pairing client
        // closes on its own.
        peer->guest_only = true;
    }
    else if (!open)
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

// A pair_request: held until our user types the code (requested). Also a new
// one after our confirm didn't match the client's code (a mistyped code).
static void on_pair_request(NetAccess* access, uint32_t index, const uint8_t* data, size_t size, NetAccessEvent* event,
                            bool* filled)
{
    NetAccessPeer* peer = &access->peers[index];
    bool retry = peer->state == NetAccessPeerState::pairing;
    if (retry)
    {
        crypto_wipe(peer->isk, sizeof(peer->isk));
        peer->failures++;
    }
    if (peer->failures >= NET_PAIRING_MAX_FAILURES ||
        !net_message_read_pair_request(data, size, peer->share, &peer->want, &peer->kind, peer->name))
    {
        if (peer->failures >= NET_PAIRING_MAX_FAILURES)
        {
            host_log(LogLevel::warning, "Network: \"%s\" got the code wrong %u times, refused", peer->name,
                     static_cast<unsigned>(peer->failures));
        }
        refuse_pairing(access, index);
        event->type = NetAccessEventType::pairing_failed;
        *filled = true;
        return;
    }
    peer->state = NetAccessPeerState::requested;
    peer->since = net_seconds();
    event->type = NetAccessEventType::pairing_requested;
    event->access = peer->want;
    event->kind = peer->kind;
    event->retry = retry;
    std::snprintf(event->name, sizeof(event->name), "%s", peer->name);
    *filled = true;
}

bool net_access_answer_pairing(NetAccess* access, uint32_t index, const char* code, NetAccessLevel level)
{
    if (index >= NET_MAX_PEERS || access->peers[index].state != NetAccessPeerState::requested ||
        !net_pair_code_valid(code) || static_cast<uint32_t>(level) >= NET_ACCESS_LEVEL_COUNT)
    {
        return false;
    }
    NetAccessPeer* peer = &access->peers[index];
    uint8_t ci[NET_PAIR_CI_SIZE];
    net_pair_ci(peer->key, access->host_key, ci);
    NetCpace cpace;
    uint8_t prs[NET_PAIR_CODE_DIGITS];
    for (size_t i = 0; i < NET_PAIR_CODE_DIGITS; i++)
    {
        prs[i] = static_cast<uint8_t>(code[i]);
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
    bool finished = started && net_cpace_finish(&cpace, false, peer->share, ad_a, ad_a_size, ad_b, ad_b_size,
                                                peer->handshake_hash, NET_PAIR_SID_SIZE, peer->isk);
    net_cpace_wipe(&cpace);
    crypto_wipe(peer->share, sizeof(peer->share));
    if (!finished)
    {
        // A low-order share: not an honest client.
        refuse_pairing(access, index);
        return true;   // its `closed` follows
    }
    uint8_t confirm[NET_PAIR_CONFIRM_SIZE];
    net_pair_confirm(peer->isk, true, confirm);
    send_control(access, index,
                 net_message_write_pair_response(access->out.data(), access->out.size(), our_share, confirm,
                                                 access->name.c_str()));
    peer->grant = level;
    peer->state = NetAccessPeerState::pairing;
    peer->since = net_seconds();
    return true;
}

void net_access_refuse_pairing(NetAccess* access, uint32_t index)
{
    if (index >= NET_MAX_PEERS)
    {
        return;
    }
    NetAccessPeer* peer = &access->peers[index];
    if (peer->state != NetAccessPeerState::requested && peer->state != NetAccessPeerState::pairing)
    {
        return;
    }
    if (!refused_before(access, peer->key))
    {
        access->refused_keys.insert(access->refused_keys.end(), peer->key, peer->key + NET_KEY_SIZE);
    }
    refuse_pairing(access, index);
}

uint32_t net_access_add_device(NetAccess* access, const uint8_t* key, const char* name, NetAccessLevel level)
{
    uint32_t device = net_trust_add(&access->trust, key, name);
    access->trust.devices[device].access = level;
    save_trust(access);
    return device;
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
        // The client accepted our confirm but its own doesn't match: not an
        // honest client.
        peer->state = NetAccessPeerState::unpaired;
        refuse_pairing(access, index);
        event->type = NetAccessEventType::pairing_failed;
        *filled = true;
        return;
    }
    uint32_t device = net_trust_add(&access->trust, peer->key, peer->name);
    access->trust.devices[device].access = peer->grant;
    save_trust(access);
    send_control(access, index, net_message_write_pair_result(access->out.data(), access->out.size(), true));
    // The level our user picked (the client only guessed what it asked for).
    send_control(access, index,
                 net_message_write_welcome(access->out.data(), access->out.size(), peer->grant, access->name.c_str()));
    peer->state = NetAccessPeerState::authorized;
    peer->device = static_cast<int32_t>(device);
    peer->just_paired = true;
    char fingerprint[32];
    net_key_fingerprint(peer->key, fingerprint, sizeof(fingerprint));
    host_log(LogLevel::info, "Network: paired with \"%s\" (%s)", access->trust.devices[device].name.c_str(), fingerprint);
    event->type = NetAccessEventType::paired;
    event->peer = index;
    event->device = static_cast<int32_t>(device);
    event->access = access->trust.devices[device].access;
    *filled = true;
}

// Forgets a paired device (saved at once). Its connections stop reaching
// the frontend (their `closed` still does). Each is told (unpair) and
// closed, except `unpaired_by`: the peer that unpaired itself, which closes
// on its own (NET_NO_PEER: none did).
static void forget_device(NetAccess* access, uint32_t device, uint32_t unpaired_by)
{
    if (device >= access->trust.devices.size())
    {
        return;
    }
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        NetAccessPeer* peer = &access->peers[i];
        if (peer->state != NetAccessPeerState::authorized)
        {
            continue;
        }
        if (peer->device == static_cast<int32_t>(device))
        {
            if (i != unpaired_by)
            {
                // Told first: the close waits for what's queued (disconnect_later).
                uint8_t unpair[1];
                net_session_send(&access->session, i, NetChannel::control, unpair,
                                 net_message_write_unpair(unpair, sizeof(unpair)));
                net_session_close(&access->session, i);
            }
            peer->state = NetAccessPeerState::none;   // nothing more from it reaches the frontend
            peer->device = -1;
            peer->forgotten = true;                   // but its `closed` does (its pads go)
        }
        else if (peer->device > static_cast<int32_t>(device))
        {
            peer->device--;   // indexes after it move down
        }
    }
    net_trust_remove(&access->trust, device);
    save_trust(access);
}

static bool guest_kicked(const NetAccess* access, const uint8_t* key)
{
    for (size_t i = 0; i + NET_KEY_SIZE <= access->guest_kicked.size(); i += NET_KEY_SIZE)
    {
        if (std::memcmp(&access->guest_kicked[i], key, NET_KEY_SIZE) == 0)
        {
            return true;
        }
    }
    return false;
}

uint32_t net_access_guest_count(const NetAccess* access)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        if (access->peers[i].state == NetAccessPeerState::guest && !access->peers[i].guest_leaving)
        {
            count++;
        }
    }
    return count;
}

static void send_guest_bye(NetAccess* access, uint32_t index, NetGuestBye reason)
{
    uint8_t bye[2];
    net_session_send(&access->session, index, NetChannel::control, bye, net_guest_write_bye(bye, sizeof(bye), reason));
}

static void send_guest_welcome(NetAccess* access, uint32_t index)
{
    uint8_t mac[NET_GUEST_MAC_SIZE];
    net_guest_mac(&access->guest_link, true, access->peers[index].handshake_hash, mac);
    send_control(access, index, net_guest_write_welcome(access->out.data(), access->out.size(), mac, access->guest_level));
}

// guest_hello from a device we don't know: the link's token, for this very
// connection. Anything wrong is closed without a word (no dialog, no reply).
static void on_guest_hello(NetAccess* access, uint32_t index, const uint8_t* data, size_t size, NetAccessEvent* event,
                           bool* filled)
{
    NetAccessPeer* peer = &access->peers[index];
    uint8_t mac[NET_GUEST_MAC_SIZE];
    char name[NET_GUEST_MAX_NAME + 1];
    uint8_t expected[NET_GUEST_MAC_SIZE];
    bool ok = access->guest_open && net_guest_read_hello(data, size, mac, name);
    if (ok)
    {
        net_guest_mac(&access->guest_link, false, peer->handshake_hash, expected);
        ok = crypto_verify32(mac, expected) == 0;
    }
    if (!ok)
    {
        net_session_close(&access->session, index);
        peer->state = NetAccessPeerState::none;
        return;
    }
    if (guest_kicked(access, peer->key))
    {
        send_guest_bye(access, index, NetGuestBye::kicked);
        net_session_close(&access->session, index);
        peer->state = NetAccessPeerState::none;
        return;
    }
    if (net_access_guest_count(access) >= access->guest_seats)
    {
        uint8_t host_mac[NET_GUEST_MAC_SIZE];
        net_guest_mac(&access->guest_link, true, peer->handshake_hash, host_mac);
        send_control(access, index, net_guest_write_full(access->out.data(), access->out.size(), host_mac));
        net_session_close(&access->session, index);
        peer->state = NetAccessPeerState::none;
        access->guest_full_count++;
        host_log(LogLevel::info, "Network: guest \"%s\" came with the link, but every seat is taken", name);
        event->type = NetAccessEventType::guest_full;
        std::snprintf(event->name, sizeof(event->name), "%s", name);
        *filled = true;
        return;
    }
    peer->state = NetAccessPeerState::guest;
    peer->guest_only = false;
    peer->since = net_seconds();
    std::snprintf(peer->guest_name, sizeof(peer->guest_name), "%s", name);
    send_guest_welcome(access, index);
    host_log(LogLevel::info, "Network: guest \"%s\" joined (%u of %u seats)", name,
             static_cast<unsigned>(net_access_guest_count(access)), static_cast<unsigned>(access->guest_seats));
    event->type = NetAccessEventType::guest_joined;
    event->guest = true;
    event->guest_level = access->guest_level;
    event->access = NetAccessLevel::stream;
    std::snprintf(event->name, sizeof(event->name), "%s", name);
    *filled = true;
}

// What a guest may send: the stream's start, stop and keyframe requests on the
// control channel, and its pad on the input channel when the link says PLAY.
// Nothing that changes the host for everyone (headless, tuning, actions).
static bool guest_may_send(const NetAccess* access, NetChannel channel, const uint8_t* data, size_t size)
{
    if (channel == NetChannel::input)
    {
        return access->guest_level == NetGuestLevel::play;
    }
    if (channel != NetChannel::control)
    {
        return false;
    }
    uint8_t type = net_message_type(data, size);
    return type == 70 || type == 71 || type == 72;   // NET_STREAM_START, STOP, KEYFRAME_REQUEST (net_stream.h)
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
        NetAccessLevel level = access->trust.devices[static_cast<size_t>(peer->device)].access;
        if (session_event->channel == NetChannel::control)
        {
            uint8_t type = net_message_type(session_event->data, session_event->size);
            if (net_message_read_unpair(session_event->data, session_event->size))
            {
                // The device forgot us: forget it. It closes the connection;
                // its `closed` comes later (forgotten).
                uint32_t device = static_cast<uint32_t>(peer->device);
                event->type = NetAccessEventType::unpaired;
                event->peer = index;
                event->device = -1;
                event->address = session_event->address;
                std::snprintf(event->name, sizeof(event->name), "%s", access->trust.devices[device].name.c_str());
                forget_device(access, device, index);
                return true;
            }
            NetAccessLevel back = NetAccessLevel::gamepad;
            if (net_message_read_grant_back(session_event->data, session_event->size, &back))
            {
                if (!peer->just_paired)
                {
                    return false;   // only right after pairing, on that connection
                }
                peer->just_paired = false;   // once
                event->type = NetAccessEventType::granted_back;
                event->peer = index;
                event->device = peer->device;
                event->access = back;
                event->address = session_event->address;
                return true;
            }
            if (type == static_cast<uint8_t>(NetMessage::device_name))
            {
                char name[NET_DEVICE_NAME_MAX + 1];
                if (net_message_read_device_name(session_event->data, session_event->size, name) &&
                    net_trust_rename(&access->trust, static_cast<uint32_t>(peer->device), name))
                {
                    save_trust(access);
                }
                return false;
            }
            // Other control messages of this layer aren't the application's,
            // and an application message needs its level.
            if (type < NET_MESSAGE_FIRST_APP || !net_access_allows(level, net_message_required_access(type)))
            {
                if (type >= NET_MESSAGE_FIRST_APP)
                {
                    access->dropped_by_access++;
                }
                return false;
            }
        }
        event->type = NetAccessEventType::message;
        event->access = level;
        event->peer = index;
        event->device = peer->device;
        event->address = session_event->address;
        event->channel = session_event->channel;
        event->data = session_event->data;
        event->size = session_event->size;
        return true;
    }
    if (peer->state == NetAccessPeerState::guest)
    {
        if (peer->guest_leaving ||
            !guest_may_send(access, session_event->channel, session_event->data, session_event->size))
        {
            access->dropped_by_access++;
            return false;
        }
        event->type = NetAccessEventType::message;
        event->access = NetAccessLevel::stream;
        event->guest = true;
        event->guest_level = access->guest_level;
        event->peer = index;
        event->device = -1;
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
    if (peer->state == NetAccessPeerState::unpaired && type == static_cast<uint8_t>(NetGuestMessage::hello))
    {
        on_guest_hello(access, index, session_event->data, session_event->size, event, &filled);
    }
    else if (peer->guest_only)
    {
        // Pairing is closed: only a guest_hello could have come.
        net_session_close(&access->session, index);
        peer->state = NetAccessPeerState::none;
    }
    else if ((peer->state == NetAccessPeerState::unpaired || peer->state == NetAccessPeerState::pairing) &&
             type == static_cast<uint8_t>(NetMessage::pair_request))
    {
        on_pair_request(access, index, session_event->data, session_event->size, event, &filled);
    }
    else if (peer->state == NetAccessPeerState::pairing && type == static_cast<uint8_t>(NetMessage::pair_confirm))
    {
        on_pair_confirm(access, index, session_event->data, session_event->size, event, &filled);
    }
    else
    {
        // Anything else before authorization is a protocol error (its
        // `closed` tells the frontend if it was a request).
        refuse_pairing(access, index);
    }
    if (filled)
    {
        event->peer = index;
        event->address = session_event->address;
    }
    return filled;
}

// Peers stuck in a step.
static bool check_timers(NetAccess* access, NetAccessEvent* event)
{
    (void)event;
    double now = net_seconds();
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        NetAccessPeer* peer = &access->peers[i];
        bool waiting = peer->state == NetAccessPeerState::unpaired || peer->state == NetAccessPeerState::pairing;
        bool requested = peer->state == NetAccessPeerState::requested;
        bool hello = peer->state == NetAccessPeerState::unpaired && peer->guest_only;
        if ((waiting && now - peer->since > NET_ACCESS_PAIRING_STEP_SECONDS) ||
            (requested && now - peer->since > NET_ACCESS_REQUEST_SECONDS) ||
            (hello && now - peer->since > NET_ACCESS_GUEST_HELLO_SECONDS))
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
    net_beacon_host_update(&access->beacon, &access->session.host, net_seconds());
    net_signal_update(&access->signal, &access->session, net_seconds());
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
        case NetSessionEventType::signal:   // WebRTC: our blob, to the device through the beacon
            net_signal_outgoing(&access->signal, session_event.peer, session_event.data, session_event.size);
            break;
        case NetSessionEventType::beacon:
            net_beacon_host_receive(&access->beacon, &access->session.host, &session_event.beacon,
                                    session_event.address, net_seconds());
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
            net_signal_peer_gone(&access->signal, session_event.peer);
            if (!session_event.was_secured && access->guest_open)
            {
                // A connection that never got through while a link was open:
                // most likely a guest whose network and ours can't reach each
                // other directly (no relay: the guest is told so).
                access->guest_failures++;
            }
            NetAccessPeer* peer = &access->peers[session_event.peer];
            NetAccessPeerState state = peer->state;
            int32_t device = peer->device;
            bool forgotten = peer->forgotten;
            peer_reset(peer);
            if (state == NetAccessPeerState::requested || state == NetAccessPeerState::pairing)
            {
                // A request went (cancelled on the client, or closed): the
                // frontend closes its dialog.
                event->type = NetAccessEventType::closed;
                event->peer = session_event.peer;
                event->device = -1;
                event->address = session_event.address;
                filled = true;
            }
            else if (state == NetAccessPeerState::guest)
            {
                event->type = NetAccessEventType::closed;
                event->peer = session_event.peer;
                event->device = -1;
                event->guest = true;
                event->address = session_event.address;
                filled = true;
            }
            else if (state == NetAccessPeerState::authorized || forgotten)
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
    if (peer >= NET_MAX_PEERS)
    {
        return false;
    }
    if (access->peers[peer].state == NetAccessPeerState::guest)
    {
        // A guest only hears what runs (game_state, type 16) and the stream
        // (64..127, and the stream channel); never the devices, settings or
        // files of this machine.
        uint8_t type = net_message_type(data, size);
        bool allowed = channel == NetChannel::stream ||
                       (channel == NetChannel::control && (type == NET_MESSAGE_FIRST_APP ||
                                                            (type >= NET_MESSAGE_FIRST_STREAM && type < NET_MESSAGE_FIRST_FULL)));
        return allowed && net_session_send(&access->session, peer, channel, data, size);
    }
    if (access->peers[peer].state != NetAccessPeerState::authorized)
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
    forget_device(access, device, NET_NO_PEER);
}

void net_access_set_level(NetAccess* access, uint32_t device, NetAccessLevel level)
{
    if (device >= access->trust.devices.size())
    {
        return;
    }
    access->trust.devices[device].access = level;
    save_trust(access);
    // A connected device gets a new welcome with its level (to show what it can use).
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        if (access->peers[i].state == NetAccessPeerState::authorized &&
            access->peers[i].device == static_cast<int32_t>(device))
        {
            send_control(access, i,
                         net_message_write_welcome(access->out.data(), access->out.size(), level, access->name.c_str()));
        }
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

static bool peer_in(const NetAccess* access, uint32_t peer)
{
    return peer < NET_MAX_PEERS && (access->peers[peer].state == NetAccessPeerState::authorized ||
                                    access->peers[peer].state == NetAccessPeerState::guest);
}

bool net_access_peer_stats(const NetAccess* access, uint32_t peer, NetLinkStats* stats)
{
    if (!peer_in(access, peer))
    {
        return false;
    }
    return net_host_peer_stats(&access->session.host, peer, stats);
}

bool net_access_peer_address(const NetAccess* access, uint32_t peer, NetAddress* address)
{
    if (!peer_in(access, peer))
    {
        return false;
    }
    return net_host_peer_address(&access->session.host, peer, address);
}

void net_access_set_beacon(NetAccess* access, const NetAddress* servers, uint32_t count)
{
    net_beacon_host_set_servers(&access->beacon, servers, count);
    beacon_refresh_ids(access);
}

NetBeaconStatus net_access_beacon_status(const NetAccess* access)
{
    return net_beacon_host_status(&access->beacon, net_seconds());
}

NetBeaconStatus net_access_internet_status(const NetAccess* access)
{
    NetBeaconStatus udp = net_access_beacon_status(access);
    NetSignalStatus signal = net_access_signal_status(access);
    if (udp == NetBeaconStatus::registered || udp == NetBeaconStatus::symmetric_nat)
    {
        return udp;
    }
    if (signal == NetSignalStatus::ready)
    {
        return NetBeaconStatus::registered;
    }
    if (udp == NetBeaconStatus::off || udp == NetBeaconStatus::unreachable)
    {
        // Signaling still trying is worth "waiting" over a UDP side that's
        // off (the browser) or got no answer.
        if (signal == NetSignalStatus::connecting)
        {
            return NetBeaconStatus::waiting;
        }
        if (signal == NetSignalStatus::unreachable)
        {
            return NetBeaconStatus::unreachable;
        }
    }
    return udp;
}

size_t net_access_peer_pending(const NetAccess* access, uint32_t peer)
{
    return net_host_peer_pending(&access->session.host, peer);
}

bool net_access_set_signal(NetAccess* access, const char* url, const char* stun)
{
    if (url == nullptr || url[0] == '\0')
    {
        net_signal_host_start(&access->signal, "");
        return true;
    }
    if (!net_session_enable_rtc(&access->session, stun))
    {
        return false;   // no WebRTC in this build
    }
    net_signal_host_start(&access->signal, url);
    access->beacon.ids.clear();   // computed again: the rooms come with them
    beacon_refresh_ids(access);
    return true;
}

NetSignalStatus net_access_signal_status(const NetAccess* access)
{
    return net_signal_status(&access->signal, net_seconds());
}

// ---------------------------------------------------------------------------
// Guest links
// ---------------------------------------------------------------------------

static uint32_t clamp_seats(uint32_t seats)
{
    if (seats < 1)
    {
        return 1;
    }
    return seats > NET_GUEST_MAX_SEATS ? NET_GUEST_MAX_SEATS : seats;
}

void net_access_guest_open(NetAccess* access, const NetGuestLink* link, uint32_t seats, NetGuestLevel level)
{
    bool level_changed = access->guest_open && access->guest_level != level;
    access->guest_link = *link;
    access->guest_seats = clamp_seats(seats);
    access->guest_level = level;
    access->guest_open = true;
    net_signal_host_set_guest_room(&access->signal, &access->guest_link.meeting, access->guest_link.signal_key);
    beacon_refresh_ids(access);
    if (level_changed)
    {
        net_access_guest_set_level(access, level);
    }
}

void net_access_guest_set_seats(NetAccess* access, uint32_t seats)
{
    access->guest_seats = clamp_seats(seats);
}

void net_access_guest_set_level(NetAccess* access, NetGuestLevel level)
{
    access->guest_level = level;
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        if (access->peers[i].state == NetAccessPeerState::guest && !access->peers[i].guest_leaving)
        {
            send_guest_welcome(access, i);
        }
    }
}

void net_access_guest_kick(NetAccess* access, uint32_t peer)
{
    if (peer >= NET_MAX_PEERS || access->peers[peer].state != NetAccessPeerState::guest ||
        access->peers[peer].guest_leaving)
    {
        return;
    }
    if (!guest_kicked(access, access->peers[peer].key))
    {
        access->guest_kicked.insert(access->guest_kicked.end(), access->peers[peer].key,
                                    access->peers[peer].key + NET_KEY_SIZE);
    }
    host_log(LogLevel::info, "Network: guest \"%s\" kicked", access->peers[peer].guest_name);
    send_guest_bye(access, peer, NetGuestBye::kicked);
    net_session_close(&access->session, peer);
    access->peers[peer].guest_leaving = true;
}

void net_access_guest_close(NetAccess* access)
{
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        NetAccessPeer* peer = &access->peers[i];
        if (peer->state == NetAccessPeerState::guest && !peer->guest_leaving)
        {
            send_guest_bye(access, i, NetGuestBye::ended);
            net_session_close(&access->session, i);
            peer->guest_leaving = true;
        }
        else if (peer->guest_only)
        {
            net_session_close(&access->session, i);
        }
    }
    bool was = access->guest_open;
    access->guest_open = false;
    net_guest_link_wipe(&access->guest_link);
    access->guest_kicked.clear();
    if (was)
    {
        net_signal_host_set_guest_room(&access->signal, nullptr, nullptr);
        beacon_refresh_ids(access);
    }
}

const NetAccessPeer* net_access_guest(const NetAccess* access, uint32_t peer)
{
    if (peer >= NET_MAX_PEERS || access->peers[peer].state != NetAccessPeerState::guest ||
        access->peers[peer].guest_leaving)
    {
        return nullptr;
    }
    return &access->peers[peer];
}
