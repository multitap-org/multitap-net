#include "net_client.h"

#include <cstdio>
#include <cstring>

#include "host_log.h"
#include "monocypher.h"

bool net_client_create(NetClient* client, const NetKeypair* identity, const char* name, const char* trust_path)
{
    client->trust_path = trust_path;
    // Kept as the messages will carry it (cut), so CPace's ADa matches the host's view.
    uint8_t name_bytes[NET_DEVICE_NAME_MAX];
    size_t name_size = net_pair_name_bytes(name, name_bytes);
    client->name.assign(name, name_size);
    std::memcpy(client->our_key, identity->public_key, NET_KEY_SIZE);
    client->out.resize(NET_PAIR_MAX_MESSAGE);
    net_trust_load(&client->trust, trust_path);
    return net_session_create_client(&client->session, identity);
}

static void forget_secrets(NetClient* client)
{
    crypto_wipe(client->isk, sizeof(client->isk));
    crypto_wipe(client->code, sizeof(client->code));
    net_cpace_wipe(&client->cpace);
    client->has_code = false;
    client->failures = 0;
    client->just_paired = false;
}

void net_client_set_pairing(NetClient* client, NetAccessLevel want, NetPairKind kind)
{
    client->want = want;
    client->kind = kind;
}

bool net_client_grant_back(NetClient* client, NetAccessLevel level)
{
    if (client->state != NetClientState::ready || !client->just_paired)
    {
        return false;
    }
    client->just_paired = false;
    size_t size = net_message_write_grant_back(client->out.data(), client->out.size(), level);
    return size > 0 && net_session_send(&client->session, client->peer, NetChannel::control, client->out.data(), size);
}

// A guest connection is over (or never started): our own key again.
static void guest_done(NetClient* client)
{
    if (!client->guest)
    {
        return;
    }
    client->session.identity = client->home_identity;
    net_keypair_wipe(&client->home_identity);
    net_guest_link_wipe(&client->guest_link);
    client->guest = false;
}

void net_client_destroy(NetClient* client)
{
    guest_done(client);
    net_keypair_wipe(&client->guest_identity);
    forget_secrets(client);
    net_signal_stop(&client->signal);
    net_session_destroy(&client->session);
}

bool net_client_connect(NetClient* client, NetAddress address, const char* code)
{
    if (client->state != NetClientState::idle)
    {
        return false;
    }
    forget_secrets(client);
    if (code != nullptr)
    {
        if (!net_pair_code_valid(code))
        {
            return false;
        }
        std::memcpy(client->code, code, NET_PAIR_CODE_DIGITS + 1);
        client->has_code = true;
    }
    if (!net_session_connect(&client->session, address, &client->peer))
    {
        return false;
    }
    client->state = NetClientState::connecting;
    client->via_beacon = false;
    client->expect_key = false;
    return true;
}

static void refuse(NetClient* client, NetClientRefusal refusal, bool we_close, NetClientEvent* event);

void net_client_set_signal(NetClient* client, const char* url, const char* stun)
{
    client->signal_url = url != nullptr ? url : "";
    client->signal_stun = stun != nullptr ? stun : "";
}

// WebRTC through the beacon's signaling, for the host being met.
static bool start_signal(NetClient* client)
{
    if (client->signal_url.empty() || client->via_signal ||
        !net_session_enable_rtc(&client->session, client->signal_stun.empty() ? nullptr : client->signal_stun.c_str()))
    {
        return false;
    }
    char slot[NET_PAIR_SLOT_DIGITS + 1] = {};
    std::memcpy(slot, client->code, NET_PAIR_SLOT_DIGITS);
    bool started = false;
    if (client->guest)
    {
        started = net_signal_client_start_guest(&client->signal, client->signal_url.c_str(), &client->guest_link.meeting,
                                                client->guest_link.signal_key, net_seconds());
    }
    else if (client->meet_pairing)
    {
        started = net_signal_client_start_pair(&client->signal, client->signal_url.c_str(), slot, net_seconds());
    }
    else
    {
        started = net_signal_client_start(&client->signal, client->signal_url.c_str(), &client->session.identity,
                                          client->meet_key, net_seconds());
    }
    if (!started)
    {
        return false;
    }
    host_log(LogLevel::info, "Network: trying WebRTC through the beacon's signaling");
    client->via_signal = true;
    client->peer = NET_NO_PEER;
    client->state = NetClientState::meeting;
    return true;
}

// UDP first (MEET `id` at the beacon), else WebRTC through its signaling.
static bool start_meeting(NetClient* client, const NetAddress* servers, uint32_t count, const BeaconId* id)
{
    client->via_signal = false;
    client->udp_host_offline = false;
    client->peer = NET_NO_PEER;
    client->via_beacon = true;   // the beacon either way: UDP or its signaling
    if (count > 0 && net_beacon_client_start(&client->beacon, servers, count, id, net_seconds()))
    {
        client->state = NetClientState::meeting;
        return true;
    }
    return start_signal(client);
}

bool net_client_connect_beacon(NetClient* client, const NetAddress* servers, uint32_t count, uint32_t device)
{
    if (client->state != NetClientState::idle || device >= client->trust.devices.size())
    {
        return false;
    }
    forget_secrets(client);
    std::memcpy(client->meet_key, client->trust.devices[device].key, NET_KEY_SIZE);
    client->meet_pairing = false;
    client->expect_key = false;   // the welcome checks it against our list
    BeaconId id;
    if (!net_beacon_meeting_id(&client->session.identity, client->meet_key, &id))
    {
        return false;
    }
    return start_meeting(client, servers, count, &id);
}

bool net_client_pair_beacon(NetClient* client, const NetAddress* servers, uint32_t count, const char* code)
{
    if (client->state != NetClientState::idle || code == nullptr || !net_pair_code_valid(code))
    {
        return false;
    }
    forget_secrets(client);
    std::memcpy(client->code, code, NET_PAIR_CODE_DIGITS + 1);
    client->has_code = true;
    std::memset(client->meet_key, 0, NET_KEY_SIZE);   // we don't know who will type it
    client->meet_pairing = true;
    client->expect_key = false;
    char slot[NET_PAIR_SLOT_DIGITS + 1] = {};
    std::memcpy(slot, code, NET_PAIR_SLOT_DIGITS);
    BeaconId id;
    net_beacon_pair_id(slot, &id);
    if (!start_meeting(client, servers, count, &id))
    {
        forget_secrets(client);
        return false;
    }
    client->beacon.patient = true;   // the host joins when its user has typed the code
    return true;
}

bool net_client_join_guest(NetClient* client, const NetGuestLink* link, const NetAddress* servers, uint32_t count)
{
    if (client->state != NetClientState::idle)
    {
        return false;
    }
    forget_secrets(client);
    if (!client->has_guest_identity)
    {
        if (!net_keypair_generate(&client->guest_identity))
        {
            return false;
        }
        client->has_guest_identity = true;
    }
    client->home_identity = client->session.identity;
    client->session.identity = client->guest_identity;
    client->guest = true;
    client->guest_link = *link;
    client->guest_bye = NetGuestBye::none;
    client->guest_level = NetGuestLevel::watch;
    std::memset(client->meet_key, 0, NET_KEY_SIZE);
    client->meet_pairing = false;
    client->expect_key = false;
    if (!start_meeting(client, servers, count, &link->meeting))
    {
        guest_done(client);
        return false;
    }
    return true;
}

// A guest's refusal for a failure to meet: no host in the link's room means
// the session ended (or the link was replaced).
static NetClientRefusal meet_refusal(const NetClient* client, bool offline)
{
    if (client->guest)
    {
        return offline ? NetClientRefusal::guest_link : NetClientRefusal::beacon_unreachable;
    }
    return offline ? NetClientRefusal::host_offline : NetClientRefusal::beacon_unreachable;
}

// The signaling side of a meeting: the client's WebRTC peer once it offered,
// or a refusal. True if `event` was filled.
static bool signal_step(NetClient* client, NetClientEvent* event)
{
    if (!client->via_signal)
    {
        return false;
    }
    net_signal_update(&client->signal, &client->session, net_seconds());
    if (client->state != NetClientState::meeting)
    {
        return false;
    }
    if (client->signal.failure != NetSignalFailure::none)
    {
        // A beacon that already said "not there" over UDP but whose signaling
        // can't be reached (one without it): the host is still offline, the
        // beacon did answer.
        bool offline = client->signal.failure == NetSignalFailure::host_offline || client->udp_host_offline;
        if (client->guest && client->signal.failure == NetSignalFailure::refused)
        {
            refuse(client, NetClientRefusal::guest_full, false, event);   // the beacon's room was full
            return true;
        }
        refuse(client, meet_refusal(client, offline), false, event);
        return true;
    }
    uint32_t peer = net_signal_client_peer(&client->signal);
    if (peer != NET_NO_PEER)
    {
        client->peer = peer;
        client->state = NetClientState::connecting;
    }
    return false;
}

// Across the internet: drives the beacon while meeting (and keeps punching
// while ENet connects). True if `event` was filled (a refusal).
static bool beacon_step(NetClient* client, NetClientEvent* event)
{
    if (!client->via_beacon)
    {
        return false;
    }
    net_beacon_client_update(&client->beacon, &client->session.host, net_seconds());
    if (client->state != NetClientState::meeting)
    {
        return false;
    }
    if (client->beacon.state == NetBeaconMeetState::failed)
    {
        client->udp_host_offline = client->beacon.failure == NetBeaconFailure::host_offline;
        if (start_signal(client))
        {
            net_beacon_client_stop(&client->beacon);   // UDP gave up: WebRTC now
            return false;
        }
        refuse(client, meet_refusal(client, client->beacon.failure == NetBeaconFailure::host_offline), false, event);
        return true;
    }
    if (client->beacon.state == NetBeaconMeetState::connect)
    {
        char text[64];
        net_address_to_text(client->beacon.target, text, sizeof(text));
        host_log(LogLevel::info, "Network: the beacon introduced us; connecting to %s", text);
        if (!net_session_connect(&client->session, client->beacon.target, &client->peer))
        {
            refuse(client, NetClientRefusal::no_route, false, event);
            return true;
        }
        client->state = NetClientState::connecting;
    }
    return false;
}

// `we_close`: true when the refusal is our own decision. When the host
// refused, it closes the connection itself: both sides disconnecting at once
// leaves ENet peers stuck until they time out.
static void refuse(NetClient* client, NetClientRefusal refusal, bool we_close, NetClientEvent* event)
{
    if (we_close && client->peer != NET_NO_PEER)
    {
        net_session_close(&client->session, client->peer);
    }
    forget_secrets(client);
    net_beacon_client_stop(&client->beacon);
    net_signal_stop(&client->signal);
    client->via_beacon = false;
    client->via_signal = false;
    client->state = NetClientState::idle;
    event->guest = client->guest;
    guest_done(client);
    event->type = NetClientEventType::refused;
    event->refusal = refusal;
}

static void send_control(NetClient* client, size_t size)
{
    if (size > 0)
    {
        net_session_send(&client->session, client->peer, NetChannel::control, client->out.data(), size);
    }
}

static void start_pairing(NetClient* client)
{
    uint8_t ci[NET_PAIR_CI_SIZE];
    net_pair_ci(client->our_key, client->host_key, ci);
    uint8_t prs[NET_PAIR_CODE_DIGITS];
    for (size_t i = 0; i < NET_PAIR_CODE_DIGITS; i++)
    {
        prs[i] = static_cast<uint8_t>(client->code[i]);
    }
    // CPace finishes when the response arrives (client->cpace keeps the scalar).
    bool started = net_cpace_start(&client->cpace, prs, sizeof(prs), ci, sizeof(ci), client->handshake_hash,
                                   NET_PAIR_SID_SIZE);
    crypto_wipe(prs, sizeof(prs));
    if (!started)
    {
        return;
    }
    send_control(client, net_message_write_pair_request(client->out.data(), client->out.size(), client->cpace.share,
                                                        client->want, client->kind, client->name.c_str()));
    client->state = NetClientState::pairing;
}

static void on_pair_response(NetClient* client, const uint8_t* data, size_t size, NetClientEvent* event)
{
    uint8_t their_share[NET_CPACE_SHARE_SIZE];
    uint8_t their_confirm[NET_PAIR_CONFIRM_SIZE];
    char host_name[NET_DEVICE_NAME_MAX + 1];
    if (!net_message_read_pair_response(data, size, their_share, their_confirm, host_name))
    {
        refuse(client, NetClientRefusal::wrong_code, true, event);
        return;
    }
    uint8_t ad_a[NET_DEVICE_NAME_MAX];
    uint8_t ad_b[NET_DEVICE_NAME_MAX];
    size_t ad_a_size = net_pair_name_bytes(client->name.c_str(), ad_a);
    size_t ad_b_size = net_pair_name_bytes(host_name, ad_b);
    bool finished = net_cpace_finish(&client->cpace, true, their_share, ad_a, ad_a_size, ad_b, ad_b_size,
                                     client->handshake_hash, NET_PAIR_SID_SIZE, client->isk);
    net_cpace_wipe(&client->cpace);
    uint8_t expected[NET_PAIR_CONFIRM_SIZE];
    if (finished)
    {
        net_pair_confirm(client->isk, true, expected);
    }
    if (!finished || crypto_verify32(their_confirm, expected) != 0)
    {
        // The host's key doesn't match ours: its user typed the code wrong (or
        // someone sits in the middle). A new code, and we ask again.
        crypto_wipe(client->isk, sizeof(client->isk));
        client->failures++;
        if (client->failures >= NET_PAIRING_MAX_FAILURES || !net_pair_code_generate(client->code))
        {
            refuse(client, NetClientRefusal::wrong_code, true, event);
            return;
        }
        start_pairing(client);
        event->type = NetClientEventType::code_changed;
        return;
    }
    std::snprintf(client->host_name, sizeof(client->host_name), "%s", host_name);
    uint8_t confirm[NET_PAIR_CONFIRM_SIZE];
    net_pair_confirm(client->isk, false, confirm);
    crypto_wipe(client->isk, sizeof(client->isk));
    send_control(client, net_message_write_pair_confirm(client->out.data(), client->out.size(), confirm));
    client->state = NetClientState::confirming;
}

// Whether `mac` is the host's proof for this connection.
static bool guest_host_mac_ok(const NetClient* client, const uint8_t* mac)
{
    uint8_t expected[NET_GUEST_MAC_SIZE];
    net_guest_mac(&client->guest_link, true, client->handshake_hash, expected);
    return crypto_verify32(mac, expected) == 0;
}

// A guest's control messages: the host proves the token (welcome, full),
// says goodbye (bye), or sends the application's.
static void on_guest_control(NetClient* client, const uint8_t* data, size_t size, NetClientEvent* event)
{
    uint8_t type = net_message_type(data, size);
    uint8_t mac[NET_GUEST_MAC_SIZE];
    NetGuestLevel level = NetGuestLevel::watch;
    NetGuestBye bye = NetGuestBye::none;
    if (net_guest_read_welcome(data, size, mac, &level))
    {
        if (!guest_host_mac_ok(client, mac))
        {
            // Not the host the link names.
            refuse(client, NetClientRefusal::unknown_host, true, event);
            return;
        }
        client->guest_level = level;
        client->access = NetAccessLevel::stream;
        event->guest = true;
        event->guest_level = level;
        event->access = NetAccessLevel::stream;
        if (client->state == NetClientState::waiting)
        {
            client->state = NetClientState::ready;
            event->type = NetClientEventType::ready;
        }
        else
        {
            event->type = NetClientEventType::access;   // the host changed the level
        }
        return;
    }
    if (client->state == NetClientState::waiting)
    {
        if (net_guest_read_full(data, size, mac) && guest_host_mac_ok(client, mac))
        {
            refuse(client, NetClientRefusal::guest_full, false, event);   // the host closes
            return;
        }
        if (net_guest_read_bye(data, size, &bye))
        {
            refuse(client, bye == NetGuestBye::kicked ? NetClientRefusal::guest_kicked : NetClientRefusal::guest_link,
                   false, event);
            return;
        }
        // pairing_needed (it doesn't know our throwaway key): not for a guest.
        return;
    }
    if (client->state != NetClientState::ready)
    {
        return;
    }
    if (net_guest_read_bye(data, size, &bye))
    {
        client->guest_bye = bye;   // `closed` follows when the host closes
        return;
    }
    if (type >= NET_MESSAGE_FIRST_APP)
    {
        event->type = NetClientEventType::message;
        event->channel = NetChannel::control;
        event->data = data;
        event->size = size;
    }
}

static void on_control(NetClient* client, const uint8_t* data, size_t size, NetClientEvent* event)
{
    if (client->guest)
    {
        on_guest_control(client, data, size, event);
        return;
    }
    uint8_t type = net_message_type(data, size);
    if (client->state == NetClientState::ready)
    {
        char host_name[NET_DEVICE_NAME_MAX + 1];
        NetAccessLevel level = NetAccessLevel::gamepad;
        if (net_message_read_unpair(data, size))
        {
            // The host forgot us: forget it. It closes the connection.
            if (client->device >= 0)
            {
                net_trust_remove(&client->trust, static_cast<uint32_t>(client->device));
                if (!net_trust_save(&client->trust, client->trust_path.c_str()))
                {
                    host_log(LogLevel::error, "Network: could not save the paired hosts to %s",
                             client->trust_path.c_str());
                }
            }
            client->device = -1;
            event->type = NetClientEventType::unpaired;
            return;
        }
        if (net_message_read_welcome(data, size, &level, host_name))
        {
            // Sent again when the host changes our level.
            client->access = level;
            event->type = NetClientEventType::access;
            event->access = level;
            return;
        }
        if (type >= NET_MESSAGE_FIRST_APP)
        {
            event->type = NetClientEventType::message;
            event->channel = NetChannel::control;
            event->data = data;
            event->size = size;
        }
        return;
    }
    if (client->state == NetClientState::waiting)
    {
        char host_name[NET_DEVICE_NAME_MAX + 1];
        bool open = false;
        NetAccessLevel level = NetAccessLevel::gamepad;
        if (net_message_read_welcome(data, size, &level, host_name))
        {
            int32_t device = net_trust_find(&client->trust, client->host_key);
            if (device < 0)
            {
                refuse(client, NetClientRefusal::unknown_host, true, event);
                return;
            }
            std::snprintf(client->host_name, sizeof(client->host_name), "%s", host_name);
            forget_secrets(client);
            client->device = device;
            client->access = level;
            client->state = NetClientState::ready;
            // Our name as it is now: the host's list follows a renamed device.
            send_control(client, net_message_write_device_name(client->out.data(), client->out.size(),
                                                               client->name.c_str()));
            event->type = NetClientEventType::ready;
            event->device = device;
            event->access = level;
            return;
        }
        if (net_message_read_pairing_needed(data, size, &open, host_name))
        {
            if (!open)
            {
                // The host closes the connection itself after this message.
                refuse(client, client->has_code ? NetClientRefusal::pairing_closed : NetClientRefusal::not_paired,
                       false, event);
            }
            else if (!client->has_code)
            {
                refuse(client, NetClientRefusal::not_paired, true, event);
            }
            else
            {
                start_pairing(client);
            }
            return;
        }
    }
    else if (client->state == NetClientState::pairing && type == static_cast<uint8_t>(NetMessage::pair_response))
    {
        on_pair_response(client, data, size, event);
        return;
    }
    else if (client->state == NetClientState::pairing || client->state == NetClientState::confirming)
    {
        bool ok = false;
        if (net_message_read_pair_result(data, size, &ok) && ok && client->state == NetClientState::confirming)
        {
            uint32_t device = net_trust_add(&client->trust, client->host_key, client->host_name);
            if (!net_trust_save(&client->trust, client->trust_path.c_str()))
            {
                host_log(LogLevel::error, "Network: could not save the paired hosts to %s", client->trust_path.c_str());
            }
            forget_secrets(client);
            client->device = static_cast<int32_t>(device);
            client->access = client->want;   // until the welcome that follows says what the host gave
            client->state = NetClientState::ready;
            client->just_paired = true;
            event->type = NetClientEventType::ready;
            event->newly_paired = true;
            event->access = client->access;
            event->device = client->device;
            return;
        }
        refuse(client, NetClientRefusal::refused, false, event);   // the host closes after a refused result
        return;
    }
    refuse(client, NetClientRefusal::connection, true, event);   // a message out of place
}

bool net_client_poll(NetClient* client, NetClientEvent* event)
{
    *event = {};
    if (beacon_step(client, event) || signal_step(client, event))
    {
        return true;
    }
    NetSessionEvent session_event;
    while (net_session_poll(&client->session, &session_event))
    {
        if (session_event.type == NetSessionEventType::signal)
        {
            // Our WebRTC blob (offer, candidates): to the host through the beacon.
            net_signal_outgoing(&client->signal, session_event.peer, session_event.data, session_event.size);
            continue;
        }
        if (session_event.type == NetSessionEventType::beacon)
        {
            if (client->via_beacon)
            {
                net_beacon_client_receive(&client->beacon, &client->session.host, &session_event.beacon,
                                          session_event.address, net_seconds());
                if (beacon_step(client, event))
                {
                    return true;
                }
            }
            continue;
        }
        if (session_event.peer != client->peer && session_event.type != NetSessionEventType::discovered)
        {
            continue;
        }
        switch (session_event.type)
        {
        case NetSessionEventType::none:
        case NetSessionEventType::discovered:
        case NetSessionEventType::beacon:
        case NetSessionEventType::signal:
            break;
        case NetSessionEventType::secured:
            if (client->expect_key && crypto_verify32(session_event.remote_key, client->meet_key) != 0)
            {
                // Someone else in the host's pairing room: not who the link names.
                refuse(client, NetClientRefusal::unknown_host, true, event);
                return true;
            }
            std::memcpy(client->host_key, session_event.remote_key, NET_KEY_SIZE);
            std::memcpy(client->handshake_hash, session_event.handshake_hash, NET_HASH_SIZE);
            client->state = NetClientState::waiting;
            if (client->guest)
            {
                // The token, for this connection, before anything else.
                uint8_t mac[NET_GUEST_MAC_SIZE];
                net_guest_mac(&client->guest_link, false, client->handshake_hash, mac);
                uint8_t hello[NET_GUEST_MAX_MESSAGE];
                size_t hello_size = net_guest_write_hello(hello, sizeof(hello), mac, client->name.c_str());
                net_session_send(&client->session, client->peer, NetChannel::control, hello, hello_size);
            }
            break;
        case NetSessionEventType::message:
            if (session_event.channel != NetChannel::control)
            {
                if (client->state == NetClientState::ready)
                {
                    event->type = NetClientEventType::message;
                    event->channel = session_event.channel;
                    event->data = session_event.data;
                    event->size = session_event.size;
                }
            }
            else
            {
                on_control(client, session_event.data, session_event.size, event);
            }
            break;
        case NetSessionEventType::closed:
        {
            NetClientState state = client->state;
            bool via_beacon = client->via_beacon;
            // UDP punched but ENet never connected: WebRTC through the
            // signaling before giving up (the same flow, another transport).
            if (via_beacon && !client->via_signal && state == NetClientState::connecting)
            {
                net_beacon_client_stop(&client->beacon);
                if (start_signal(client))
                {
                    break;
                }
            }
            forget_secrets(client);
            net_beacon_client_stop(&client->beacon);
            net_signal_stop(&client->signal);
            client->via_beacon = false;
            client->via_signal = false;
            client->state = NetClientState::idle;
            bool guest = client->guest;
            event->guest = guest;
            event->guest_bye = client->guest_bye;
            guest_done(client);
            if (state == NetClientState::ready)
            {
                event->type = NetClientEventType::closed;
            }
            else if (state != NetClientState::idle)
            {
                event->type = NetClientEventType::refused;
                // Through the beacon, a connection that never came up means
                // the NATs didn't let it through.
                event->refusal = via_beacon && state == NetClientState::connecting ? NetClientRefusal::no_route
                                                                                    : NetClientRefusal::connection;
                if (guest && state == NetClientState::waiting)
                {
                    // The host got through to us and closed without a word:
                    // the token isn't this session's (ended, or a new link).
                    event->refusal = NetClientRefusal::guest_link;
                }
            }
            break;
        }
        }
        if (event->type != NetClientEventType::none)
        {
            if (event->type == NetClientEventType::ready && client->via_signal)
            {
                net_signal_stop(&client->signal);   // connected: the beacon's socket isn't needed any more
            }
            return true;
        }
    }
    return false;
}

bool net_client_send(NetClient* client, NetChannel channel, const uint8_t* data, size_t size)
{
    if (client->state != NetClientState::ready)
    {
        return false;
    }
    if (channel == NetChannel::control && net_message_type(data, size) < NET_MESSAGE_FIRST_APP)
    {
        return false;
    }
    return net_session_send(&client->session, client->peer, channel, data, size);
}

void net_client_close(NetClient* client)
{
    if (client->state == NetClientState::meeting)
    {
        net_beacon_client_stop(&client->beacon);
        net_signal_stop(&client->signal);
        client->via_signal = false;
        client->via_beacon = false;
        client->state = NetClientState::idle;
        guest_done(client);
        return;
    }
    if (client->state != NetClientState::idle)
    {
        net_session_close(&client->session, client->peer);
    }
}

bool net_client_unpair(NetClient* client, uint32_t device)
{
    if (device >= client->trust.devices.size())
    {
        return false;
    }
    if (client->state == NetClientState::ready && client->device == static_cast<int32_t>(device))
    {
        // Told first: the close waits for what's queued (disconnect_later).
        uint8_t unpair[1];
        net_session_send(&client->session, client->peer, NetChannel::control, unpair,
                         net_message_write_unpair(unpair, sizeof(unpair)));
        net_session_close(&client->session, client->peer);
        client->device = -1;
    }
    else if (client->device > static_cast<int32_t>(device))
    {
        client->device--;   // indexes after it move down
    }
    net_trust_remove(&client->trust, device);
    if (!net_trust_save(&client->trust, client->trust_path.c_str()))
    {
        host_log(LogLevel::error, "Network: could not save the paired hosts to %s", client->trust_path.c_str());
    }
    return true;
}

bool net_client_stats(const NetClient* client, NetLinkStats* stats)
{
    if (client->state != NetClientState::ready)
    {
        return false;
    }
    return net_host_peer_stats(&client->session.host, client->peer, stats);
}

size_t net_client_pending(const NetClient* client)
{
    if (client->state != NetClientState::ready)
    {
        return 0;
    }
    return net_host_peer_pending(&client->session.host, client->peer);
}
