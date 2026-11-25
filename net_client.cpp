#include "net_client.h"

#include <cstdio>
#include <cstring>

#include "host_log.h"
#include "monocypher.h"

// --- the paired devices: our copy, and changes under the file lock ----------

static void load_trust(NetClient* client)
{
    client->trust_generation = net_trust_generation();
    net_trust_load(&client->trust, client->trust_path.c_str());
}

// The device we're connected to keeps its place in our list after a reload.
static void remap_device(NetClient* client)
{
    if (client->device < 0)
    {
        return;
    }
    client->device = net_trust_find(&client->trust, client->host_key);
}

static void refresh_trust(NetClient* client)
{
    if (client->trust_generation == net_trust_generation())
    {
        return;
    }
    net_trust_file_lock();
    load_trust(client);
    net_trust_file_unlock();
    remap_device(client);
}

static void edit_begin(NetClient* client)
{
    net_trust_file_lock();
    load_trust(client);
    remap_device(client);
}

static void edit_end(NetClient* client)
{
    if (!net_trust_save(&client->trust, client->trust_path.c_str()))
    {
        host_log(LogLevel::error, "Network: could not save the paired devices to %s", client->trust_path.c_str());
    }
    client->trust_generation = net_trust_generation();
    net_trust_file_unlock();
}

bool net_client_create(NetClient* client, const NetKeypair* identity, const NetDeviceInfo* info,
                       const char* trust_path)
{
    client->trust_path = trust_path;
    client->info = *info;
    // Kept as the messages will carry it (cut), so CPace's ADa matches the host's view.
    net_device_info_set_name(&client->info, info->name);
    client->name = client->info.name;
    std::memcpy(client->our_key, identity->public_key, NET_KEY_SIZE);
    client->out.resize(NET_PAIR_MAX_MESSAGE);
    net_trust_file_lock();
    load_trust(client);
    net_trust_file_unlock();
    return net_session_create_client(&client->session, identity);
}

void net_client_set_verify_build(NetClient* client, NetVerifyBuildFn verify, void* user)
{
    client->verify_build = verify;
    client->verify_user = user;
}

static void forget_secrets(NetClient* client)
{
    crypto_wipe(client->isk, sizeof(client->isk));
    crypto_wipe(client->code, sizeof(client->code));
    net_cpace_wipe(&client->cpace);
    client->has_code = false;
    client->failures = 0;
    client->welcome_pending = false;
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

bool net_client_connect(NetClient* client, NetAddress address, bool pair)
{
    if (client->state != NetClientState::idle)
    {
        return false;
    }
    forget_secrets(client);
    client->pair = pair;
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
    refresh_trust(client);
    if (client->state != NetClientState::idle || device >= client->trust.devices.size())
    {
        return false;
    }
    forget_secrets(client);
    client->pair = false;
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
    client->pair = true;
    std::memset(client->meet_key, 0, NET_KEY_SIZE);   // we don't know who shows it
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
    client->beacon.patient = true;   // the host may not be in its room yet
    return true;
}

bool net_client_join_guest(NetClient* client, const NetGuestLink* link, const NetAddress* servers, uint32_t count)
{
    if (client->state != NetClientState::idle)
    {
        return false;
    }
    forget_secrets(client);
    client->pair = false;
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

// Asks the host for a code (it shows one); our user types it.
static void ask_code(NetClient* client)
{
    send_control(client, net_message_write_pair_ask(client->out.data(), client->out.size()));
    client->state = NetClientState::code_wait;
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
    send_control(client, net_message_write_pair_request(client->out.data(), client->out.size(), client->cpace.share));
    client->state = NetClientState::pairing;
}

bool net_client_enter_code(NetClient* client, const char* code)
{
    if (client->state != NetClientState::code_wait || !net_pair_code_valid(code))
    {
        return false;
    }
    std::memcpy(client->code, code, NET_PAIR_CODE_DIGITS + 1);
    client->has_code = true;
    start_pairing(client);
    return true;
}

static void on_pair_response(NetClient* client, const uint8_t* data, size_t size, NetClientEvent* event)
{
    uint8_t their_share[NET_CPACE_SHARE_SIZE];
    uint8_t their_confirm[NET_PAIR_CONFIRM_SIZE];
    if (!net_message_read_pair_response(data, size, their_share, their_confirm))
    {
        refuse(client, NetClientRefusal::wrong_code, true, event);
        return;
    }
    uint8_t ad_a[NET_DEVICE_NAME_MAX];
    uint8_t ad_b[NET_DEVICE_NAME_MAX];
    size_t ad_a_size = net_pair_name_bytes(client->info.name, ad_a);
    size_t ad_b_size = net_pair_name_bytes(client->host.name, ad_b);
    bool finished = net_cpace_finish(&client->cpace, true, their_share, ad_a, ad_a_size, ad_b, ad_b_size,
                                     client->handshake_hash, NET_PAIR_SID_SIZE, client->isk);
    net_cpace_wipe(&client->cpace);
    crypto_wipe(client->code, sizeof(client->code));
    client->has_code = false;
    uint8_t expected[NET_PAIR_CONFIRM_SIZE];
    if (finished)
    {
        net_pair_confirm(client->isk, true, expected);
    }
    if (!finished || crypto_verify32(their_confirm, expected) != 0)
    {
        // The host's key doesn't match ours: our user typed the code wrong (or
        // someone sits in the middle). We ask again (the host makes a new code
        // unless it shows one) and our user types again.
        crypto_wipe(client->isk, sizeof(client->isk));
        client->failures++;
        if (client->failures >= NET_PAIRING_MAX_FAILURES)
        {
            refuse(client, NetClientRefusal::wrong_code, true, event);
            return;
        }
        ask_code(client);
        event->type = NetClientEventType::code_needed;
        event->retry = true;
        event->host = client->host;
        event->host_signed = client->host_signed;
        return;
    }
    uint8_t confirm[NET_PAIR_CONFIRM_SIZE];
    net_pair_confirm(client->isk, false, confirm);
    crypto_wipe(client->isk, sizeof(client->isk));
    send_control(client, net_message_write_pair_confirm(client->out.data(), client->out.size(), confirm));
    client->state = NetClientState::confirming;
}

static bool check_build(const NetClient* client, const NetDeviceInfo* info)
{
    return client->verify_build != nullptr && info->record_size > 0 && client->verify_build(client->verify_user, info);
}

// What the host said about itself, and what it lets us use, kept in its record.
static void store_host(NetClient* client)
{
    if (client->device < 0)
    {
        return;
    }
    const NetTrustedDevice* known = &client->trust.devices[static_cast<size_t>(client->device)];
    if (known->name == client->host.name && known->kind == client->host.kind &&
        known->signed_build == client->host_signed && known->granted == client->caps)
    {
        return;
    }
    edit_begin(client);
    if (client->device >= 0)
    {
        NetTrustedDevice* record = &client->trust.devices[static_cast<size_t>(client->device)];
        net_trust_rename(&client->trust, static_cast<uint32_t>(client->device), client->host.name);
        record->kind = client->host.kind;
        record->signed_build = client->host_signed;
        record->granted = client->caps;
    }
    edit_end(client);
}

// What the host may use here, as our list says.
static void send_grant(NetClient* client)
{
    if (client->device < 0)
    {
        return;
    }
    NetCaps grants = client->trust.devices[static_cast<size_t>(client->device)].grants;
    send_control(client, net_message_write_grant(client->out.data(), client->out.size(), grants));
}

void net_client_set_grants(NetClient* client, uint32_t device, NetCaps grants)
{
    if (device >= client->trust.devices.size())
    {
        return;
    }
    uint8_t key[NET_KEY_SIZE];
    std::memcpy(key, client->trust.devices[device].key, NET_KEY_SIZE);
    edit_begin(client);
    int32_t found = net_trust_find(&client->trust, key);
    if (found >= 0)
    {
        client->trust.devices[static_cast<size_t>(found)].grants = grants & NET_CAPS_ALL;
    }
    edit_end(client);
    if (found >= 0 && client->state == NetClientState::ready && client->device == found)
    {
        send_grant(client);
    }
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
        client->caps = NET_CAP_STREAM;
        event->guest = true;
        event->guest_level = level;
        event->caps = NET_CAP_STREAM;
        if (client->state == NetClientState::waiting)
        {
            client->state = NetClientState::ready;
            event->type = NetClientEventType::ready;
        }
        else
        {
            event->type = NetClientEventType::caps;   // the host changed the level
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
        NetDeviceInfo host;
        NetCaps caps = 0;
        if (net_message_read_unpair(data, size))
        {
            // The host forgot us: forget it. It closes the connection.
            edit_begin(client);
            if (client->device >= 0)
            {
                net_trust_remove(&client->trust, static_cast<uint32_t>(client->device));
            }
            edit_end(client);
            client->device = -1;
            event->type = NetClientEventType::unpaired;
            return;
        }
        if (net_message_read_welcome(data, size, &caps, &host))
        {
            // Sent again when the host changes what we may use.
            client->caps = caps;
            store_host(client);
            event->type = NetClientEventType::caps;
            event->caps = caps;
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
        bool open = false;
        NetCaps caps = 0;
        if (net_message_read_welcome(data, size, &caps, &client->host))
        {
            client->host_signed = check_build(client, &client->host);
            refresh_trust(client);
            int32_t device = net_trust_find(&client->trust, client->host_key);
            if (device < 0)
            {
                refuse(client, NetClientRefusal::unknown_host, true, event);
                return;
            }
            forget_secrets(client);
            client->device = device;
            client->caps = caps;
            client->state = NetClientState::ready;
            store_host(client);
            send_grant(client);
            event->type = NetClientEventType::ready;
            event->device = client->device;
            event->caps = caps;
            event->host = client->host;
            event->host_signed = client->host_signed;
            return;
        }
        if (net_message_read_pairing_needed(data, size, &open, &client->host))
        {
            client->host_signed = check_build(client, &client->host);
            if (!open)
            {
                // The host closes the connection itself after this message.
                refuse(client, client->pair ? NetClientRefusal::pairing_closed : NetClientRefusal::not_paired, false,
                       event);
            }
            else if (!client->pair)
            {
                refuse(client, NetClientRefusal::not_paired, true, event);
            }
            else if (client->has_code)
            {
                // Typed before we met (GENERATE PAIRING CODE there): ask and
                // answer at once.
                ask_code(client);
                start_pairing(client);
            }
            else
            {
                ask_code(client);
                event->type = NetClientEventType::code_needed;
                event->host = client->host;
                event->host_signed = client->host_signed;
            }
            return;
        }
    }
    else if (client->state == NetClientState::code_wait)
    {
        // Waiting for our user's code: only a refusal can come (the host's
        // user said no); the host closes after it.
        bool ok = true;
        if (net_message_read_pair_result(data, size, &ok) && !ok)
        {
            refuse(client, NetClientRefusal::refused, false, event);
        }
        return;
    }
    else if (client->state == NetClientState::pairing && type == static_cast<uint8_t>(NetMessage::pair_response))
    {
        on_pair_response(client, data, size, event);
        return;
    }
    else if (client->state == NetClientState::pairing || client->state == NetClientState::confirming)
    {
        // Paired: the host's welcome right after its result says what its
        // user lets us use.
        NetCaps caps = 0;
        NetDeviceInfo host;
        if (client->welcome_pending && net_message_read_welcome(data, size, &caps, &host))
        {
            client->welcome_pending = false;
            client->caps = caps;
            client->state = NetClientState::ready;
            store_host(client);
            event->type = NetClientEventType::ready;
            event->newly_paired = true;
            event->caps = caps;
            event->device = client->device;
            event->host = client->host;
            event->host_signed = client->host_signed;
            return;
        }
        bool ok = false;
        if (net_message_read_pair_result(data, size, &ok) && ok && client->state == NetClientState::confirming)
        {
            edit_begin(client);
            uint32_t device = net_trust_add(&client->trust, client->host_key, client->host.name);
            NetTrustedDevice* record = &client->trust.devices[device];
            record->kind = client->host.kind;
            record->signed_build = client->host_signed;
            record->grants = 0;   // our user ticks them on the last screen (net_client_set_grants)
            client->device = static_cast<int32_t>(device);
            edit_end(client);
            forget_secrets(client);
            client->welcome_pending = true;   // `ready` once the welcome says what we may use (just after)
            return;
        }
        refuse(client, NetClientRefusal::refused, false, event);   // the host closes after a refused result
        return;
    }
    host_log(LogLevel::warning, "Network: message %u out of place (state %d): closed", static_cast<unsigned>(type),
             static_cast<int>(client->state));
    refuse(client, NetClientRefusal::connection, true, event);   // a message out of place
}

bool net_client_poll(NetClient* client, NetClientEvent* event)
{
    *event = {};
    refresh_trust(client);
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
        if (session_event.type == NetSessionEventType::beacon &&
            session_event.beacon.type == BeaconType::PRESENT)
        {
            uint64_t round = session_event.beacon.nonce - client->presence_base;
            if (client->presence_base != 0 && round < (client->online_pending.size() + 7) / 8)
            {
                for (uint32_t bit = 0; bit < BEACON_MAX_IDS; bit++)
                {
                    size_t device = static_cast<size_t>(round) * BEACON_MAX_IDS + bit;
                    if (device < client->online_pending.size() && (session_event.beacon.present & (1u << bit)) != 0)
                    {
                        client->online_pending[device] = 1;
                    }
                }
                client->online = client->online_pending;
                client->presence_answered = true;
            }
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
            if (!client->guest)
            {
                // Who we are, before anything else.
                send_control(client, net_message_write_hello(client->out.data(), client->out.size(), &client->info));
            }
            else
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
    uint8_t key[NET_KEY_SIZE];
    std::memcpy(key, client->trust.devices[device].key, NET_KEY_SIZE);
    if (client->state == NetClientState::ready && client->device == static_cast<int32_t>(device))
    {
        // Told first: the close waits for what's queued (disconnect_later).
        uint8_t unpair[1];
        net_session_send(&client->session, client->peer, NetChannel::control, unpair,
                         net_message_write_unpair(unpair, sizeof(unpair)));
        net_session_close(&client->session, client->peer);
        client->device = -1;
    }
    edit_begin(client);
    int32_t found = net_trust_find(&client->trust, key);
    if (found >= 0)
    {
        net_trust_remove(&client->trust, static_cast<uint32_t>(found));
    }
    edit_end(client);
    remap_device(client);
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

void net_client_ask_presence(NetClient* client, const NetAddress* servers, uint32_t count)
{
    size_t devices = client->trust.devices.size();
    client->online_pending.assign(devices, 0);
    if (client->online.size() != devices)
    {
        client->online.assign(devices, 0);
    }
    if (devices == 0 || count == 0)
    {
        return;
    }
    // A new range of nonces per round, so a late answer from the last one is
    // told apart (it falls outside).
    client->presence_base = (client->presence_base == 0 ? 0x10000u : client->presence_base) + 0x100u;
    for (size_t first = 0; first < devices; first += BEACON_MAX_IDS)
    {
        BeaconId ids[BEACON_MAX_IDS];
        uint32_t id_count = 0;
        for (size_t i = first; i < devices && id_count < BEACON_MAX_IDS; i++)
        {
            if (!net_beacon_meeting_id(&client->session.identity, client->trust.devices[i].key, &ids[id_count]))
            {
                std::memset(ids[id_count].bytes, 0xff, BEACON_ID_SIZE);   // can't be met: asks for nothing real
            }
            id_count++;
        }
        net_beacon_ask_presence(&client->session.host, servers, count, ids, id_count,
                                client->presence_base + first / BEACON_MAX_IDS);
    }
}
