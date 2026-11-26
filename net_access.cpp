#include "net_access.h"

#include <cstdio>
#include <cstring>

#include "host_log.h"
#include "monocypher.h"

static void beacon_refresh_ids(NetAccess* access);
static void remap_peers(NetAccess* access);

// --- the paired devices: our copy, and changes under the file lock ----------

static void load_trust(NetAccess* access)
{
    access->trust_generation = net_trust_generation();
    net_trust_load(&access->trust, access->trust_path.c_str());
}

// Another side (net_client.h) saved: our copy again, peers moved to their
// devices' new places (a device forgotten there closes here).
static void refresh_trust(NetAccess* access)
{
    if (access->trust_generation == net_trust_generation())
    {
        return;
    }
    net_trust_file_lock();
    load_trust(access);
    net_trust_file_unlock();
    remap_peers(access);
    beacon_refresh_ids(access);
}

// A change: lock, a fresh copy, then edit_end saves it and unlocks.
static void edit_begin(NetAccess* access)
{
    net_trust_file_lock();
    load_trust(access);
    remap_peers(access);
}

static void edit_end(NetAccess* access)
{
    if (!net_trust_save(&access->trust, access->trust_path.c_str()))
    {
        host_log(LogLevel::error, "Network: could not save the paired devices to %s", access->trust_path.c_str());
    }
    access->trust_generation = net_trust_generation();
    net_trust_file_unlock();
    beacon_refresh_ids(access);
}

bool net_access_create(NetAccess* access, uint16_t port, const NetDeviceInfo* info, const NetKeypair* identity,
                       const char* trust_path)
{
    access->trust_path = trust_path;
    access->info = *info;
    net_device_info_set_name(&access->info, info->name);   // as read_info will show it to the other side
    access->name = access->info.name;
    std::memcpy(access->host_key, identity->public_key, NET_KEY_SIZE);
    access->out.resize(NET_PAIR_MAX_MESSAGE);
    net_trust_file_lock();
    load_trust(access);
    net_trust_file_unlock();
    if (!net_session_create_listener(&access->session, port, access->info.name, identity))
    {
        return false;
    }
    net_host_set_discovery_info(&access->session.host, static_cast<uint8_t>(info->kind), info->offers,
                                info->record_size > 0);
    net_host_set_discovery_key(&access->session.host, identity->public_key);   // lets lists tell paired from unpaired by key
    beacon_refresh_ids(access);
    return true;
}

void net_access_set_verify_build(NetAccess* access, NetVerifyBuildFn verify, void* user)
{
    access->verify_build = verify;
    access->verify_user = user;
}

static void peer_reset(NetAccessPeer* peer)
{
    crypto_wipe(peer->isk, sizeof(peer->isk));
    crypto_wipe(peer->code, sizeof(peer->code));
    *peer = {};
}

void net_access_destroy(NetAccess* access)
{
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        peer_reset(&access->peers[i]);
    }
    net_access_end_code(access);
    net_guest_link_wipe(&access->guest_link);
    net_signal_stop(&access->signal);
    net_session_destroy(&access->session);
}

// The beacon registers one meeting id per paired device; computed again when
// the list changes (only then: a change of grants leaves the ids alone).
static void beacon_refresh_ids(NetAccess* access)
{
    std::vector<BeaconId> ids;
    ids.reserve(access->trust.devices.size() + 2);
    for (size_t i = 0; i < access->trust.devices.size(); i++)
    {
        BeaconId id;
        if (net_beacon_meeting_id(&access->session.identity, access->trust.devices[i].key, &id))
        {
            ids.push_back(id);
        }
    }
    if (access->showing)
    {
        // The pairing room of the code we show: the device that types it comes there.
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
                                  access->showing ? access->invite_slot : nullptr);
    }
}

static void send_control(NetAccess* access, uint32_t peer, size_t size)
{
    if (size > 0)
    {
        net_session_send(&access->session, peer, NetChannel::control, access->out.data(), size);
    }
}

// What a peer may use now: the stored grant, what we offer, what it uses.
static NetCaps effective_caps(const NetAccess* access, const NetAccessPeer* peer)
{
    if (peer->state != NetAccessPeerState::authorized || peer->device < 0 ||
        static_cast<size_t>(peer->device) >= access->trust.devices.size())
    {
        return 0;
    }
    return access->trust.devices[static_cast<size_t>(peer->device)].grants & access->info.offers & peer->info.uses;
}

NetCaps net_access_peer_caps(const NetAccess* access, uint32_t peer)
{
    return peer < NET_MAX_PEERS ? effective_caps(access, &access->peers[peer]) : 0;
}

static void send_welcome(NetAccess* access, uint32_t index)
{
    send_control(access, index,
                 net_message_write_welcome(access->out.data(), access->out.size(),
                                           effective_caps(access, &access->peers[index]), &access->info));
}

// After the list was loaded again: each authorized peer finds its device by
// key; one whose device is gone was unpaired on the other side (forgotten).
static void remap_peers(NetAccess* access)
{
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        NetAccessPeer* peer = &access->peers[i];
        if (peer->state != NetAccessPeerState::authorized && peer->state != NetAccessPeerState::hello_wait)
        {
            continue;
        }
        int32_t device = net_trust_find(&access->trust, peer->key);
        if (device < 0)
        {
            host_log(LogLevel::info, "Network: a connected device was forgotten on this device's other side: closed");
            net_session_close(&access->session, i);
            peer->state = NetAccessPeerState::none;
            peer->device = -1;
            peer->forgotten = true;
            continue;
        }
        peer->device = device;
    }
}

bool net_access_show_code(NetAccess* access, NetCaps grants, char* code)
{
    if (!net_pair_code_generate(access->shown_code))
    {
        return false;
    }
    std::memcpy(code, access->shown_code, NET_PAIR_CODE_DIGITS + 1);
    std::memcpy(access->invite_slot, access->shown_code, NET_PAIR_SLOT_DIGITS);
    access->invite_slot[NET_PAIR_SLOT_DIGITS] = '\0';
    access->shown_grants = grants & access->info.offers;
    access->shown_since = net_seconds();
    access->showing = true;
    access->beacon.ids.clear();   // the pairing room (maybe a new slot) joins
    beacon_refresh_ids(access);
    return true;
}

void net_access_set_shown_grants(NetAccess* access, NetCaps grants)
{
    access->shown_grants = grants & access->info.offers;
}

void net_access_end_code(NetAccess* access)
{
    bool was = access->showing;
    access->showing = false;
    crypto_wipe(access->shown_code, sizeof(access->shown_code));
    std::memset(access->invite_slot, 0, sizeof(access->invite_slot));
    access->shown_grants = 0;
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

static void on_secured(NetAccess* access, const NetSessionEvent* session_event)
{
    uint32_t index = session_event->peer;
    if (index >= NET_MAX_PEERS)
    {
        return;
    }
    refresh_trust(access);
    NetAccessPeer* peer = &access->peers[index];
    peer_reset(peer);
    std::memcpy(peer->key, session_event->remote_key, NET_KEY_SIZE);
    std::memcpy(peer->handshake_hash, session_event->handshake_hash, NET_HASH_SIZE);
    peer->since = net_seconds();

    int32_t device = net_trust_find(&access->trust, peer->key);
    if (device >= 0)
    {
        // Welcomed once it says who it is (hello): what it may use depends
        // on what it uses.
        peer->state = NetAccessPeerState::hello_wait;
        peer->device = device;
        return;
    }
    peer->state = NetAccessPeerState::unpaired;
    bool open = access->accept_pairing && !refused_before(access, peer->key);
    send_control(access, index,
                 net_message_write_pairing_needed(access->out.data(), access->out.size(), open, &access->info));
    if (!open && access->guest_open)
    {
        // It may be a guest (guest_hello follows at once); a pairing client
        // closes on its own.
        peer->guest_only = true;
    }
    else if (!open)
    {
        // Sent first: ENet delivers queued messages before disconnecting.
        net_session_close(&access->session, index);
    }
}

static void refuse_pairing(NetAccess* access, uint32_t index)
{
    send_control(access, index, net_message_write_pair_result(access->out.data(), access->out.size(), false));
    net_session_close(&access->session, index);
}

static bool check_build(const NetAccess* access, const NetDeviceInfo* info)
{
    return access->verify_build != nullptr && info->record_size > 0 && access->verify_build(access->verify_user, info);
}

// What a device would get here by default: what it uses and we offer; for an
// unsigned build not FILE TRANSFER or SETTINGS (Andrés, 2026-11-25).
static NetCaps default_grants(const NetAccess* access, const NetAccessPeer* peer, NetCaps base)
{
    NetCaps grants = base & access->info.offers & peer->info.uses;
    if (!peer->signed_build)
    {
        grants &= ~NET_CAPS_UNSIGNED_OFF;
    }
    return grants;
}

// hello from a paired device: welcome it with what it may use, and keep its
// name, kind and build up to date.
static void on_paired_hello(NetAccess* access, uint32_t index, const uint8_t* data, size_t size, NetAccessEvent* event,
                            bool* filled)
{
    NetAccessPeer* peer = &access->peers[index];
    if (!net_message_read_hello(data, size, &peer->info))
    {
        host_log(LogLevel::warning, "Network: a paired device's hello didn't read: closed");
        net_session_close(&access->session, index);
        peer->state = NetAccessPeerState::none;
        return;
    }
    peer->has_info = true;
    peer->signed_build = check_build(access, &peer->info);
    refresh_trust(access);
    if (peer->state != NetAccessPeerState::hello_wait)
    {
        return;   // forgotten meanwhile (remap_peers closed it)
    }
    const NetTrustedDevice* known = &access->trust.devices[static_cast<size_t>(peer->device)];
    if (known->name != peer->info.name || known->kind != peer->info.kind || known->signed_build != peer->signed_build)
    {
        edit_begin(access);
        if (peer->state == NetAccessPeerState::hello_wait)
        {
            NetTrustedDevice* device = &access->trust.devices[static_cast<size_t>(peer->device)];
            net_trust_rename(&access->trust, static_cast<uint32_t>(peer->device), peer->info.name);
            device->kind = peer->info.kind;
            device->signed_build = peer->signed_build;
        }
        edit_end(access);
    }
    if (peer->state != NetAccessPeerState::hello_wait)
    {
        return;
    }
    peer->state = NetAccessPeerState::authorized;
    send_welcome(access, index);
    event->type = NetAccessEventType::authorized;
    event->device = peer->device;
    std::memcpy(event->key, peer->key, NET_KEY_SIZE);
    event->caps = effective_caps(access, peer);
    event->info = peer->info;
    event->signed_build = peer->signed_build;
    *filled = true;
}

// pair_ask: the device wants to pair. With a shown code it takes that one;
// otherwise we make a code and the frontend shows it (pairing_requested). A
// pair_ask after our pair_response is the other side saying the code was
// wrong: a request gets a new code.
static void on_pair_ask(NetAccess* access, uint32_t index, NetAccessEvent* event, bool* filled)
{
    NetAccessPeer* peer = &access->peers[index];
    bool retry = peer->state == NetAccessPeerState::pairing || peer->state == NetAccessPeerState::requested;
    if (retry)
    {
        crypto_wipe(peer->isk, sizeof(peer->isk));
        peer->failures++;
    }
    if (!peer->has_info || peer->failures >= NET_PAIRING_MAX_FAILURES)
    {
        if (peer->failures >= NET_PAIRING_MAX_FAILURES)
        {
            host_log(LogLevel::warning, "Network: \"%s\" got the code wrong %u times, refused", peer->info.name,
                     static_cast<unsigned>(peer->failures));
        }
        refuse_pairing(access, index);
        event->type = NetAccessEventType::pairing_failed;
        *filled = true;
        return;
    }
    peer->state = NetAccessPeerState::requested;
    peer->since = net_seconds();
    if (access->showing && (!retry || peer->shown_code))
    {
        std::memcpy(peer->code, access->shown_code, sizeof(peer->code));
        peer->shown_code = true;
        peer->grants = default_grants(access, peer, access->shown_grants);
        return;   // no dialog: the user already sees the code
    }
    if (!net_pair_code_generate(peer->code))
    {
        refuse_pairing(access, index);
        event->type = NetAccessEventType::pairing_failed;
        *filled = true;
        return;
    }
    peer->shown_code = false;
    if (!retry)
    {
        peer->grants = default_grants(access, peer, NET_CAPS_ALL);
    }
    event->type = NetAccessEventType::pairing_requested;
    std::memcpy(event->code, peer->code, sizeof(event->code));
    event->info = peer->info;
    event->signed_build = peer->signed_build;
    event->caps = peer->grants;
    event->retry = retry;
    *filled = true;
}

// pair_request: the other side's CPace share, from the code its user typed.
// We know the code, so we answer at once.
static void on_pair_request(NetAccess* access, uint32_t index, const uint8_t* data, size_t size)
{
    NetAccessPeer* peer = &access->peers[index];
    uint8_t their_share[NET_CPACE_SHARE_SIZE];
    if (!net_message_read_pair_request(data, size, their_share))
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
        prs[i] = static_cast<uint8_t>(peer->code[i]);
    }
    bool started = net_cpace_start(&cpace, prs, sizeof(prs), ci, sizeof(ci), peer->handshake_hash, NET_PAIR_SID_SIZE);
    crypto_wipe(prs, sizeof(prs));
    uint8_t our_share[NET_CPACE_SHARE_SIZE];
    std::memcpy(our_share, cpace.share, sizeof(our_share));
    // ADa = the client's name as its hello said it, ADb = ours as we send it.
    uint8_t ad_a[NET_DEVICE_NAME_MAX];
    uint8_t ad_b[NET_DEVICE_NAME_MAX];
    size_t ad_a_size = net_pair_name_bytes(peer->info.name, ad_a);
    size_t ad_b_size = net_pair_name_bytes(access->info.name, ad_b);
    bool finished = started && net_cpace_finish(&cpace, false, their_share, ad_a, ad_a_size, ad_b, ad_b_size,
                                                peer->handshake_hash, NET_PAIR_SID_SIZE, peer->isk);
    net_cpace_wipe(&cpace);
    if (!finished)
    {
        // A low-order share: not an honest client.
        refuse_pairing(access, index);
        return;
    }
    uint8_t confirm[NET_PAIR_CONFIRM_SIZE];
    net_pair_confirm(peer->isk, true, confirm);
    send_control(access, index,
                 net_message_write_pair_response(access->out.data(), access->out.size(), our_share, confirm));
    peer->state = NetAccessPeerState::pairing;
    peer->since = net_seconds();
}

bool net_access_set_pairing_grants(NetAccess* access, uint32_t index, NetCaps grants)
{
    if (index >= NET_MAX_PEERS || (access->peers[index].state != NetAccessPeerState::requested &&
                                   access->peers[index].state != NetAccessPeerState::pairing))
    {
        return false;
    }
    NetAccessPeer* peer = &access->peers[index];
    peer->grants = grants & access->info.offers & peer->info.uses;
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

static void on_pair_confirm(NetAccess* access, uint32_t index, const uint8_t* data, size_t size, NetAccessEvent* event,
                            bool* filled)
{
    NetAccessPeer* peer = &access->peers[index];
    uint8_t received[NET_PAIR_CONFIRM_SIZE];
    uint8_t expected[NET_PAIR_CONFIRM_SIZE];
    net_pair_confirm(peer->isk, false, expected);
    bool ok = net_message_read_pair_confirm(data, size, received) && crypto_verify32(received, expected) == 0;
    crypto_wipe(peer->isk, sizeof(peer->isk));
    crypto_wipe(peer->code, sizeof(peer->code));
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
    edit_begin(access);
    uint32_t device = net_trust_add(&access->trust, peer->key, peer->info.name);
    NetTrustedDevice* record = &access->trust.devices[device];
    record->grants = peer->grants;
    record->kind = peer->info.kind;
    record->signed_build = peer->signed_build;
    peer->state = NetAccessPeerState::authorized;
    peer->device = static_cast<int32_t>(device);
    edit_end(access);
    send_control(access, index, net_message_write_pair_result(access->out.data(), access->out.size(), true));
    // What it may use here (our user's ticks ∩ what it uses).
    send_welcome(access, index);
    if (peer->shown_code)
    {
        net_access_end_code(access);   // one code, one device: the window shows who paired
    }
    char fingerprint[32];
    net_key_fingerprint(peer->key, fingerprint, sizeof(fingerprint));
    host_log(LogLevel::info, "Network: paired with \"%s\" (%s)", peer->info.name, fingerprint);
    event->type = NetAccessEventType::paired;
    event->device = peer->device;
    std::memcpy(event->key, peer->key, NET_KEY_SIZE);
    event->caps = effective_caps(access, peer);
    event->info = peer->info;
    event->signed_build = peer->signed_build;
    *filled = true;
}

// Forgets a paired device (saved at once). Its connections stop reaching
// the frontend (their `closed` still does). Each is told (unpair) and
// closed, except `unpaired_by`: the peer that unpaired itself, which closes
// on its own (NET_NO_PEER: none did).
static void forget_device(NetAccess* access, const uint8_t* key, uint32_t unpaired_by)
{
    edit_begin(access);
    int32_t found = net_trust_find(&access->trust, key);
    if (found < 0)
    {
        net_trust_file_unlock();
        return;
    }
    uint32_t device = static_cast<uint32_t>(found);
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        NetAccessPeer* peer = &access->peers[i];
        if (peer->state != NetAccessPeerState::authorized && peer->state != NetAccessPeerState::hello_wait)
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
    edit_end(access);
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
        net_device_info_set_name(&event->info, name);
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
    event->caps = NET_CAP_STREAM;
    net_device_info_set_name(&event->info, name);
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

// A control message from an authorized peer. True if `event` was filled.
static bool on_authorized_control(NetAccess* access, uint32_t index, const NetSessionEvent* session_event,
                                  NetAccessEvent* event)
{
    NetAccessPeer* peer = &access->peers[index];
    const uint8_t* data = session_event->data;
    size_t size = session_event->size;
    uint8_t type = net_message_type(data, size);
    if (net_message_read_unpair(data, size))
    {
        // The device forgot us: forget it. It closes the connection;
        // its `closed` comes later (forgotten).
        event->type = NetAccessEventType::unpaired;
        event->peer = index;
        event->device = -1;
        event->address = session_event->address;
        event->info = peer->info;
        forget_device(access, peer->key, index);
        return true;
    }
    NetCaps granted = 0;
    if (net_message_read_grant(data, size, &granted))
    {
        edit_begin(access);
        if (peer->state == NetAccessPeerState::authorized)
        {
            access->trust.devices[static_cast<size_t>(peer->device)].granted = granted;
        }
        edit_end(access);
        if (peer->state != NetAccessPeerState::authorized)
        {
            return false;
        }
        event->type = NetAccessEventType::granted;
        event->peer = index;
        event->device = peer->device;
        std::memcpy(event->key, peer->key, NET_KEY_SIZE);
        event->caps = granted;
        event->address = session_event->address;
        return true;
    }
    // Other control messages of this layer aren't the application's, and an
    // application message needs its capability.
    if (type < NET_MESSAGE_FIRST_APP || !net_caps_allow(effective_caps(access, peer), type))
    {
        if (type >= NET_MESSAGE_FIRST_APP)
        {
            access->dropped_by_access++;
        }
        return false;
    }
    return false;   // the caller reports it as a message
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
        if (session_event->channel == NetChannel::input)
        {
            // Pad packets need the GAMEPAD grant, like the control messages
            // need theirs: a device granted only SHARE can't press buttons.
            if ((effective_caps(access, peer) & NET_CAP_GAMEPAD) == 0)
            {
                access->dropped_by_access++;
                return false;
            }
        }
        if (session_event->channel == NetChannel::control)
        {
            uint8_t type = net_message_type(session_event->data, session_event->size);
            if (on_authorized_control(access, index, session_event, event))
            {
                return true;
            }
            if (type < NET_MESSAGE_FIRST_APP || !net_caps_allow(effective_caps(access, peer), type) ||
                peer->state != NetAccessPeerState::authorized)
            {
                return false;
            }
        }
        event->type = NetAccessEventType::message;
        event->caps = effective_caps(access, peer);
        event->peer = index;
        event->device = peer->device;
        std::memcpy(event->key, peer->key, NET_KEY_SIZE);
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
        event->caps = NET_CAP_STREAM;
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
    if (peer->state == NetAccessPeerState::hello_wait)
    {
        if (type == static_cast<uint8_t>(NetMessage::hello))
        {
            on_paired_hello(access, index, session_event->data, session_event->size, event, &filled);
        }
        else
        {
            host_log(LogLevel::warning, "Network: a paired device sent %u before hello: closed", static_cast<unsigned>(type));
            refuse_pairing(access, index);   // nothing before hello
        }
    }
    else if (peer->state == NetAccessPeerState::unpaired && type == static_cast<uint8_t>(NetGuestMessage::hello))
    {
        on_guest_hello(access, index, session_event->data, session_event->size, event, &filled);
    }
    else if (peer->state == NetAccessPeerState::unpaired && type == static_cast<uint8_t>(NetMessage::hello))
    {
        // A device we don't know says who it is: kept for a pair_ask.
        peer->has_info = net_message_read_hello(session_event->data, session_event->size, &peer->info);
        peer->signed_build = peer->has_info && check_build(access, &peer->info);
        if (!peer->has_info)
        {
            refuse_pairing(access, index);
        }
    }
    else if (peer->guest_only)
    {
        // Pairing is closed: only a guest_hello could have come.
        net_session_close(&access->session, index);
        peer->state = NetAccessPeerState::none;
    }
    else if ((peer->state == NetAccessPeerState::unpaired || peer->state == NetAccessPeerState::requested ||
              peer->state == NetAccessPeerState::pairing) &&
             net_message_read_pair_ask(session_event->data, session_event->size))
    {
        on_pair_ask(access, index, event, &filled);
    }
    else if (peer->state == NetAccessPeerState::requested && type == static_cast<uint8_t>(NetMessage::pair_request))
    {
        on_pair_request(access, index, session_event->data, session_event->size);
    }
    else if (peer->state == NetAccessPeerState::pairing && type == static_cast<uint8_t>(NetMessage::pair_confirm))
    {
        on_pair_confirm(access, index, session_event->data, session_event->size, event, &filled);
    }
    else
    {
        // Anything else before authorization is a protocol error (its
        // `closed` tells the frontend if it was a request).
        host_log(LogLevel::warning, "Network: message %u out of place (state %d): closed", static_cast<unsigned>(type),
                 static_cast<int>(peer->state));
        refuse_pairing(access, index);
    }
    if (filled)
    {
        event->peer = index;
        event->address = session_event->address;
    }
    return filled;
}

// Peers stuck in a step, and the shown code's time.
static bool check_timers(NetAccess* access, NetAccessEvent* event)
{
    double now = net_seconds();
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        NetAccessPeer* peer = &access->peers[i];
        bool waiting = peer->state == NetAccessPeerState::unpaired || peer->state == NetAccessPeerState::pairing ||
                       peer->state == NetAccessPeerState::hello_wait;
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
    if (access->showing && now - access->shown_since > NET_ACCESS_REQUEST_SECONDS)
    {
        net_access_end_code(access);
        event->type = NetAccessEventType::code_expired;
        return true;
    }
    return false;
}

bool net_access_poll(NetAccess* access, NetAccessEvent* event)
{
    *event = {};
    net_beacon_host_update(&access->beacon, &access->session.host, net_seconds());
    net_signal_update(&access->signal, &access->session, net_seconds());
    refresh_trust(access);
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
            on_secured(access, &session_event);
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
            uint8_t closed_key[NET_KEY_SIZE];
            std::memcpy(closed_key, peer->key, NET_KEY_SIZE);   // peer_reset wipes it
            bool forgotten = peer->forgotten;
            bool shown = peer->shown_code;
            peer_reset(peer);
            if ((state == NetAccessPeerState::requested && !shown) || state == NetAccessPeerState::pairing)
            {
                // A request went (cancelled on the other side, or closed): the
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
                std::memcpy(event->key, closed_key, NET_KEY_SIZE);
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
                       (channel == NetChannel::control &&
                        (type == NET_MESSAGE_FIRST_APP ||
                         (type >= NET_MESSAGE_FIRST_STREAM && type < NET_MESSAGE_FIRST_SETTINGS)));
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
    if (device >= access->trust.devices.size())
    {
        return;
    }
    uint8_t key[NET_KEY_SIZE];
    std::memcpy(key, access->trust.devices[device].key, NET_KEY_SIZE);
    forget_device(access, key, NET_NO_PEER);
}

void net_access_set_grants(NetAccess* access, uint32_t device, NetCaps grants)
{
    if (device >= access->trust.devices.size())
    {
        return;
    }
    uint8_t key[NET_KEY_SIZE];
    std::memcpy(key, access->trust.devices[device].key, NET_KEY_SIZE);
    edit_begin(access);
    int32_t found = net_trust_find(&access->trust, key);
    if (found >= 0)
    {
        access->trust.devices[static_cast<size_t>(found)].grants = grants & NET_CAPS_ALL;
    }
    edit_end(access);
    // A connected device gets a new welcome (to show what it can use).
    for (uint32_t i = 0; i < NET_MAX_PEERS; i++)
    {
        if (found >= 0 && access->peers[i].state == NetAccessPeerState::authorized &&
            access->peers[i].device == found)
        {
            send_welcome(access, i);
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

bool net_access_guest_ready(const NetAccess* access)
{
    return access->guest_open && net_signal_guest_room_joined(&access->signal);
}
