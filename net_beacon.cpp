#include "net_beacon.h"

#include "net_pairing.h"

#include <cstring>

#include <monocypher.h>

#include "host_log.h"
#include "net_random.h"

static const char MEETING_ID_PREFIX[] = "multitap beacon v1";
static const char SIGNAL_KEY_PREFIX[] = "multitap signal v1";
static const char PAIR_ID_PREFIX[] = "multitap pair v2";
static const char PAIR_SIGNAL_KEY_PREFIX[] = "multitap pair signal v2";

// BLAKE2b(prefix || X25519(own, other)), `size` bytes. False for a shared
// secret of all zeros (a key that can't be used).
static bool derive(const NetKeypair* own, const uint8_t* other_public_key, const char* prefix, size_t prefix_size,
                   uint8_t* out, size_t size)
{
    uint8_t shared[NET_KEY_SIZE];
    crypto_x25519(shared, own->secret, other_public_key);
    uint8_t any = 0;
    for (size_t i = 0; i < sizeof(shared); i++)
    {
        any = static_cast<uint8_t>(any | shared[i]);
    }
    if (any == 0)
    {
        return false;
    }
    crypto_blake2b_ctx context;
    crypto_blake2b_init(&context, size);
    crypto_blake2b_update(&context, reinterpret_cast<const uint8_t*>(prefix), prefix_size);
    crypto_blake2b_update(&context, shared, sizeof(shared));
    crypto_blake2b_final(&context, out);
    crypto_wipe(shared, sizeof(shared));
    return true;
}

bool net_beacon_meeting_id(const NetKeypair* own, const uint8_t* other_public_key, BeaconId* id)
{
    return derive(own, other_public_key, MEETING_ID_PREFIX, sizeof(MEETING_ID_PREFIX) - 1, id->bytes, BEACON_ID_SIZE);
}

bool net_beacon_signal_key(const NetKeypair* own, const uint8_t* other_public_key, uint8_t* key)
{
    return derive(own, other_public_key, SIGNAL_KEY_PREFIX, sizeof(SIGNAL_KEY_PREFIX) - 1, key, 32);
}

// BLAKE2b(prefix || slot digits), `size` bytes.
static void derive_slot(const char* slot, const char* prefix, size_t prefix_size, uint8_t* out, size_t size)
{
    crypto_blake2b_ctx context;
    crypto_blake2b_init(&context, size);
    crypto_blake2b_update(&context, reinterpret_cast<const uint8_t*>(prefix), prefix_size);
    crypto_blake2b_update(&context, reinterpret_cast<const uint8_t*>(slot), NET_PAIR_SLOT_DIGITS);
    crypto_blake2b_final(&context, out);
}

void net_beacon_pair_id(const char* slot, BeaconId* id)
{
    derive_slot(slot, PAIR_ID_PREFIX, sizeof(PAIR_ID_PREFIX) - 1, id->bytes, BEACON_ID_SIZE);
}

void net_beacon_pair_signal_key(const char* slot, uint8_t* key)
{
    derive_slot(slot, PAIR_SIGNAL_KEY_PREFIX, sizeof(PAIR_SIGNAL_KEY_PREFIX) - 1, key, 32);
}

const char* net_beacon_status_name(NetBeaconStatus status)
{
    switch (status)
    {
    case NetBeaconStatus::off:
        return "off";
    case NetBeaconStatus::waiting:
        return "waiting";
    case NetBeaconStatus::registered:
        return "registered";
    case NetBeaconStatus::symmetric_nat:
        return "symmetric NAT";
    case NetBeaconStatus::unreachable:
        return "unreachable";
    }
    return "?";
}

static uint64_t random_nonce()
{
    uint64_t nonce = 0;
    while (nonce == 0)
    {
        uint8_t bytes[8];
        if (!net_random_bytes(bytes, sizeof(bytes)))
        {
            return 1;   // no randomness: the nonce only matches replies, it isn't a secret
        }
        std::memcpy(&nonce, bytes, sizeof(nonce));
    }
    return nonce;
}

static NetAddress from_beacon(const BeaconAddress* address)
{
    NetAddress result;
    std::memcpy(result.ip, address->ip, sizeof(result.ip));
    result.port = address->port;
    return result;
}

static bool send_message(NetHost* host, NetAddress to, const BeaconMessage* message)
{
    uint8_t packet[BEACON_MAX_MESSAGE_SIZE];
    uint32_t size = beacon_encode(message, packet, sizeof(packet));
    return size > 0 && net_host_send_datagram(host, to, packet, size);
}

// --- Punches (both sides) -------------------------------------------------

static void punch_add(NetBeaconPunch* punches, uint32_t count, NetAddress to, const BeaconId* id, uint64_t nonce,
                      double now)
{
    NetBeaconPunch* free_slot = nullptr;
    for (uint32_t i = 0; i < count; i++)
    {
        NetBeaconPunch* punch = &punches[i];
        if (punch->active && punch->nonce == nonce && net_address_equal(punch->to, to) &&
            beacon_id_equal(&punch->id, id))
        {
            return;   // already punching there
        }
        if (!punch->active && free_slot == nullptr)
        {
            free_slot = punch;
        }
    }
    if (free_slot == nullptr)
    {
        // All busy: the one that ends first makes room (the newest meeting matters most).
        free_slot = &punches[0];
        for (uint32_t i = 1; i < count; i++)
        {
            if (punches[i].until < free_slot->until)
            {
                free_slot = &punches[i];
            }
        }
    }
    free_slot->active = true;
    free_slot->to = to;
    free_slot->id = *id;
    free_slot->nonce = nonce;
    free_slot->until = now + NET_BEACON_PUNCH_SECONDS;
    free_slot->next = now;
}

static void punch_update(NetBeaconPunch* punches, uint32_t count, NetHost* host, double now)
{
    for (uint32_t i = 0; i < count; i++)
    {
        NetBeaconPunch* punch = &punches[i];
        if (!punch->active)
        {
            continue;
        }
        if (now >= punch->until)
        {
            punch->active = false;
            continue;
        }
        if (now < punch->next)
        {
            continue;
        }
        BeaconMessage message;
        message.type = BeaconType::PUNCH;
        message.nonce = punch->nonce;
        message.ids[0] = punch->id;
        send_message(host, punch->to, &message);
        punch->next = now + NET_BEACON_PUNCH_INTERVAL;
    }
}

// A PUNCH with an id and nonce we punch for. True if it matched; a new source
// address gets punched too.
static bool punch_heard(NetBeaconPunch* punches, uint32_t count, const BeaconMessage* message, NetAddress from,
                        double now)
{
    for (uint32_t i = 0; i < count; i++)
    {
        NetBeaconPunch* punch = &punches[i];
        if (punch->active && punch->nonce == message->nonce && beacon_id_equal(&punch->id, &message->ids[0]))
        {
            if (!net_address_equal(punch->to, from))
            {
                punch_add(punches, count, from, &punch->id, punch->nonce, now);
            }
            return true;
        }
    }
    return false;
}

// --- Host -------------------------------------------------------------------

void net_beacon_host_set_servers(NetBeaconHost* beacon, const NetAddress* servers, uint32_t count)
{
    if (count > NET_BEACON_MAX_SERVERS)
    {
        count = NET_BEACON_MAX_SERVERS;
    }
    for (uint32_t i = 0; i < NET_BEACON_MAX_SERVERS; i++)
    {
        beacon->servers[i] = {};
    }
    for (uint32_t i = 0; i < count; i++)
    {
        beacon->servers[i].address = servers[i];
    }
    beacon->server_count = count;
}

void net_beacon_host_set_ids(NetBeaconHost* beacon, const BeaconId* ids, uint32_t count)
{
    beacon->ids.assign(ids, ids + count);
    for (uint32_t i = 0; i < beacon->server_count; i++)
    {
        beacon->servers[i].next_register = 0.0;   // now
        beacon->servers[i].registered = false;
    }
}

static NetAddress secondary_of(NetAddress primary)
{
    primary.port = static_cast<uint16_t>(primary.port + 1);
    return primary;
}

// Every id, BEACON_MAX_IDS per REGISTER, with the cookie we have (or the
// first REGISTER only, without one: the server answers COOKIE and we resend).
static void send_registers(NetBeaconHost* beacon, NetHost* host, NetBeaconServer* server)
{
    size_t total = beacon->ids.size();
    for (size_t first = 0; first < total; first += BEACON_MAX_IDS)
    {
        BeaconMessage message;
        message.type = BeaconType::REGISTER;
        message.nonce = server->nonce;
        if (server->has_cookie)
        {
            std::memcpy(message.cookie, server->cookie, BEACON_COOKIE_SIZE);
        }
        size_t count = total - first < BEACON_MAX_IDS ? total - first : BEACON_MAX_IDS;
        message.id_count = static_cast<uint8_t>(count);
        for (size_t i = 0; i < count; i++)
        {
            message.ids[i] = beacon->ids[first + i];
        }
        send_message(host, server->address, &message);
        if (!server->has_cookie)
        {
            break;
        }
    }
}

static void start_round(NetBeaconHost* beacon, NetHost* host, NetBeaconServer* server, double now)
{
    server->nonce = random_nonce();
    if (server->first_sent < 0.0)
    {
        server->first_sent = now;
    }
    // BIND both ports: how the server sees us, and whether our NAT keeps one
    // port for every destination (punching needs that).
    BeaconMessage bind;
    bind.type = BeaconType::BIND;
    bind.nonce = server->nonce;
    send_message(host, server->address, &bind);
    send_message(host, secondary_of(server->address), &bind);
    send_registers(beacon, host, server);

    bool heard_lately = server->last_heard >= 0.0 && now - server->last_heard < NET_BEACON_SILENT_SECONDS;
    if (server->registered || (heard_lately && beacon->ids.empty()))
    {
        server->next_register = now + NET_BEACON_REGISTER_SECONDS;
    }
    else if (server->first_sent >= 0.0 && now - server->first_sent > NET_BEACON_SILENT_SECONDS && !heard_lately)
    {
        server->next_register = now + NET_BEACON_SILENT_SECONDS;   // down: ask less often
    }
    else
    {
        server->next_register = now + NET_BEACON_RETRY_SECONDS;
    }
}

void net_beacon_host_update(NetBeaconHost* beacon, NetHost* host, double now)
{
    for (uint32_t i = 0; i < beacon->server_count; i++)
    {
        NetBeaconServer* server = &beacon->servers[i];
        if (now >= server->next_register)
        {
            start_round(beacon, host, server, now);
        }
    }
    punch_update(beacon->punches, NET_BEACON_MAX_PUNCHES, host, now);
}

static NetBeaconServer* server_from(NetBeaconHost* beacon, NetAddress from, bool* secondary)
{
    for (uint32_t i = 0; i < beacon->server_count; i++)
    {
        NetBeaconServer* server = &beacon->servers[i];
        if (net_address_equal(server->address, from))
        {
            *secondary = false;
            return server;
        }
        if (net_address_equal(secondary_of(server->address), from))
        {
            *secondary = true;
            return server;
        }
    }
    return nullptr;
}

static bool host_knows_id(const NetBeaconHost* beacon, const BeaconId* id)
{
    for (size_t i = 0; i < beacon->ids.size(); i++)
    {
        if (beacon_id_equal(&beacon->ids[i], id))
        {
            return true;
        }
    }
    return false;
}

bool net_beacon_host_receive(NetBeaconHost* beacon, NetHost* host, const BeaconMessage* message, NetAddress from,
                             double now)
{
    if (message->type == BeaconType::PUNCH)
    {
        return punch_heard(beacon->punches, NET_BEACON_MAX_PUNCHES, message, from, now);
    }
    bool secondary = false;
    NetBeaconServer* server = server_from(beacon, from, &secondary);
    if (server == nullptr)
    {
        return false;
    }
    switch (message->type)
    {
    case BeaconType::BOUND:
        if (message->nonce != server->nonce)
        {
            return false;
        }
        if (secondary)
        {
            server->observed_secondary = from_beacon(&message->address);
            server->has_observed_secondary = true;
        }
        else
        {
            server->observed = from_beacon(&message->address);
            server->has_observed = true;
        }
        server->last_heard = now;
        return true;
    case BeaconType::COOKIE:
        if (secondary || message->nonce != server->nonce)
        {
            return false;
        }
        // A cookie at any time means "send again with this one" (first
        // REGISTER, server restarted, ours aged out).
        std::memcpy(server->cookie, message->cookie, BEACON_COOKIE_SIZE);
        server->has_cookie = true;
        server->last_heard = now;
        send_registers(beacon, host, server);
        return true;
    case BeaconType::REGISTERED_REPLY:
        if (secondary || message->nonce != server->nonce)
        {
            return false;
        }
        std::memcpy(server->cookie, message->cookie, BEACON_COOKIE_SIZE);   // a fresh one for the next round
        server->has_cookie = true;
        if (!server->registered)
        {
            host_log(LogLevel::info, "Network: beacon has our %u meeting id(s)",
                     static_cast<unsigned>(beacon->ids.size()));
        }
        // One REGISTERED per REGISTER; any refusal (server full, our limit) shows.
        server->registered = message->id_count > 0;
        server->last_heard = now;
        server->next_register = now + NET_BEACON_REGISTER_SECONDS;
        return true;
    case BeaconType::INTRO:
        if (secondary || !host_knows_id(beacon, &message->ids[0]))
        {
            return false;
        }
        punch_add(beacon->punches, NET_BEACON_MAX_PUNCHES, from_beacon(&message->address), &message->ids[0],
                  message->nonce, now);
        beacon->intros++;
        server->last_heard = now;
        return true;
    case BeaconType::BIND:
    case BeaconType::REGISTER:
    case BeaconType::MEET:
    case BeaconType::NOT_FOUND:
    case BeaconType::PUNCH:
        return false;
    }
    return false;
}

NetBeaconStatus net_beacon_host_status(const NetBeaconHost* beacon, double now)
{
    if (beacon->server_count == 0)
    {
        return NetBeaconStatus::off;
    }
    bool heard = false;
    bool registered = false;
    bool symmetric = false;
    bool silent_long = false;
    // An entry lives 60 s on the server: heard within two rounds and a bit is alive.
    double alive = NET_BEACON_REGISTER_SECONDS * 2.0 + 5.0;
    for (uint32_t i = 0; i < beacon->server_count; i++)
    {
        const NetBeaconServer* server = &beacon->servers[i];
        if (server->last_heard >= 0.0 && now - server->last_heard < alive)
        {
            heard = true;
            if (server->registered || beacon->ids.empty())
            {
                registered = true;
            }
            if (server->has_observed && server->has_observed_secondary &&
                server->observed.port != server->observed_secondary.port)
            {
                symmetric = true;
            }
        }
        else if (server->first_sent >= 0.0 && now - server->first_sent > NET_BEACON_SILENT_SECONDS)
        {
            silent_long = true;
        }
    }
    if (registered)
    {
        return symmetric ? NetBeaconStatus::symmetric_nat : NetBeaconStatus::registered;
    }
    if (!heard && silent_long)
    {
        return NetBeaconStatus::unreachable;
    }
    return NetBeaconStatus::waiting;
}

// --- Client -----------------------------------------------------------------

bool net_beacon_client_start(NetBeaconClient* beacon, const NetAddress* servers, uint32_t count, const BeaconId* id,
                             double now)
{
    *beacon = {};
    if (count == 0)
    {
        return false;
    }
    if (count > NET_BEACON_MAX_SERVERS)
    {
        count = NET_BEACON_MAX_SERVERS;
    }
    for (uint32_t i = 0; i < count; i++)
    {
        beacon->servers[i] = servers[i];
    }
    beacon->server_count = count;
    beacon->id = *id;
    beacon->nonce = random_nonce();
    beacon->state = NetBeaconMeetState::meeting;
    beacon->started = now;
    beacon->next_meet = now;
    return true;
}

void net_beacon_client_stop(NetBeaconClient* beacon)
{
    *beacon = {};
}

static constexpr uint32_t CLIENT_PUNCHES = NET_BEACON_MAX_SERVERS * 2;

void net_beacon_client_update(NetBeaconClient* beacon, NetHost* host, double now)
{
    if (beacon->state == NetBeaconMeetState::meeting)
    {
        if (!beacon->patient && now - beacon->started > NET_BEACON_MEET_SECONDS)
        {
            beacon->state = NetBeaconMeetState::failed;
            beacon->failure = beacon->not_found > 0 ? NetBeaconFailure::host_offline : NetBeaconFailure::unreachable;
            return;
        }
        if (now >= beacon->next_meet)
        {
            BeaconMessage meet;
            meet.type = BeaconType::MEET;
            meet.nonce = beacon->nonce;
            meet.ids[0] = beacon->id;
            for (uint32_t i = 0; i < beacon->server_count; i++)
            {
                send_message(host, beacon->servers[i], &meet);
            }
            beacon->next_meet = now + (beacon->patient ? NET_BEACON_PATIENT_INTERVAL : NET_BEACON_MEET_INTERVAL);
        }
        return;
    }
    if (beacon->state == NetBeaconMeetState::punching && now - beacon->intro_at >= NET_BEACON_CONNECT_AFTER)
    {
        // The host's PUNCH hasn't come through (its NAT may only open once
        // ours has sent to it): try the address the beacon gave.
        for (uint32_t i = 0; i < CLIENT_PUNCHES; i++)
        {
            if (beacon->punches[i].active)
            {
                beacon->target = beacon->punches[i].to;
                beacon->state = NetBeaconMeetState::connect;
                break;
            }
        }
    }
    if (beacon->state == NetBeaconMeetState::punching || beacon->state == NetBeaconMeetState::connect)
    {
        punch_update(beacon->punches, CLIENT_PUNCHES, host, now);
    }
}

static int32_t client_server_index(const NetBeaconClient* beacon, NetAddress from)
{
    for (uint32_t i = 0; i < beacon->server_count; i++)
    {
        if (net_address_equal(beacon->servers[i], from))
        {
            return static_cast<int32_t>(i);
        }
    }
    return -1;
}

bool net_beacon_client_receive(NetBeaconClient* beacon, NetHost* host, const BeaconMessage* message, NetAddress from,
                               double now)
{
    (void)host;
    if (beacon->state == NetBeaconMeetState::idle || beacon->state == NetBeaconMeetState::failed)
    {
        return false;
    }
    if (message->type == BeaconType::PUNCH)
    {
        if (message->nonce != beacon->nonce || !beacon_id_equal(&message->ids[0], &beacon->id))
        {
            return false;
        }
        punch_heard(beacon->punches, CLIENT_PUNCHES, message, from, now);
        punch_add(beacon->punches, CLIENT_PUNCHES, from, &beacon->id, beacon->nonce, now);
        if (!beacon->heard_punch && beacon->state != NetBeaconMeetState::connect)
        {
            // Where the host really is, as its NAT shows it: connect there.
            beacon->target = from;
            beacon->state = NetBeaconMeetState::connect;
        }
        beacon->heard_punch = true;
        return true;
    }
    int32_t server = client_server_index(beacon, from);
    if (server < 0 || !beacon_id_equal(&message->ids[0], &beacon->id))
    {
        return false;
    }
    if (message->type == BeaconType::INTRO)
    {
        if (message->nonce != beacon->nonce)
        {
            return false;
        }
        punch_add(beacon->punches, CLIENT_PUNCHES, from_beacon(&message->address), &beacon->id, beacon->nonce, now);
        if (beacon->state == NetBeaconMeetState::meeting)
        {
            beacon->state = NetBeaconMeetState::punching;
            beacon->intro_at = now;
        }
        return true;
    }
    if (message->type == BeaconType::NOT_FOUND && beacon->state == NetBeaconMeetState::meeting)
    {
        if (beacon->patient)
        {
            return true;   // not there yet: the next MEET asks again
        }
        beacon->not_found |= 1u << static_cast<uint32_t>(server);
        if (beacon->not_found == (1u << beacon->server_count) - 1u)
        {
            beacon->state = NetBeaconMeetState::failed;
            beacon->failure = NetBeaconFailure::host_offline;
        }
        return true;
    }
    return false;
}
