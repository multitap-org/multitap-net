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
}

void net_client_destroy(NetClient* client)
{
    forget_secrets(client);
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
    return true;
}

static void refuse(NetClient* client, NetClientRefusal refusal, bool we_close, NetClientEvent* event);

bool net_client_connect_beacon(NetClient* client, const NetAddress* servers, uint32_t count, uint32_t device)
{
    if (client->state != NetClientState::idle || device >= client->trust.devices.size())
    {
        return false;
    }
    forget_secrets(client);
    BeaconId id;
    if (!net_beacon_meeting_id(&client->session.identity, client->trust.devices[device].key, &id) ||
        !net_beacon_client_start(&client->beacon, servers, count, &id, net_seconds()))
    {
        return false;
    }
    client->peer = NET_NO_PEER;
    client->via_beacon = true;
    client->state = NetClientState::meeting;
    return true;
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
        NetClientRefusal refusal = client->beacon.failure == NetBeaconFailure::host_offline
                                       ? NetClientRefusal::host_offline
                                       : NetClientRefusal::beacon_unreachable;
        refuse(client, refusal, false, event);
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
    client->via_beacon = false;
    client->state = NetClientState::idle;
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
                                                        client->name.c_str()));
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
        // The host's key doesn't match ours: a different code (or someone in
        // the middle). Closing counts as a failed attempt on the host.
        refuse(client, NetClientRefusal::wrong_code, true, event);
        return;
    }
    std::snprintf(client->host_name, sizeof(client->host_name), "%s", host_name);
    uint8_t confirm[NET_PAIR_CONFIRM_SIZE];
    net_pair_confirm(client->isk, false, confirm);
    crypto_wipe(client->isk, sizeof(client->isk));
    send_control(client, net_message_write_pair_confirm(client->out.data(), client->out.size(), confirm));
    client->state = NetClientState::confirming;
}

static void on_control(NetClient* client, const uint8_t* data, size_t size, NetClientEvent* event)
{
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
            client->access = NetAccessLevel::gamepad;   // where every new device starts
            client->state = NetClientState::ready;
            event->type = NetClientEventType::ready;
            event->newly_paired = true;
            event->access = client->access;
            event->device = client->device;
            return;
        }
        refuse(client, NetClientRefusal::wrong_code, false, event);   // the host closes after a refused result
        return;
    }
    refuse(client, NetClientRefusal::connection, true, event);   // a message out of place
}

bool net_client_poll(NetClient* client, NetClientEvent* event)
{
    *event = {};
    if (beacon_step(client, event))
    {
        return true;
    }
    NetSessionEvent session_event;
    while (net_session_poll(&client->session, &session_event))
    {
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
        case NetSessionEventType::signal:   // WebRTC signaling: carried by the beacon (next step)
            break;
        case NetSessionEventType::secured:
            std::memcpy(client->host_key, session_event.remote_key, NET_KEY_SIZE);
            std::memcpy(client->handshake_hash, session_event.handshake_hash, NET_HASH_SIZE);
            client->state = NetClientState::waiting;
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
            forget_secrets(client);
            net_beacon_client_stop(&client->beacon);
            client->via_beacon = false;
            client->state = NetClientState::idle;
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
            }
            break;
        }
        }
        if (event->type != NetClientEventType::none)
        {
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
        client->via_beacon = false;
        client->state = NetClientState::idle;
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
