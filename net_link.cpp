#include "net_link.h"

#include <cstring>

static void write_u64(uint8_t* out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; i++)
    {
        out[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
    }
}

static uint64_t read_u64(const uint8_t* data)
{
    uint64_t value = 0;
    for (uint32_t i = 0; i < 8; i++)
    {
        value |= static_cast<uint64_t>(data[i]) << (8 * i);
    }
    return value;
}

void net_link_init(NetLink* link, NetNoiseRole role, const NetKeypair* identity)
{
    *link = {};
    // The prologue as bytes (Noise takes bytes; the constant is text).
    uint8_t prologue[32];
    size_t prologue_size = std::strlen(NET_LINK_PROLOGUE);
    for (size_t i = 0; i < prologue_size && i < sizeof(prologue); i++)
    {
        prologue[i] = static_cast<uint8_t>(NET_LINK_PROLOGUE[i]);
    }
    net_noise_init(&link->noise, role, identity, prologue, prologue_size);
}

static NetLinkReceive link_fail(NetLink* link)
{
    link->state = NetLinkState::failed;
    net_noise_wipe(&link->noise);
    net_cipher_wipe(&link->send);
    net_cipher_wipe(&link->receive);
    return NetLinkReceive::failed;
}

// The handshake just finished: keep what the session needs, then split.
static void link_ready(NetLink* link)
{
    std::memcpy(link->remote_key, link->noise.rs, NET_KEY_SIZE);
    std::memcpy(link->handshake_hash, link->noise.h, NET_HASH_SIZE);
    net_noise_split(&link->noise, &link->send, &link->receive);
    net_noise_wipe(&link->noise);
    link->state = NetLinkState::ready;
}

bool net_link_start(NetLink* link, uint8_t* out, size_t capacity, size_t* out_size)
{
    if (link->state != NetLinkState::handshaking || link->noise.role != NetNoiseRole::initiator ||
        !net_noise_write(&link->noise, nullptr, 0, out, capacity, out_size))
    {
        link_fail(link);
        return false;
    }
    return true;
}

NetLinkReceive net_link_receive_control(NetLink* link, const uint8_t* data, size_t size, uint8_t* reply,
                                        size_t reply_capacity, size_t* reply_size, uint8_t* payload,
                                        size_t payload_capacity, size_t* payload_size)
{
    *reply_size = 0;
    *payload_size = 0;
    if (link->state == NetLinkState::failed)
    {
        return NetLinkReceive::failed;
    }
    if (link->state == NetLinkState::ready)
    {
        if (size < NET_MAC_SIZE || size - NET_MAC_SIZE > payload_capacity ||
            !net_cipher_decrypt(&link->receive, nullptr, 0, data, size, payload))
        {
            // On a reliable, ordered channel a bad message is never noise:
            // someone tampered with it. The link can't be trusted any more.
            return link_fail(link);
        }
        *payload_size = size - NET_MAC_SIZE;
        return NetLinkReceive::message;
    }

    // Handshaking. Handshake payloads aren't used yet (pairing will use them).
    uint8_t handshake_payload[256];
    size_t handshake_payload_size = 0;
    if (!net_noise_read(&link->noise, data, size, handshake_payload, sizeof(handshake_payload), &handshake_payload_size))
    {
        return link_fail(link);
    }
    if (net_noise_my_turn(&link->noise))
    {
        if (!net_noise_write(&link->noise, nullptr, 0, reply, reply_capacity, reply_size))
        {
            return link_fail(link);
        }
    }
    if (net_noise_done(&link->noise))
    {
        link_ready(link);
    }
    return NetLinkReceive::handshake;
}

bool net_link_open_input(NetLink* link, const uint8_t* data, size_t size, uint8_t* payload, size_t capacity,
                         size_t* payload_size)
{
    *payload_size = 0;
    if (link->state != NetLinkState::ready || size < NET_LINK_OVERHEAD ||
        size - NET_LINK_OVERHEAD > capacity)
    {
        link->input_dropped++;
        return false;
    }
    uint64_t nonce = read_u64(data);
    // Must be an input nonce, and newer than the last one we accepted.
    if ((nonce & NET_LINK_INPUT_NONCE_BIT) == 0 || nonce <= link->input_last)
    {
        link->input_dropped++;
        return false;
    }
    size_t cipher_size = size - NET_LINK_INPUT_HEADER_SIZE;
    if (!net_cipher_decrypt_at(&link->receive, nonce, nullptr, 0, data + NET_LINK_INPUT_HEADER_SIZE, cipher_size,
                               payload))
    {
        // Unlike control, a bad input packet doesn't kill the link: anyone can
        // send a datagram that looks like ENet's. It's just dropped.
        link->input_dropped++;
        return false;
    }
    link->input_last = nonce;
    *payload_size = cipher_size - NET_MAC_SIZE;
    return true;
}

bool net_link_seal(NetLink* link, NetChannel channel, const uint8_t* data, size_t size, uint8_t* out,
                   size_t capacity, size_t* out_size)
{
    *out_size = 0;
    if (link->state != NetLinkState::ready || size > NET_LINK_MAX_PAYLOAD || size + NET_LINK_OVERHEAD > capacity)
    {
        return false;
    }
    if (channel == NetChannel::control)
    {
        net_cipher_encrypt(&link->send, nullptr, 0, data, size, out);
        *out_size = size + NET_MAC_SIZE;
        return true;
    }
    uint64_t nonce = link->input_next;
    link->input_next++;
    write_u64(out, nonce);
    net_cipher_encrypt_at(&link->send, nonce, nullptr, 0, data, size, out + NET_LINK_INPUT_HEADER_SIZE);
    *out_size = NET_LINK_INPUT_HEADER_SIZE + size + NET_MAC_SIZE;
    return true;
}

void net_link_wipe(NetLink* link)
{
    net_noise_wipe(&link->noise);
    net_cipher_wipe(&link->send);
    net_cipher_wipe(&link->receive);
    link->state = NetLinkState::failed;
}
