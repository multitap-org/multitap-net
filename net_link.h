#pragma once

// One peer's encrypted link, as pure functions (no sockets): the Noise
// handshake (net_noise.h) on the control channel, then every payload on both
// channels encrypted. net_session.h runs one per connected ENet peer.
//
// control (reliable, in order): the three handshake messages, then transport
//   messages with Noise's implicit nonces 0, 1, 2... Order and delivery are
//   guaranteed by ENet, so both sides always agree on the next nonce.
// input (unreliable, sequenced: packets can be lost, never reordered): the
//   nonce travels with each packet, 8 bytes little-endian before the
//   ciphertext, as WireGuard does over Noise. A packet is accepted only if
//   its nonce is above the last one accepted (replays and duplicates are
//   dropped); gaps are fine.
// stream (unreliable, sequenced): like input, with its own nonces and its
// own "last accepted", so packets of one channel never make the other's look
// old.
// The channels use the same key per direction, so their nonces must never
// meet: input nonces have the top bit set, stream nonces the top two bits,
// control nonces never get there (2^62 messages each).
//
// ENet's own headers stay in the clear: someone on the path can see that
// packets flow and can cut the connection, but can't read, forge or replay
// what's inside.

#include <cstddef>
#include <cstdint>

#include "net_host.h"
#include "net_noise.h"

// Both sides put this in the Noise prologue: a different protocol version
// makes the handshake fail instead of being misread.
constexpr const char* NET_LINK_PROLOGUE = "multitap-net 1";
constexpr uint64_t NET_LINK_INPUT_NONCE_BIT = 1ull << 63;
constexpr uint64_t NET_LINK_STREAM_NONCE_BIT = 1ull << 62;   // with the input bit
constexpr size_t NET_LINK_INPUT_HEADER_SIZE = 8;
// The most a sealed packet adds to its payload (input: nonce + MAC).
constexpr size_t NET_LINK_OVERHEAD = NET_LINK_INPUT_HEADER_SIZE + NET_MAC_SIZE;
// The largest payload one message can carry (Noise's message limit).
constexpr size_t NET_LINK_MAX_PAYLOAD = NET_NOISE_MAX_MESSAGE - NET_LINK_OVERHEAD;

enum class NetLinkState
{
    handshaking,
    ready,
    failed,
};

struct NetLink
{
    NetLinkState state = NetLinkState::handshaking;
    NetNoise  noise;
    NetCipher send;      // ours -> theirs (control: its nonce; input: explicit)
    NetCipher receive;   // theirs -> ours
    uint64_t  input_next = NET_LINK_INPUT_NONCE_BIT;   // our next input nonce
    uint64_t  input_last = 0;                          // the last input nonce accepted (0 = none yet)
    uint64_t  stream_next = NET_LINK_INPUT_NONCE_BIT | NET_LINK_STREAM_NONCE_BIT;
    uint64_t  stream_last = 0;
    uint8_t   remote_key[NET_KEY_SIZE] = {};           // their static (device) key, once ready
    uint8_t   handshake_hash[NET_HASH_SIZE] = {};      // equal on both sides; binds pairing codes later
    uint32_t  input_dropped = 0;                       // bad or replayed input packets
};

void net_link_init(NetLink* link, NetNoiseRole role, const NetKeypair* identity);

// Initiator only: the first handshake message, to send on control.
bool net_link_start(NetLink* link, uint8_t* out, size_t capacity, size_t* out_size);

enum class NetLinkReceive
{
    handshake,   // handshake progress: send `reply` if reply_size > 0; check `state` for ready
    message,     // a transport message: `payload`
    failed,      // the link is dead (state == failed): close the connection
};

// A packet on the control channel. `reply` needs NET_NOISE_MAX_MESSAGE bytes,
// `payload` NET_LINK_MAX_PAYLOAD.
NetLinkReceive net_link_receive_control(NetLink* link, const uint8_t* data, size_t size, uint8_t* reply,
                                        size_t reply_capacity, size_t* reply_size, uint8_t* payload,
                                        size_t payload_capacity, size_t* payload_size);

// A packet on the input channel. False (and counted in input_dropped) if it
// doesn't authenticate, is a replay, or the link isn't ready.
bool net_link_open_input(NetLink* link, const uint8_t* data, size_t size, uint8_t* payload, size_t capacity,
                         size_t* payload_size);
// The same for either unreliable channel (input or stream).
bool net_link_open_unreliable(NetLink* link, NetChannel channel, const uint8_t* data, size_t size, uint8_t* payload,
                              size_t capacity, size_t* payload_size);

// Encrypts a payload for `channel`. Only when ready. `out` needs
// `size` + NET_LINK_OVERHEAD bytes.
bool net_link_seal(NetLink* link, NetChannel channel, const uint8_t* data, size_t size, uint8_t* out,
                   size_t capacity, size_t* out_size);

void net_link_wipe(NetLink* link);
