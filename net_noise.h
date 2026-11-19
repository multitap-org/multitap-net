#pragma once

// The Noise handshake (noiseprotocol.org, specification revision 34), exactly
// one protocol: Noise_XX_25519_ChaChaPoly_BLAKE2b, on Monocypher (deps/,
// BSD-2/CC0). Pure functions: bytes in, bytes out; net_link.h carries them.
//
// Why XX (decided 2026-11-19): neither side needs to know the other's key
// beforehand, and both learn each other's static (device) key, encrypted.
// Whether that key is trusted is decided above this module (pairing,
// milestone 3), never here.
//
//   -> e                     initiator's ephemeral key
//   <- e, ee, s, es          responder's ephemeral, its static key (encrypted)
//   -> s, se                 initiator's static key (encrypted)
//
// Each message may carry a payload (encrypted from the second message on).
// After the third message both sides call net_noise_split() for one cipher
// per direction. Checked against the official test vectors (cacophony) in
// tests/net_test.cpp.
//
// The spec's names are kept (MixHash, MixKey, EncryptAndHash, Split) in the
// .cpp so it can be read side by side with the specification.

#include <cstddef>
#include <cstdint>

constexpr size_t NET_KEY_SIZE = 32;    // X25519 keys, cipher keys
constexpr size_t NET_HASH_SIZE = 64;   // BLAKE2b
constexpr size_t NET_MAC_SIZE = 16;    // Poly1305
// The spec's limit for any Noise message, handshake or transport.
constexpr size_t NET_NOISE_MAX_MESSAGE = 65535;

struct NetKeypair
{
    uint8_t secret[NET_KEY_SIZE] = {};
    uint8_t public_key[NET_KEY_SIZE] = {};
};

// A new random keypair (net_random.h). False if the system gave no randomness.
bool net_keypair_generate(NetKeypair* keypair);
void net_keypair_from_secret(NetKeypair* keypair, const uint8_t* secret);
void net_keypair_wipe(NetKeypair* keypair);

// ChaCha20-Poly1305 (RFC 8439) with Noise's nonce: 4 zero bytes, then the
// 64-bit counter little-endian.
struct NetCipher
{
    uint8_t  key[NET_KEY_SIZE] = {};
    uint64_t nonce = 0;     // the next one (implicit-nonce use)
    bool     has_key = false;
};

// Writes `size` + NET_MAC_SIZE bytes to `out` with the cipher's next nonce,
// then advances it. `out` must not overlap `plain`.
void net_cipher_encrypt(NetCipher* cipher, const uint8_t* ad, size_t ad_size, const uint8_t* plain, size_t size,
                        uint8_t* out);
// `size` includes the MAC; writes `size` - NET_MAC_SIZE bytes. False (and
// the nonce not advanced) if it doesn't authenticate.
bool net_cipher_decrypt(NetCipher* cipher, const uint8_t* ad, size_t ad_size, const uint8_t* data, size_t size,
                        uint8_t* out);
// The same with a nonce given by the caller (the cipher's own is untouched):
// for channels that can lose packets, where the nonce travels with each one.
void net_cipher_encrypt_at(const NetCipher* cipher, uint64_t nonce, const uint8_t* ad, size_t ad_size,
                           const uint8_t* plain, size_t size, uint8_t* out);
bool net_cipher_decrypt_at(const NetCipher* cipher, uint64_t nonce, const uint8_t* ad, size_t ad_size,
                           const uint8_t* data, size_t size, uint8_t* out);
void net_cipher_wipe(NetCipher* cipher);

enum class NetNoiseRole
{
    initiator,   // the side that connects
    responder,
};

struct NetNoise
{
    NetNoiseRole role = NetNoiseRole::initiator;
    uint32_t  message = 0;   // handshake messages done (0..3)
    bool      failed = false;
    // SymmetricState
    uint8_t   h[NET_HASH_SIZE] = {};    // handshake hash: the same on both sides when done
    uint8_t   ck[NET_HASH_SIZE] = {};   // chaining key
    NetCipher cipher;
    // HandshakeState
    NetKeypair s;                        // our static (device) key
    NetKeypair e;                        // our ephemeral key
    bool      e_given = false;           // set by net_noise_set_ephemeral (tests)
    uint8_t   rs[NET_KEY_SIZE] = {};     // their static key, once received
    uint8_t   re[NET_KEY_SIZE] = {};     // their ephemeral key
};

// `prologue`: data both sides must agree on, never sent (our protocol name and
// version: a mismatch makes the handshake fail instead of misreading).
void net_noise_init(NetNoise* noise, NetNoiseRole role, const NetKeypair* static_key, const uint8_t* prologue,
                    size_t prologue_size);
// Tests only: the ephemeral key a test vector prescribes, instead of a random one.
void net_noise_set_ephemeral(NetNoise* noise, const NetKeypair* ephemeral);

// Is the next handshake message ours to write?
bool net_noise_my_turn(const NetNoise* noise);
bool net_noise_done(const NetNoise* noise);

// Write or read the next handshake message. Any failure marks the handshake
// failed for good (`failed`), as the spec requires.
bool net_noise_write(NetNoise* noise, const uint8_t* payload, size_t payload_size, uint8_t* out, size_t capacity,
                     size_t* out_size);
bool net_noise_read(NetNoise* noise, const uint8_t* message, size_t size, uint8_t* payload, size_t capacity,
                    size_t* payload_size);

// After the handshake: the two transport ciphers (`send` for our messages,
// `receive` for theirs). Wipes the handshake's secrets; `h` and `rs` stay.
void net_noise_split(NetNoise* noise, NetCipher* send, NetCipher* receive);
// Wipes everything (a handshake given up halfway).
void net_noise_wipe(NetNoise* noise);
