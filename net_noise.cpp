#include "net_noise.h"

#include <cstring>

#include "monocypher.h"
#include "net_random.h"

static constexpr const char* PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
static constexpr size_t BLAKE2B_BLOCK_SIZE = 128;

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

void net_keypair_from_secret(NetKeypair* keypair, const uint8_t* secret)
{
    std::memcpy(keypair->secret, secret, NET_KEY_SIZE);
    crypto_x25519_public_key(keypair->public_key, keypair->secret);
}

bool net_keypair_generate(NetKeypair* keypair)
{
    uint8_t secret[NET_KEY_SIZE];
    if (!net_random_bytes(secret, sizeof(secret)))
    {
        return false;
    }
    net_keypair_from_secret(keypair, secret);
    crypto_wipe(secret, sizeof(secret));
    return true;
}

void net_keypair_wipe(NetKeypair* keypair)
{
    crypto_wipe(keypair, sizeof(*keypair));
}

// ---------------------------------------------------------------------------
// CipherState: ChaCha20-Poly1305 (IETF) with Noise's nonce layout
// ---------------------------------------------------------------------------

static void nonce_bytes(uint64_t nonce, uint8_t* out)
{
    // 32 bits of zeros, then the counter little-endian (spec 12.3).
    std::memset(out, 0, 4);
    for (uint32_t i = 0; i < 8; i++)
    {
        out[4 + i] = static_cast<uint8_t>((nonce >> (8 * i)) & 0xFF);
    }
}

void net_cipher_encrypt_at(const NetCipher* cipher, uint64_t nonce, const uint8_t* ad, size_t ad_size,
                           const uint8_t* plain, size_t size, uint8_t* out)
{
    uint8_t nonce12[12];
    nonce_bytes(nonce, nonce12);
    // A fresh context per message: Monocypher's incremental interface changes
    // the key after each message, so one write on a new context is exactly
    // RFC 8439's AEAD.
    crypto_aead_ctx context;
    crypto_aead_init_ietf(&context, cipher->key, nonce12);
    crypto_aead_write(&context, out, out + size, ad, ad_size, plain, size);
    crypto_wipe(&context, sizeof(context));
}

bool net_cipher_decrypt_at(const NetCipher* cipher, uint64_t nonce, const uint8_t* ad, size_t ad_size,
                           const uint8_t* data, size_t size, uint8_t* out)
{
    if (size < NET_MAC_SIZE)
    {
        return false;
    }
    size_t text_size = size - NET_MAC_SIZE;
    uint8_t nonce12[12];
    nonce_bytes(nonce, nonce12);
    crypto_aead_ctx context;
    crypto_aead_init_ietf(&context, cipher->key, nonce12);
    int mismatch = crypto_aead_read(&context, out, data + text_size, ad, ad_size, data, text_size);
    crypto_wipe(&context, sizeof(context));
    return mismatch == 0;
}

void net_cipher_encrypt(NetCipher* cipher, const uint8_t* ad, size_t ad_size, const uint8_t* plain, size_t size,
                        uint8_t* out)
{
    net_cipher_encrypt_at(cipher, cipher->nonce, ad, ad_size, plain, size, out);
    cipher->nonce++;
}

bool net_cipher_decrypt(NetCipher* cipher, const uint8_t* ad, size_t ad_size, const uint8_t* data, size_t size,
                        uint8_t* out)
{
    if (!net_cipher_decrypt_at(cipher, cipher->nonce, ad, ad_size, data, size, out))
    {
        return false;
    }
    cipher->nonce++;
    return true;
}

void net_cipher_wipe(NetCipher* cipher)
{
    crypto_wipe(cipher, sizeof(*cipher));
}

// ---------------------------------------------------------------------------
// HMAC-BLAKE2b and HKDF (spec 4.3): Noise defines them over the hash with
// HMAC (RFC 2104), not with BLAKE2b's own keyed mode.
// ---------------------------------------------------------------------------

static void hmac(const uint8_t* key, size_t key_size, const uint8_t* data1, size_t size1, const uint8_t* data2,
                 size_t size2, uint8_t* out)
{
    // Keys here are at most NET_HASH_SIZE bytes, under the block size: padded
    // with zeros, never hashed first.
    uint8_t pad[BLAKE2B_BLOCK_SIZE];
    uint8_t inner[NET_HASH_SIZE];
    crypto_blake2b_ctx context;

    std::memset(pad, 0x36, sizeof(pad));
    for (size_t i = 0; i < key_size; i++)
    {
        pad[i] = static_cast<uint8_t>(pad[i] ^ key[i]);
    }
    crypto_blake2b_init(&context, NET_HASH_SIZE);
    crypto_blake2b_update(&context, pad, sizeof(pad));
    crypto_blake2b_update(&context, data1, size1);
    crypto_blake2b_update(&context, data2, size2);
    crypto_blake2b_final(&context, inner);

    std::memset(pad, 0x5C, sizeof(pad));
    for (size_t i = 0; i < key_size; i++)
    {
        pad[i] = static_cast<uint8_t>(pad[i] ^ key[i]);
    }
    crypto_blake2b_init(&context, NET_HASH_SIZE);
    crypto_blake2b_update(&context, pad, sizeof(pad));
    crypto_blake2b_update(&context, inner, sizeof(inner));
    crypto_blake2b_final(&context, out);

    crypto_wipe(pad, sizeof(pad));
    crypto_wipe(inner, sizeof(inner));
}

// HKDF with two outputs (the only count XX needs).
static void hkdf2(const uint8_t* chaining_key, const uint8_t* input, size_t input_size, uint8_t* out1, uint8_t* out2)
{
    uint8_t temp_key[NET_HASH_SIZE];
    hmac(chaining_key, NET_HASH_SIZE, input, input_size, nullptr, 0, temp_key);
    const uint8_t one = 0x01;
    hmac(temp_key, NET_HASH_SIZE, &one, 1, nullptr, 0, out1);
    const uint8_t two = 0x02;
    hmac(temp_key, NET_HASH_SIZE, out1, NET_HASH_SIZE, &two, 1, out2);
    crypto_wipe(temp_key, sizeof(temp_key));
}

// ---------------------------------------------------------------------------
// SymmetricState (spec 5.2)
// ---------------------------------------------------------------------------

static void mix_hash(NetNoise* noise, const uint8_t* data, size_t size)
{
    crypto_blake2b_ctx context;
    crypto_blake2b_init(&context, NET_HASH_SIZE);
    crypto_blake2b_update(&context, noise->h, NET_HASH_SIZE);
    crypto_blake2b_update(&context, data, size);
    crypto_blake2b_final(&context, noise->h);
}

static void mix_key(NetNoise* noise, const uint8_t* input, size_t input_size)
{
    uint8_t temp_k[NET_HASH_SIZE];
    hkdf2(noise->ck, input, input_size, noise->ck, temp_k);
    std::memcpy(noise->cipher.key, temp_k, NET_KEY_SIZE);   // truncated to 32 bytes
    noise->cipher.nonce = 0;
    noise->cipher.has_key = true;
    crypto_wipe(temp_k, sizeof(temp_k));
}

// Encrypted (with h as associated data) once there's a key, plain before.
static void encrypt_and_hash(NetNoise* noise, const uint8_t* plain, size_t size, uint8_t* out, size_t* out_size)
{
    if (noise->cipher.has_key)
    {
        net_cipher_encrypt(&noise->cipher, noise->h, NET_HASH_SIZE, plain, size, out);
        *out_size = size + NET_MAC_SIZE;
    }
    else
    {
        if (size > 0)   // `plain` may be null for an empty payload (memcpy forbids null)
        {
            std::memcpy(out, plain, size);
        }
        *out_size = size;
    }
    mix_hash(noise, out, *out_size);
}

static bool decrypt_and_hash(NetNoise* noise, const uint8_t* data, size_t size, uint8_t* out, size_t* out_size)
{
    if (noise->cipher.has_key)
    {
        if (size < NET_MAC_SIZE || !net_cipher_decrypt(&noise->cipher, noise->h, NET_HASH_SIZE, data, size, out))
        {
            return false;
        }
        *out_size = size - NET_MAC_SIZE;
    }
    else
    {
        if (size > 0)
        {
            std::memcpy(out, data, size);
        }
        *out_size = size;
    }
    mix_hash(noise, data, size);   // the ciphertext, as received
    return true;
}

static void dh_mix(NetNoise* noise, const uint8_t* secret, const uint8_t* public_key)
{
    uint8_t shared[NET_KEY_SIZE];
    crypto_x25519(shared, secret, public_key);
    mix_key(noise, shared, sizeof(shared));
    crypto_wipe(shared, sizeof(shared));
}

// ---------------------------------------------------------------------------
// HandshakeState for XX (spec 5.3, pattern in 7.5)
// ---------------------------------------------------------------------------

void net_noise_init(NetNoise* noise, NetNoiseRole role, const NetKeypair* static_key, const uint8_t* prologue,
                    size_t prologue_size)
{
    *noise = {};
    noise->role = role;
    noise->s = *static_key;
    // InitializeSymmetric: the name fits in HASHLEN, so h = name padded with zeros.
    std::memcpy(noise->h, PROTOCOL_NAME, std::strlen(PROTOCOL_NAME));
    std::memcpy(noise->ck, noise->h, NET_HASH_SIZE);
    mix_hash(noise, prologue, prologue_size);
}

void net_noise_set_ephemeral(NetNoise* noise, const NetKeypair* ephemeral)
{
    noise->e = *ephemeral;
    noise->e_given = true;
}

bool net_noise_my_turn(const NetNoise* noise)
{
    // Messages 0 and 2 are the initiator's, message 1 the responder's.
    bool initiator_turn = noise->message != 1;
    return !noise->failed && noise->message < 3 && (initiator_turn == (noise->role == NetNoiseRole::initiator));
}

bool net_noise_done(const NetNoise* noise)
{
    return !noise->failed && noise->message == 3;
}

static bool fail(NetNoise* noise)
{
    noise->failed = true;
    return false;
}

bool net_noise_write(NetNoise* noise, const uint8_t* payload, size_t payload_size, uint8_t* out, size_t capacity,
                     size_t* out_size)
{
    if (!net_noise_my_turn(noise))
    {
        return fail(noise);
    }
    // The largest message is the second: e (32) + encrypted s (48) + payload + MAC.
    size_t needed = NET_KEY_SIZE + NET_KEY_SIZE + NET_MAC_SIZE + payload_size + NET_MAC_SIZE;
    if (needed > capacity || needed > NET_NOISE_MAX_MESSAGE)
    {
        return fail(noise);
    }
    size_t used = 0;
    size_t written = 0;

    if (noise->message == 0 || noise->message == 1)
    {
        // e
        if (!noise->e_given && !net_keypair_generate(&noise->e))
        {
            return fail(noise);
        }
        std::memcpy(out, noise->e.public_key, NET_KEY_SIZE);
        mix_hash(noise, noise->e.public_key, NET_KEY_SIZE);
        used = NET_KEY_SIZE;
    }
    if (noise->message == 1)
    {
        // ee, s, es (responder)
        dh_mix(noise, noise->e.secret, noise->re);
        encrypt_and_hash(noise, noise->s.public_key, NET_KEY_SIZE, out + used, &written);
        used += written;
        dh_mix(noise, noise->s.secret, noise->re);
    }
    if (noise->message == 2)
    {
        // s, se (initiator)
        encrypt_and_hash(noise, noise->s.public_key, NET_KEY_SIZE, out + used, &written);
        used += written;
        dh_mix(noise, noise->s.secret, noise->re);
    }
    encrypt_and_hash(noise, payload, payload_size, out + used, &written);
    used += written;
    *out_size = used;
    noise->message++;
    return true;
}

bool net_noise_read(NetNoise* noise, const uint8_t* message, size_t size, uint8_t* payload, size_t capacity,
                    size_t* payload_size)
{
    if (noise->failed || noise->message >= 3 || net_noise_my_turn(noise) || size > NET_NOISE_MAX_MESSAGE)
    {
        return fail(noise);
    }
    size_t used = 0;
    size_t read = 0;
    // Room for the encrypted size too: decrypt_and_hash copies it as it is
    // when there's no key yet (never the case for s, but GCC can't tell and
    // -Warray-bounds refuses it in Release builds).
    uint8_t static_key[NET_KEY_SIZE + NET_MAC_SIZE];

    if (noise->message == 0 || noise->message == 1)
    {
        // e
        if (size < NET_KEY_SIZE)
        {
            return fail(noise);
        }
        std::memcpy(noise->re, message, NET_KEY_SIZE);
        mix_hash(noise, noise->re, NET_KEY_SIZE);
        used = NET_KEY_SIZE;
    }
    if (noise->message == 1)
    {
        // ee, s, es (initiator reading the responder's)
        dh_mix(noise, noise->e.secret, noise->re);
        if (size < used + NET_KEY_SIZE + NET_MAC_SIZE ||
            !decrypt_and_hash(noise, message + used, NET_KEY_SIZE + NET_MAC_SIZE, static_key, &read))
        {
            return fail(noise);
        }
        std::memcpy(noise->rs, static_key, NET_KEY_SIZE);
        used += NET_KEY_SIZE + NET_MAC_SIZE;
        dh_mix(noise, noise->e.secret, noise->rs);
    }
    if (noise->message == 2)
    {
        // s, se (responder reading the initiator's)
        if (size < NET_KEY_SIZE + NET_MAC_SIZE ||
            !decrypt_and_hash(noise, message, NET_KEY_SIZE + NET_MAC_SIZE, static_key, &read))
        {
            return fail(noise);
        }
        std::memcpy(noise->rs, static_key, NET_KEY_SIZE);
        used = NET_KEY_SIZE + NET_MAC_SIZE;
        dh_mix(noise, noise->e.secret, noise->rs);
    }
    size_t rest = size - used;
    size_t plain_size = noise->cipher.has_key ? (rest >= NET_MAC_SIZE ? rest - NET_MAC_SIZE : 0) : rest;
    if (plain_size > capacity || !decrypt_and_hash(noise, message + used, rest, payload, payload_size))
    {
        return fail(noise);
    }
    noise->message++;
    return true;
}

void net_noise_split(NetNoise* noise, NetCipher* send, NetCipher* receive)
{
    uint8_t k1[NET_HASH_SIZE];
    uint8_t k2[NET_HASH_SIZE];
    hkdf2(noise->ck, nullptr, 0, k1, k2);
    // The first cipher is the initiator's sending direction.
    NetCipher* initiator_to_responder = noise->role == NetNoiseRole::initiator ? send : receive;
    NetCipher* responder_to_initiator = noise->role == NetNoiseRole::initiator ? receive : send;
    *initiator_to_responder = {};
    std::memcpy(initiator_to_responder->key, k1, NET_KEY_SIZE);
    initiator_to_responder->has_key = true;
    *responder_to_initiator = {};
    std::memcpy(responder_to_initiator->key, k2, NET_KEY_SIZE);
    responder_to_initiator->has_key = true;
    crypto_wipe(k1, sizeof(k1));
    crypto_wipe(k2, sizeof(k2));
    // The handshake's secrets are no longer needed; h and rs are public.
    crypto_wipe(noise->ck, sizeof(noise->ck));
    net_cipher_wipe(&noise->cipher);
    net_keypair_wipe(&noise->e);
    net_keypair_wipe(&noise->s);
}

void net_noise_wipe(NetNoise* noise)
{
    crypto_wipe(noise, sizeof(*noise));
}
