#include "net_cpace.h"

#include <cstring>
#include <vector>

#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "net_random.h"

// The draft's names: DSI (domain separation), PRS (the password), CI
// (channel identifier), sid (session id), AD (associated data).
static constexpr uint8_t DSI[] = {'C', 'P', 'a', 'c', 'e', '2', '5', '5'};
static constexpr uint8_t DSI_ISK[] = {'C', 'P', 'a', 'c', 'e', '2', '5', '5', '_', 'I', 'S', 'K'};
static constexpr size_t SHA512_BLOCK_SIZE = 128;   // H.s_in_bytes

// LEB128 length, then the bytes (the draft's prepend_len).
static void prepend_len(std::vector<uint8_t>* out, const uint8_t* data, size_t size)
{
    size_t length = size;
    do
    {
        uint8_t byte = static_cast<uint8_t>(length & 0x7F);
        length >>= 7;
        if (length != 0)
        {
            byte = static_cast<uint8_t>(byte | 0x80);
        }
        out->push_back(byte);
    } while (length != 0);
    for (size_t i = 0; i < size; i++)
    {
        out->push_back(data[i]);
    }
}

static size_t prepended_size(size_t size)
{
    size_t bytes = 1;
    while (size >= 0x80)
    {
        size >>= 7;
        bytes++;
    }
    return bytes + size;
}

// --- 255-bit numbers, little-endian, for decodeUCoordinate ------------------

// p = 2^255 - 19
static constexpr uint8_t FIELD_P[32] = {0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};

static bool at_least(const uint8_t* a, const uint8_t* b)
{
    for (int32_t i = 31; i >= 0; i--)
    {
        size_t k = static_cast<size_t>(i);
        if (a[k] != b[k])
        {
            return a[k] > b[k];
        }
    }
    return true;
}

// out = a - b (a >= b).
static void subtract(const uint8_t* a, const uint8_t* b, uint8_t* out)
{
    int32_t borrow = 0;
    for (size_t i = 0; i < 32; i++)
    {
        int32_t difference = static_cast<int32_t>(a[i]) - static_cast<int32_t>(b[i]) - borrow;
        borrow = difference < 0 ? 1 : 0;
        out[i] = static_cast<uint8_t>(difference + (borrow << 8));
    }
}

// The hash as a field element, ready for Monocypher's Elligator map.
// The draft decodes 255 bits (RFC 7748's decodeUCoordinate) and reduces mod p;
// Monocypher's crypto_elligator_map reads only 254 bits. The map depends on
// r^2 only, so r and p - r give the same point: a reduced r at or above 2^254
// is replaced by p - r, which is below 2^254. Same result as the draft for
// every input (checked with extra vectors where bit 254 is set).
static void decode_u(const uint8_t* hash, uint8_t* out)
{
    uint8_t r[32];
    std::memcpy(r, hash, 32);
    r[31] &= 0x7F;   // clear bit 255
    if (at_least(r, FIELD_P))
    {
        subtract(r, FIELD_P, r);
    }
    if ((r[31] & 0x40) != 0)
    {
        subtract(FIELD_P, r, r);
    }
    std::memcpy(out, r, 32);
    crypto_wipe(r, sizeof(r));
}

// --- CPace ------------------------------------------------------------------

void net_cpace_generator(const uint8_t* prs, size_t prs_size, const uint8_t* ci, size_t ci_size, const uint8_t* sid,
                         size_t sid_size, uint8_t* generator)
{
    // generator_string = lv_cat(DSI, PRS, zero padding, CI, sid): the padding
    // fills the hash's first block so its cost doesn't depend on the password.
    size_t used = prepended_size(prs_size) + prepended_size(sizeof(DSI)) + 1;
    size_t zero_padding = used < SHA512_BLOCK_SIZE ? SHA512_BLOCK_SIZE - used : 0;
    std::vector<uint8_t> zeros(zero_padding, 0);
    std::vector<uint8_t> text;
    prepend_len(&text, DSI, sizeof(DSI));
    prepend_len(&text, prs, prs_size);
    prepend_len(&text, zeros.data(), zeros.size());
    prepend_len(&text, ci, ci_size);
    prepend_len(&text, sid, sid_size);

    uint8_t hash[64];
    crypto_sha512(hash, text.data(), text.size());
    uint8_t u[32];
    decode_u(hash, u);   // the first 32 bytes of the hash
    crypto_elligator_map(generator, u);
    crypto_wipe(text.data(), text.size());
    crypto_wipe(hash, sizeof(hash));
    crypto_wipe(u, sizeof(u));
}

void net_cpace_start_with_scalar(NetCpace* cpace, const uint8_t* prs, size_t prs_size, const uint8_t* ci,
                                 size_t ci_size, const uint8_t* sid, size_t sid_size, const uint8_t* scalar)
{
    uint8_t generator[32];
    net_cpace_generator(prs, prs_size, ci, ci_size, sid, sid_size, generator);
    std::memcpy(cpace->scalar, scalar, 32);
    crypto_x25519(cpace->share, cpace->scalar, generator);
    crypto_wipe(generator, sizeof(generator));
}

bool net_cpace_start(NetCpace* cpace, const uint8_t* prs, size_t prs_size, const uint8_t* ci, size_t ci_size,
                     const uint8_t* sid, size_t sid_size)
{
    uint8_t scalar[32];
    if (!net_random_bytes(scalar, sizeof(scalar)))
    {
        return false;
    }
    net_cpace_start_with_scalar(cpace, prs, prs_size, ci, ci_size, sid, sid_size, scalar);
    crypto_wipe(scalar, sizeof(scalar));
    return true;
}

bool net_cpace_finish(NetCpace* cpace, bool initiator, const uint8_t* their_share, const uint8_t* ad_a,
                      size_t ad_a_size, const uint8_t* ad_b, size_t ad_b_size, const uint8_t* sid, size_t sid_size,
                      uint8_t* isk)
{
    uint8_t k[32];
    crypto_x25519(k, cpace->scalar, their_share);
    crypto_wipe(cpace->scalar, sizeof(cpace->scalar));
    // K must not be the neutral element (all zeros): their share was a
    // low-order point, which would make K independent of the password.
    uint8_t zero[32] = {};
    if (crypto_verify32(k, zero) == 0)
    {
        crypto_wipe(k, sizeof(k));
        return false;
    }
    const uint8_t* ya = initiator ? cpace->share : their_share;
    const uint8_t* yb = initiator ? their_share : cpace->share;
    // lv_cat(DSI_ISK, sid, K) || transcript_ir(Ya, ADa, Yb, ADb)
    std::vector<uint8_t> text;
    prepend_len(&text, DSI_ISK, sizeof(DSI_ISK));
    prepend_len(&text, sid, sid_size);
    prepend_len(&text, k, sizeof(k));
    prepend_len(&text, ya, NET_CPACE_SHARE_SIZE);
    prepend_len(&text, ad_a, ad_a_size);
    prepend_len(&text, yb, NET_CPACE_SHARE_SIZE);
    prepend_len(&text, ad_b, ad_b_size);
    crypto_sha512(isk, text.data(), text.size());
    crypto_wipe(text.data(), text.size());
    crypto_wipe(k, sizeof(k));
    return true;
}

void net_cpace_wipe(NetCpace* cpace)
{
    crypto_wipe(cpace, sizeof(*cpace));
}
