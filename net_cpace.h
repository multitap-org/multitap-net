#pragma once

// CPace, a password-authenticated key exchange (draft-irtf-cfrg-cpace-18,
// cipher suite CPACE-X25519-SHA512), on Monocypher (X25519, Elligator 2,
// SHA-512 from its optional/ folder). Pure functions.
//
// Why: pairing uses a 6-digit code (decided 2026-11-19: digits are easy on an
// on-screen keyboard and can be passed over chat). A short code can't be
// checked with a plain MAC (anyone who sees one MAC tries all 10^6 codes
// offline in a second); with CPace the code never leaves either side and an
// attacker gets exactly one online guess per run. net_pairing.h uses it.
//
//   A (initiator)                     B (responder)
//   Ya = ya * g(code, CI, sid)  --->
//                               <---  Yb = yb * g(code, CI, sid)
//   K = ya * Yb                       K = yb * Ya
//   ISK = SHA-512(lv_cat("CPace255_ISK", sid, K) || lv_cat(Ya, ADa) || lv_cat(Yb, ADb))
//
// Both get the same ISK only if they used the same code, CI and sid (and saw
// the same shares and associated data). Checked against the draft's test
// vectors in tests/net_noise_test.cpp.

#include <cstddef>
#include <cstdint>

constexpr size_t NET_CPACE_SHARE_SIZE = 32;
constexpr size_t NET_CPACE_ISK_SIZE = 64;

struct NetCpace
{
    uint8_t scalar[32] = {};
    uint8_t share[NET_CPACE_SHARE_SIZE] = {};   // ours, to send
};

// The generator for a password: exposed for the test vectors.
void net_cpace_generator(const uint8_t* prs, size_t prs_size, const uint8_t* ci, size_t ci_size, const uint8_t* sid,
                         size_t sid_size, uint8_t* generator);

// Our share for this password: `share` is what we send. False if the system
// gave no randomness.
bool net_cpace_start(NetCpace* cpace, const uint8_t* prs, size_t prs_size, const uint8_t* ci, size_t ci_size,
                     const uint8_t* sid, size_t sid_size);
// Tests only: with the scalar a test vector prescribes.
void net_cpace_start_with_scalar(NetCpace* cpace, const uint8_t* prs, size_t prs_size, const uint8_t* ci,
                                 size_t ci_size, const uint8_t* sid, size_t sid_size, const uint8_t* scalar);

// The other side's share arrived: the session key. `initiator` = we are A
// (our share is Ya). False when the shared point is the neutral element (a
// low-order share: the draft requires aborting). Wipes the scalar either way.
bool net_cpace_finish(NetCpace* cpace, bool initiator, const uint8_t* their_share, const uint8_t* ad_a,
                      size_t ad_a_size, const uint8_t* ad_b, size_t ad_b_size, const uint8_t* sid, size_t sid_size,
                      uint8_t* isk);

void net_cpace_wipe(NetCpace* cpace);
