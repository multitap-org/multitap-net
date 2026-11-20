// Checks net_noise against the official Noise test vector for our protocol
// (Noise_XX_25519_ChaChaPoly_BLAKE2b, from the cacophony vectors used by
// every Noise implementation): with the vector's keys and payloads, every
// handshake and transport message must come out byte for byte, and the
// handshake hash must match. Then a few ways a handshake must fail, and
// net_link (the channels on top) in memory: both channels both ways, lost
// and replayed input packets, tampering. And CPace (net_cpace) against the
// draft's test vectors (draft-irtf-cfrg-cpace-18, appendix B.1), plus three
// generators where bit 254 of the hash is set (from an independent Python
// reference that reproduces the draft's vector), and its low-order aborts.
//
// Exit code 0 = all checks passed. Each failure is printed.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "net_cpace.h"
#include "net_link.h"
#include "net_noise.h"

static int g_failures = 0;

static void check(bool condition, const char* what)
{
    if (!condition)
    {
        std::printf("FAIL %s\n", what);
        g_failures++;
    }
}

static std::vector<uint8_t> from_hex(const char* hex)
{
    std::vector<uint8_t> bytes;
    size_t length = std::strlen(hex);
    for (size_t i = 0; i + 1 < length; i += 2)
    {
        char pair[3] = {hex[i], hex[i + 1], '\0'};
        bytes.push_back(static_cast<uint8_t>(std::strtoul(pair, nullptr, 16)));
    }
    return bytes;
}

struct VectorMessage
{
    const char* payload;
    const char* ciphertext;
};

// cacophony.txt, protocol_name "Noise_XX_25519_ChaChaPoly_BLAKE2b".
static const char* PROLOGUE = "4a6f686e2047616c74";
static const char* INIT_STATIC = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
static const char* INIT_EPHEMERAL = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
static const char* RESP_STATIC = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
static const char* RESP_EPHEMERAL = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";
static const char* HANDSHAKE_HASH =
    "8cf47d7b3cb5804c0109d48e8bcdbee2cbb65687d8ea2c92994ca361fb86151ad93627b98936cbb32de56e8abb21def3925011ac3e35db9cbeea73ab9a4392c2";
static const VectorMessage MESSAGES[] = {
    {"4c756477696720766f6e204d69736573",
     "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573"},
    {"4d757272617920526f746862617264",
     "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088430505b6745ce64a5f33f0e8e3b83f11ce8802bca507f4f2d8b564dbe277e1966116e132faa2dfd70b8b077b9f94b913df5056ae1319469b824a98d54bbaa82c325595587064f978c4b6d104f7596e6f"},
    {"462e20412e20486179656b",
     "99579e1c1ee15e422a57ddd6b16d37087b17558e8369c18991b4b2ca3a824abf904cdcf5458b5431a75af034ca9e9b982de039eaaf156775e2d580cd4e5ebae89c3f8cb2594b556d8a8169"},
    {"4361726c204d656e676572", "fc56eea290b3f3a21aac0c70cd5787b5ee99be37d2f4d751329b55"},
    {"4a65616e2d426170746973746520536179", "bb31c9da10d5639a4cdb88a12f5c61de41bbc7df09bf75d94f8184fe4157f5c68f"},
    {"457567656e2042f6686d20766f6e2042617765726b",
     "f6199cadb152fb27f82be0a0891ec76a33598ae92a46cab2fb5a8ed5bf48b7f267f8370af7"},
};
constexpr size_t MESSAGE_COUNT = sizeof(MESSAGES) / sizeof(MESSAGES[0]);

static void keypair_from_hex(NetKeypair* keypair, const char* hex)
{
    std::vector<uint8_t> secret = from_hex(hex);
    net_keypair_from_secret(keypair, secret.data());
}

static void test_vector()
{
    std::vector<uint8_t> prologue = from_hex(PROLOGUE);
    NetKeypair init_static;
    NetKeypair init_ephemeral;
    NetKeypair resp_static;
    NetKeypair resp_ephemeral;
    keypair_from_hex(&init_static, INIT_STATIC);
    keypair_from_hex(&init_ephemeral, INIT_EPHEMERAL);
    keypair_from_hex(&resp_static, RESP_STATIC);
    keypair_from_hex(&resp_ephemeral, RESP_EPHEMERAL);

    NetNoise initiator;
    NetNoise responder;
    net_noise_init(&initiator, NetNoiseRole::initiator, &init_static, prologue.data(), prologue.size());
    net_noise_init(&responder, NetNoiseRole::responder, &resp_static, prologue.data(), prologue.size());
    net_noise_set_ephemeral(&initiator, &init_ephemeral);
    net_noise_set_ephemeral(&responder, &resp_ephemeral);

    NetCipher send[2];      // [0] initiator's, [1] responder's
    NetCipher receive[2];
    uint8_t out[1024];
    uint8_t payload[1024];
    char what[96];
    for (size_t i = 0; i < MESSAGE_COUNT; i++)
    {
        // Messages alternate, the initiator first, through the transport ones too.
        bool from_initiator = i % 2 == 0;
        std::vector<uint8_t> expected_payload = from_hex(MESSAGES[i].payload);
        std::vector<uint8_t> expected_cipher = from_hex(MESSAGES[i].ciphertext);
        size_t out_size = 0;
        size_t payload_size = 0;
        bool read_ok = false;
        if (i < 3)
        {
            NetNoise* writer = from_initiator ? &initiator : &responder;
            NetNoise* reader = from_initiator ? &responder : &initiator;
            bool written = net_noise_write(writer, expected_payload.data(), expected_payload.size(), out, sizeof(out),
                                           &out_size);
            std::snprintf(what, sizeof(what), "handshake message %zu written", i);
            check(written, what);
            read_ok = net_noise_read(reader, out, out_size, payload, sizeof(payload), &payload_size);
            if (i == 2)
            {
                check(net_noise_done(&initiator) && net_noise_done(&responder), "both sides done after 3 messages");
                check(std::memcmp(initiator.h, responder.h, NET_HASH_SIZE) == 0, "same handshake hash on both sides");
                std::vector<uint8_t> hash = from_hex(HANDSHAKE_HASH);
                check(std::memcmp(initiator.h, hash.data(), NET_HASH_SIZE) == 0, "handshake hash matches the vector");
                check(std::memcmp(initiator.rs, resp_static.public_key, NET_KEY_SIZE) == 0, "initiator learned the responder's key");
                check(std::memcmp(responder.rs, init_static.public_key, NET_KEY_SIZE) == 0, "responder learned the initiator's key");
                net_noise_split(&initiator, &send[0], &receive[0]);
                net_noise_split(&responder, &send[1], &receive[1]);
            }
        }
        else
        {
            NetCipher* sender = from_initiator ? &send[0] : &send[1];
            NetCipher* receiver = from_initiator ? &receive[1] : &receive[0];
            net_cipher_encrypt(sender, nullptr, 0, expected_payload.data(), expected_payload.size(), out);
            out_size = expected_payload.size() + NET_MAC_SIZE;
            read_ok = net_cipher_decrypt(receiver, nullptr, 0, out, out_size, payload);
            payload_size = read_ok ? out_size - NET_MAC_SIZE : 0;
        }
        std::snprintf(what, sizeof(what), "message %zu matches the vector byte for byte", i);
        check(out_size == expected_cipher.size() && std::memcmp(out, expected_cipher.data(), out_size) == 0, what);
        std::snprintf(what, sizeof(what), "message %zu read back to its payload", i);
        check(read_ok && payload_size == expected_payload.size() &&
                  std::memcmp(payload, expected_payload.data(), payload_size) == 0,
              what);
    }
}

// A fresh handshake with random keys; `tamper` = the message index whose
// first byte after the ephemeral key gets flipped (-1 = none). `other_prologue`
// gives the responder a different prologue.
static bool handshake(int tamper, bool other_prologue)
{
    NetKeypair a;
    NetKeypair b;
    if (!net_keypair_generate(&a) || !net_keypair_generate(&b))
    {
        return false;
    }
    const uint8_t prologue1[] = {'v', '1'};
    const uint8_t prologue2[] = {'v', '2'};
    NetNoise initiator;
    NetNoise responder;
    net_noise_init(&initiator, NetNoiseRole::initiator, &a, prologue1, sizeof(prologue1));
    net_noise_init(&responder, NetNoiseRole::responder, &b, other_prologue ? prologue2 : prologue1, 2);
    uint8_t out[512];
    uint8_t payload[512];
    for (int i = 0; i < 3; i++)
    {
        NetNoise* writer = i % 2 == 0 ? &initiator : &responder;
        NetNoise* reader = i % 2 == 0 ? &responder : &initiator;
        size_t size = 0;
        size_t payload_size = 0;
        if (!net_noise_write(writer, nullptr, 0, out, sizeof(out), &size))
        {
            return false;
        }
        if (i == tamper)
        {
            out[size - 1] ^= 0x01;
        }
        if (!net_noise_read(reader, out, size, payload, sizeof(payload), &payload_size))
        {
            check(reader->failed, "a failed read marks the handshake failed");
            return false;
        }
    }
    return net_noise_done(&initiator) && net_noise_done(&responder);
}

static void test_failures()
{
    check(handshake(-1, false), "random keys: handshake completes");
    check(!handshake(1, false), "tampered second message refused");
    check(!handshake(2, false), "tampered third message refused");
    check(!handshake(-1, true), "different prologues refused");

    // Out of turn: the responder can't write first.
    NetKeypair key;
    net_keypair_generate(&key);
    NetNoise responder;
    const uint8_t prologue[] = {'v', '1'};
    net_noise_init(&responder, NetNoiseRole::responder, &key, prologue, sizeof(prologue));
    uint8_t out[256];
    size_t size = 0;
    check(!net_noise_write(&responder, nullptr, 0, out, sizeof(out), &size), "responder can't write first");
    check(responder.failed, "and the handshake is failed for good");
}

// Two links shake hands in memory; control and input both ways.
struct LinkPair
{
    NetLink a;   // initiator
    NetLink b;
    std::vector<uint8_t> wire = std::vector<uint8_t>(NET_NOISE_MAX_MESSAGE);
    std::vector<uint8_t> reply = std::vector<uint8_t>(NET_NOISE_MAX_MESSAGE);
    std::vector<uint8_t> payload = std::vector<uint8_t>(NET_NOISE_MAX_MESSAGE);
};

static bool link_handshake(LinkPair* pair)
{
    NetKeypair ka;
    NetKeypair kb;
    net_keypair_generate(&ka);
    net_keypair_generate(&kb);
    net_link_init(&pair->a, NetNoiseRole::initiator, &ka);
    net_link_init(&pair->b, NetNoiseRole::responder, &kb);
    size_t size = 0;
    if (!net_link_start(&pair->a, pair->wire.data(), pair->wire.size(), &size))
    {
        return false;
    }
    // Ping-pong until neither has a reply: a -> b, b -> a, a -> b.
    NetLink* to = &pair->b;
    NetLink* from = &pair->a;
    for (int i = 0; i < 3 && size > 0; i++)
    {
        size_t reply_size = 0;
        size_t payload_size = 0;
        NetLinkReceive result = net_link_receive_control(to, pair->wire.data(), size, pair->reply.data(),
                                                         pair->reply.size(), &reply_size, pair->payload.data(),
                                                         pair->payload.size(), &payload_size);
        if (result != NetLinkReceive::handshake)
        {
            return false;
        }
        std::memcpy(pair->wire.data(), pair->reply.data(), reply_size);
        size = reply_size;
        NetLink* swap = to;
        to = from;
        from = swap;
    }
    return pair->a.state == NetLinkState::ready && pair->b.state == NetLinkState::ready;
}

static bool link_send(LinkPair* pair, NetLink* from, NetLink* to, NetChannel channel, const char* text,
                      std::vector<uint8_t>* sealed_out)
{
    size_t size = std::strlen(text);
    std::vector<uint8_t> plain(text, text + size);
    std::vector<uint8_t> sealed(size + NET_LINK_OVERHEAD);
    size_t sealed_size = 0;
    if (!net_link_seal(from, channel, plain.data(), size, sealed.data(), sealed.size(), &sealed_size))
    {
        return false;
    }
    sealed.resize(sealed_size);
    if (sealed_out != nullptr)
    {
        *sealed_out = sealed;
    }
    size_t payload_size = 0;
    if (channel == NetChannel::input)
    {
        if (!net_link_open_input(to, sealed.data(), sealed.size(), pair->payload.data(), pair->payload.size(),
                                 &payload_size))
        {
            return false;
        }
    }
    else
    {
        size_t reply_size = 0;
        if (net_link_receive_control(to, sealed.data(), sealed.size(), pair->reply.data(), pair->reply.size(),
                                     &reply_size, pair->payload.data(), pair->payload.size(),
                                     &payload_size) != NetLinkReceive::message)
        {
            return false;
        }
    }
    return payload_size == size && std::memcmp(pair->payload.data(), text, size) == 0;
}

static void test_link()
{
    LinkPair pair;
    check(link_handshake(&pair), "links: handshake completes");
    check(std::memcmp(pair.a.handshake_hash, pair.b.handshake_hash, NET_HASH_SIZE) == 0, "links: same handshake hash");
    check(link_send(&pair, &pair.a, &pair.b, NetChannel::control, "hello", nullptr), "control a -> b");
    check(link_send(&pair, &pair.b, &pair.a, NetChannel::control, "hi there", nullptr), "control b -> a");
    check(link_send(&pair, &pair.a, &pair.b, NetChannel::control, "second", nullptr), "control a -> b again");

    std::vector<uint8_t> first;
    check(link_send(&pair, &pair.a, &pair.b, NetChannel::input, "frame 1", &first), "input a -> b");
    check(link_send(&pair, &pair.b, &pair.a, NetChannel::input, "frame 1 back", nullptr), "input b -> a");

    // A lost packet: seal one and never deliver it; the next still opens.
    uint8_t lost[64];
    size_t lost_size = 0;
    const uint8_t lost_text[] = {'x'};
    net_link_seal(&pair.a, NetChannel::input, lost_text, 1, lost, sizeof(lost), &lost_size);
    check(link_send(&pair, &pair.a, &pair.b, NetChannel::input, "frame 3", nullptr), "input after a lost packet");

    // The first packet again (a replay): dropped, link alive.
    size_t payload_size = 0;
    uint32_t dropped = pair.b.input_dropped;
    check(!net_link_open_input(&pair.b, first.data(), first.size(), pair.payload.data(), pair.payload.size(),
                               &payload_size),
          "replayed input refused");
    // The lost one arriving late is older than the last accepted: dropped too.
    check(!net_link_open_input(&pair.b, lost, lost_size, pair.payload.data(), pair.payload.size(), &payload_size),
          "late input refused");
    // A tampered input packet: dropped, link alive.
    std::vector<uint8_t> tampered;
    link_send(&pair, &pair.a, &pair.b, NetChannel::input, "frame 4", &tampered);
    tampered.back() ^= 0x01;
    tampered[0] = static_cast<uint8_t>(tampered[0] + 1);   // a newer nonce, so only the MAC decides
    check(!net_link_open_input(&pair.b, tampered.data(), tampered.size(), pair.payload.data(), pair.payload.size(),
                               &payload_size),
          "tampered input refused");
    check(pair.b.input_dropped == dropped + 3, "dropped input counted");
    check(pair.b.state == NetLinkState::ready, "bad input doesn't kill the link");
    check(link_send(&pair, &pair.a, &pair.b, NetChannel::input, "frame 5", nullptr), "input still flows");

    // An input packet on control (or the other way round) never opens.
    net_link_seal(&pair.a, NetChannel::input, lost_text, 1, lost, sizeof(lost), &lost_size);
    size_t reply_size = 0;
    check(net_link_receive_control(&pair.b, lost, lost_size, pair.reply.data(), pair.reply.size(), &reply_size,
                                   pair.payload.data(), pair.payload.size(), &payload_size) == NetLinkReceive::failed,
          "an input packet on control kills the link (tampering)");
    check(pair.b.state == NetLinkState::failed, "and the link is failed");

    // Nothing can be sealed before the handshake.
    NetLink fresh;
    NetKeypair key;
    net_keypair_generate(&key);
    net_link_init(&fresh, NetNoiseRole::responder, &key);
    size_t sealed_size = 0;
    check(!net_link_seal(&fresh, NetChannel::control, lost_text, 1, lost, sizeof(lost), &sealed_size),
          "no sealing before the handshake");
}

static bool equal_hex(const uint8_t* bytes, size_t size, const char* hex)
{
    std::vector<uint8_t> expected = from_hex(hex);
    return expected.size() == size && std::memcmp(bytes, expected.data(), size) == 0;
}

static std::vector<uint8_t> text_bytes(const char* text)
{
    return std::vector<uint8_t>(text, text + std::strlen(text));
}

static void test_cpace()
{
    // B.1.1
    std::vector<uint8_t> prs = text_bytes("Password");
    std::vector<uint8_t> ci = from_hex("6f630b425f726573706f6e6465720b415f696e69746961746f72");
    std::vector<uint8_t> sid = from_hex("7e4b4791d6a8ef019b936c79fb7f2c57");
    uint8_t g[32];
    net_cpace_generator(prs.data(), prs.size(), ci.data(), ci.size(), sid.data(), sid.size(), g);
    check(equal_hex(g, 32, "64e8099e3ea682cfdc5cb665c057ebb514d06bf23ebc9f743b51b82242327074"), "cpace: generator");

    // B.1.2 - B.1.5
    std::vector<uint8_t> ya = from_hex("21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080");
    std::vector<uint8_t> yb = from_hex("848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a");
    std::vector<uint8_t> ad_a = text_bytes("ADa");
    std::vector<uint8_t> ad_b = text_bytes("ADb");
    NetCpace a;
    NetCpace b;
    net_cpace_start_with_scalar(&a, prs.data(), prs.size(), ci.data(), ci.size(), sid.data(), sid.size(), ya.data());
    net_cpace_start_with_scalar(&b, prs.data(), prs.size(), ci.data(), ci.size(), sid.data(), sid.size(), yb.data());
    check(equal_hex(a.share, 32, "1b02dad6dbd29a07b6d28c9e04cb2f184f0734350e32bb7e62ff9dbcfdb63d15"), "cpace: Ya");
    check(equal_hex(b.share, 32, "20cda5955f82c4931545bcbf40758ce1010d7db4db2a907013d79c7a8fcf957f"), "cpace: Yb");
    uint8_t share_a[32];
    uint8_t share_b[32];
    std::memcpy(share_a, a.share, 32);
    std::memcpy(share_b, b.share, 32);
    uint8_t isk_a[NET_CPACE_ISK_SIZE];
    uint8_t isk_b[NET_CPACE_ISK_SIZE];
    const char* expected_isk = "a051ee5ee2499d16da3f69f430218b8ea94a18a45b67f9e86495b382c33d14a5"
                               "c38cecc0cc834f960e39e0d1bf7d76b9ef5d54eecc5e0f386c97ad12da8c3d5f";
    check(net_cpace_finish(&a, true, share_b, ad_a.data(), ad_a.size(), ad_b.data(), ad_b.size(), sid.data(),
                           sid.size(), isk_a),
          "cpace: A finishes");
    check(net_cpace_finish(&b, false, share_a, ad_a.data(), ad_a.size(), ad_b.data(), ad_b.size(), sid.data(),
                           sid.size(), isk_b),
          "cpace: B finishes");
    check(equal_hex(isk_a, sizeof(isk_a), expected_isk), "cpace: A's ISK matches the vector");
    check(equal_hex(isk_b, sizeof(isk_b), expected_isk), "cpace: B's ISK matches the vector");

    // Generators where the hash has bit 254 set (empty CI and sid).
    const char* extra[3][2] = {
        {"100000", "87c6b62122a02c4f27ab1a2308ce85f98236691d98dda0641db0b3d766b36d31"},
        {"100002", "0fe9faa50d0f6bf26ea526f1b74eb0a1f7c5ce8a74d96d306aabc8ff968a6a3b"},
        {"100005", "2f9812348a82e44e2f593ad55ab40bc886b109622125244593f445168821506f"},
    };
    for (uint32_t i = 0; i < 3; i++)
    {
        std::vector<uint8_t> password = text_bytes(extra[i][0]);
        net_cpace_generator(password.data(), password.size(), nullptr, 0, nullptr, 0, g);
        char what[64];
        std::snprintf(what, sizeof(what), "cpace: generator with bit 254 set (%s)", extra[i][0]);
        check(equal_hex(g, 32, extra[i][1]), what);
    }

    // B.1.10: shares that are low-order points must abort; u6, u8-ub must not.
    const char* low_order[12] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
    };
    const bool must_abort[12] = {true, true, true, true, true, true, false, true, false, false, false, false};
    std::vector<uint8_t> s = from_hex("af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff");
    for (uint32_t i = 0; i < 12; i++)
    {
        NetCpace c;
        net_cpace_start_with_scalar(&c, prs.data(), prs.size(), nullptr, 0, nullptr, 0, s.data());
        std::vector<uint8_t> u = from_hex(low_order[i]);
        uint8_t isk[NET_CPACE_ISK_SIZE];
        bool finished = net_cpace_finish(&c, true, u.data(), nullptr, 0, nullptr, 0, nullptr, 0, isk);
        char what[64];
        std::snprintf(what, sizeof(what), "cpace: low-order share u%x %s", i, must_abort[i] ? "aborts" : "accepted");
        check(finished == !must_abort[i], what);
    }

    // Different passwords: both finish, the keys differ.
    NetCpace c;
    NetCpace d;
    std::vector<uint8_t> right = text_bytes("482915");
    std::vector<uint8_t> wrong = text_bytes("482916");
    net_cpace_start(&c, right.data(), right.size(), nullptr, 0, sid.data(), sid.size());
    net_cpace_start(&d, wrong.data(), wrong.size(), nullptr, 0, sid.data(), sid.size());
    std::memcpy(share_a, c.share, 32);
    std::memcpy(share_b, d.share, 32);
    net_cpace_finish(&c, true, share_b, nullptr, 0, nullptr, 0, sid.data(), sid.size(), isk_a);
    net_cpace_finish(&d, false, share_a, nullptr, 0, nullptr, 0, sid.data(), sid.size(), isk_b);
    check(std::memcmp(isk_a, isk_b, NET_CPACE_ISK_SIZE) != 0, "cpace: a wrong code gives a different key");
}

int main()
{
    test_vector();
    test_failures();
    test_link();
    test_cpace();
    if (g_failures == 0)
    {
        std::printf("all noise checks passed\n");
    }
    return g_failures == 0 ? 0 : 1;
}
