#pragma once

// A link that names a host: its public key, and the beacon when it isn't the
// default one (and its QR code, drawn by the frontend).
//
// Not used for pairing since 2026-11-22 (the device that is asked shows the
// code and the other one types it: net_pairing.h). Kept, with piccolo's QR drawing and
// piccoletto's link intent, for the links to come (Andrés, 2026-11-22: a QR or
// a click to join a game from the lobby).
//
//   https://get-piccolo.app/pair/#k=<host key, base32>[&b=<beacon>]
//
// Base32: RFC 4648 alphabet, lowercase, no padding (52 characters).

#include <cstdint>
#include <string>

#include "net_noise.h"

constexpr const char* NET_PAIR_LINK_BASE = "https://get-piccolo.app/pair/#";

// `beacon`: the host's beacon setting; nullptr, "" or the default leaves it out.
std::string net_pair_link(const uint8_t* host_key, const char* beacon);

// Reads a link (or just the part after '#'). `beacon` gets the beacon it
// names, or "" for the default. False if there's no valid key.
bool net_pair_link_parse(const char* text, uint8_t* host_key, std::string* beacon);
