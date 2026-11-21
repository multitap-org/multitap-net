#pragma once

// The pair link (and its QR code): what a device needs to pair with a host
// it can't find on the LAN (mobile data, a browser). It carries the host's
// public key, and the beacon when it isn't the default one. The 6-digit code
// still has to be typed: the link says who to pair with, the code proves it
// (net_client_pair_beacon). Knowing a host's key gives nothing else: the
// pairing room exists only while the host shows its code.
//
//   https://get-piccolo.app/pair#k=<host key, base32>[&b=<beacon>]
//
// Base32: RFC 4648 alphabet, lowercase, no padding (52 characters).

#include <cstdint>
#include <string>

#include "net_noise.h"

constexpr const char* NET_PAIR_LINK_BASE = "https://get-piccolo.app/pair#";

// `beacon`: the host's beacon setting; nullptr, "" or the default leaves it out.
std::string net_pair_link(const uint8_t* host_key, const char* beacon);

// Reads a link (or just the part after '#'). `beacon` gets the beacon it
// names, or "" for the default. False if there's no valid key.
bool net_pair_link_parse(const char* text, uint8_t* host_key, std::string* beacon);
