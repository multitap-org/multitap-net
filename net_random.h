#pragma once

// Secret random bytes from the operating system (keys, nonces that must not
// be guessed). Monocypher has no random generator of its own by design.
// One file per platform, chosen by CMake (like game_mode_*.cpp):
//   net_random_posix.cpp    /dev/urandom (Linux, Android, macOS)
//   net_random_windows.cpp  BCryptGenRandom
// /dev/urandom rather than getrandom()/getentropy(): every POSIX target has
// it, including Android versions before API 28, and it never blocks once the
// system has booted.

#include <cstddef>
#include <cstdint>

// False (and logged) only if the system source can't be read: callers must
// not go on without the bytes.
bool net_random_bytes(uint8_t* out, size_t size);
