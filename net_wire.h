#pragma once

// Writing and reading the fields of our network messages (little-endian
// numbers, text = u16 length + UTF-8 bytes), for net_content and
// net_settings. A writer stops at its capacity and a reader at the end of
// the payload: once something doesn't fit (or isn't there), `ok` stays false
// and the rest does nothing, so a message is checked once, at the end.

#include <cstddef>
#include <cstdint>
#include <string>

constexpr size_t NET_WIRE_TEXT_MAX = 4096;   // bytes of any text field (NET_CONTENT_PATH_MAX)

// A writer that stops at `capacity`: once something doesn't fit, `ok` stays
// false and nothing more is written.
struct NetWriter
{
    uint8_t* out = nullptr;
    size_t   capacity = 0;
    size_t   size = 0;
    bool     ok = true;
};

struct NetReader
{
    const uint8_t* data = nullptr;
    size_t         size = 0;
    size_t         at = 0;
    bool           ok = true;
};

bool     net_wire_room(NetWriter* writer, size_t bytes);
void     net_wire_put_u8(NetWriter* writer, uint8_t value);
void     net_wire_put_u16(NetWriter* writer, uint16_t value);
void     net_wire_put_u32(NetWriter* writer, uint32_t value);
void     net_wire_put_i32(NetWriter* writer, int32_t value);
void     net_wire_put_u64(NetWriter* writer, uint64_t value);
// A text longer than NET_WIRE_TEXT_MAX fails the writer (never cut: a cut
// path would name something else).
void     net_wire_put_text(NetWriter* writer, const char* text, size_t length);
void     net_wire_put_string(NetWriter* writer, const std::string* text);

bool     net_wire_has(NetReader* reader, size_t bytes);
uint8_t  net_wire_get_u8(NetReader* reader);
uint16_t net_wire_get_u16(NetReader* reader);
uint32_t net_wire_get_u32(NetReader* reader);
int32_t  net_wire_get_i32(NetReader* reader);
uint64_t net_wire_get_u64(NetReader* reader);
// Refuses texts over NET_WIRE_TEXT_MAX or with a NUL byte.
void     net_wire_get_text(NetReader* reader, std::string* text);
// Read to the last byte, nothing left over.
bool     net_wire_done(const NetReader* reader);
