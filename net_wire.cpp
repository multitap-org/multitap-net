#include "net_wire.h"

#include <cstring>

bool net_wire_room(NetWriter* writer, size_t bytes)
{
    if (!writer->ok || writer->capacity - writer->size < bytes)
    {
        writer->ok = false;
        return false;
    }
    return true;
}

void net_wire_put_u8(NetWriter* writer, uint8_t value)
{
    if (net_wire_room(writer, 1))
    {
        writer->out[writer->size] = value;
        writer->size += 1;
    }
}

void net_wire_put_u16(NetWriter* writer, uint16_t value)
{
    if (net_wire_room(writer, 2))
    {
        writer->out[writer->size] = static_cast<uint8_t>(value);
        writer->out[writer->size + 1] = static_cast<uint8_t>(value >> 8);
        writer->size += 2;
    }
}

void net_wire_put_u32(NetWriter* writer, uint32_t value)
{
    if (net_wire_room(writer, 4))
    {
        for (size_t i = 0; i < 4; i++)
        {
            writer->out[writer->size + i] = static_cast<uint8_t>(value >> (8 * i));
        }
        writer->size += 4;
    }
}

void net_wire_put_u64(NetWriter* writer, uint64_t value)
{
    if (net_wire_room(writer, 8))
    {
        for (size_t i = 0; i < 8; i++)
        {
            writer->out[writer->size + i] = static_cast<uint8_t>(value >> (8 * i));
        }
        writer->size += 8;
    }
}

void net_wire_put_text(NetWriter* writer, const char* text, size_t length)
{
    if (length > NET_WIRE_TEXT_MAX)
    {
        writer->ok = false;   // never cut: a cut path would name something else
        return;
    }
    net_wire_put_u16(writer, static_cast<uint16_t>(length));
    if (net_wire_room(writer, length))
    {
        std::memcpy(writer->out + writer->size, text, length);
        writer->size += length;
    }
}

bool net_wire_has(NetReader* reader, size_t bytes)
{
    if (!reader->ok || reader->size - reader->at < bytes)
    {
        reader->ok = false;
        return false;
    }
    return true;
}

uint8_t net_wire_get_u8(NetReader* reader)
{
    if (!net_wire_has(reader, 1))
    {
        return 0;
    }
    uint8_t value = reader->data[reader->at];
    reader->at += 1;
    return value;
}

uint16_t net_wire_get_u16(NetReader* reader)
{
    if (!net_wire_has(reader, 2))
    {
        return 0;
    }
    uint16_t value = static_cast<uint16_t>(reader->data[reader->at] | (reader->data[reader->at + 1] << 8));
    reader->at += 2;
    return value;
}

uint32_t net_wire_get_u32(NetReader* reader)
{
    if (!net_wire_has(reader, 4))
    {
        return 0;
    }
    uint32_t value = 0;
    for (size_t i = 0; i < 4; i++)
    {
        value |= static_cast<uint32_t>(reader->data[reader->at + i]) << (8 * i);
    }
    reader->at += 4;
    return value;
}

uint64_t net_wire_get_u64(NetReader* reader)
{
    if (!net_wire_has(reader, 8))
    {
        return 0;
    }
    uint64_t value = 0;
    for (size_t i = 0; i < 8; i++)
    {
        value |= static_cast<uint64_t>(reader->data[reader->at + i]) << (8 * i);
    }
    reader->at += 8;
    return value;
}

void net_wire_get_text(NetReader* reader, std::string* text)
{
    size_t length = net_wire_get_u16(reader);
    if (length > NET_WIRE_TEXT_MAX || !net_wire_has(reader, length) ||
        std::memchr(reader->data + reader->at, 0, length) != nullptr)
    {
        reader->ok = false;
        return;
    }
    text->assign(static_cast<const char*>(static_cast<const void*>(reader->data + reader->at)), length);
    reader->at += length;
}


void net_wire_put_i32(NetWriter* writer, int32_t value)
{
    net_wire_put_u32(writer, static_cast<uint32_t>(value));
}

int32_t net_wire_get_i32(NetReader* reader)
{
    return static_cast<int32_t>(net_wire_get_u32(reader));
}

void net_wire_put_string(NetWriter* writer, const std::string* text)
{
    net_wire_put_text(writer, text->c_str(), text->size());
}

bool net_wire_done(const NetReader* reader)
{
    return reader->ok && reader->at == reader->size;
}
