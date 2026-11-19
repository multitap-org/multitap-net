#include "net_content.h"

#include <cstring>

#include "net_wire.h"


// The message's type byte and id.
static NetReader reader_begin(const uint8_t* data, size_t size, NetContentMessage type, uint32_t* id)
{
    NetReader reader;
    reader.data = data;
    reader.size = size;
    if (net_wire_get_u8(&reader) != static_cast<uint8_t>(type))
    {
        reader.ok = false;
    }
    *id = net_wire_get_u32(&reader);
    return reader;
}

static bool read_status(NetReader* reader, NetContentStatus* status)
{
    uint8_t value = net_wire_get_u8(reader);
    if (value >= NET_CONTENT_STATUS_COUNT)
    {
        reader->ok = false;
        return false;
    }
    *status = static_cast<NetContentStatus>(value);
    return reader->ok;
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

size_t net_content_write_cores_request(uint8_t* out, size_t capacity, uint32_t id, uint32_t start)
{
    NetWriter writer = {out, capacity, 0, true};
    net_wire_put_u8(&writer, static_cast<uint8_t>(NetContentMessage::cores_request));
    net_wire_put_u32(&writer, id);
    net_wire_put_u32(&writer, start);
    return writer.ok ? writer.size : 0;
}

bool net_content_read_cores_request(const uint8_t* data, size_t size, uint32_t* id, uint32_t* start)
{
    NetReader reader = reader_begin(data, size, NetContentMessage::cores_request, id);
    *start = net_wire_get_u32(&reader);
    return net_wire_done(&reader);
}

// A paged result's header; `count_at` is where the count goes once known.
static void put_page_header(NetWriter* writer, NetContentMessage type, uint32_t id, NetContentStatus status,
                            uint32_t start, uint32_t total, size_t* count_at)
{
    net_wire_put_u8(writer, static_cast<uint8_t>(type));
    net_wire_put_u32(writer, id);
    net_wire_put_u8(writer, static_cast<uint8_t>(status));
    net_wire_put_u32(writer, start);
    net_wire_put_u32(writer, total);
    *count_at = writer->size;
    net_wire_put_u16(writer, 0);
}

static void set_page_count(NetWriter* writer, size_t count_at, uint16_t count)
{
    writer->out[count_at] = static_cast<uint8_t>(count);
    writer->out[count_at + 1] = static_cast<uint8_t>(count >> 8);
}

static void put_core(NetWriter* writer, const NetContentCore* core)
{
    net_wire_put_u8(writer, core->flags);
    net_wire_put_text(writer, core->file.c_str(), core->file.size());
    net_wire_put_text(writer, core->name.c_str(), core->name.size());
    net_wire_put_text(writer, core->version.c_str(), core->version.size());
    net_wire_put_text(writer, core->extensions.c_str(), core->extensions.size());
}

size_t net_content_write_cores_result(uint8_t* out, size_t capacity, uint32_t id, NetContentStatus status,
                                      const std::vector<NetContentCore>* cores, uint32_t start)
{
    bool ok = status == NetContentStatus::ok;
    uint32_t total = ok ? static_cast<uint32_t>(cores->size()) : 0;
    NetWriter writer = {out, capacity, 0, true};
    size_t count_at = 0;
    put_page_header(&writer, NetContentMessage::cores_result, id, status, start, total, &count_at);
    if (!writer.ok)
    {
        return 0;
    }
    // As many as fit: each is written whole or the writer goes back to
    // before it.
    uint16_t count = 0;
    for (uint32_t i = start; i < total && count < UINT16_MAX; i++)
    {
        size_t before = writer.size;
        put_core(&writer, &(*cores)[i]);
        if (!writer.ok)
        {
            writer.size = before;
            writer.ok = true;
            break;
        }
        count++;
    }
    set_page_count(&writer, count_at, count);
    return writer.size;
}

bool net_content_read_cores_result(const uint8_t* data, size_t size, uint32_t* id, NetContentStatus* status,
                                   uint32_t* start, uint32_t* total, std::vector<NetContentCore>* cores)
{
    cores->clear();
    NetReader reader = reader_begin(data, size, NetContentMessage::cores_result, id);
    read_status(&reader, status);
    *start = net_wire_get_u32(&reader);
    *total = net_wire_get_u32(&reader);
    uint16_t count = net_wire_get_u16(&reader);
    for (uint16_t i = 0; i < count && reader.ok; i++)
    {
        NetContentCore core;
        core.flags = net_wire_get_u8(&reader);
        net_wire_get_text(&reader, &core.file);
        net_wire_get_text(&reader, &core.name);
        net_wire_get_text(&reader, &core.version);
        net_wire_get_text(&reader, &core.extensions);
        cores->push_back(core);
    }
    return net_wire_done(&reader);
}

size_t net_content_write_list_request(uint8_t* out, size_t capacity, uint32_t id, uint32_t start, const char* path)
{
    NetWriter writer = {out, capacity, 0, true};
    net_wire_put_u8(&writer, static_cast<uint8_t>(NetContentMessage::list_request));
    net_wire_put_u32(&writer, id);
    net_wire_put_u32(&writer, start);
    net_wire_put_text(&writer, path, std::strlen(path));
    return writer.ok ? writer.size : 0;
}

bool net_content_read_list_request(const uint8_t* data, size_t size, uint32_t* id, uint32_t* start, std::string* path)
{
    NetReader reader = reader_begin(data, size, NetContentMessage::list_request, id);
    *start = net_wire_get_u32(&reader);
    net_wire_get_text(&reader, path);
    return net_wire_done(&reader);
}

size_t net_content_write_list_result(uint8_t* out, size_t capacity, uint32_t id, NetContentStatus status,
                                     const std::vector<NetContentEntry>* entries, uint32_t start)
{
    bool ok = status == NetContentStatus::ok;
    uint32_t total = ok ? static_cast<uint32_t>(entries->size()) : 0;
    NetWriter writer = {out, capacity, 0, true};
    size_t count_at = 0;
    put_page_header(&writer, NetContentMessage::list_result, id, status, start, total, &count_at);
    if (!writer.ok)
    {
        return 0;
    }
    uint16_t count = 0;
    for (uint32_t i = start; i < total && count < UINT16_MAX; i++)
    {
        const NetContentEntry* entry = &(*entries)[i];
        size_t before = writer.size;
        net_wire_put_u8(&writer, static_cast<uint8_t>(entry->kind));
        net_wire_put_u64(&writer, entry->size);
        net_wire_put_text(&writer, entry->name.c_str(), entry->name.size());
        if (!writer.ok)
        {
            writer.size = before;
            writer.ok = true;
            break;
        }
        count++;
    }
    set_page_count(&writer, count_at, count);
    return writer.size;
}

bool net_content_read_list_result(const uint8_t* data, size_t size, uint32_t* id, NetContentStatus* status,
                                  uint32_t* start, uint32_t* total, std::vector<NetContentEntry>* entries)
{
    entries->clear();
    NetReader reader = reader_begin(data, size, NetContentMessage::list_result, id);
    read_status(&reader, status);
    *start = net_wire_get_u32(&reader);
    *total = net_wire_get_u32(&reader);
    uint16_t count = net_wire_get_u16(&reader);
    for (uint16_t i = 0; i < count && reader.ok; i++)
    {
        NetContentEntry entry;
        uint8_t kind = net_wire_get_u8(&reader);
        if (kind >= NET_CONTENT_KIND_COUNT)
        {
            reader.ok = false;
            break;
        }
        entry.kind = static_cast<NetContentKind>(kind);
        entry.size = net_wire_get_u64(&reader);
        net_wire_get_text(&reader, &entry.name);
        entries->push_back(entry);
    }
    return net_wire_done(&reader);
}

size_t net_content_write_load_request(uint8_t* out, size_t capacity, uint32_t id, const char* core_file,
                                      const char* path)
{
    NetWriter writer = {out, capacity, 0, true};
    net_wire_put_u8(&writer, static_cast<uint8_t>(NetContentMessage::load_request));
    net_wire_put_u32(&writer, id);
    net_wire_put_text(&writer, core_file, std::strlen(core_file));
    net_wire_put_text(&writer, path, std::strlen(path));
    return writer.ok ? writer.size : 0;
}

bool net_content_read_load_request(const uint8_t* data, size_t size, uint32_t* id, std::string* core_file,
                                   std::string* path)
{
    NetReader reader = reader_begin(data, size, NetContentMessage::load_request, id);
    net_wire_get_text(&reader, core_file);
    net_wire_get_text(&reader, path);
    return net_wire_done(&reader);
}

size_t net_content_write_load_result(uint8_t* out, size_t capacity, uint32_t id, NetContentStatus status)
{
    NetWriter writer = {out, capacity, 0, true};
    net_wire_put_u8(&writer, static_cast<uint8_t>(NetContentMessage::load_result));
    net_wire_put_u32(&writer, id);
    net_wire_put_u8(&writer, static_cast<uint8_t>(status));
    return writer.ok ? writer.size : 0;
}

bool net_content_read_load_result(const uint8_t* data, size_t size, uint32_t* id, NetContentStatus* status)
{
    NetReader reader = reader_begin(data, size, NetContentMessage::load_result, id);
    read_status(&reader, status);
    return net_wire_done(&reader);
}

size_t net_content_write_game_state(uint8_t* out, size_t capacity, const NetGameState* state)
{
    NetWriter writer = {out, capacity, 0, true};
    net_wire_put_u8(&writer, NET_GAME_STATE_MESSAGE);
    net_wire_put_u8(&writer, state->running ? 1 : 0);
    net_wire_put_text(&writer, state->core_file.c_str(), state->core_file.size());
    net_wire_put_text(&writer, state->core_name.c_str(), state->core_name.size());
    net_wire_put_text(&writer, state->core_version.c_str(), state->core_version.size());
    net_wire_put_text(&writer, state->game.c_str(), state->game.size());
    return writer.ok ? writer.size : 0;
}

bool net_content_read_game_state(const uint8_t* data, size_t size, NetGameState* state)
{
    NetReader reader;
    reader.data = data;
    reader.size = size;
    if (net_wire_get_u8(&reader) != NET_GAME_STATE_MESSAGE)
    {
        return false;
    }
    uint8_t running = net_wire_get_u8(&reader);
    if (running > 1)
    {
        return false;
    }
    state->running = running == 1;
    net_wire_get_text(&reader, &state->core_file);
    net_wire_get_text(&reader, &state->core_name);
    net_wire_get_text(&reader, &state->core_version);
    net_wire_get_text(&reader, &state->game);
    return net_wire_done(&reader);
}
