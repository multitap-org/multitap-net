#include "net_content.h"

#include <cstring>


// ---------------------------------------------------------------------------
// Writing and reading fields
// ---------------------------------------------------------------------------

// A writer that stops at `capacity`: once something doesn't fit, `ok` stays
// false and nothing more is written.
struct Writer
{
    uint8_t* out = nullptr;
    size_t   capacity = 0;
    size_t   size = 0;
    bool     ok = true;
};

static bool writer_room(Writer* writer, size_t bytes)
{
    if (!writer->ok || writer->capacity - writer->size < bytes)
    {
        writer->ok = false;
        return false;
    }
    return true;
}

static void put_u8(Writer* writer, uint8_t value)
{
    if (writer_room(writer, 1))
    {
        writer->out[writer->size] = value;
        writer->size += 1;
    }
}

static void put_u16(Writer* writer, uint16_t value)
{
    if (writer_room(writer, 2))
    {
        writer->out[writer->size] = static_cast<uint8_t>(value);
        writer->out[writer->size + 1] = static_cast<uint8_t>(value >> 8);
        writer->size += 2;
    }
}

static void put_u32(Writer* writer, uint32_t value)
{
    if (writer_room(writer, 4))
    {
        for (size_t i = 0; i < 4; i++)
        {
            writer->out[writer->size + i] = static_cast<uint8_t>(value >> (8 * i));
        }
        writer->size += 4;
    }
}

static void put_u64(Writer* writer, uint64_t value)
{
    if (writer_room(writer, 8))
    {
        for (size_t i = 0; i < 8; i++)
        {
            writer->out[writer->size + i] = static_cast<uint8_t>(value >> (8 * i));
        }
        writer->size += 8;
    }
}

static void put_text(Writer* writer, const char* text, size_t length)
{
    if (length > NET_CONTENT_PATH_MAX)
    {
        writer->ok = false;   // never cut: a cut path would name something else
        return;
    }
    put_u16(writer, static_cast<uint16_t>(length));
    if (writer_room(writer, length))
    {
        std::memcpy(writer->out + writer->size, text, length);
        writer->size += length;
    }
}

struct Reader
{
    const uint8_t* data = nullptr;
    size_t         size = 0;
    size_t         at = 0;
    bool           ok = true;
};

static bool reader_has(Reader* reader, size_t bytes)
{
    if (!reader->ok || reader->size - reader->at < bytes)
    {
        reader->ok = false;
        return false;
    }
    return true;
}

static uint8_t get_u8(Reader* reader)
{
    if (!reader_has(reader, 1))
    {
        return 0;
    }
    uint8_t value = reader->data[reader->at];
    reader->at += 1;
    return value;
}

static uint16_t get_u16(Reader* reader)
{
    if (!reader_has(reader, 2))
    {
        return 0;
    }
    uint16_t value = static_cast<uint16_t>(reader->data[reader->at] | (reader->data[reader->at + 1] << 8));
    reader->at += 2;
    return value;
}

static uint32_t get_u32(Reader* reader)
{
    if (!reader_has(reader, 4))
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

static uint64_t get_u64(Reader* reader)
{
    if (!reader_has(reader, 8))
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

static void get_text(Reader* reader, std::string* text)
{
    size_t length = get_u16(reader);
    if (length > NET_CONTENT_PATH_MAX || !reader_has(reader, length) ||
        std::memchr(reader->data + reader->at, 0, length) != nullptr)
    {
        reader->ok = false;
        return;
    }
    text->assign(static_cast<const char*>(static_cast<const void*>(reader->data + reader->at)), length);
    reader->at += length;
}

// The message's type byte and id.
static Reader reader_begin(const uint8_t* data, size_t size, NetContentMessage type, uint32_t* id)
{
    Reader reader;
    reader.data = data;
    reader.size = size;
    if (get_u8(&reader) != static_cast<uint8_t>(type))
    {
        reader.ok = false;
    }
    *id = get_u32(&reader);
    return reader;
}

// Read to the last byte, nothing left over.
static bool reader_done(const Reader* reader)
{
    return reader->ok && reader->at == reader->size;
}

static bool read_status(Reader* reader, NetContentStatus* status)
{
    uint8_t value = get_u8(reader);
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
    Writer writer = {out, capacity, 0, true};
    put_u8(&writer, static_cast<uint8_t>(NetContentMessage::cores_request));
    put_u32(&writer, id);
    put_u32(&writer, start);
    return writer.ok ? writer.size : 0;
}

bool net_content_read_cores_request(const uint8_t* data, size_t size, uint32_t* id, uint32_t* start)
{
    Reader reader = reader_begin(data, size, NetContentMessage::cores_request, id);
    *start = get_u32(&reader);
    return reader_done(&reader);
}

// A paged result's header; `count_at` is where the count goes once known.
static void put_page_header(Writer* writer, NetContentMessage type, uint32_t id, NetContentStatus status,
                            uint32_t start, uint32_t total, size_t* count_at)
{
    put_u8(writer, static_cast<uint8_t>(type));
    put_u32(writer, id);
    put_u8(writer, static_cast<uint8_t>(status));
    put_u32(writer, start);
    put_u32(writer, total);
    *count_at = writer->size;
    put_u16(writer, 0);
}

static void set_page_count(Writer* writer, size_t count_at, uint16_t count)
{
    writer->out[count_at] = static_cast<uint8_t>(count);
    writer->out[count_at + 1] = static_cast<uint8_t>(count >> 8);
}

static void put_core(Writer* writer, const NetContentCore* core)
{
    put_u8(writer, core->flags);
    put_text(writer, core->file.c_str(), core->file.size());
    put_text(writer, core->name.c_str(), core->name.size());
    put_text(writer, core->version.c_str(), core->version.size());
    put_text(writer, core->extensions.c_str(), core->extensions.size());
}

size_t net_content_write_cores_result(uint8_t* out, size_t capacity, uint32_t id, NetContentStatus status,
                                      const std::vector<NetContentCore>* cores, uint32_t start)
{
    bool ok = status == NetContentStatus::ok;
    uint32_t total = ok ? static_cast<uint32_t>(cores->size()) : 0;
    Writer writer = {out, capacity, 0, true};
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
    Reader reader = reader_begin(data, size, NetContentMessage::cores_result, id);
    read_status(&reader, status);
    *start = get_u32(&reader);
    *total = get_u32(&reader);
    uint16_t count = get_u16(&reader);
    for (uint16_t i = 0; i < count && reader.ok; i++)
    {
        NetContentCore core;
        core.flags = get_u8(&reader);
        get_text(&reader, &core.file);
        get_text(&reader, &core.name);
        get_text(&reader, &core.version);
        get_text(&reader, &core.extensions);
        cores->push_back(core);
    }
    return reader_done(&reader);
}

size_t net_content_write_list_request(uint8_t* out, size_t capacity, uint32_t id, uint32_t start, const char* path)
{
    Writer writer = {out, capacity, 0, true};
    put_u8(&writer, static_cast<uint8_t>(NetContentMessage::list_request));
    put_u32(&writer, id);
    put_u32(&writer, start);
    put_text(&writer, path, std::strlen(path));
    return writer.ok ? writer.size : 0;
}

bool net_content_read_list_request(const uint8_t* data, size_t size, uint32_t* id, uint32_t* start, std::string* path)
{
    Reader reader = reader_begin(data, size, NetContentMessage::list_request, id);
    *start = get_u32(&reader);
    get_text(&reader, path);
    return reader_done(&reader);
}

size_t net_content_write_list_result(uint8_t* out, size_t capacity, uint32_t id, NetContentStatus status,
                                     const std::vector<NetContentEntry>* entries, uint32_t start)
{
    bool ok = status == NetContentStatus::ok;
    uint32_t total = ok ? static_cast<uint32_t>(entries->size()) : 0;
    Writer writer = {out, capacity, 0, true};
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
        put_u8(&writer, static_cast<uint8_t>(entry->kind));
        put_u64(&writer, entry->size);
        put_text(&writer, entry->name.c_str(), entry->name.size());
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
    Reader reader = reader_begin(data, size, NetContentMessage::list_result, id);
    read_status(&reader, status);
    *start = get_u32(&reader);
    *total = get_u32(&reader);
    uint16_t count = get_u16(&reader);
    for (uint16_t i = 0; i < count && reader.ok; i++)
    {
        NetContentEntry entry;
        uint8_t kind = get_u8(&reader);
        if (kind >= NET_CONTENT_KIND_COUNT)
        {
            reader.ok = false;
            break;
        }
        entry.kind = static_cast<NetContentKind>(kind);
        entry.size = get_u64(&reader);
        get_text(&reader, &entry.name);
        entries->push_back(entry);
    }
    return reader_done(&reader);
}

size_t net_content_write_load_request(uint8_t* out, size_t capacity, uint32_t id, const char* core_file,
                                      const char* path)
{
    Writer writer = {out, capacity, 0, true};
    put_u8(&writer, static_cast<uint8_t>(NetContentMessage::load_request));
    put_u32(&writer, id);
    put_text(&writer, core_file, std::strlen(core_file));
    put_text(&writer, path, std::strlen(path));
    return writer.ok ? writer.size : 0;
}

bool net_content_read_load_request(const uint8_t* data, size_t size, uint32_t* id, std::string* core_file,
                                   std::string* path)
{
    Reader reader = reader_begin(data, size, NetContentMessage::load_request, id);
    get_text(&reader, core_file);
    get_text(&reader, path);
    return reader_done(&reader);
}

size_t net_content_write_load_result(uint8_t* out, size_t capacity, uint32_t id, NetContentStatus status)
{
    Writer writer = {out, capacity, 0, true};
    put_u8(&writer, static_cast<uint8_t>(NetContentMessage::load_result));
    put_u32(&writer, id);
    put_u8(&writer, static_cast<uint8_t>(status));
    return writer.ok ? writer.size : 0;
}

bool net_content_read_load_result(const uint8_t* data, size_t size, uint32_t* id, NetContentStatus* status)
{
    Reader reader = reader_begin(data, size, NetContentMessage::load_result, id);
    read_status(&reader, status);
    return reader_done(&reader);
}
