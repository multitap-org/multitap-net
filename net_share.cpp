#include "net_share.h"

#include <cstring>

#include "net_wire.h"

// The message's type byte and id.
static NetReader reader_begin(const uint8_t* data, size_t size, NetShareMessage type, uint32_t* id)
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

static NetWriter writer_begin(uint8_t* out, size_t capacity, NetShareMessage type, uint32_t id)
{
    NetWriter writer = {out, capacity, 0, true};
    net_wire_put_u8(&writer, static_cast<uint8_t>(type));
    net_wire_put_u32(&writer, id);
    return writer;
}

static void read_status(NetReader* reader, NetShareStatus* status)
{
    uint8_t value = net_wire_get_u8(reader);
    if (value >= NET_SHARE_STATUS_COUNT)
    {
        reader->ok = false;
        return;
    }
    *status = static_cast<NetShareStatus>(value);
}

static size_t writer_end(const NetWriter* writer)
{
    return writer->ok ? writer->size : 0;
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

size_t net_share_write_list_request(uint8_t* out, size_t capacity, uint32_t id, uint32_t start, const char* path)
{
    NetWriter writer = writer_begin(out, capacity, NetShareMessage::list_request, id);
    net_wire_put_u32(&writer, start);
    net_wire_put_text(&writer, path, std::strlen(path));
    return writer_end(&writer);
}

bool net_share_read_list_request(const uint8_t* data, size_t size, uint32_t* id, uint32_t* start, std::string* path)
{
    NetReader reader = reader_begin(data, size, NetShareMessage::list_request, id);
    *start = net_wire_get_u32(&reader);
    net_wire_get_text(&reader, path);
    return net_wire_done(&reader);
}

size_t net_share_write_list_result(uint8_t* out, size_t capacity, uint32_t id, NetShareStatus status,
                                   const std::vector<NetShareEntry>* entries, uint32_t start)
{
    bool ok = status == NetShareStatus::ok;
    uint32_t total = ok ? static_cast<uint32_t>(entries->size()) : 0;
    NetWriter writer = writer_begin(out, capacity, NetShareMessage::list_result, id);
    net_wire_put_u8(&writer, static_cast<uint8_t>(status));
    net_wire_put_u32(&writer, start);
    net_wire_put_u32(&writer, total);
    size_t count_at = writer.size;
    net_wire_put_u16(&writer, 0);
    if (!writer.ok)
    {
        return 0;
    }
    // As many as fit: each is written whole or the writer goes back to before it.
    uint16_t count = 0;
    for (uint32_t i = start; i < total && count < UINT16_MAX; i++)
    {
        const NetShareEntry* entry = &(*entries)[i];
        size_t before = writer.size;
        net_wire_put_u8(&writer, static_cast<uint8_t>(entry->kind));
        net_wire_put_u64(&writer, entry->size);
        net_wire_put_u64(&writer, entry->mtime);
        net_wire_put_text(&writer, entry->name.c_str(), entry->name.size());
        if (!writer.ok)
        {
            writer.size = before;
            writer.ok = true;
            break;
        }
        count++;
    }
    out[count_at] = static_cast<uint8_t>(count);
    out[count_at + 1] = static_cast<uint8_t>(count >> 8);
    return writer.size;
}

bool net_share_read_list_result(const uint8_t* data, size_t size, uint32_t* id, NetShareStatus* status,
                                uint32_t* start, uint32_t* total, std::vector<NetShareEntry>* entries)
{
    entries->clear();
    NetReader reader = reader_begin(data, size, NetShareMessage::list_result, id);
    read_status(&reader, status);
    *start = net_wire_get_u32(&reader);
    *total = net_wire_get_u32(&reader);
    uint16_t count = net_wire_get_u16(&reader);
    for (uint16_t i = 0; i < count && reader.ok; i++)
    {
        NetShareEntry entry;
        uint8_t kind = net_wire_get_u8(&reader);
        if (kind >= NET_SHARE_KIND_COUNT)
        {
            reader.ok = false;
            break;
        }
        entry.kind = static_cast<NetShareKind>(kind);
        entry.size = net_wire_get_u64(&reader);
        entry.mtime = net_wire_get_u64(&reader);
        net_wire_get_text(&reader, &entry.name);
        entries->push_back(entry);
    }
    return net_wire_done(&reader);
}

// ---------------------------------------------------------------------------
// Get and put
// ---------------------------------------------------------------------------

size_t net_share_write_get_request(uint8_t* out, size_t capacity, uint32_t id, uint64_t offset, const char* path)
{
    NetWriter writer = writer_begin(out, capacity, NetShareMessage::get_request, id);
    net_wire_put_u64(&writer, offset);
    net_wire_put_text(&writer, path, std::strlen(path));
    return writer_end(&writer);
}

bool net_share_read_get_request(const uint8_t* data, size_t size, uint32_t* id, uint64_t* offset, std::string* path)
{
    NetReader reader = reader_begin(data, size, NetShareMessage::get_request, id);
    *offset = net_wire_get_u64(&reader);
    net_wire_get_text(&reader, path);
    return net_wire_done(&reader);
}

size_t net_share_write_get_ready(uint8_t* out, size_t capacity, uint32_t id, NetShareStatus status,
                                 uint64_t file_size, uint64_t mtime)
{
    NetWriter writer = writer_begin(out, capacity, NetShareMessage::get_ready, id);
    net_wire_put_u8(&writer, static_cast<uint8_t>(status));
    net_wire_put_u64(&writer, file_size);
    net_wire_put_u64(&writer, mtime);
    return writer_end(&writer);
}

bool net_share_read_get_ready(const uint8_t* data, size_t size, uint32_t* id, NetShareStatus* status,
                              uint64_t* file_size, uint64_t* mtime)
{
    NetReader reader = reader_begin(data, size, NetShareMessage::get_ready, id);
    read_status(&reader, status);
    *file_size = net_wire_get_u64(&reader);
    *mtime = net_wire_get_u64(&reader);
    return net_wire_done(&reader);
}

size_t net_share_write_put_request(uint8_t* out, size_t capacity, uint32_t id, uint64_t file_size, uint64_t mtime,
                                   uint8_t flags, const char* path)
{
    NetWriter writer = writer_begin(out, capacity, NetShareMessage::put_request, id);
    net_wire_put_u64(&writer, file_size);
    net_wire_put_u64(&writer, mtime);
    net_wire_put_u8(&writer, flags);
    net_wire_put_text(&writer, path, std::strlen(path));
    return writer_end(&writer);
}

bool net_share_read_put_request(const uint8_t* data, size_t size, uint32_t* id, uint64_t* file_size, uint64_t* mtime,
                                uint8_t* flags, std::string* path)
{
    NetReader reader = reader_begin(data, size, NetShareMessage::put_request, id);
    *file_size = net_wire_get_u64(&reader);
    *mtime = net_wire_get_u64(&reader);
    *flags = net_wire_get_u8(&reader);
    if ((*flags | NET_SHARE_PUT_REPLACE) != NET_SHARE_PUT_REPLACE)
    {
        reader.ok = false;   // flags from a newer version: refused rather than half understood
    }
    net_wire_get_text(&reader, path);
    return net_wire_done(&reader);
}

size_t net_share_write_put_ready(uint8_t* out, size_t capacity, uint32_t id, NetShareStatus status, uint64_t offset)
{
    NetWriter writer = writer_begin(out, capacity, NetShareMessage::put_ready, id);
    net_wire_put_u8(&writer, static_cast<uint8_t>(status));
    net_wire_put_u64(&writer, offset);
    return writer_end(&writer);
}

bool net_share_read_put_ready(const uint8_t* data, size_t size, uint32_t* id, NetShareStatus* status,
                              uint64_t* offset)
{
    NetReader reader = reader_begin(data, size, NetShareMessage::put_ready, id);
    read_status(&reader, status);
    *offset = net_wire_get_u64(&reader);
    return net_wire_done(&reader);
}

// ---------------------------------------------------------------------------
// The file's bytes
// ---------------------------------------------------------------------------

size_t net_share_write_chunk(uint8_t* out, size_t capacity, uint32_t id, uint64_t offset, const uint8_t* bytes,
                             size_t count)
{
    if (count == 0 || count > NET_SHARE_CHUNK)
    {
        return 0;
    }
    NetWriter writer = writer_begin(out, capacity, NetShareMessage::chunk, id);
    net_wire_put_u64(&writer, offset);
    if (!writer.ok || !net_wire_room(&writer, count))
    {
        return 0;
    }
    std::memcpy(out + writer.size, bytes, count);
    return writer.size + count;
}

bool net_share_read_chunk(const uint8_t* data, size_t size, uint32_t* id, uint64_t* offset, const uint8_t** bytes,
                          size_t* count)
{
    NetReader reader = reader_begin(data, size, NetShareMessage::chunk, id);
    *offset = net_wire_get_u64(&reader);
    if (!reader.ok || reader.at != NET_SHARE_CHUNK_HEADER)
    {
        return false;
    }
    size_t left = size - reader.at;
    if (left == 0 || left > NET_SHARE_CHUNK)
    {
        return false;
    }
    *bytes = data + reader.at;
    *count = left;
    return true;
}

size_t net_share_write_progress(uint8_t* out, size_t capacity, uint32_t id, uint64_t received)
{
    NetWriter writer = writer_begin(out, capacity, NetShareMessage::progress, id);
    net_wire_put_u64(&writer, received);
    return writer_end(&writer);
}

bool net_share_read_progress(const uint8_t* data, size_t size, uint32_t* id, uint64_t* received)
{
    NetReader reader = reader_begin(data, size, NetShareMessage::progress, id);
    *received = net_wire_get_u64(&reader);
    return net_wire_done(&reader);
}

size_t net_share_write_end(uint8_t* out, size_t capacity, uint32_t id, const uint8_t* hash)
{
    NetWriter writer = writer_begin(out, capacity, NetShareMessage::end, id);
    if (!writer.ok || !net_wire_room(&writer, NET_SHARE_HASH_SIZE))
    {
        return 0;
    }
    std::memcpy(out + writer.size, hash, NET_SHARE_HASH_SIZE);
    return writer.size + NET_SHARE_HASH_SIZE;
}

bool net_share_read_end(const uint8_t* data, size_t size, uint32_t* id, uint8_t* hash)
{
    NetReader reader = reader_begin(data, size, NetShareMessage::end, id);
    if (!reader.ok || !net_wire_has(&reader, NET_SHARE_HASH_SIZE))
    {
        return false;
    }
    std::memcpy(hash, data + reader.at, NET_SHARE_HASH_SIZE);
    reader.at += NET_SHARE_HASH_SIZE;
    return net_wire_done(&reader);
}

size_t net_share_write_result(uint8_t* out, size_t capacity, uint32_t id, NetShareStatus status)
{
    NetWriter writer = writer_begin(out, capacity, NetShareMessage::result, id);
    net_wire_put_u8(&writer, static_cast<uint8_t>(status));
    return writer_end(&writer);
}

bool net_share_read_result(const uint8_t* data, size_t size, uint32_t* id, NetShareStatus* status)
{
    NetReader reader = reader_begin(data, size, NetShareMessage::result, id);
    read_status(&reader, status);
    return net_wire_done(&reader);
}

size_t net_share_write_cancel(uint8_t* out, size_t capacity, uint32_t id)
{
    NetWriter writer = writer_begin(out, capacity, NetShareMessage::cancel, id);
    return writer_end(&writer);
}

bool net_share_read_cancel(const uint8_t* data, size_t size, uint32_t* id)
{
    NetReader reader = reader_begin(data, size, NetShareMessage::cancel, id);
    return net_wire_done(&reader);
}
