#include "net_share_client.h"

#include <chrono>
#include <thread>

#include "host_log.h"

void net_share_client_start(NetShareClient* client, const NetShareFolders* local)
{
    client->local = local;
    net_share_engine_start(&client->engine);
    client->started = true;
}

void net_share_client_stop(NetShareClient* client)
{
    if (client->started)
    {
        net_share_engine_stop(&client->engine);
        client->started = false;
    }
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

void net_share_client_list(NetShareClient* client, const char* path)
{
    client->list_path = path;
    client->list_id = client->next_id++;
    client->list_next = 0;
    client->list_send = true;
    client->list_waiting = false;
    client->list_done = false;
    client->list_status = NetShareStatus::ok;
    client->list_entries.clear();
}

bool net_share_client_listing(const NetShareClient* client, std::string* path, NetShareStatus* status,
                              std::vector<NetShareEntry>* entries)
{
    if (!client->list_done)
    {
        return false;
    }
    *path = client->list_path;
    *status = client->list_status;
    *entries = client->list_entries;
    return true;
}

static void handle_list_result(NetShareClient* client, const uint8_t* data, size_t size)
{
    uint32_t id = 0;
    NetShareStatus status = NetShareStatus::failed;
    uint32_t start = 0;
    uint32_t total = 0;
    if (!net_share_read_list_result(data, size, &id, &status, &start, &total, &client->page) ||
        id != client->list_id || !client->list_waiting || start != client->list_next)
    {
        return;   // a page of a listing we've left
    }
    client->list_waiting = false;
    if (status != NetShareStatus::ok)
    {
        client->list_status = status;
        client->list_entries.clear();
        client->list_done = true;
        return;
    }
    for (size_t i = 0; i < client->page.size(); i++)
    {
        client->list_entries.push_back(client->page[i]);
    }
    uint32_t next = start + static_cast<uint32_t>(client->page.size());
    if (next < total && !client->page.empty())
    {
        client->list_next = next;
        client->list_send = true;
    }
    else
    {
        client->list_done = true;
    }
}

// ---------------------------------------------------------------------------
// Copies
// ---------------------------------------------------------------------------

uint32_t net_share_client_copy(NetShareClient* client, bool to_remote, const char* local, const char* remote,
                               uint64_t size, uint8_t flags)
{
    NetShareClientCopy copy;
    copy.id = client->next_id++;
    copy.to_remote = to_remote;
    copy.local = local;
    copy.remote = remote;
    copy.size = size;
    copy.flags = flags;
    client->queue.push_back(copy);
    return copy.id;
}

static void finish_current(NetShareClient* client, NetShareStatus status)
{
    NetShareClientDone done;
    done.copy = client->current;
    done.status = status;
    client->done.push_back(done);
    client->step = NetShareClientStep::idle;
    client->request_due = false;
    host_log(LogLevel::info, "Network: share: %s %s: status %u", client->current.to_remote ? "put" : "get",
             client->current.remote.c_str(), static_cast<unsigned>(status));
}

// The next copy in the queue, checked on our side before anything is asked.
static void begin_next(NetShareClient* client)
{
    while (client->step == NetShareClientStep::idle && !client->queue.empty())
    {
        client->current = client->queue.front();
        client->queue.erase(client->queue.begin());
        NetShareStatus status = NetShareStatus::ok;
        if (client->local == nullptr)
        {
            status = NetShareStatus::failed;
        }
        else if (client->current.to_remote)
        {
            status = net_share_resolve_get(client->local, client->current.local.c_str(), &client->real,
                                           &client->put_size, &client->put_mtime);
        }
        else
        {
            status = net_share_begin_put(client->local, client->current.local.c_str(), client->current.size,
                                         client->current.flags, &client->target, &client->part, &client->offset);
        }
        if (status != NetShareStatus::ok)
        {
            finish_current(client, status);
            continue;
        }
        client->step = NetShareClientStep::asked;
        client->request_due = true;
    }
}

void net_share_client_cancel(NetShareClient* client)
{
    client->queue.clear();
    if (client->step == NetShareClientStep::asked)
    {
        client->cancel_due = !client->request_due;   // the host may have started already
        finish_current(client, NetShareStatus::failed);
    }
    else if (client->step == NetShareClientStep::copying)
    {
        client->cancel_due = true;
        net_share_engine_cancel(&client->engine);   // finished in take, once the engine lets go
    }
}

static void handle_get_ready(NetShareClient* client, const uint8_t* data, size_t size)
{
    uint32_t id = 0;
    NetShareStatus status = NetShareStatus::failed;
    uint64_t file_size = 0;
    uint64_t mtime = 0;
    if (!net_share_read_get_ready(data, size, &id, &status, &file_size, &mtime) ||
        client->step != NetShareClientStep::asked || client->current.to_remote || id != client->current.id)
    {
        return;
    }
    if (status == NetShareStatus::ok && client->offset > file_size)
    {
        status = NetShareStatus::failed;   // the file got shorter than our part: can't be its beginning
        client->cancel_due = true;
    }
    if (status == NetShareStatus::ok &&
        !net_share_engine_receive(&client->engine, id, client->part.c_str(), client->target.c_str(), file_size, mtime,
                                  client->offset))
    {
        status = NetShareStatus::failed;
        client->cancel_due = true;
    }
    if (status != NetShareStatus::ok)
    {
        finish_current(client, status);
        return;
    }
    client->step = NetShareClientStep::copying;
}

static void handle_put_ready(NetShareClient* client, const uint8_t* data, size_t size)
{
    uint32_t id = 0;
    NetShareStatus status = NetShareStatus::failed;
    uint64_t offset = 0;
    if (!net_share_read_put_ready(data, size, &id, &status, &offset) || client->step != NetShareClientStep::asked ||
        !client->current.to_remote || id != client->current.id)
    {
        return;
    }
    if (status == NetShareStatus::ok &&
        !net_share_engine_send(&client->engine, id, client->real.c_str(), client->put_size, offset))
    {
        status = NetShareStatus::failed;
        client->cancel_due = true;
    }
    if (status != NetShareStatus::ok)
    {
        finish_current(client, status);
        return;
    }
    client->step = NetShareClientStep::copying;
}

// What arrives for the copy running.
static void handle_copy(NetShareClient* client, const uint8_t* data, size_t size)
{
    if (client->step != NetShareClientStep::copying)
    {
        return;
    }
    uint8_t type = data[0];
    uint32_t id = 0;
    bool broken = false;
    if (type == static_cast<uint8_t>(NetShareMessage::chunk))
    {
        uint64_t offset = 0;
        const uint8_t* bytes = nullptr;
        size_t count = 0;
        broken = !net_share_read_chunk(data, size, &id, &offset, &bytes, &count) ||
                 !net_share_engine_on_chunk(&client->engine, id, offset, bytes, count);
    }
    else if (type == static_cast<uint8_t>(NetShareMessage::progress))
    {
        uint64_t received = 0;
        broken = !net_share_read_progress(data, size, &id, &received) ||
                 !net_share_engine_on_progress(&client->engine, id, received);
    }
    else if (type == static_cast<uint8_t>(NetShareMessage::end))
    {
        uint8_t hash[NET_SHARE_HASH_SIZE];
        broken = !net_share_read_end(data, size, &id, hash) || !net_share_engine_on_end(&client->engine, id, hash);
    }
    else if (type == static_cast<uint8_t>(NetShareMessage::result))
    {
        NetShareStatus status = NetShareStatus::failed;
        broken = !net_share_read_result(data, size, &id, &status) ||
                 !net_share_engine_on_result(&client->engine, id, status);
    }
    else if (type == static_cast<uint8_t>(NetShareMessage::cancel))
    {
        if (net_share_read_cancel(data, size, &id) && id == client->current.id)
        {
            net_share_engine_cancel(&client->engine);
        }
    }
    if (broken && id == client->current.id)
    {
        // The host broke the protocol: the engine failed the copy; tell it.
        client->cancel_due = true;
        net_share_engine_cancel(&client->engine);
    }
}

bool net_share_client_handle(NetShareClient* client, const uint8_t* data, size_t size)
{
    if (size == 0 || data[0] < static_cast<uint8_t>(NetShareMessage::list_request) ||
        data[0] > static_cast<uint8_t>(NetShareMessage::cancel))
    {
        return false;
    }
    if (!client->started)
    {
        return true;
    }
    switch (static_cast<NetShareMessage>(data[0]))
    {
    case NetShareMessage::list_result:
        handle_list_result(client, data, size);
        break;
    case NetShareMessage::get_ready:
        handle_get_ready(client, data, size);
        break;
    case NetShareMessage::put_ready:
        handle_put_ready(client, data, size);
        break;
    default:
        handle_copy(client, data, size);
        break;
    }
    return true;
}

size_t net_share_client_take(NetShareClient* client, bool may_send, uint8_t* out, size_t capacity,
                             NetChannel* channel)
{
    *channel = NetChannel::control;
    if (!client->started)
    {
        return 0;
    }
    if (client->cancel_due)
    {
        client->cancel_due = false;
        return net_share_write_cancel(out, capacity, client->current.id);
    }
    if (client->list_send)
    {
        client->list_send = false;
        client->list_waiting = true;
        return net_share_write_list_request(out, capacity, client->list_id, client->list_next,
                                            client->list_path.c_str());
    }
    begin_next(client);
    if (client->step == NetShareClientStep::asked && client->request_due)
    {
        client->request_due = false;
        if (client->current.to_remote)
        {
            return net_share_write_put_request(out, capacity, client->current.id, client->put_size, client->put_mtime,
                                               client->current.flags, client->current.remote.c_str());
        }
        return net_share_write_get_request(out, capacity, client->current.id, client->offset,
                                           client->current.remote.c_str());
    }
    if (client->step != NetShareClientStep::copying)
    {
        return 0;
    }
    size_t size = net_share_engine_take(&client->engine, may_send, out, capacity);
    if (size > 0)
    {
        if (out[0] == static_cast<uint8_t>(NetShareMessage::chunk))
        {
            *channel = NetChannel::files;
        }
        return size;
    }
    NetShareProgress progress;
    net_share_engine_progress(&client->engine, &progress);
    if (progress.finished && net_share_engine_clear(&client->engine))
    {
        finish_current(client, progress.status);
        return net_share_client_take(client, may_send, out, capacity, channel);   // the next copy may start now
    }
    return 0;
}

void net_share_client_progress(NetShareClient* client, NetShareProgress* progress, NetShareClientCopy* copy,
                               uint32_t* queued)
{
    net_share_engine_progress(&client->engine, progress);
    if (client->step == NetShareClientStep::asked)
    {
        progress->role = client->current.to_remote ? NetShareRole::sender : NetShareRole::receiver;
        progress->id = client->current.id;
        progress->size = client->current.to_remote ? client->put_size : client->current.size;
        progress->done = client->current.to_remote ? 0 : client->offset;
    }
    *copy = client->current;
    *queued = static_cast<uint32_t>(client->queue.size());
    if (client->step == NetShareClientStep::idle)
    {
        progress->role = NetShareRole::none;
    }
}

void net_share_client_disconnected(NetShareClient* client)
{
    client->queue.clear();
    client->list_send = false;
    client->list_waiting = false;
    client->list_done = false;
    client->cancel_due = false;
    if (client->step == NetShareClientStep::copying)
    {
        net_share_engine_cancel(&client->engine);
        // The worker closes the file: short, but wait for it so the next
        // connection starts clean.
        for (int i = 0; i < 5000 && !net_share_engine_clear(&client->engine); i++)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    if (client->step != NetShareClientStep::idle)
    {
        finish_current(client, NetShareStatus::failed);
    }
}
