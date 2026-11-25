#include "net_share_host.h"

#include "host_log.h"
#include "net_link.h"

void net_share_host_start(NetShareHost* share)
{
    share->out.assign(NET_LINK_MAX_PAYLOAD, 0);
    for (uint32_t i = 0; i < NET_SHARE_HOST_MAX_COPIES; i++)
    {
        net_share_engine_start(&share->copies[i].engine);
        share->copies[i].peer = NET_NO_PEER;
    }
    share->started = true;
}

void net_share_host_stop(NetShareHost* share)
{
    if (share->started)
    {
        for (uint32_t i = 0; i < NET_SHARE_HOST_MAX_COPIES; i++)
        {
            net_share_engine_stop(&share->copies[i].engine);
            share->copies[i].peer = NET_NO_PEER;
        }
        share->started = false;
    }
}

void net_share_host_set_folders(NetShareHost* share, const NetShareFolderPaths* paths)
{
    net_share_set_folders(&share->folders, paths);
}

static void send_control(NetShareHost* share, NetAccess* access, uint32_t peer, size_t size)
{
    if (size > 0)
    {
        net_access_send(access, peer, NetChannel::control, share->out.data(), size);
    }
}

// The copy `peer` runs (or nullptr).
static NetShareHostCopy* copy_of(NetShareHost* share, uint32_t peer)
{
    for (uint32_t i = 0; i < NET_SHARE_HOST_MAX_COPIES; i++)
    {
        if (share->copies[i].peer == peer && peer != NET_NO_PEER)
        {
            return &share->copies[i];
        }
    }
    return nullptr;
}

// An engine for a new copy of `peer`: its own if that one finished (cleared
// now), else a free one. nullptr = busy (its copy still runs, or all are taken).
static NetShareHostCopy* copy_for(NetShareHost* share, uint32_t peer)
{
    NetShareHostCopy* own = copy_of(share, peer);
    if (own != nullptr)
    {
        if (!net_share_engine_clear(&own->engine))
        {
            return nullptr;
        }
        own->peer = NET_NO_PEER;
        return own;
    }
    for (uint32_t i = 0; i < NET_SHARE_HOST_MAX_COPIES; i++)
    {
        NetShareHostCopy* copy = &share->copies[i];
        if (copy->peer == NET_NO_PEER && net_share_engine_clear(&copy->engine))
        {
            return copy;
        }
    }
    return nullptr;
}

static void handle_get(NetShareHost* share, NetAccess* access, const NetAccessEvent* event)
{
    uint32_t id = 0;
    uint64_t offset = 0;
    std::string path;
    if (!net_share_read_get_request(event->data, event->size, &id, &offset, &path))
    {
        return;
    }
    std::string real_path;
    uint64_t file_size = 0;
    uint64_t mtime = 0;
    NetShareStatus status = NetShareStatus::busy;
    NetShareHostCopy* copy = copy_for(share, event->peer);
    if (copy != nullptr)
    {
        status = net_share_resolve_get(&share->folders, path.c_str(), &real_path, &file_size, &mtime);
        if (status == NetShareStatus::ok && offset > file_size)
        {
            status = NetShareStatus::refused;   // more than the file has: not a part of it
        }
        if (status == NetShareStatus::ok &&
            !net_share_engine_send(&copy->engine, id, real_path.c_str(), file_size, offset))
        {
            status = NetShareStatus::busy;
        }
    }
    if (status == NetShareStatus::ok)
    {
        copy->peer = event->peer;
        host_log(LogLevel::info, "Network: share: sending %s", path.c_str());
    }
    send_control(share, access, event->peer,
                 net_share_write_get_ready(share->out.data(), share->out.size(), id, status, file_size, mtime));
}

static void handle_put(NetShareHost* share, NetAccess* access, const NetAccessEvent* event)
{
    uint32_t id = 0;
    uint64_t file_size = 0;
    uint64_t mtime = 0;
    uint8_t flags = 0;
    std::string path;
    if (!net_share_read_put_request(event->data, event->size, &id, &file_size, &mtime, &flags, &path))
    {
        return;
    }
    std::string target;
    std::string part;
    uint64_t offset = 0;
    NetShareStatus status = NetShareStatus::busy;
    NetShareHostCopy* copy = copy_for(share, event->peer);
    if (copy != nullptr)
    {
        status = net_share_begin_put(&share->folders, path.c_str(), file_size, mtime, flags, &target, &part, &offset);
        if (status == NetShareStatus::ok &&
            !net_share_engine_receive(&copy->engine, id, part.c_str(), target.c_str(), file_size, mtime, offset))
        {
            status = NetShareStatus::busy;
        }
    }
    if (status == NetShareStatus::ok)
    {
        copy->peer = event->peer;
        host_log(LogLevel::info, "Network: share: receiving %s", path.c_str());
    }
    send_control(share, access, event->peer,
                 net_share_write_put_ready(share->out.data(), share->out.size(), id, status, offset));
}

// What arrives for a copy: to the one its peer runs.
static void handle_copy(NetShareHost* share, NetAccess* access, const NetAccessEvent* event)
{
    NetShareHostCopy* copy = copy_of(share, event->peer);
    if (copy == nullptr)
    {
        return;
    }
    NetShareEngine* engine = &copy->engine;
    uint8_t type = event->data[0];
    uint32_t id = 0;
    bool broken = false;
    if (type == static_cast<uint8_t>(NetShareMessage::chunk))
    {
        uint64_t offset = 0;
        const uint8_t* bytes = nullptr;
        size_t count = 0;
        broken = !net_share_read_chunk(event->data, event->size, &id, &offset, &bytes, &count) ||
                 !net_share_engine_on_chunk(engine, id, offset, bytes, count);
    }
    else if (type == static_cast<uint8_t>(NetShareMessage::progress))
    {
        uint64_t received = 0;
        broken = !net_share_read_progress(event->data, event->size, &id, &received) ||
                 !net_share_engine_on_progress(engine, id, received);
    }
    else if (type == static_cast<uint8_t>(NetShareMessage::end))
    {
        uint8_t hash[NET_SHARE_HASH_SIZE];
        broken = !net_share_read_end(event->data, event->size, &id, hash) ||
                 !net_share_engine_on_end(engine, id, hash);
    }
    else if (type == static_cast<uint8_t>(NetShareMessage::result))
    {
        NetShareStatus status = NetShareStatus::failed;
        broken = !net_share_read_result(event->data, event->size, &id, &status) ||
                 !net_share_engine_on_result(engine, id, status);
    }
    else if (type == static_cast<uint8_t>(NetShareMessage::cancel))
    {
        if (net_share_read_cancel(event->data, event->size, &id))
        {
            NetShareProgress progress;
            net_share_engine_progress(engine, &progress);
            if (progress.id == id)
            {
                net_share_engine_cancel(engine);
            }
        }
    }
    if (broken)
    {
        // Not this copy's (late, after a cancel), or the device broke the
        // protocol: the engine already failed the copy in the second case.
        NetShareProgress progress;
        net_share_engine_progress(engine, &progress);
        if (progress.finished && progress.status == NetShareStatus::failed && progress.id == id)
        {
            send_control(share, access, event->peer, net_share_write_cancel(share->out.data(), share->out.size(), id));
            net_share_engine_cancel(engine);
        }
    }
}

bool net_share_host_handle(NetShareHost* share, NetAccess* access, const NetAccessEvent* event)
{
    if (event->type != NetAccessEventType::message || event->size == 0 ||
        event->data[0] < static_cast<uint8_t>(NetShareMessage::list_request) ||
        event->data[0] > static_cast<uint8_t>(NetShareMessage::cancel))
    {
        return false;
    }
    if (!share->started)
    {
        return true;   // ours, but not running: dropped
    }
    switch (static_cast<NetShareMessage>(event->data[0]))
    {
    case NetShareMessage::list_request:
        send_control(share, access, event->peer,
                     net_share_answer_list(&share->folders, event->data, event->size, share->out.data(),
                                           share->out.size()));
        break;
    case NetShareMessage::get_request:
        handle_get(share, access, event);
        break;
    case NetShareMessage::put_request:
        handle_put(share, access, event);
        break;
    default:
        handle_copy(share, access, event);
        break;
    }
    return true;
}

static void pump_copy(NetShareHost* share, NetShareHostCopy* copy, NetAccess* access, bool streaming)
{
    for (;;)
    {
        bool may_send = !streaming && net_access_peer_pending(access, copy->peer) < NET_SHARE_HOST_PENDING;
        size_t size = net_share_engine_take(&copy->engine, may_send, share->out.data(), share->out.size());
        if (size == 0)
        {
            break;
        }
        NetChannel channel = share->out[0] == static_cast<uint8_t>(NetShareMessage::chunk) ? NetChannel::files
                                                                                          : NetChannel::control;
        if (!net_access_send(access, copy->peer, channel, share->out.data(), size))
        {
            // The device can't take files (an older build with three
            // channels, or it lost FILE TRANSFER): the copy can't go on.
            net_share_engine_cancel(&copy->engine);
            break;
        }
    }
    NetShareProgress progress;
    net_share_engine_progress(&copy->engine, &progress);
    if (progress.finished && net_share_engine_clear(&copy->engine))
    {
        host_log(LogLevel::info, "Network: share: copy %u finished (status %u)", progress.id,
                 static_cast<unsigned>(progress.status));
        copy->peer = NET_NO_PEER;
    }
}

void net_share_host_pump(NetShareHost* share, NetAccess* access, bool streaming)
{
    if (!share->started)
    {
        return;
    }
    for (uint32_t i = 0; i < NET_SHARE_HOST_MAX_COPIES; i++)
    {
        if (share->copies[i].peer != NET_NO_PEER)
        {
            pump_copy(share, &share->copies[i], access, streaming);
        }
    }
}

void net_share_host_peer_closed(NetShareHost* share, uint32_t peer)
{
    NetShareHostCopy* copy = share->started ? copy_of(share, peer) : nullptr;
    if (copy != nullptr)
    {
        net_share_engine_cancel(&copy->engine);
    }
}

void net_share_host_progress(NetShareHost* share, uint32_t peer, NetShareProgress* progress)
{
    *progress = {};
    NetShareHostCopy* copy = copy_of(share, peer);
    if (copy != nullptr)
    {
        net_share_engine_progress(&copy->engine, progress);
    }
}
