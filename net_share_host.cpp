#include "net_share_host.h"

#include "host_log.h"
#include "net_link.h"

void net_share_host_start(NetShareHost* share)
{
    share->out.assign(NET_LINK_MAX_PAYLOAD, 0);
    net_share_engine_start(&share->engine);
    share->started = true;
}

void net_share_host_stop(NetShareHost* share)
{
    if (share->started)
    {
        net_share_engine_stop(&share->engine);
        share->started = false;
    }
}

void net_share_host_set_folders(NetShareHost* share, const std::vector<std::string>* game_paths,
                                const char* saves_path, const char* states_path)
{
    net_share_set_folders(&share->folders, game_paths, saves_path, states_path);
}

static void send_control(NetShareHost* share, NetAccess* access, uint32_t peer, size_t size)
{
    if (size > 0)
    {
        net_access_send(access, peer, NetChannel::control, share->out.data(), size);
    }
}

// A copy can begin: none runs (or the last one is cleared).
static bool engine_free(NetShareHost* share)
{
    if (!net_share_engine_clear(&share->engine))
    {
        return false;
    }
    share->peer = NET_NO_PEER;
    return true;
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
    if (engine_free(share))
    {
        status = net_share_resolve_get(&share->folders, path.c_str(), &real_path, &file_size, &mtime);
        if (status == NetShareStatus::ok && offset > file_size)
        {
            status = NetShareStatus::refused;   // more than the file has: not a part of it
        }
        if (status == NetShareStatus::ok &&
            !net_share_engine_send(&share->engine, id, real_path.c_str(), file_size, offset))
        {
            status = NetShareStatus::busy;
        }
    }
    if (status == NetShareStatus::ok)
    {
        share->peer = event->peer;
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
    if (engine_free(share))
    {
        status = net_share_begin_put(&share->folders, path.c_str(), file_size, flags, &target, &part, &offset);
        if (status == NetShareStatus::ok &&
            !net_share_engine_receive(&share->engine, id, part.c_str(), target.c_str(), file_size, mtime, offset))
        {
            status = NetShareStatus::busy;
        }
    }
    if (status == NetShareStatus::ok)
    {
        share->peer = event->peer;
        host_log(LogLevel::info, "Network: share: receiving %s", path.c_str());
    }
    send_control(share, access, event->peer,
                 net_share_write_put_ready(share->out.data(), share->out.size(), id, status, offset));
}

// What arrives for the copy running: only from its peer.
static void handle_copy(NetShareHost* share, NetAccess* access, const NetAccessEvent* event)
{
    if (event->peer != share->peer)
    {
        return;
    }
    uint8_t type = event->data[0];
    uint32_t id = 0;
    bool broken = false;
    if (type == static_cast<uint8_t>(NetShareMessage::chunk))
    {
        uint64_t offset = 0;
        const uint8_t* bytes = nullptr;
        size_t count = 0;
        broken = !net_share_read_chunk(event->data, event->size, &id, &offset, &bytes, &count) ||
                 !net_share_engine_on_chunk(&share->engine, id, offset, bytes, count);
    }
    else if (type == static_cast<uint8_t>(NetShareMessage::progress))
    {
        uint64_t received = 0;
        broken = !net_share_read_progress(event->data, event->size, &id, &received) ||
                 !net_share_engine_on_progress(&share->engine, id, received);
    }
    else if (type == static_cast<uint8_t>(NetShareMessage::end))
    {
        uint8_t hash[NET_SHARE_HASH_SIZE];
        broken = !net_share_read_end(event->data, event->size, &id, hash) ||
                 !net_share_engine_on_end(&share->engine, id, hash);
    }
    else if (type == static_cast<uint8_t>(NetShareMessage::result))
    {
        NetShareStatus status = NetShareStatus::failed;
        broken = !net_share_read_result(event->data, event->size, &id, &status) ||
                 !net_share_engine_on_result(&share->engine, id, status);
    }
    else if (type == static_cast<uint8_t>(NetShareMessage::cancel))
    {
        if (net_share_read_cancel(event->data, event->size, &id))
        {
            NetShareProgress progress;
            net_share_engine_progress(&share->engine, &progress);
            if (progress.id == id)
            {
                net_share_engine_cancel(&share->engine);
            }
        }
    }
    if (broken)
    {
        // Not this copy's (late, after a cancel), or the device broke the
        // protocol: the engine already failed the copy in the second case.
        NetShareProgress progress;
        net_share_engine_progress(&share->engine, &progress);
        if (progress.finished && progress.status == NetShareStatus::failed && progress.id == id)
        {
            send_control(share, access, event->peer, net_share_write_cancel(share->out.data(), share->out.size(), id));
            net_share_engine_cancel(&share->engine);
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

void net_share_host_pump(NetShareHost* share, NetAccess* access, bool streaming)
{
    if (!share->started || share->peer == NET_NO_PEER)
    {
        return;
    }
    for (;;)
    {
        bool may_send = !streaming && net_access_peer_pending(access, share->peer) < NET_SHARE_HOST_PENDING;
        size_t size = net_share_engine_take(&share->engine, may_send, share->out.data(), share->out.size());
        if (size == 0)
        {
            break;
        }
        NetChannel channel = share->out[0] == static_cast<uint8_t>(NetShareMessage::chunk) ? NetChannel::files
                                                                                          : NetChannel::control;
        if (!net_access_send(access, share->peer, channel, share->out.data(), size))
        {
            // The device can't take files (an older build with three
            // channels): the copy can't go on.
            net_share_engine_cancel(&share->engine);
            break;
        }
    }
    NetShareProgress progress;
    net_share_engine_progress(&share->engine, &progress);
    if (progress.finished && net_share_engine_clear(&share->engine))
    {
        host_log(LogLevel::info, "Network: share: copy %u finished (status %u)", progress.id,
                 static_cast<unsigned>(progress.status));
        share->peer = NET_NO_PEER;
    }
}

void net_share_host_peer_closed(NetShareHost* share, uint32_t peer)
{
    if (share->started && share->peer == peer)
    {
        net_share_engine_cancel(&share->engine);
    }
}

void net_share_host_progress(NetShareHost* share, NetShareProgress* progress)
{
    net_share_engine_progress(&share->engine, progress);
}
