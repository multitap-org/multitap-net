#pragma once

// The host's side of piccolo-share (net_share.h), on the network thread
// (net_service): answers SHARE devices' listings, gets and puts from its
// shared folders (net_share_folders.h) and runs the copy with one
// NetShareEngine. One copy at a time; a device asking while another copy
// runs gets `busy` and asks again.
//
// Transport: requests and answers on the control channel, chunks on the
// files channel. Chunks leave only while little is in flight on the
// connection (NET_SHARE_HOST_PENDING) and nobody plays remotely (remote play
// first: piccolo-netcode, a full reliable queue makes ENet drop stream
// packets); the copy waits meanwhile.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "net_access.h"
#include "net_share_engine.h"
#include "net_share_folders.h"

constexpr size_t NET_SHARE_HOST_PENDING = 128 * 1024;   // bytes in flight past which chunks wait

struct NetShareHost
{
    NetShareFolders      folders;
    NetShareEngine       engine;
    uint32_t             peer = NET_NO_PEER;   // whose copy runs
    std::vector<uint8_t> out;                  // messages we write (NET_LINK_MAX_PAYLOAD)
    bool                 started = false;
};

void net_share_host_start(NetShareHost* share);
void net_share_host_stop(NetShareHost* share);

// The shared folders (the frontend's settings). A copy running isn't stopped.
void net_share_host_set_folders(NetShareHost* share, const std::vector<std::string>* game_paths,
                                const char* saves_path, const char* states_path);

// A message from an authorized peer: true if it was piccolo-share's (handled
// here, not for the frontend). NetAccess already dropped what a device below
// SHARE sent.
bool net_share_host_handle(NetShareHost* share, NetAccess* access, const NetAccessEvent* event);

// After each poll: what the copy has to send, paced as above; a finished copy
// is cleared for the next one.
void net_share_host_pump(NetShareHost* share, NetAccess* access, bool streaming);

// The peer left: its copy stops (a put keeps its part file to resume).
void net_share_host_peer_closed(NetShareHost* share, uint32_t peer);

// For the frontend (SETTINGS > NETWORK could show it): the copy running.
void net_share_host_progress(NetShareHost* share, NetShareProgress* progress);
