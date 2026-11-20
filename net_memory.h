#pragma once

// ENet's memory, from size classes that are reused: STYLE.md says the frame
// loop never allocates, and ENet allocates for every packet sent and received
// (the packet, its data, its commands). Installed by net_init() through
// enet_initialize_with_callbacks.
//
// Each request is rounded up to a class (64, 128, 256, 512, 1536, 4096 bytes:
// ENet's structures, one MTU, a fragment or a few); a freed block goes back to
// its class's free list. New blocks come from the system only while the free
// lists are still filling (the first frames, or a burst bigger than any
// before); after that the loop reuses them. A request above the largest class
// (a big control message, ENet's peer array) goes to malloc as before: those
// are rare and not per frame.
//
// Blocks are kept until net_memory_release (at net_shutdown). ENet may run
// on more than one thread at once (net_service / net_client_service poll on
// their own, a client's discovery host on the main thread, a test's host and
// client in one process): the free lists are global, so one mutex guards
// them (taken for a few instructions; uncontended it costs next to nothing).

#include <cstddef>
#include <cstdint>

struct NetMemoryStats
{
    uint64_t system_allocations = 0;   // blocks taken from the system (classes and large)
    uint64_t reused = 0;               // requests served from a free list
    uint64_t large = 0;                // requests above the largest class
    uint64_t in_use = 0;               // blocks handed out and not freed yet
};

void* net_memory_alloc(size_t size);
void  net_memory_free(void* memory);

// Frees every block kept in the free lists (none may be in use).
void net_memory_release();

NetMemoryStats net_memory_stats();
