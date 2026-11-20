#include "net_memory.h"

#include <cstdlib>
#include <mutex>

#include "host_log.h"

static constexpr size_t CLASS_SIZES[] = {64, 128, 256, 512, 1536, 4096};
static constexpr uint32_t CLASS_COUNT = sizeof(CLASS_SIZES) / sizeof(CLASS_SIZES[0]);
static constexpr uint32_t LARGE = CLASS_COUNT;   // the header's class for malloc'd blocks

// Every block starts with this header, so free() knows where it goes. 16
// bytes keep the memory after it aligned like malloc's. The link shares 8
// bytes with a uint64_t so the size is the same on 32-bit machines (armv7:
// the Android 5 APK), where a pointer is 4 bytes.
struct BlockHeader
{
    uint32_t size_class = 0;
    uint32_t unused = 0;
    union
    {
        BlockHeader* next = nullptr;   // in a free list
        uint64_t     next_space;
    };
};
static_assert(sizeof(BlockHeader) == 16, "the header keeps 16-byte alignment");

// ENet's allocator callbacks carry no userdata, so the free lists live here
// (one set for the process, like ENet's own global setup).
static BlockHeader*   g_free[CLASS_COUNT] = {};
static NetMemoryStats g_stats;
static std::mutex     g_lock;   // guards g_free and g_stats (see the header)

static uint32_t class_for(size_t size)
{
    for (uint32_t i = 0; i < CLASS_COUNT; i++)
    {
        if (size <= CLASS_SIZES[i])
        {
            return i;
        }
    }
    return LARGE;
}

static void* block_memory(BlockHeader* header)
{
    return header + 1;
}

void* net_memory_alloc(size_t size)
{
    uint32_t size_class = class_for(size);
    BlockHeader* header = nullptr;
    g_lock.lock();
    if (size_class != LARGE && g_free[size_class] != nullptr)
    {
        header = g_free[size_class];
        g_free[size_class] = header->next;
        g_stats.reused++;
        g_stats.in_use++;
    }
    g_lock.unlock();
    if (header == nullptr)
    {
        size_t bytes = sizeof(BlockHeader) + (size_class == LARGE ? size : CLASS_SIZES[size_class]);
        header = static_cast<BlockHeader*>(std::malloc(bytes));
        if (header == nullptr)
        {
            return nullptr;   // ENet calls its no_memory callback
        }
        g_lock.lock();
        g_stats.system_allocations++;
        if (size_class == LARGE)
        {
            g_stats.large++;
        }
        g_stats.in_use++;
        g_lock.unlock();
    }
    header->size_class = size_class;
    header->next = nullptr;
    return block_memory(header);
}

void net_memory_free(void* memory)
{
    if (memory == nullptr)
    {
        return;
    }
    BlockHeader* header = static_cast<BlockHeader*>(memory) - 1;
    g_lock.lock();
    g_stats.in_use--;
    bool large = header->size_class == LARGE;
    if (!large)
    {
        header->next = g_free[header->size_class];
        g_free[header->size_class] = header;
    }
    g_lock.unlock();
    if (large)
    {
        std::free(header);
    }
}

void net_memory_release()
{
    std::lock_guard<std::mutex> guard(g_lock);
    if (g_stats.in_use != 0)
    {
        host_log(LogLevel::warning, "Network: %llu ENet blocks still in use at shutdown",
                 static_cast<unsigned long long>(g_stats.in_use));
    }
    for (uint32_t i = 0; i < CLASS_COUNT; i++)
    {
        while (g_free[i] != nullptr)
        {
            BlockHeader* next = g_free[i]->next;
            std::free(g_free[i]);
            g_free[i] = next;
        }
    }
}

NetMemoryStats net_memory_stats()
{
    std::lock_guard<std::mutex> guard(g_lock);
    return g_stats;
}
