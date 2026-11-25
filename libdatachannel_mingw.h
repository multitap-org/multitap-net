// Forced into libdatachannel's C++ sources on MinGW (CMakeLists.txt).
//
// libstdc++'s std::shared_mutex on MinGW sits on winpthreads' rwlock, and its
// pthread_rwlock_wrlock sometimes returns EINVAL to a writer that should wait
// for a reader (every winpthreads tried, 2026-04 to 2026-11). libdatachannel's
// SctpTransport::Instances hits it when two connections overlap: in Debug the
// libstdc++ assertion aborts, in Release the error is ignored and the write
// goes in without the lock. This gives libdatachannel a std::shared_mutex on
// an SRWLOCK, Windows' own reader / writer lock. Drop it once winpthreads (or
// libdatachannel) is fixed: notes in piccolo-agents, notes/multitap-net.

#pragma once

#ifdef __MINGW32__

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// Every standard header that could name shared_mutex comes in before the
// macro below, so only libdatachannel's own code sees the rename.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class MultitapSharedMutex
{
public:
    MultitapSharedMutex() = default;
    MultitapSharedMutex(const MultitapSharedMutex&) = delete;
    MultitapSharedMutex& operator=(const MultitapSharedMutex&) = delete;

    void lock()
    {
        AcquireSRWLockExclusive(&srw);
    }

    bool try_lock()
    {
        return TryAcquireSRWLockExclusive(&srw) != 0;
    }

    void unlock()
    {
        ReleaseSRWLockExclusive(&srw);
    }

    void lock_shared()
    {
        AcquireSRWLockShared(&srw);
    }

    bool try_lock_shared()
    {
        return TryAcquireSRWLockShared(&srw) != 0;
    }

    void unlock_shared()
    {
        ReleaseSRWLockShared(&srw);
    }

private:
    SRWLOCK srw = SRWLOCK_INIT;
};

namespace std
{
using multitap_shared_mutex = ::MultitapSharedMutex;
}

#define shared_mutex multitap_shared_mutex

#endif
