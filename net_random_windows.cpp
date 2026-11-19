#include "net_random.h"

#include <windows.h>
#include <bcrypt.h>

#include "host_log.h"

bool net_random_bytes(uint8_t* out, size_t size)
{
    // The system's preferred generator (no algorithm handle needed). It takes
    // a ULONG size: larger requests go in pieces.
    while (size > 0)
    {
        ULONG piece = size > 0x10000000u ? 0x10000000u : static_cast<ULONG>(size);
        if (BCryptGenRandom(nullptr, out, piece, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        {
            host_log(LogLevel::error, "Network: BCryptGenRandom failed");
            return false;
        }
        out += piece;
        size -= piece;
    }
    return true;
}
