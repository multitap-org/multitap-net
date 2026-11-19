#include "net_random.h"

#include <cstdio>

#include "host_log.h"

bool net_random_bytes(uint8_t* out, size_t size)
{
    std::FILE* file = std::fopen("/dev/urandom", "rb");
    if (file == nullptr)
    {
        host_log(LogLevel::error, "Network: can't open /dev/urandom");
        return false;
    }
    size_t got = std::fread(out, 1, size, file);
    std::fclose(file);
    if (got != size)
    {
        host_log(LogLevel::error, "Network: short read from /dev/urandom");
        return false;
    }
    return true;
}
