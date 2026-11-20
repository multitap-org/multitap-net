// net_rtc.h for builds without WebRTC (no deps/libdatachannel, or
// MULTITAP_NET_RTC=OFF): ENet only. Nothing connects, nothing is reported.

#include "net_rtc.h"

bool net_rtc_available()
{
    return false;
}

NetRtc* net_rtc_create(const char* stun)
{
    (void)stun;
    return nullptr;
}

void net_rtc_destroy(NetRtc* rtc)
{
    (void)rtc;
}

bool net_rtc_connect(NetRtc* rtc, uint32_t* index)
{
    (void)rtc;
    (void)index;
    return false;
}

bool net_rtc_accept(NetRtc* rtc, uint32_t* index)
{
    (void)rtc;
    (void)index;
    return false;
}

bool net_rtc_signal(NetRtc* rtc, uint32_t index, const uint8_t* data, size_t size)
{
    (void)rtc;
    (void)index;
    (void)data;
    (void)size;
    return false;
}

bool net_rtc_poll(NetRtc* rtc, NetRtcEvent* event, double now)
{
    (void)rtc;
    (void)now;
    *event = {};
    return false;
}

bool net_rtc_send(NetRtc* rtc, uint32_t index, NetChannel channel, const uint8_t* data, size_t size)
{
    (void)rtc;
    (void)index;
    (void)channel;
    (void)data;
    (void)size;
    return false;
}

bool net_rtc_connected(const NetRtc* rtc, uint32_t index)
{
    (void)rtc;
    (void)index;
    return false;
}

void net_rtc_close(NetRtc* rtc, uint32_t index)
{
    (void)rtc;
    (void)index;
}

size_t net_rtc_buffered(const NetRtc* rtc, uint32_t index, NetChannel channel)
{
    (void)rtc;
    (void)index;
    (void)channel;
    return 0;
}
