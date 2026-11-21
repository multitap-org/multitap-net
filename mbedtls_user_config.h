#pragma once

// Additions to Mbed TLS's default configuration (include/mbedtls/mbedtls_config.h),
// for libdatachannel (WebRTC on Android: CMakeLists.txt, MULTITAP_NET_RTC_MBEDTLS).
// Plain C preprocessor: Mbed TLS's C sources include it too.

// libdatachannel's DTLS transport sets its SRTP profiles even when built
// without media; harmless for data channels.
#define MBEDTLS_SSL_DTLS_SRTP
