# multitap-net: Multitap's network core. One UDP port (ENet + LAN discovery),
# encrypted links (Noise XX), pairing (CPace), trust and access levels, guest
# links, the beacon (across the internet), WebRTC data channels, SHARE (files
# between devices). No GUI: no SDL, ImGui or Vulkan. What a frontend adds on
# top (remote play, remote pads, the service threads) is in frontends-common's
# frontend_net.
#
# Two ways to build it:
# - As a library (piccolo, piccoletto, piccolino): the program adds
#   hosts-common first, sets MULTITAP_DEPS_DIR to its deps folder (enet,
#   monocypher, beacon; optionally libdatachannel and mbedtls), then adds this
#   folder. Third-party code is built here from those sources.
# - On its own (its CI, or to work on it): cmake -S . -B build. It then uses
#   its own deps/ (git submodule update --init --checkout).

cmake_minimum_required(VERSION 3.25)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(multitap_net LANGUAGES C CXX)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    option(MULTITAP_WARNINGS_AS_ERRORS "Treat warnings in our own code as errors" OFF)
    option(MULTITAP_SANITIZE           "Build our own code with ASan + UBSan"      OFF)
    option(MULTITAP_BUILD_TESTS        "Build tests and register CTest tests"      ON)
    if(MULTITAP_BUILD_TESTS)
        enable_testing()
    endif()
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/hosts-common/CMakeLists.txt")
        message(FATAL_ERROR "deps/ is empty. Run: git submodule update --init --checkout")
    endif()
    set(MULTITAP_DEPS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps")
    add_subdirectory(deps/hosts-common)
    set(MULTITAP_NET_TOP_LEVEL ON)
else()
    set(MULTITAP_NET_TOP_LEVEL OFF)
endif()

multitap_require(multitap-net host_common VAR:MULTITAP_DEPS_DIR)

# ENet (deps/enet, MIT): connections over UDP. zpl-c's ENet (a maintained
# fork of lsalzman's with IPv6: one dual-stack socket, IPv4 addresses as
# ::ffff:a.b.c.d), a single header. Its code is compiled once, in net_enet.c,
# with ENET_IMPLEMENTATION set here and without our warning flags.
set(MULTITAP_ENET "${MULTITAP_DEPS_DIR}/enet")
if(EXISTS "${MULTITAP_ENET}/host.c")
    message(FATAL_ERROR "deps/enet is lsalzman's ENet: multitap-net needs zpl-c's (https://github.com/zpl-c/enet, v2.7.0)")
elseif(NOT EXISTS "${MULTITAP_ENET}/include/enet.h")
    message(FATAL_ERROR "multitap-net needs deps/enet (zpl-c's ENet, https://github.com/zpl-c/enet, v2.7.0)")
endif()
add_library(multitap_dep_enet STATIC "${CMAKE_CURRENT_SOURCE_DIR}/net_enet.c")
target_include_directories(multitap_dep_enet SYSTEM PUBLIC "${MULTITAP_ENET}/include")
target_compile_definitions(multitap_dep_enet PRIVATE ENET_IMPLEMENTATION)
if(WIN32)
    target_link_libraries(multitap_dep_enet PUBLIC ws2_32 winmm)
endif()

# Monocypher (deps/monocypher, BSD-2-Clause or CC0): X25519, ChaCha20-Poly1305
# and BLAKE2b for the Noise handshake; optional/ adds SHA-512, for CPace
# (pairing). One C file each; built without our warning flags, optimized even
# in Debug builds: handshakes and every packet go through it.
set(MULTITAP_MONOCYPHER "${MULTITAP_DEPS_DIR}/monocypher")
if(NOT EXISTS "${MULTITAP_MONOCYPHER}/src/monocypher.c")
    message(FATAL_ERROR "multitap-net needs deps/monocypher")
endif()
add_library(multitap_dep_monocypher STATIC "${MULTITAP_MONOCYPHER}/src/monocypher.c"
            "${MULTITAP_MONOCYPHER}/src/optional/monocypher-ed25519.c")
target_include_directories(multitap_dep_monocypher SYSTEM PUBLIC "${MULTITAP_MONOCYPHER}/src"
                           "${MULTITAP_MONOCYPHER}/src/optional")
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(multitap_dep_monocypher PRIVATE -O2)
endif()

# beacon (deps/beacon, multitap-org/multitap-beacon, MIT): our introduction
# server for connections across the internet. As a subproject it builds only
# `beacon_wire` (the exact message layouts, no dependencies); with the tests
# on Linux also the server itself (beacon_core, the `beacon` binary), which
# the network tests run against. Both stay out of `all` unless something
# links them.
set(MULTITAP_BEACON "${MULTITAP_DEPS_DIR}/beacon")
if(NOT EXISTS "${MULTITAP_BEACON}/wire/beacon_wire.cpp")
    message(FATAL_ERROR "multitap-net needs deps/beacon (https://github.com/multitap-org/multitap-beacon)")
endif()
if(MULTITAP_BUILD_TESTS AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(BEACON_SERVER ON CACHE BOOL "" FORCE)
endif()
set(BEACON_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory("${MULTITAP_BEACON}" "${CMAKE_BINARY_DIR}/deps/beacon" EXCLUDE_FROM_ALL)
add_library(multitap_dep_beacon_wire ALIAS beacon_wire)

# libdatachannel (deps/libdatachannel, MPL-2.0; Andrés accepted it 2026-11-20):
# WebRTC data channels natively, so desktop and Android meet browsers (the
# browser has its own WebRTC: net_webrtc.js). Built static, with its
# WebSocket client (the beacon's signaling, wss) and without media. TLS and
# DTLS from the system's OpenSSL on the desktop; Android has none, so there
# it's Mbed TLS (deps/mbedtls, Apache-2.0; Andrés, 2026-11-21: "we have no
# other TLS library, it's fine"), built here with the rest
# (MULTITAP_NET_RTC_MBEDTLS, also usable on the desktop to test it).
# Optional: a program without deps/libdatachannel (or MULTITAP_NET_RTC=OFF)
# gets ENet only.
set(MULTITAP_LIBDATACHANNEL "${MULTITAP_DEPS_DIR}/libdatachannel")
set(MULTITAP_HAVE_RTC OFF)
if(NOT EMSCRIPTEN AND EXISTS "${MULTITAP_LIBDATACHANNEL}/CMakeLists.txt")
    option(MULTITAP_NET_RTC "WebRTC data channels with libdatachannel" ON)
    if(MULTITAP_NET_RTC)
        set(MULTITAP_HAVE_RTC ON)
        set(NO_WEBSOCKET OFF CACHE BOOL "" FORCE)   # the beacon's signaling socket (wss)
        set(NO_MEDIA ON CACHE BOOL "" FORCE)
        set(NO_EXAMPLES ON CACHE BOOL "" FORCE)
        set(NO_TESTS ON CACHE BOOL "" FORCE)
        if(ANDROID)
            set(MULTITAP_NET_RTC_MBEDTLS_DEFAULT ON)
        else()
            set(MULTITAP_NET_RTC_MBEDTLS_DEFAULT OFF)
        endif()
        option(MULTITAP_NET_RTC_MBEDTLS "libdatachannel's TLS and DTLS from deps/mbedtls instead of OpenSSL" ${MULTITAP_NET_RTC_MBEDTLS_DEFAULT})
        if(MULTITAP_NET_RTC_MBEDTLS)
            set(MULTITAP_MBEDTLS "${MULTITAP_DEPS_DIR}/mbedtls")
            if(NOT EXISTS "${MULTITAP_MBEDTLS}/framework/CMakeLists.txt")
                message(FATAL_ERROR "MULTITAP_NET_RTC_MBEDTLS needs deps/mbedtls with its submodules (git submodule update --init --recursive)")
            endif()
            # The library only: static, no programs, tests or install.
            set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
            set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
            set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
            set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
            set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
            set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
            add_subdirectory("${MULTITAP_MBEDTLS}" "${CMAKE_BINARY_DIR}/deps/mbedtls" EXCLUDE_FROM_ALL)
            # Our additions to Mbed TLS's default configuration (DTLS-SRTP:
            # libdatachannel's DTLS sets its profiles even without media),
            # seen by Mbed TLS and by whatever includes its headers.
            foreach(target mbedcrypto mbedx509 mbedtls)
                target_compile_definitions(${target} PUBLIC
                    "MBEDTLS_USER_CONFIG_FILE=\"${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_user_config.h\"")
            endforeach()
            # The one target libdatachannel asks for (find_package's name).
            add_library(multitap_mbedtls INTERFACE)
            target_link_libraries(multitap_mbedtls INTERFACE mbedtls mbedx509 mbedcrypto)
            add_library(MbedTLS::MbedTLS ALIAS multitap_mbedtls)
            set(USE_MBEDTLS ON CACHE BOOL "" FORCE)
        else()
            set(USE_MBEDTLS OFF CACHE BOOL "" FORCE)
        endif()
        add_subdirectory("${MULTITAP_LIBDATACHANNEL}" "${CMAKE_BINARY_DIR}/deps/libdatachannel" EXCLUDE_FROM_ALL)
        # v0.24.6's src/configuration.cpp uses std::transform without
        # <algorithm>: libstdc++ brings it in through other headers, libc++
        # (CLANGARM64) doesn't. Fixed upstream in 69bee9a7 (master only, not
        # in v0.24.7); drop this once a release has it.
        if(TARGET datachannel-static AND NOT MSVC)
            target_compile_options(datachannel-static PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:SHELL:-include algorithm>")
        endif()
    endif()
endif()
# In the browser WebRTC is the browser's own (net_rtc_emscripten.cpp +
# net_webrtc.js). multitap_net adds the JS library to whatever links it; the
# path is also exported, for a program that links it some other way.
set(MULTITAP_HAVE_WEBRTC_JS OFF)
if(EMSCRIPTEN)
    set(MULTITAP_HAVE_WEBRTC_JS ON)
    set(MULTITAP_NET_WEBRTC_JS "${CMAKE_CURRENT_SOURCE_DIR}/net_webrtc.js" CACHE INTERNAL "net_webrtc.js (Emscripten)")
endif()

# The library: everything links it as `multitap_net`.
add_library(multitap_net STATIC
    net_discovery.cpp
    net_host.cpp
    net_memory.cpp
    net_noise.cpp
    net_link.cpp
    net_session.cpp
    net_cpace.cpp
    net_trust.cpp
    net_pairing.cpp
    net_pair_link.cpp
    net_guest.cpp
    net_access.cpp
    net_client.cpp
    net_content.cpp
    net_share.cpp
    net_share_folders.cpp
    net_share_engine.cpp
    net_share_host.cpp
    net_share_client.cpp
    net_share_link.cpp
    net_wire.cpp
    net_speed.cpp
    net_beacon.cpp
    net_signal.cpp
)
if(MULTITAP_HAVE_RTC)
    target_sources(multitap_net PRIVATE net_rtc_datachannel.cpp)
    target_link_libraries(multitap_net PRIVATE datachannel-static)
    if(MULTITAP_NET_RTC_MBEDTLS)
        # The signaling socket can't check the beacon's certificate there
        # (net_rtc_datachannel.cpp, net_rtc_socket_open).
        target_compile_definitions(multitap_net PRIVATE MULTITAP_NET_RTC_MBEDTLS=1)
    endif()
elseif(MULTITAP_HAVE_WEBRTC_JS)
    target_sources(multitap_net PRIVATE net_rtc_emscripten.cpp)
    target_link_options(multitap_net INTERFACE "--js-library=${MULTITAP_NET_WEBRTC_JS}")
    set_property(TARGET multitap_net APPEND PROPERTY INTERFACE_LINK_DEPENDS "${MULTITAP_NET_WEBRTC_JS}")
else()
    target_sources(multitap_net PRIVATE net_rtc_none.cpp)
endif()
if(WIN32)
    target_sources(multitap_net PRIVATE net_random_windows.cpp)
    target_link_libraries(multitap_net PRIVATE bcrypt)
else()
    target_sources(multitap_net PRIVATE net_random_posix.cpp)
endif()
target_include_directories(multitap_net PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
find_package(Threads REQUIRED)   # the share engine's copy thread, the RTC callbacks' locks
target_link_libraries(multitap_net PUBLIC host_common Threads::Threads multitap_dep_beacon_wire
                      PRIVATE multitap_dep_enet multitap_dep_monocypher)
multitap_set_project_flags(multitap_net)

# What frontends-common (added after this folder) needs to know: which
# transports are built, for its own tests.
if(NOT MULTITAP_NET_TOP_LEVEL)
    set(MULTITAP_HAVE_RTC ${MULTITAP_HAVE_RTC} PARENT_SCOPE)
    set(MULTITAP_HAVE_WEBRTC_JS ${MULTITAP_HAVE_WEBRTC_JS} PARENT_SCOPE)
endif()

# The browser test page (tests/web/README.md): net_rtc_emscripten.cpp +
# net_webrtc.js, and the signaling flow against a beacon run natively. Opened
# by hand or by a driven browser, not by ctest.
option(MULTITAP_WEB_TESTS "Emscripten: build the browser test page for WebRTC" OFF)
if(EMSCRIPTEN AND MULTITAP_WEB_TESTS AND MULTITAP_HAVE_WEBRTC_JS)
    add_executable(multitap_net_web_test tests/net_web_test.cpp)
    target_link_libraries(multitap_net_web_test PRIVATE multitap_net)
    multitap_set_project_flags(multitap_net_web_test)
    target_link_options(multitap_net_web_test PRIVATE -pthread -sPROXY_TO_PTHREAD -sPTHREAD_POOL_SIZE=2
                        -sEXIT_RUNTIME -sINITIAL_MEMORY=64mb -sSTACK_SIZE=1mb -sDEFAULT_PTHREAD_STACK_SIZE=1mb)
    add_custom_command(TARGET multitap_net_web_test POST_BUILD
                       COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/tests/web/net_web_test.html"
                               "$<TARGET_FILE_DIR:multitap_net_web_test>/net_web_test.html")
endif()

if(MULTITAP_BUILD_TESTS)
    set(MULTITAP_NET_TEST_FAIL "FAIL|ERROR: AddressSanitizer|ERROR: LeakSanitizer|runtime error:")

    # Discovery packets, then a listener and a client over loopback.
    add_executable(multitap_net_test tests/net_test.cpp)
    target_link_libraries(multitap_net_test PRIVATE multitap_net multitap_dep_enet)
    multitap_set_project_flags(multitap_net_test)
    add_test(NAME multitap_net COMMAND multitap_net_test "${CMAKE_CURRENT_BINARY_DIR}/net_test")
    set_tests_properties(multitap_net PROPERTIES
                         PASS_REGULAR_EXPRESSION "all net checks passed"
                         FAIL_REGULAR_EXPRESSION "${MULTITAP_NET_TEST_FAIL}")

    # Across the internet through a beacon, end to end over loopback against
    # the real server (deps/beacon's server code, built here for the test;
    # Linux only, like the server).
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_executable(multitap_net_beacon_test tests/net_beacon_test.cpp)
        target_link_libraries(multitap_net_beacon_test PRIVATE multitap_net beacon_core)
        multitap_set_project_flags(multitap_net_beacon_test)
        add_test(NAME multitap_net_beacon
                 COMMAND multitap_net_beacon_test "${CMAKE_CURRENT_BINARY_DIR}/net_beacon_test")
        set_tests_properties(multitap_net_beacon PROPERTIES
                             PASS_REGULAR_EXPRESSION "net beacon: all checks passed"
                             FAIL_REGULAR_EXPRESSION "${MULTITAP_NET_TEST_FAIL}")
    endif()

    # WebRTC data channels under NetSession, in one process (libdatachannel).
    if(MULTITAP_HAVE_RTC)
        add_executable(multitap_net_rtc_test tests/net_rtc_test.cpp)
        target_link_libraries(multitap_net_rtc_test PRIVATE multitap_net)
        multitap_set_project_flags(multitap_net_rtc_test)
        add_test(NAME multitap_net_rtc COMMAND multitap_net_rtc_test)
        set_tests_properties(multitap_net_rtc PROPERTIES
                             PASS_REGULAR_EXPRESSION "net rtc: all checks passed"
                             FAIL_REGULAR_EXPRESSION "${MULTITAP_NET_TEST_FAIL}")

        # The native half of the mixed browser test (tests/net_web_test.cpp
        # "host": a libdatachannel host the page meets). Run by hand, not by ctest.
        add_executable(multitap_net_web_host tests/net_web_test.cpp)
        target_link_libraries(multitap_net_web_host PRIVATE multitap_net)
        multitap_set_project_flags(multitap_net_web_host)
    endif()

    # WebRTC through the beacon's signaling: the real `beacon` binary runs
    # (spawned by the test), host and client meet in their room, the data
    # channels connect, Noise runs on them; then host_offline and unreachable.
    if(MULTITAP_HAVE_RTC AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_executable(multitap_net_signal_test tests/net_signal_test.cpp)
        target_link_libraries(multitap_net_signal_test PRIVATE multitap_net)
        add_dependencies(multitap_net_signal_test beacon)
        multitap_set_project_flags(multitap_net_signal_test)
        add_test(NAME multitap_net_signal
                 COMMAND multitap_net_signal_test $<TARGET_FILE:beacon> "${CMAKE_CURRENT_BINARY_DIR}/net_signal_test")
        set_tests_properties(multitap_net_signal PROPERTIES
                             PASS_REGULAR_EXPRESSION "net signal: all checks passed"
                             FAIL_REGULAR_EXPRESSION "${MULTITAP_NET_TEST_FAIL}")
    endif()

    # Files between devices (OWNER): messages, chunks, pages.
    add_executable(multitap_net_share_test tests/net_share_test.cpp)
    target_link_libraries(multitap_net_share_test PRIVATE multitap_net)
    multitap_set_project_flags(multitap_net_share_test)
    add_test(NAME multitap_net_share COMMAND multitap_net_share_test)
    set_tests_properties(multitap_net_share PROPERTIES
                         PASS_REGULAR_EXPRESSION "net share: all checks passed"
                         FAIL_REGULAR_EXPRESSION "${MULTITAP_NET_TEST_FAIL}")
    add_executable(multitap_net_share_engine_test tests/net_share_engine_test.cpp)
    target_link_libraries(multitap_net_share_engine_test PRIVATE multitap_net)
    multitap_set_project_flags(multitap_net_share_engine_test)
    add_test(NAME multitap_net_share_engine
             COMMAND multitap_net_share_engine_test "${CMAKE_CURRENT_BINARY_DIR}/net_share_engine_test")
    set_tests_properties(multitap_net_share_engine PROPERTIES
                         PASS_REGULAR_EXPRESSION "net share engine: all checks passed"
                         FAIL_REGULAR_EXPRESSION "${MULTITAP_NET_TEST_FAIL}|ThreadSanitizer")
    add_executable(multitap_net_share_folders_test tests/net_share_folders_test.cpp)
    target_link_libraries(multitap_net_share_folders_test PRIVATE multitap_net)
    multitap_set_project_flags(multitap_net_share_folders_test)
    add_test(NAME multitap_net_share_folders
             COMMAND multitap_net_share_folders_test "${CMAKE_CURRENT_BINARY_DIR}/net_share_folders_test")
    set_tests_properties(multitap_net_share_folders PROPERTIES
                         PASS_REGULAR_EXPRESSION "net share folders: all checks passed"
                         FAIL_REGULAR_EXPRESSION "${MULTITAP_NET_TEST_FAIL}")

    # Guest links: the derivations, the link's forms, the messages, the card.
    add_executable(multitap_net_guest_test tests/net_guest_test.cpp)
    target_link_libraries(multitap_net_guest_test PRIVATE multitap_net)
    multitap_set_project_flags(multitap_net_guest_test)
    add_test(NAME multitap_net_guest COMMAND multitap_net_guest_test)
    set_tests_properties(multitap_net_guest PROPERTIES
                         PASS_REGULAR_EXPRESSION "net guest: all checks passed"
                         FAIL_REGULAR_EXPRESSION "${MULTITAP_NET_TEST_FAIL}")

    # The host link (net_pair_link.h): kept for links to come, checked here.
    add_executable(multitap_net_pair_link_test tests/net_pair_link_test.cpp)
    target_link_libraries(multitap_net_pair_link_test PRIVATE multitap_net)
    multitap_set_project_flags(multitap_net_pair_link_test)
    add_test(NAME multitap_net_pair_link COMMAND multitap_net_pair_link_test)
    set_tests_properties(multitap_net_pair_link PROPERTIES
                         PASS_REGULAR_EXPRESSION "net pair link: all checks passed"
                         FAIL_REGULAR_EXPRESSION "${MULTITAP_NET_TEST_FAIL}")

    # Speed test: messages, pacing, counting.
    add_executable(multitap_net_speed_test tests/net_speed_test.cpp)
    target_link_libraries(multitap_net_speed_test PRIVATE multitap_net)
    multitap_set_project_flags(multitap_net_speed_test)
    add_test(NAME multitap_net_speed COMMAND multitap_net_speed_test)
    set_tests_properties(multitap_net_speed PROPERTIES
                         PASS_REGULAR_EXPRESSION "net speed: all checks passed"
                         FAIL_REGULAR_EXPRESSION "${MULTITAP_NET_TEST_FAIL}")

    # The Noise handshake against the official test vector, then failures.
    add_executable(multitap_net_noise_test tests/net_noise_test.cpp)
    target_link_libraries(multitap_net_noise_test PRIVATE multitap_net)
    multitap_set_project_flags(multitap_net_noise_test)
    add_test(NAME multitap_net_noise COMMAND multitap_net_noise_test)
    set_tests_properties(multitap_net_noise PROPERTIES
                         PASS_REGULAR_EXPRESSION "all noise checks passed"
                         FAIL_REGULAR_EXPRESSION "${MULTITAP_NET_TEST_FAIL}")
endif()
