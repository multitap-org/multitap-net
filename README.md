# multitap-net

Multitap's network core: what piccolo, piccoletto and piccolino use to find,
pair with and talk to each other. No GUI: no SDL, ImGui or Vulkan.

- **One UDP port** (`net_host`): ENet connections and LAN discovery
  (`net_discovery`) share it.
- **Encrypted links**: Noise XX (`net_noise`) on Monocypher, one channel set
  per peer (`net_link`, `net_session`).
- **Pairing and capabilities**: a 9-digit code through CPace (`net_cpace`,
  `net_pairing`), made and shown by the device asked to pair (it grants the
  permissions); the device's identity and one record per paired device with
  both directions (`net_trust`); capabilities as independent bits (GAMEPAD,
  STREAM, SETTINGS, SHARE: what a device may use is its grant ∩ what the host
  offers ∩ what it uses), on the host (`net_access`) and the client's side
  (`net_client`); guest links (`net_guest`, `net_pair_link`).
- **Across the internet**: the
  [beacon](https://github.com/multitap-org/multitap-beacon) introduces peers
  and helps punch through NATs (`net_beacon`); it never relays. WebRTC data
  channels (`net_rtc_*`, signaling in `net_signal`) carry the same channels:
  libdatachannel natively, the browser's own WebRTC in Emscripten builds
  (`net_webrtc.js`).
- **SHARE**: listing and copying files between devices granted SHARE
  (`net_share*`); CONFIG never shows a device's identity or paired devices.
- Messages: `net_wire` (fields), `net_content` (browsing and loading games),
  `net_speed` (speed test).

## Building

As a library (how piccolo and piccoletto use it): the program adds
[hosts-common](https://github.com/multitap-org/hosts-common) first, sets
`MULTITAP_DEPS_DIR` to its `deps/` folder (enet, monocypher, beacon;
optionally libdatachannel, and mbedtls for Android), then
`add_subdirectory()`s this folder and links `multitap_net`.

On its own (tests, CI):

```sh
git submodule update --init --recursive --checkout
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DMULTITAP_WARNINGS_AS_ERRORS=ON
cmake --build build && ctest --test-dir build
```

The submodules in `deps/` are marked `update = none`, so a program that has
this repo as a submodule doesn't fetch second copies of them.

Code style: [multitap's STYLE.md](https://github.com/multitap-org/multitap).

MIT License (see LICENSE). History: these files lived in
[frontends-common](https://github.com/multitap-org/frontends-common) until
2026-11-25; their history came with them.
