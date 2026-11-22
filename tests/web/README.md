# WebRTC in the browser: the test page

`tests/net_web_test.cpp` checks net_rtc_emscripten.cpp + net_webrtc.js in a
real browser. ctest can't run it, so it's run by hand or from a driven browser.

1. Build it with Emscripten. Configure like `web/build.sh` in piccolo, adding
   `-DMULTITAP_WEB_TESTS=ON`, then build the target `frontend_net_web_test`.
   The target writes `frontend_net_web_test.js`, `.wasm` and
   `net_web_test.html` in its build folder.
2. Start a beacon natively with signaling on:
   `beacon --bind 127.0.0.1 --port 47430 --secondary-port 0 --signal-port 47432`
3. Serve the build folder with the headers threads need:
   `python3 tests/web/serve.py <build folder> 8765`
4. Open `http://127.0.0.1:8765/net_web_test.html?beacon=ws://127.0.0.1:47432/signal`.
   The page title becomes PASS or FAIL, and each check is listed on the page.

Leave out `beacon=` to check only the two peers in one page.

**Browser ↔ native.** Run the native `frontend_net_web_host` (built with
the normal tests when libdatachannel is there):

    frontend_net_web_host ws://127.0.0.1:47432/signal host <scratch folder>

Then open the page with `&mode=client`. The page meets that host through
the beacon, the phone ↔ browser case. Both sides use fixed test keys.

**Native ↔ browser** (the other way): open the page with `&mode=host`
first (it waits 60 s for its client), then run

    frontend_net_web_host ws://127.0.0.1:47432/signal client <scratch folder> 127.0.0.1:47430

The native client tries UDP through the beacon first, as piccolo does. The
page only signals, so the client falls back to WebRTC. Both print "all
checks passed" (the page's title becomes PASS).
