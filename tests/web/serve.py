#!/usr/bin/env python3
# Serves a folder with the headers a threaded wasm needs (SharedArrayBuffer):
#   python3 serve.py <folder> [port]
import functools
import http.server
import sys


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


folder = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), functools.partial(Handler, directory=folder))
print(f"serving {folder} on http://127.0.0.1:{port}/")
server.serve_forever()
