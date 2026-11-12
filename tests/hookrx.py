#!/usr/bin/env python3
# Webhook receiver for the Notifications tests: answers 200 to every POST
# and appends {path, headers, body, at} as one JSON line to OUTFILE.
# Usage: hookrx.py PORT OUTFILE
import json, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port, out = int(sys.argv[1]), sys.argv[2]
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        with open(out, "a") as f:
            f.write(json.dumps({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body, "at": time.time()}) + "\n")
        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
