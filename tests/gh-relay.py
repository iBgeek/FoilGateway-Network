#!/usr/bin/env python3
"""Byte relay for update-check tests: a Unix socket that connects ONLY to
api.github.com:443. No TLS termination: encrypted bytes pass through unchanged,
so the client still validates GitHub's real certificate. Bounded connections,
bytes and lifetime. Usage: gh-relay.py SOCKET_PATH [max_conns] [seconds]"""
import os, socket, sys, threading, time, json, signal
signal.signal(signal.SIGTERM, lambda *a: (_ for _ in ()).throw(KeyboardInterrupt()))
path = sys.argv[1]; max_conns = int(sys.argv[2]) if len(sys.argv) > 2 else 4; life = int(sys.argv[3]) if len(sys.argv) > 3 else 300
CAP = 4 * 1024 * 1024
try: os.unlink(path)
except FileNotFoundError: pass
srv = socket.socket(socket.AF_UNIX); srv.bind(path); os.chmod(path, 0o600); srv.listen(4); srv.settimeout(1)
log = []; end = time.time() + life; n = 0
def pump(a, b, rec, key):
    try:
        while rec[key] < CAP:
            d = a.recv(65536)
            if not d: break
            rec[key] += len(d); b.sendall(d)
    except OSError: pass
    finally:
        for s in (a, b):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass
try:
    while time.time() < end and n < max_conns:
        try: c, _ = srv.accept()
        except socket.timeout: continue
        n += 1
        up = socket.create_connection(("api.github.com", 443), timeout=10); up.settimeout(30); c.settimeout(30)
        rec = {"n": n, "at": time.time(), "peer": up.getpeername()[0], "up": 0, "down": 0}; log.append(rec)
        for a, b, k in ((c, up, "up"), (up, c, "down")): threading.Thread(target=pump, args=(a, b, rec, k), daemon=True).start()
    time.sleep(2)
except KeyboardInterrupt: pass
finally:
    srv.close()
    try: os.unlink(path)
    except FileNotFoundError: pass
    print(json.dumps({"connections": log}), flush=True)
