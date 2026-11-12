#!/usr/bin/env python3
# One Send Test to the unreachable Dead End, no other events, then watch its
# Recent Sends row until it is given up (failed = "Not delivered").
# Usage (in fgw-lap): dead120.py URL OUT.json
import http.client, json, ssl, sys, time, urllib.parse
URL, OUT = sys.argv[1:3]; u = urllib.parse.urlparse(URL); CTX = ssl._create_unverified_context()
def call(m, p, b=None, ck=None):
    c = http.client.HTTPSConnection(u.hostname, u.port, context=CTX, timeout=30)
    h = {"Content-Type": "application/json", "X-FG": "1"}
    if ck: h["Cookie"] = "fg_session=" + ck
    c.request(m, p, body=None if b is None else json.dumps(b), headers=h); r = c.getresponse(); d = r.read(); sc = r.getheader("Set-Cookie") or ""; c.close()
    return r.status, (json.loads(d) if d else None), (sc.split("fg_session=")[1].split(";")[0] if "fg_session=" in sc else None)
def login(): return call("POST", "/api/login", {"user": "admin", "password": "correct horse battery"})[2]
ck = login()
v = call("GET", "/api/notify", ck=ck)[1]
did = next(d["id"] for d in v["dests"] if d["name"] == "Dead End")
t0 = time.time(); s, _, _ = call("POST", "/api/notify", {"action": "test", "id": did}, ck=ck)
print("Send Test to Dead End:", s, time.strftime("%H:%M:%S"))
seen = []
while time.time() - t0 < 1200:
    time.sleep(30)
    st, v, _ = call("GET", "/api/notify", ck=ck)
    if st == 401: ck = login(); continue
    row = next((r for r in v["recent"] if r["to"] == "Dead End"), None)
    d = next(d for d in v["dests"] if d["id"] == did)
    line = (round(time.time() - t0), row and row["result"], row and row["tries"], d.get("last_result"))
    seen.append(line); print("t+%ss result=%s tries=%s dest_last=%s" % line, flush=True)
    if row and row["result"] == "failed": break
ok = bool(seen) and seen[-1][1] == "failed"
print(("PASS" if ok else "FAIL") + " Dead End given up after %ss: %s (UI shows %s)" % (seen[-1][0] if seen else "?", seen[-1][1] if seen else None, "Not delivered" if ok else "?"))
json.dump({"seen": seen, "pass": ok}, open(OUT, "w"))
