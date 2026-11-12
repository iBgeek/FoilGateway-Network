#!/usr/bin/env python3
# How long a Send Test to Jarvis takes to arrive while other destinations
# are failing. Usage (in fgw-lap): latency120.py URL STATE
import http.client, json, ssl, sys, time, urllib.parse
URL, ST = sys.argv[1:3]; u = urllib.parse.urlparse(URL); CTX = ssl._create_unverified_context()
def call(m, p, b=None, ck=None):
    c = http.client.HTTPSConnection(u.hostname, u.port, context=CTX, timeout=30)
    h = {"Content-Type": "application/json", "X-FG": "1"}
    if ck: h["Cookie"] = "fg_session=" + ck
    c.request(m, p, body=None if b is None else json.dumps(b), headers=h); r = c.getresponse(); d = r.read(); sc = r.getheader("Set-Cookie") or ""; c.close()
    return r.status, (json.loads(d) if d else None), (sc.split("fg_session=")[1].split(";")[0] if "fg_session=" in sc else None)
_, _, ck = call("POST", "/api/login", {"user": "admin", "password": "correct horse battery"})
v = call("GET", "/api/notify", ck=ck)[1]
from collections import Counter
print("recent by (to, result):", dict(Counter((r["to"], r["result"]) for r in v["recent"])))
jid = next(d["id"] for d in v["dests"] if d["name"] == "Jarvis")
n0 = sum(1 for _ in open(ST + "/hooks.jsonl"))
t = time.time(); call("POST", "/api/notify", {"action": "test", "id": jid}, ck=ck)
while time.time() - t < 300:
    hs = [json.loads(l) for l in list(open(ST + "/hooks.jsonl"))[n0:]]
    if any(h["headers"].get("x-foilgateway-event") == "test" and h["path"] == "/foilgateway" for h in hs):
        print(f"Send Test to Jarvis arrived after {time.time() - t:.1f} s"); break
    time.sleep(0.2)
else: print("Send Test to Jarvis did not arrive within 300 s")
