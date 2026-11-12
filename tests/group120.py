#!/usr/bin/env python3
# Notification grouping and sign-in check (run in fgw-lap, bench up, traffic run).
# Usage: group120.py URL STATE_DIR OUT.json
import json, os, re, ssl, sys, time, http.client, urllib.parse, subprocess
URL, ST, OUT = sys.argv[1:4]
u = urllib.parse.urlparse(URL); CTX = ssl._create_unverified_context(); results = []
def call(m, p, b=None, ck=None):
    c = http.client.HTTPSConnection(u.hostname, u.port, context=CTX, timeout=30)
    h = {"Content-Type": "application/json", "X-FG": "1"}
    if ck: h["Cookie"] = "fg_session=" + ck
    c.request(m, p, body=None if b is None else json.dumps(b), headers=h); r = c.getresponse(); d = r.read(); c.close()
    mm = re.search(r"fg_session=([^;]*)", r.getheader("Set-Cookie") or "")
    return r.status, (json.loads(d) if d else None), (mm.group(1) if mm else None)
def check(name, ok, detail=""):
    results.append({"check": name, "ok": bool(ok), "detail": str(detail)[:400]})
    print(("PASS " if ok else "FAIL ") + name + "  " + str(detail)[:300], flush=True)
def hooks(n0):
    out = []
    for l in list(open(ST + "/hooks.jsonl"))[n0:]:
        h = json.loads(l); b = json.loads(h["body"]) if isinstance(h["body"], str) else h["body"]
        if h["path"] == "/grp": out.append(b)
    return out
A = call("POST", "/api/login", {"user": "admin", "password": "correct horse battery"})[2]
s, v, _ = call("POST", "/api/notify", {"action": "save", "name": "Group", "url": "http://10.10.10.1:8797/grp", "events": ["new_device", "look", "settings"]}, ck=A)
check("destination added (or already there)", s == 200 or "already exists" in json.dumps(v), s)
open(ST + "/hooks.jsonl", "a").close()
n0 = sum(1 for _ in open(ST + "/hooks.jsonl"))
time.sleep(3)
call("POST", "/api/login", {"user": "admin", "password": "correct horse battery"})
time.sleep(5)
check("a sign-in sends nothing", not any("signed in" in b["text"] for b in hooks(n0)), [b["text"] for b in hooks(n0)])
cip = open(ST + "/device.txt").read().split()[-1]
n1 = sum(1 for _ in open(ST + "/hooks.jsonl")); t0 = time.time()
for port in range(21001, 21007):
    subprocess.run(["curl", "-s", "-o", "/dev/null", "-m", "1", f"http://{cip}:{port}/"])
time.sleep(25)
look = [b for b in hooks(n1) if b["event"] == "look"]
devs = {}
for b in look: devs.setdefault(b["device"], []).append(b["text"])
check("6 new-port attempts on one device: at most 1 message so far", all(len(t) <= 1 for t in devs.values()), devs)
while time.time() - t0 < 360:
    more = [b for b in hooks(n1) if b["event"] == "look" and "more like this" in b["text"]]
    if more: break
    time.sleep(10)
check("the rest arrive as one message with the count after 5 minutes", len(more) == 1 and re.match(r"^\d+ more like this in 5 minutes\. Latest: ", more[0]["text"]), (round(time.time() - t0), [m["text"] for m in more]))
json.dump(results, open(OUT, "w"), indent=1)
print(f"{sum(r['ok'] for r in results)} passed, {sum(not r['ok'] for r in results)} failed")
