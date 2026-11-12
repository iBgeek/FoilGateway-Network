#!/usr/bin/env python3
# Notifications against the running gateway, from fgw-lap. The receiver
# (hookrx.py) runs on the router at 10.10.10.1:8797 and writes every POST
# to STATE/hooks.jsonl; signatures are checked here with the secrets the
# gateway handed out (kept in STATE/secrets, never printed).
# Usage: notify120.py URL STATE OUT.json [phase]   phase: setup (default) | check
import hashlib, hmac, http.client, json, os, ssl, sys, time, urllib.parse, subprocess
URL, ST, OUT = sys.argv[1:4]
PHASE = sys.argv[4] if len(sys.argv) > 4 else "setup"
u = urllib.parse.urlparse(URL); CTX = ssl._create_unverified_context()
SEC = ST + "/secrets"; os.makedirs(SEC, mode=0o700, exist_ok=True)
results, fails = [], []
def call(method, path, body=None, cookie=None):
    c = http.client.HTTPSConnection(u.hostname, u.port, context=CTX, timeout=30)
    h = {"Content-Type": "application/json", "X-FG": "1"}
    if cookie: h["Cookie"] = "fg_session=" + cookie
    c.request(method, path, body=None if body is None else json.dumps(body), headers=h)
    r = c.getresponse(); data = r.read(); sc = r.getheader("Set-Cookie") or ""; c.close()
    ck = sc.split("fg_session=")[1].split(";")[0] if "fg_session=" in sc else None
    try: return r.status, json.loads(data), ck
    except Exception: return r.status, None, ck
def check(name, ok, detail=""):
    results.append({"check": name, "ok": bool(ok), "detail": detail})
    if not ok: fails.append(name)
    print(("PASS " if ok else "FAIL ") + name + ("  " + str(detail)[:300] if detail else ""), flush=True)
def secret(name, value=None):
    p = SEC + "/notify-" + name
    if value is None: return [l for l in open(p).read().split("\n") if l]
    with open(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "a") as f: f.write(value + "\n")
def hooks():
    try: return [json.loads(l) for l in open(ST + "/hooks.jsonl")]
    except FileNotFoundError: return []
def verify(h, secrets):
    ts = h["headers"].get("x-foilgateway-timestamp", ""); sig = h["headers"].get("x-foilgateway-signature", "")
    for i, s in enumerate(secrets):
        want = "sha256=" + hmac.new(s.encode(), (ts + "." + h["body"]).encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(want, sig): return i
    return None
def wait_hook(pred, secs=30, after=0):
    end = time.time() + secs
    while time.time() < end:
        for h in hooks():
            if h["at"] >= after and pred(h): return h
        time.sleep(0.5)
    return None
s, _, ADM = call("POST", "/api/login", {"user": "admin", "password": "correct horse battery"})
def adm(m, p, b=None): return call(m, p, b, cookie=ADM)
def recent(): return adm("GET", "/api/notify")[1]["recent"]
def dest(name): return next((d for d in adm("GET", "/api/notify")[1]["dests"] if d["name"] == name), None)

if PHASE == "setup":
    t0 = time.time()
    s, v, _ = adm("POST", "/api/notify", {"action": "save", "name": "Jarvis", "url": "http://10.10.10.1:8797/foilgateway", "events": ["new_device", "look", "settings", "update", "started"]})
    sec = (v or {}).get("secret", "")
    check("Add destination returns a signing secret once (64 hex)", s == 200 and len(sec) == 64 and all(c in "0123456789abcdef" for c in sec), s)
    secret("Jarvis", sec)
    check("the secret isn't in the destination list", s == 200 and "secret" not in v["dests"][0] and sec not in json.dumps(adm("GET", "/api/notify")[1]))
    nj = open(ST + "/notify.json").read()
    check("notify.json is mode 600", (os.stat(ST + "/notify.json").st_mode & 0o777) == 0o600)
    s, v, _ = adm("POST", "/api/notify", {"action": "save", "name": "Dead End", "url": "http://10.10.10.250:8797/hook", "events": ["settings", "look"]})
    secret("Dead End", (v or {}).get("secret", ""))
    s, v, _ = adm("POST", "/api/notify", {"action": "save", "name": "Temp", "url": "http://10.10.10.1:8797/temp", "events": ["settings"]})
    secret("Temp", (v or {}).get("secret", ""))
    for bad in ({"name": "x", "url": "ftp://a/"}, {"name": "", "url": "http://a/"}, {"name": "jarvis", "url": "http://a/"}):
        s2, v2, _ = adm("POST", "/api/notify", dict({"action": "save", "events": []}, **bad))
        check("refused: " + json.dumps(bad), s2 == 400, (v2 or {}).get("error"))
    # Send Test
    jid = dest("Jarvis")["id"]
    t1 = time.time()
    s, _, _ = adm("POST", "/api/notify", {"action": "test", "id": jid})
    h = wait_hook(lambda h: h["headers"].get("x-foilgateway-event") == "test" and h["path"] == "/foilgateway", 20, t1)
    check("Send Test arrives, signature verifies", s == 200 and h and verify(h, secret("Jarvis")) == 0, h and {k: h["headers"].get(k) for k in ("x-foilgateway-event", "x-foilgateway-timestamp")})
    if h:
        b = json.loads(h["body"]); check("test body fields", set(b) >= {"gateway", "version", "event", "title", "text", "device", "at"} and b["version"] == "1.2.0", b)
    # A settings change -> settings event (to Jarvis and Temp; Dead End retries)
    t2 = time.time()
    adm("POST", "/api/list", {"list": "black", "add": "203.0.113.50"})
    h = wait_hook(lambda h: h["headers"].get("x-foilgateway-event") == "settings" and "203.0.113.50" in h["body"] and h["path"] == "/foilgateway", 20, t2)
    check("settings event arrives at Jarvis, signature verifies", h and verify(h, secret("Jarvis")) == 0, h and json.loads(h["body"]).get("text"))
    ht = wait_hook(lambda h: h["path"] == "/temp" and "203.0.113.50" in h["body"], 20, t2)
    check("same event to a second destination signed with its own secret", ht and verify(ht, secret("Temp")) == 0 and verify(ht, secret("Jarvis")) is None)
    # Edit: change events, secret stays the same
    s, v, _ = adm("POST", "/api/notify", {"action": "save", "id": jid, "name": "Jarvis", "url": "http://10.10.10.1:8797/foilgateway", "events": ["new_device", "look", "settings", "started"]})
    check("Edit saves without a new secret", s == 200 and "secret" not in v and dest("Jarvis")["events"] == ["new_device", "look", "settings", "started"])
    # New Secret: old one stops verifying
    s, v, _ = adm("POST", "/api/notify", {"action": "new_secret", "id": jid})
    secret("Jarvis", v.get("secret", ""))
    t3 = time.time()
    adm("POST", "/api/notify", {"action": "test", "id": jid})
    h = wait_hook(lambda h: h["headers"].get("x-foilgateway-event") == "test" and h["path"] == "/foilgateway", 20, t3)
    check("after New Secret, messages verify with the new secret only", h and verify(h, secret("Jarvis")) == 1)
    # Remove
    tid = dest("Temp")["id"]
    s, _, _ = adm("POST", "/api/notify", {"action": "remove", "id": tid})
    check("Remove", s == 200 and dest("Temp") is None)
    # new_device: give the LAN client a new MAC and ask for an address again.
    t4 = time.time()
    subprocess.run(["ip", "netns", "exec", "fgw-cli", "ip", "link", "set", "c-lan", "down"])
    subprocess.run(["ip", "netns", "exec", "fgw-cli", "ip", "link", "set", "c-lan", "address", "02:12:34:56:78:9a"])
    subprocess.run(["ip", "netns", "exec", "fgw-cli", "ip", "addr", "flush", "dev", "c-lan"])
    subprocess.run(["ip", "netns", "exec", "fgw-cli", "ip", "link", "set", "c-lan", "up"])
    ip = subprocess.run(["ip", "netns", "exec", "fgw-cli", "python3", os.path.dirname(os.path.abspath(__file__)) + "/dhcpc.py", "c-lan", "30"], capture_output=True, text=True).stdout.strip()
    subprocess.run(["ip", "netns", "exec", "fgw-cli", "ip", "route", "replace", "default", "via", "10.10.10.1"])
    for _ in range(3): subprocess.run(["ip", "netns", "exec", "fgw-cli", "curl", "-s", "-o", "/dev/null", "-m", "1", "http://1.1.1.1/"])
    open(ST + "/device.txt", "w").write(ip + "\n")
    h = wait_hook(lambda h: h["headers"].get("x-foilgateway-event") == "new_device" and h["path"] == "/foilgateway", 60, t4)
    check("new_device event arrives, signature verifies", h and verify(h, secret("Jarvis")) == 1, h and json.loads(h["body"]).get("text"))
    # Unreachable: Dead End shows Retrying in Recent Sends.
    time.sleep(8)
    r = [x for x in recent() if x["to"] == "Dead End"]
    check("unreachable destination: Recent Sends says retrying", r and any(x["result"] == "retrying" and x["tries"] >= 1 for x in r), r[:1] and {k: r[0][k] for k in ("result", "tries", "error")})
    d = dest("Dead End"); check("destination row: last result retrying", d and d["last_result"] == "retrying", d and d["last_result"])
    sigs = [verify(h, secret("Jarvis")) for h in hooks() if h["path"] == "/foilgateway" and h["at"] >= t0]
    check("every message to Jarvis verified with one of its secrets", sigs and all(x is not None for x in sigs), f"{len(sigs)} messages")
    json.dump({"phase": PHASE, "t0": t0, "results": results, "fails": fails}, open(OUT, "w"), indent=1)
else:
    # After the soak: retries stop after 10 minutes.
    r = [x for x in recent() if x["to"] == "Dead End"]
    gave = [x for x in r if x["result"] == "failed"]
    check("unreachable destination: given up after 10 minutes (failed)", gave, gave[:1] and {k: gave[0][k] for k in ("tries", "at", "done_at", "error")} and {"tries": gave[0]["tries"], "secs": gave[0]["done_at"] - gave[0]["at"], "error": gave[0]["error"]})
    ok = [x for x in recent() if x["to"] == "Jarvis"]
    check("reachable destination still delivering", any(x["result"] == "delivered" for x in ok), f"{sum(x['result']=='delivered' for x in ok)} of {len(ok)} recent delivered")
    hs = [h for h in hooks() if h["path"] == "/foilgateway"]
    sec = secret("Jarvis")
    v = [verify(h, sec) for h in hs]
    check("all Jarvis messages so far verify", all(x is not None for x in v), f"{len(hs)} messages, events {sorted(set(h['headers'].get('x-foilgateway-event') for h in hs))}")
    json.dump({"phase": PHASE, "results": results, "fails": fails, "recent": recent()}, open(OUT, "w"), indent=1)
print(f"\n{len(results) - len(fails)} passed, {len(fails)} failed")
