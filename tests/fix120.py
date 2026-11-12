#!/usr/bin/env python3
# Round-2 fixes against the running gateway (run in fgw-lap).
# Usage: fix120.py URL STATE_DIR OUT.json   Keys stay in STATE_DIR/secrets.
import json, os, re, ssl, sys, time, http.client, urllib.parse, subprocess
URL, ST, OUT = sys.argv[1:4]
u = urllib.parse.urlparse(URL); CTX = ssl._create_unverified_context()
SEC = ST + "/secrets"; os.makedirs(SEC, mode=0o700, exist_ok=True)
results = []
def call(m, p, b=None, key=None, ck=None, src="10.10.10.60"):
    c = http.client.HTTPSConnection(u.hostname, u.port, context=CTX, timeout=30, source_address=(src, 0))
    h = {"Content-Type": "application/json", "X-FG": "1"}
    if key: h["Authorization"] = "Bearer " + key
    if ck: h["Cookie"] = "fg_session=" + ck
    c.request(m, p, body=None if b is None else json.dumps(b), headers=h); r = c.getresponse(); d = r.read(); c.close()
    try: j = json.loads(d)
    except Exception: j = None
    mm = re.search(r"fg_session=([^;]*)", r.getheader("Set-Cookie") or "")
    return r.status, j, (mm.group(1) if mm else None)
def check(name, ok, detail=""):
    results.append({"check": name, "ok": bool(ok), "detail": str(detail)[:300]})
    print(("PASS " if ok else "FAIL ") + name + ("  " + str(detail)[:200] if detail != "" else ""), flush=True)
A = call("POST", "/api/login", {"user": "admin", "password": "correct horse battery"})[2]
def adm(m, p, b=None): return call(m, p, b, ck=A)
K = {}
for name, perms in [("blocker", ["block_list"]), ("allower", ["allow_list", "alerts", "devices"]), ("both", ["block_list", "allow_list"]), ("kid", ["status"]), ("helper", ["handle_alerts", "log", "status"])]:
    s, j, _ = adm("POST", "/api/users", {"action": "save", "old_name": "", "name": name, "role": "custom", "perms": perms, "web": False, "api": True, "password": ""})
    s2, j2, _ = adm("POST", "/api/users", {"action": "new_key", "name": name})
    K[name] = (j2 or {}).get("key", "")
    with open(f"{SEC}/key-r2-{name}", "w") as f: f.write(K[name] + "\n")
check("5 test users with keys made", all(k.startswith("fgk_") for k in K.values()), sorted(K))
def keep(name): return call("POST", "/api/confirm", {}, key=K[name])[1]
def lists(): j = adm("GET", "/api/firewall")[1]; return j.get("white", j.get("policy", {}).get("white")), j.get("black", j.get("policy", {}).get("black"))
w0 = adm("GET", "/api/firewall")[1]
# --- Fix 1
s, j, _ = call("POST", "/api/list", {"list": "black", "add": "8.8.8.8"}, key=K["blocker"])
check("1 block_list only: Black-listing a White list entry refused", s == 403 and "White list" in (j or {}).get("error", ""), (s, j))
s, j, _ = call("POST", "/api/list", {"list": "white", "add": "9.9.9.9"}, key=K["allower"])
check("1 allow_list only: White-listing a Black list entry refused", s == 403 and "Black list" in (j or {}).get("error", ""), (s, j))
s, j, _ = call("POST", "/api/list", {"list": "black", "add": "203.0.113.61"}, key=K["blocker"])
check("1 block_list only: new Black list entry allowed", s == 200, (s, j)); keep("blocker")
s, j, _ = call("POST", "/api/list", {"list": "black", "add": "8.8.8.8"}, key=K["both"])
check("1 both permissions: moving 8.8.8.8 to the Black list allowed", s == 200, (s, j)); check("1 owner keeps it", keep("both").get("kept") is True)
s, j, _ = call("POST", "/api/list", {"list": "white", "add": "8.8.8.8"}, key=K["both"]); keep("both")
check("1 both permissions: moved back", s == 200, (s, j))
mac = (adm("GET", "/api/devices")[1].get("devices") or [{}])[0].get("mac", "")
s, j, _ = call("POST", "/api/allow", {"mac": mac, "reason": "devdeny", "remote": "192.0.2.1"}, key=K["allower"])
check("1 allow_list only: /api/allow devdeny refused", s == 403, (s, j))
s, j, _ = call("POST", "/api/allow", {"mac": mac, "reason": "devdeny", "remote": "192.0.2.1"}, key=K["both"])
check("1 both: /api/allow devdeny passes the permission check", s != 403, (s, j))
# --- Fix 2
adm("POST", "/api/list", {"list": "black", "add": "203.0.113.62"}); adm("POST", "/api/confirm")
logrows = adm("GET", "/api/log?limit=200")[1]["rows"]
sid = next(r["id"] for r in logrows if r["kind"] == "setting")
s, j, _ = call("POST", "/api/alerts/clear", {"ids": [sid]}, key=K["helper"])
check("2 clear a settings line refused", s == 400 and "Only alerts" in (j or {}).get("error", ""), (s, j))
s, j, _ = call("POST", "/api/alert", {"id": sid}, key=K["helper"])
check("2 /api/alert on a settings line refused", s == 400, (s, j))
row = next(r for r in adm("GET", f"/api/log?limit=500")[1]["rows"] if r["id"] == sid)
check("2 the settings line is not marked handled", row["handled"] is False)
dash = adm("GET", "/api/dashboard")[1]["alerts"]
aid = dash[0]["id"] if dash else None
s, j, _ = call("POST", "/api/alerts/clear", {"ids": [aid, sid]}, key=K["helper"])
check("2 mixed alert + settings ids refused, nothing cleared", s == 400 and any(a["id"] == aid for a in adm("GET", "/api/dashboard")[1]["alerts"]), (s, j))
s, j, _ = call("POST", "/api/alerts/clear", {"ids": [aid]}, key=K["helper"])
check("2 clear a real alert allowed", s == 200 and (j or {}).get("cleared") == 1, (s, j))
# --- Fix 3
s, j, _ = call("POST", "/api/list", {"list": "black", "add": "203.0.113.63"}, key=K["blocker"])
k_other = keep("kid"); st = adm("GET", "/api/status")[1]
check("3 another user's confirm: kept false, still waiting", s == 200 and k_other.get("kept") is False and st.get("pending"), (k_other, bool(st.get("pending"))))
check("3 the owner keeps it", keep("blocker").get("kept") is True)
call("POST", "/api/list", {"list": "black", "add": "203.0.113.64"}, key=K["blocker"])
check("3 an admin can keep someone's change", adm("POST", "/api/confirm")[1].get("kept") is True)
adm("POST", "/api/list", {"list": "black", "add": "203.0.113.65"})
check("3 a Custom user can't keep an admin's change", keep("blocker").get("kept") is False)
adm("POST", "/api/confirm")
ref = adm("GET", "/api/reference")[1]
cf = next(r for r in ref["routes"] if r["path"] == "/api/confirm")
check("3 API Reference says who can keep a change", "Only the user who made the change, or an admin" in cf["what"], cf["what"])
# --- Fix 4
before = [a for a in adm("GET", "/api/dashboard")[1]["alerts"] if "refused" in a["text"]]
for p in ["/api/settings", "/api/users", "/api/notify", "/api/log", "/api/devices"]:
    call("GET", p, key=K["kid"])
dash = adm("GET", "/api/dashboard")[1]["alerts"]
mine = [a["text"] for a in dash if "from kid" in a["text"] or "kid was refused" in a["text"]]
check("4 five refusals: one dashboard alert with the count", mine == ["5 refused calls from kid. Each one is in the Capture Log."], mine)
logged = [r for r in adm("GET", "/api/log?q=kid%20was%20refused&limit=50")[1]["rows"]]
check("4 each refusal is in the Capture Log", len(logged) == 5, len(logged))
logged_a = adm("GET", "/api/log?kind=alert&q=kid%20was%20refused&limit=50")[1]["rows"]
check("4 refusals listed under the Alerts filter", len(logged_a) == 5, len(logged_a))
look = adm("GET", "/api/log?kind=look&q=refused&limit=50")[1]["rows"]
check("4 Needs a Look has only the summary", [r["text"] for r in look if "kid" in r["text"]] == ["5 refused calls from kid. Each one is in the Capture Log."], [r["text"] for r in look])
json.dump(results, open(OUT, "w"), indent=1)
print(f"{sum(r['ok'] for r in results)} passed, {sum(not r['ok'] for r in results)} failed")
