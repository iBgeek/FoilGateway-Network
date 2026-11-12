#!/usr/bin/env python3
# 1.2.0 Users, permissions, keys, notifications and alert clearing against
# the running gateway, run from the laptop namespace (fgw-lap).
# Usage: api120.py URL STATE_DIR OUT.json
# Secrets (keys, signing secrets) go only to STATE_DIR/secrets/, never to
# stdout or OUT.json.
import hashlib, hmac, http.client, json, os, re, ssl, sys, time, urllib.parse
URL, ST, OUT = sys.argv[1:4]
HOST = urllib.parse.urlparse(URL).hostname
PORT = urllib.parse.urlparse(URL).port
SEC = ST + "/secrets"; os.makedirs(SEC, mode=0o700, exist_ok=True)
CTX = ssl._create_unverified_context()
results, fails = [], []
PW = "correct horse battery"
UPW = "custom-password-123"

def call(method, path, body=None, key=None, cookie=None, xfg=True, src="10.10.10.60", raw_auth=None):
    c = http.client.HTTPSConnection(HOST, PORT, context=CTX, timeout=30, source_address=(src, 0))
    h = {"Content-Type": "application/json"}
    if xfg: h["X-FG"] = "1"
    if key is not None: h["Authorization"] = "Bearer " + key
    if raw_auth is not None: h["Authorization"] = raw_auth
    if cookie: h["Cookie"] = "fg_session=" + cookie
    c.request(method, path, body=None if body is None else json.dumps(body), headers=h)
    r = c.getresponse(); data = r.read(); c.close()
    try: j = json.loads(data)
    except Exception: j = None
    sc = r.getheader("Set-Cookie") or ""
    m = re.search(r"fg_session=([^;]*)", sc)
    return r.status, j, (m.group(1) if m else None), data

def check(name, ok, detail=""):
    results.append({"check": name, "ok": bool(ok), "detail": detail})
    if not ok: fails.append(name)
    print(("PASS " if ok else "FAIL ") + name + ("  " + str(detail)[:300] if detail else ""), flush=True)

def login(user, pw, src="10.10.10.60"):
    s, j, ck, _ = call("POST", "/api/login", {"user": user, "password": pw}, src=src)
    return s, ck

def save_secret(name, value):
    p = SEC + "/" + name
    with open(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f: f.write(value + "\n")

s, ADM = login("admin", PW)
check("admin signs in (session)", s == 200 and ADM, s)
def adm(method, path, body=None): return call(method, path, body, cookie=ADM)

# ---------- reference ----------
s, ref, _, _ = adm("GET", "/api/reference")
PERMS = [p["id"] for p in ref["perms"]]
WANT = ["status", "devices", "alerts", "log", "firewall_view", "speed_view", "updates_view", "device_actions", "block_list", "allow_list", "handle_alerts", "speed_run", "updates_check"]
check("13 permission ids, in order", PERMS == WANT, PERMS)
ROUTES = [(r["method"], r["path"], r["needs"]) for r in ref["routes"]]
check("/api/reference lists routes", s == 200 and len(ROUTES) >= 20, len(ROUTES))

# ---------- users ----------
def save_user(name, role, perms, web, api, password="", old=""):
    return adm("POST", "/api/users", {"action": "save", "old_name": old, "name": name, "role": role, "perms": perms, "web": web, "api": api, "password": password})
def new_key(name):
    s, j, _, _ = adm("POST", "/api/users", {"action": "new_key", "name": name})
    return s, (j or {}).get("key")

KEYS = {}
for p in PERMS:
    n = "p_" + p
    s, j, _, _ = save_user(n, "custom", [p], True, True, UPW)
    s2, k = new_key(n)
    KEYS[n] = k; save_secret("key-" + n, k or "")
    if not (s == 200 and s2 == 200 and k and re.fullmatch(r"fgk_[0-9a-f]{64}", k)):
        check("make user and key " + n, False, (s, s2))
# Each action brings the view it is used from (1.2.0 round 3).
IMPLIED = [("speed_run", "speed_view"), ("updates_check", "updates_view"), ("handle_alerts", "status"), ("device_actions", "devices"),
           ("block_list", "firewall_view"), ("allow_list", "firewall_view"), ("alerts", "devices"), ("alerts", "firewall_view")]
HAS = {p: {p} | {v for a, v in IMPLIED if a == p} for p in PERMS}
_, uv0, _, _ = adm("GET", "/api/users")
saved = {u["name"]: set(u["perms"]) for u in uv0["users"]}
check("each single-permission user is saved with its implied view", all(saved.get("p_" + p) == HAS[p] for p in PERMS), {p: sorted(saved.get("p_" + p, [])) for p in PERMS if saved.get("p_" + p) != HAS[p]})
check("GET /api/users lists the implied views", sorted(map(tuple, uv0.get("implies", []))) == sorted(IMPLIED), uv0.get("implies"))
check("13 single-permission users made, each key is fgk_ + 64 hex", all(k and re.fullmatch(r"fgk_[0-9a-f]{64}", k) for k in KEYS.values()), len(KEYS))
users_file = open(ST + "/users.json").read()
check("no key is stored in users.json", not any(k[4:] in users_file or k in users_file for k in KEYS.values()))
uf = json.load(open(ST + "/users.json"))
check("users.json keeps SHA-256 of each key", all(any(u.get("key_hash") == hashlib.sha256(k.encode()).hexdigest() for u in uf) for k in KEYS.values()))
check("users.json is mode 600", (os.stat(ST + "/users.json").st_mode & 0o777) == 0o600, oct(os.stat(ST + "/users.json").st_mode & 0o777))
s, uv, _, raw = adm("GET", "/api/users")
check("GET /api/users never shows hash or key", s == 200 and b"argon2" not in raw and b"key_hash" not in raw and not any(k.encode() in raw for k in KEYS.values()))

# ---------- permission matrix ----------
CMAC = open(ST + "/device.txt").read().split()[-1] if os.path.exists(ST + "/device.txt") else ""
s, dv, _, _ = adm("GET", "/api/devices")
MAC = (dv.get("devices") or [{}])[0].get("mac", "aa:bb:cc:dd:ee:ff")
def body_for(m, p):
    return {
        ("POST", "/api/device"): {"mac": MAC, "seen": True},
        ("POST", "/api/list"): {"list": "black", "add": "203.0.113.9"},
        ("POST", "/api/allow"): {"mac": MAC},
        ("POST", "/api/alert"): {"id": 0},
        ("POST", "/api/alerts/clear"): {"ids": [-1]},
        ("POST", "/api/audit"): {"action": "keep"},
        ("POST", "/api/ports"): {"action": "seen"},
        ("POST", "/api/speed-test"): {"action": "cancel"},
        ("POST", "/api/updates/check"): {},
    }.get((m, p), None if m == "GET" else {})
# Admin-only probes: none of these may open to a Custom user.
ADMIN_ONLY = [("GET", "/api/settings", None), ("GET", "/api/users", None), ("GET", "/api/notify", None), ("GET", "/api/certs", None), ("GET", "/api/coach", None),
              ("GET", "/api/made-up", None), ("POST", "/api/settings", {"action": "nothing"}), ("POST", "/api/users", {"action": "nothing"}),
              ("POST", "/api/notify", {"action": "nothing"}), ("POST", "/api/firewall", {}), ("POST", "/api/list", {"list": "other"}),
              ("POST", "/api/audit", {"action": "on"}), ("POST", "/api/ports", {"action": "add"}), ("POST", "/api/device", {"mac": MAC, "forget": True}),
              ("POST", "/api/updates/install", {}), ("POST", "/api/updates/rollback", {}), ("POST", "/api/profile", {}), ("POST", "/api/restart", {}),
              ("POST", "/api/certs", {"action": "nothing"}), ("POST", "/api/coach", {})]
matrix = {}
bad_cells = []
for p in PERMS:
    n = "p_" + p
    s, ck = login(n, UPW)
    if s != 200: check("custom user signs in " + n, False, s); continue
    for via in ("key", "web"):
        for (m, path, needs) in ROUTES + [(m, pth, "admin") for (m, pth, _) in ADMIN_ONLY]:
            b = body_for(m, path) if needs != "admin" else next(x[2] for x in ADMIN_ONLY if x[0] == m and x[1] == path)
            if via == "key": st = call(m, path, b, key=KEYS[n])[0]
            else: st = call(m, path, b, cookie=ck)[0]
            allowed = needs in HAS[p] or needs == "any"
            ok = (st not in (401, 403)) if allowed else st == 403
            matrix.setdefault(n, {})[f"{via} {m} {path} needs={needs}"] = st
            if not ok: bad_cells.append(f"{n} {via} {m} {path} -> {st} (allowed={allowed})")
    # The list's other side: block_list can't add to the allow list, and the reverse.
    if p in ("block_list", "allow_list"):
        other = "white" if p == "block_list" else "black"
        st = call("POST", "/api/list", {"list": other, "add": "203.0.113.10"}, key=KEYS[n])[0]
        if st != 403: bad_cells.append(f"{n} list {other} -> {st}")
    if p == "device_actions":
        for extra in ({"allow": ["203.0.113.11"]}, {"deny": ["203.0.113.11"]}):
            st = call("POST", "/api/device", dict({"mac": MAC}, **extra), key=KEYS[n])[0]
            if st != 403: bad_cells.append(f"{n} device {list(extra)[0]} -> {st}")
    call("POST", "/api/logout", {}, cookie=ck)
cells = sum(len(v) for v in matrix.values())
check(f"permission matrix: {len(PERMS)} users x (key + web session) x {len(ROUTES)} listed + {len(ADMIN_ONLY)} admin-only calls", not bad_cells, f"{cells} calls; bad: {bad_cells[:10]}")
json.dump(matrix, open(os.path.dirname(OUT) + "/perm-matrix.json", "w"), indent=1)
# A change made with a key waits for a confirm; the key can send it (fixed in this run: was 404).
s1 = call("POST", "/api/list", {"list": "black", "add": "198.51.100.250"}, key=KEYS["p_block_list"])[0]
s2, cj, _, _ = call("POST", "/api/confirm", {}, key=KEYS["p_block_list"])
s3, lg, _, _ = adm("GET", "/api/log?q=" + urllib.parse.quote("Kept: added 198.51.100.250") + "&limit=5")
check("key change + POST /api/confirm with the key: kept", s1 == 200 and s2 == 200 and (cj or {}).get("kept") is True and lg["total"] >= 1, (s1, s2, cj))
adm("POST", "/api/list", {"list": "black", "remove": "198.51.100.250"}); adm("POST", "/api/confirm", {})
# Clean up what the block_list user added.
adm("POST", "/api/list", {"list": "black", "remove": "203.0.113.9"})

# ---------- one user, both ways ----------
s, j, _, _ = save_user("both", "custom", ["status", "log"], True, True, UPW); _, kb = new_key("both"); save_secret("key-both", kb)
s, ckb = login("both", UPW)
check("user with web + API: session and key both work", call("GET", "/api/dashboard", cookie=ckb)[0] == 200 and call("GET", "/api/dashboard", key=kb)[0] == 200 and call("GET", "/api/devices", key=kb)[0] == 403 and call("GET", "/api/devices", cookie=ckb)[0] == 403)
check("POST with a session but no X-FG header is refused", call("POST", "/api/alerts/clear", {"ids": [-1]}, cookie=ADM, xfg=False)[0] == 403)
check("a key never opens a page", call("GET", "/", key=kb)[0] == 404)
check("a key can't be used for /api/login", call("POST", "/api/login", {"user": "admin", "password": PW}, key=kb)[0] == 404)
st = call("GET", "/api/me", key="fgk_" + "0" * 64, cookie=ADM, src="10.10.10.62")[0]
check("valid admin cookie + wrong key: the key decides (401)", st == 401, st)
s, me, _, _ = call("GET", "/api/me", key=kb)
check("/api/me via key", s == 200 and me.get("name") == "both" and me.get("admin") is False and me.get("perms") == ["status", "log"], me)

# ---------- keys: replace, revoke, api off, web off ----------
_, kb2 = new_key("both"); save_secret("key-both", kb2)
check("New Key: the old key stops (401), the new one works", call("GET", "/api/me", key=kb, src="10.10.10.62")[0] == 401 and call("GET", "/api/me", key=kb2)[0] == 200)
s, uv, _, _ = adm("GET", "/api/users")
ub = next(u for u in uv["users"] if u["name"] == "both")
check("API Keys table data: last used and from are filled", ub["key_used"] > 0 and ub["key_from"] == "10.10.10.60" and ub["key_hint"].startswith("fgk_"), {k: ub[k] for k in ("key_hint", "key_used", "key_from")})
s, _, _, _ = adm("POST", "/api/users", {"action": "revoke_key", "name": "both"})
check("Revoke: key refused at once (401)", s == 200 and call("GET", "/api/me", key=kb2, src="10.10.10.62")[0] == 401)
_, kb3 = new_key("both"); save_secret("key-both", kb3)
save_user("both", "custom", ["status", "log"], True, False, "", old="both")
check("API switched off: the key is refused (401)", call("GET", "/api/me", key=kb3, src="10.10.10.63")[0] == 401)
save_user("both", "custom", ["status", "log"], True, True, "", old="both")
check("API switched on again: same key works", call("GET", "/api/me", key=kb3)[0] == 200)
save_user("both", "custom", ["status", "log"], False, True, "", old="both")
check("Web switched off: open session ends (401)", call("GET", "/api/dashboard", cookie=ckb)[0] == 401)
s, _ = login("both", UPW, src="10.10.10.63")
check("Web switched off: sign-in refused", s != 200, s)
check("Web off, API on: key still works", call("GET", "/api/dashboard", key=kb3)[0] == 200)
save_user("both", "custom", ["log"], False, True, "", old="both")
check("Permission taken away works on the next call (403)", call("GET", "/api/dashboard", key=kb3)[0] == 403)

# ---------- wrong keys and lockout (own address .61) ----------
codes = [call("GET", "/api/me", key="fgk_" + "1" * 64, src="10.10.10.61")[0] for _ in range(6)]
check("wrong key -> 401 five times, then 429 (sign-in lockout)", codes == [401] * 5 + [429], codes)
s, _ = login("admin", PW, src="10.10.10.61")
check("the locked-out address can't sign in with the right password either", s == 429, s)
check("other addresses are not locked out", call("GET", "/api/me", key=KEYS["p_status"])[0] == 200)
st = call("GET", "/api/me", raw_auth="Basic YWRtaW46eA==", src="10.10.10.63")[0]
check("non-Bearer Authorization is treated as a wrong key", st == 401, st)

# ---------- last admin, self removal, sessions, password ----------
s, j, _, _ = save_user("admin", "custom", [], True, False, "", old="admin")
check("last admin can't be made Custom", s == 400, (j or {}).get("error"))
s, j, _, _ = save_user("admin", "admin", [], False, True, "", old="admin")
check("last admin can't switch off web sign-in", s == 400, (j or {}).get("error"))
s, j, _, _ = adm("POST", "/api/users", {"action": "remove", "name": "admin"})
check("can't remove yourself", s == 400, (j or {}).get("error"))
save_user("admin2", "admin", [], False, True)
s, j, _, _ = save_user("admin", "custom", [], True, False, "", old="admin")
check("an API-only admin doesn't count as the last admin", s == 400, (j or {}).get("error"))
s, _, _, _ = adm("POST", "/api/users", {"action": "remove", "name": "admin2"})
check("Remove another user", s == 200 and not any(u["name"] == "admin2" for u in adm("GET", "/api/users")[1]["users"]))
# Monitoring-only and Jarvis-like users for the page tests.
MON = ["status", "devices", "alerts", "log", "firewall_view", "speed_view", "updates_view"]
save_user("watcher", "custom", MON, True, False, UPW)
save_user("jarvis", "custom", MON + ["device_actions", "block_list"], True, True, UPW)
_, kj = new_key("jarvis"); save_secret("key-jarvis", kj)
s, ckw = login("watcher", UPW)
s, uv, _, _ = adm("GET", "/api/users")
sess = [x for x in uv["sessions"] if x["user"] == "watcher"]
check("Signed In list shows the watcher session", len(sess) >= 1, len(sess))
for x in sess: adm("POST", "/api/users", {"action": "end_session", "id": x["id"]})
check("Sign out (end_session) ends that session", call("GET", "/api/dashboard", cookie=ckw)[0] == 401)
NEWPW = "battery horse correct staple"
s, _, _, _ = adm("POST", "/api/users", {"action": "password", "password": NEWPW})
ok1 = login("admin", NEWPW, src="10.10.10.63")[0] == 200
s2, _, _, _ = adm("POST", "/api/users", {"action": "password", "password": PW})
check("Your Password changes the admin's own password (and back)", s == 200 and ok1 and s2 == 200 and login("admin", PW, src="10.10.10.63")[0] == 200)
check("Short password refused", adm("POST", "/api/users", {"action": "password", "password": "short"})[0] == 400)
s, j, _, _ = save_user("p_status", "custom", ["status", "bogus"], True, True, "", old="p_status")
check("unknown permission id refused", s == 400, (j or {}).get("error"))
check("/settings/account and /settings/users both open the page", all(call("GET", p, cookie=ADM)[0] == 200 for p in ("/settings/users", "/settings/account", "/settings/notify", "/settings/api")))
# Refusals in the Capture Log.
s, lg, _, _ = adm("GET", "/api/log?kind=alert&q=was+refused&limit=5")
check("refusals are written to the Capture Log", s == 200 and lg["total"] > 0, lg["total"] if lg else None)

# ---------- alerts: clear via handle_alerts key ----------
s, d, _, _ = adm("GET", "/api/dashboard")
al = d.get("alerts", [])
if al:
    one = al[0]["id"]
    st = call("POST", "/api/alerts/clear", {"ids": [one]}, key=KEYS["p_handle_alerts"])[0]
    s, d2, _, _ = adm("GET", "/api/dashboard")
    gone = all(a["id"] != one for a in d2.get("alerts", []))
    s, lg, _, _ = adm("GET", "/api/log?limit=1000")
    row = next((r for r in lg["rows"] if r.get("id") == one), None)
    check("Clear one alert: leaves dashboard, stays in log marked handled", st == 200 and gone and row and row.get("handled"), {"id": one, "row_handled": row and row.get("handled")})
    st = call("POST", "/api/alerts/clear", {"ids": [one]}, key=KEYS["p_status"])[0]
    check("Clear refused without handle_alerts", st == 403, st)
else:
    check("dashboard has alerts to clear", False, "none")
check("Clear with no ids -> 400", call("POST", "/api/alerts/clear", {"ids": []}, key=KEYS["p_handle_alerts"])[0] == 400)
check("Clear with 501 ids -> 400", call("POST", "/api/alerts/clear", {"ids": list(range(501))}, key=KEYS["p_handle_alerts"])[0] == 400)

json.dump({"results": results, "fails": fails}, open(OUT, "w"), indent=1)
print(f"\n{len(results) - len(fails)} passed, {len(fails)} failed")
sys.exit(1 if fails else 0)
