#!/usr/bin/env python3
# Signs in as admin and saves what the upgrade test compares: settings,
# firewall lists, devices, and hashes of the state files.
# Usage (in fgw-lap): snap120.py URL STATE OUT.json
import json, ssl, sys, hashlib, urllib.request, http.cookiejar
url, st, out = sys.argv[1:4]
ctx = ssl._create_unverified_context()
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(jar))
def call(path, body=None):
    r = urllib.request.Request(url + path, data=None if body is None else json.dumps(body).encode(), headers={"X-FG": "1", "Content-Type": "application/json"})
    try:
        with op.open(r, timeout=20) as f: return f.status, json.loads(f.read() or b"null")
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"null")
res = {"login": call("/api/login", {"user": "admin", "password": "correct horse battery"})[0]}
s = call("/api/settings")[1]; f = call("/api/firewall")[1]; d = call("/api/devices")[1]; stt = call("/api/status")[1]
res["version"] = stt.get("version"); res["status_user"] = stt.get("user"); res["status_admin"] = stt.get("admin")
res["cfg"] = s.get("cfg"); res["timezone"] = s.get("timezone")
res["black"] = sorted(e["entry"] for e in f.get("black", [])) if isinstance(f.get("black"), list) and f["black"] and isinstance(f["black"][0], dict) else f.get("black")
res["white"] = sorted(e["entry"] for e in f.get("white", [])) if isinstance(f.get("white"), list) and f["white"] and isinstance(f["white"][0], dict) else f.get("white")
res["mode"] = f.get("mode")
res["devices"] = sorted((x.get("mac"), x.get("policy"), x.get("name")) for x in d.get("devices", []))
users = json.load(open(st + "/users.json"))
res["users_file"] = [{"name": u["name"], "role": u.get("role"), "hash_sha": hashlib.sha256(u.get("hash", "").encode()).hexdigest()[:16], "fields": sorted(u)} for u in users]
pol = json.load(open(st + "/policy.json"))
import shutil; shutil.copy(st + "/policy.json", st + "/policy-" + res["version"] + ".json"); shutil.copy(st + "/users.json", st + "/users-" + res["version"] + ".json")
res["policy_keys"] = sorted(pol); res["policy_black"] = pol.get("black"); res["policy_white"] = pol.get("white")
res["policy_sha"] = hashlib.sha256(json.dumps(pol, sort_keys=True).encode()).hexdigest()[:16]
res["conf_sha"] = hashlib.sha256(open(st + "/gateway.conf", "rb").read()).hexdigest()[:16]
json.dump(res, open(out, "w"), indent=1, default=str)
print(json.dumps({k: res[k] for k in ("login", "version", "status_user", "status_admin", "black", "white", "mode", "devices", "users_file", "policy_sha", "conf_sha")}, default=str))
