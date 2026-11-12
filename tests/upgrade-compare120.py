#!/usr/bin/env python3
# Compares what snap120.py saved under 1.1.2 and under 1.2.0 on the same
# state. Usage: upgrade-compare120.py STATE before.json after.json
import json, sys
st, a, b = sys.argv[1:4]
A, B = json.load(open(a)), json.load(open(b))
bad = []
for k in ("login", "status_user", "black", "white", "mode", "devices", "cfg", "timezone", "conf_sha", "policy_keys", "policy_black", "policy_white"):
    print(f"{'same' if A[k] == B[k] else 'DIFF'} {k}: {str(B[k])[:120]}")
    if A[k] != B[k]: bad.append(k)
print("1.2.0 /api/status admin:", B["status_admin"]); bad += [] if B["status_admin"] is True else ["admin"]
pa, pb = json.load(open(st + "/policy-1.1.2.json")), json.load(open(st + "/policy-1.2.0.json"))
diffs = []
def walk(x, y, p=""):
    if isinstance(x, dict) and isinstance(y, dict):
        for k in sorted(set(x) | set(y)): walk(x.get(k), y.get(k), p + "/" + k)
    elif x != y: diffs.append(f"{p}: {str(x)[:60]} -> {str(y)[:60]}")
walk(pa, pb)
print("policy.json differences:", diffs or "none")
ua, ub = json.load(open(st + "/users-1.1.2.json")), json.load(open(st + "/users-1.2.0.json"))
print("users.json 1.1.2:", [sorted(u) for u in ua], " 1.2.0 (before any user change):", [sorted(u) for u in ub])
same_hash = [x["hash"] == y["hash"] for x, y in zip(ua, ub)]
print("admin password hashes unchanged:", all(same_hash) and len(ua) == len(ub))
if not (all(same_hash) and len(ua) == len(ub)): bad.append("users")
live = [d for d in diffs if not any(s in d for s in ("/last_seen", "/out_seen", "/hostname", "/ip:", "/inbound"))]
print("non-live policy differences:", live or "none")
print("UPGRADE", "PASS" if not bad and not live else "FAIL " + str(bad + live))
