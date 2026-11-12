#!/bin/bash
# The whole 1.2.0 bench run, in order. Needs root. Output: V/run120.log
set -u
cd "$(dirname "$0")"
V=${V:-/workspace/fg120/versions/1.2.0/verification}
ST=/tmp/fg120-run; export ST
OLD=${OLD:-/workspace/fgnet/versions/1.1.2/foilgw-x86_64}
NEW=$(realpath ../target/x86_64-unknown-linux-musl/release/foilgw)
NP=/tmp/pt/node_modules
lap() { ip netns exec fgw-lap "$@"; }
step() { echo; echo "===== $* ($(date '+%H:%M:%S %Z'))"; }
./net120.sh down >/dev/null; rm -rf $ST
step "bench up"; ./net120.sh up
step "1.1.2 ($(sha256sum $OLD | cut -c1-16)) first setup through the page"
./net120.sh start $OLD || exit 1
lap env NODE_PATH=$NP node setup120.cjs $(cat $ST/url) $V/upgrade || exit 1
./net120.sh traffic
U=$(cat $ST/url)
lap curl -sk -c $ST/j -H 'X-FG: 1' -d '{"user":"admin","password":"correct horse battery"}' $U/api/login >/dev/null
MAC=$(lap curl -sk -b $ST/j $U/api/devices | python3 -c "import json,sys; print(json.load(sys.stdin)['devices'][0]['mac'])")
lap curl -sk -b $ST/j -H 'X-FG: 1' -d "{\"mac\":\"$MAC\",\"name\":\"Office PC\"}" -o /dev/null -w "name device: %{http_code}\n" $U/api/device; rm -f $ST/j
sleep 2
lap python3 snap120.py $U $ST $V/upgrade/before-1.1.2.json
step "stop 1.1.2, start 1.2.0 ($(sha256sum $NEW | cut -c1-16)) on the same state"
./net120.sh stop; ./net120.sh start $NEW || exit 1
sleep 3
lap python3 snap120.py $(cat $ST/url) $ST $V/upgrade/after-1.2.0.json
python3 upgrade-compare120.py $ST $V/upgrade/before-1.1.2.json $V/upgrade/after-1.2.0.json
U=$(cat $ST/url)
step "API: users, keys, permissions, alerts"; lap python3 api120.py $U $ST $V/api/api120.json
step "notifications"; lap python3 notify120.py $U $ST $V/notify/notify-setup.json
step "pages in Chrome"; lap env NODE_PATH=$NP node ui120.cjs $U $V/ui $ST
step "Send Test latency with Dead End failing"; lap python3 latency120.py $U $ST
step "soak ${SOAK:-600} s"; ./soak120.sh
step "after the soak: notifications"; lap python3 notify120.py $U $ST $V/notify/notify-after-soak.json check
step "Send Test latency after the soak"; lap python3 latency120.py $U $ST
step "setup run again: only admins reach it"
lap curl -sk -c $ST/ja -H 'X-FG: 1' -d '{"user":"admin","password":"correct horse battery"}' $U/api/login >/dev/null
lap curl -sk -c $ST/jw -H 'X-FG: 1' -d '{"user":"watcher","password":"custom-password-123"}' $U/api/login >/dev/null
lap curl -sk -b $ST/ja -H 'X-FG: 1' -d '{"action":"rerun_setup","confirm":"YES"}' -o /dev/null -w "admin rerun_setup %{http_code}\n" $U/api/settings
lap curl -sk -b $ST/ja -o /dev/null -w "admin GET /api/setup/info %{http_code}\n" $U/api/setup/info
lap curl -sk -b $ST/jw -o /dev/null -w "watcher GET /api/setup/info %{http_code}\n" $U/api/setup/info
lap curl -sk -b $ST/jw -H 'X-FG: 1' -d '{"admin_port":9443}' -o /dev/null -w "watcher POST /api/setup/state %{http_code}\n" $U/api/setup/state
lap curl -sk -b $ST/jw -H 'X-FG: 1' -d '{}' -o /dev/null -w "watcher POST /api/setup %{http_code}\n" $U/api/setup
lap curl -sk -b $ST/jw -o /dev/null -w "watcher GET /setup %{http_code}\n" $U/setup
rm -f $ST/ja $ST/jw
step "serve log tail"; tail -15 $ST/serve.log
step "teardown"; ./net120.sh stop; ./net120.sh down
