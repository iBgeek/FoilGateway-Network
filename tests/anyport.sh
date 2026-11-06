#!/bin/bash
# Setup on a box with three ports, where the browser's cable moves.
# Needs root, ip, nft, python3, node with puppeteer-core, google-chrome.
#
#   lap (the browser)          gw                     rt (home router)
#   la 10.77.0.10        --    pa 10.77.0.1
#      169.254.10.10
#   lb (cable not in yet) --   pb (nothing)
#                              pc (gets DHCP)    --   r0 10.10.10.1, DHCP server
set -u
cd "$(dirname "$0")"
BIN=$(realpath "${BIN:-../target/x86_64-unknown-linux-musl/release/foilgw}")
SHOTS=$(realpath -m "${SHOTS:-../_notes/shots}")
ST=$(mktemp -d /tmp/fgnet-ap.XXXX)
PASS=0; FAIL=0
gw() { ip netns exec ap-gw "$@"; }
lap() { ip netns exec ap-lap "$@"; }
rt() { ip netns exec ap-rt "$@"; }
cleanup() { for n in ap-gw ap-lap ap-rt; do ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT
cleanup
for n in ap-gw ap-lap ap-rt; do ip netns add $n; ip netns exec $n ip link set lo up; done
ip link add pa netns ap-gw type veth peer name la netns ap-lap
ip link add pb netns ap-gw type veth peer name lb netns ap-lap
ip link add pc netns ap-gw type veth peer name r0 netns ap-rt
gw ip addr add 10.77.0.1/24 dev pa
for p in pa pb pc; do gw ip link set $p up; done
lap ip addr add 10.77.0.10/24 dev la; lap ip addr add 169.254.10.10/16 dev la; lap ip link set la up
lap ip route add 224.0.0.0/4 dev la
rt ip addr add 10.10.10.1/24 dev r0; rt ip link set r0 up
rt python3 dhcpd.py r0 10.10.10.50 10.10.10.1 > $ST/dhcpd.log 2>&1 &
# Stand-in for sshd on the gateway.
gw python3 -c 'import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",22));s.listen(9)
while True: c,_=s.accept();c.send(b"SSH-2.0-test\r\n");c.close()' &
mkdir -p "$SHOTS"; rm -f "$SHOTS"/ap-*.png

export FOILGW_CONF=$ST/gateway.conf FOILGW_STATE=$ST FOILGW_ALLOW_NO_SYSTEMD=1 FOILGW_VETH_PORTS=1 FOILGW_ROLLBACK_SECS=20
start() { gw $BIN serve </dev/null >> $ST/serve.log 2>&1 & }
start
sleep 2

check() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1 (expected $3, got $2)"; fi; }
ssh_from() { lap timeout 3 python3 -c "import socket,sys;s=socket.create_connection(('$1',22),2);print(s.recv(20).decode().strip())" 2>/dev/null || echo closed; }

echo "Before the browser"
for i in $(seq 1 20); do gw ip -4 -o addr show dev pc | grep -q 10.10.10.50 && break; sleep 1; done
check "WAN side gets its address by DHCP" "$(gw ip -4 -o addr show dev pc | grep -o '10.10.10.50/24' | head -1)" "10.10.10.50/24"
check "setup address on every port" "$(for p in pa pb pc; do gw ip -4 -o addr show dev $p | grep -c 169.254.42.1; done | tr -d '\n')" "111"
check "foilgateway.local answers on pa" "$(lap python3 mdnsq.py la)" "10.77.0.1"
sleep 17
check "router answered on pc, so no DHCP server of ours" "$(gw ss -Huln 'sport = :67' | wc -l)$(gw ip -4 -o addr show dev pc | grep -c 192.168.30.1)" "00"

# The browser drives the rest. It calls back into this script to move the
# cable and to restart the service.
cat > $ST/move.sh <<M
#!/bin/bash
# Pull the cable out of pa and put it into pb.
ip netns exec ap-lap ip link set la down
ip netns exec ap-lap ip addr flush dev la
ip netns exec ap-lap ip addr add 169.254.10.10/16 dev lb
ip netns exec ap-lap ip link set lb up
ip netns exec ap-lap ip route replace 224.0.0.0/4 dev lb
M
cat > $ST/restart.sh <<R
#!/bin/bash
ip netns pids ap-gw | while read p; do grep -q foilgw /proc/\$p/cmdline 2>/dev/null && kill \$p; done
sleep 1
FOILGW_CONF=$ST/gateway.conf FOILGW_STATE=$ST FOILGW_ALLOW_NO_SYSTEMD=1 FOILGW_VETH_PORTS=1 FOILGW_ROLLBACK_SECS=20 ip netns exec ap-gw $BIN serve </dev/null >> $ST/serve.log 2>&1 &
R
chmod +x $ST/move.sh $ST/restart.sh
echo "Browser"
lap env NODE_PATH=/tmp/pt/node_modules ST=$ST node anyport.js https://10.77.0.1:8443 "$SHOTS" 2>&1 | sed 's/^/  /'
R=${PIPESTATUS[0]}
if [ "$R" != 0 ] && [ -n "${HOLD:-}" ]; then echo holding; sleep $HOLD; fi
check "browser walk" "$R" 0

echo "After setup"
check "gateway.conf has the new roles" "$(grep -E '^(lan|wan) =' $ST/gateway.conf | tr -d ' ' | tr '\n' ' ')" "lan=pb wan=pc "
check "setup address gone from pa and pc" "$(for p in pa pc; do gw ip -4 -o addr show dev $p | grep -c 169.254.42.1; done | tr -d '\n')" "00"
check "pb and pc are in the bridge, pa isn't" "$(gw ip -o link show master br-fgw | awk -F': ' '{print $2}' | cut -d@ -f1 | sort | tr '\n' ' ')" "pb pc "
check "setup address kept on the bridge, the browser used it" "$(gw ip -4 -o addr show dev br-fgw | grep -c 169.254.42.1)" "1"
check "bridge has the router's DHCP address" "$(gw ip -4 -o addr show dev br-fgw | grep -o '10.10.10.50/24' | head -1)" "10.10.10.50/24"
check "members have no addresses of their own" "$(for p in pb pc; do gw ip -4 -o addr show dev $p | wc -l; done | tr -d '\n')" "00"
check "SSH reachable from the LAN" "$(ssh_from 169.254.42.1)" "SSH-2.0-test"
check "foilgateway.local answers on the LAN side" "$(lap python3 mdnsq.py lb | grep -cE '^(169\.254\.42\.1|10\.10\.10\.234)$')" "1"
check "foilgateway.local answers on the router side too" "$(rt python3 mdnsq.py r0 | grep -cE '^(169\.254\.42\.1|10\.10\.10\.234)$')" "1"
check "SSH reachable from the router side" "$(rt timeout 3 python3 -c "import socket;s=socket.create_connection(('10.10.10.50',22),2);print(s.recv(20).decode().strip())" 2>/dev/null || echo closed)" "SSH-2.0-test"
check "no safety free-pass in forward" "$(gw nft list chain inet foilgateway forward | grep -c foilgw-safety || true)" "0"
check "first input rule is safety" "$(gw nft list chain inet foilgateway input | grep -v hook | grep -m1 -E 'accept|drop|jump' | grep -c foilgw-safety)" "1"
check "SSH and settings open in the input chain" "$(gw nft list chain inet foilgateway input | grep -c 'tcp dport { 22, 8443 } accept' | awk '{print ($1>0)}')" "1"
check "wizard file says done" "$(python3 -c "import json;w=json.load(open('$ST/setup.json'));print(w['active'], w['step'])")" "False Done"
check "no DHCP server of ours after setup" "$(gw ss -Huln 'sport = :67' | wc -l)" "0"
check "no 192.168.30.1 left on any port" "$(gw ip -4 -o addr | grep -c 192.168.30.1)" "0"
check "admin account made once" "$(python3 -c "import json;print([u['name'] for u in json.load(open('$ST/users.json'))])")" "['admin']"
echo "serve log:"; grep -v '^foilgw: settings page' $ST/serve.log | tail -5 | sed 's/^/  /'
echo "passed $PASS, failed $FAIL"
[ $FAIL = 0 ]
