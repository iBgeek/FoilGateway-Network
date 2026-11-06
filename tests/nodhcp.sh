#!/bin/bash
# Setup on a network where nothing hands out addresses: the gateway serves
# 192.168.30.x itself, then stands down when a real router turns up.
# Needs root, ip, nft, ss, python3, node with puppeteer-core, google-chrome.
#
#   pcl (a PC, no address)  --  pa  gw  pc  --  r0 (router, DHCP off at first)
set -u
cd "$(dirname "$0")"
BIN=$(realpath "${BIN:-../target/x86_64-unknown-linux-musl/release/foilgw}")
SHOTS=$(realpath -m "${SHOTS:-../_notes/shots}")
ST=$(mktemp -d /tmp/fgnet-nd.XXXX)
PASS=0; FAIL=0
gw() { ip netns exec nd-gw "$@"; }
pcl() { ip netns exec nd-pc "$@"; }
rt() { ip netns exec nd-rt "$@"; }
cleanup() { for n in nd-gw nd-pc nd-rt; do ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT
cleanup
for n in nd-gw nd-pc nd-rt; do ip netns add $n; ip netns exec $n ip link set lo up; done
ip link add pa netns nd-gw type veth peer name la netns nd-pc
ip link add pc netns nd-gw type veth peer name r0 netns nd-rt
for p in pa pc; do gw ip link set $p up; done
pcl ip link set la up
rt ip addr add 10.10.10.1/24 dev r0; rt ip link set r0 up
mkdir -p "$SHOTS"; rm -f "$SHOTS"/nd-*.png
export FOILGW_CONF=$ST/gateway.conf FOILGW_STATE=$ST FOILGW_ALLOW_NO_SYSTEMD=1 FOILGW_VETH_PORTS=1 FOILGW_ROLLBACK_SECS=20
gw $BIN serve </dev/null >> $ST/serve.log 2>&1 &
check() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1 (expected $3, got $2)"; fi; }
servers() { gw ss -Huln 'sport = :67' | wc -l; }

echo "No router anywhere"
check "nothing served in the first seconds" "$(sleep 5; servers)" "0"
GOT=$(pcl python3 dhcpc.py la 40)
check "the PC gets a 192.168.30.x address" "$(echo $GOT | grep -cE '^192\.168\.30\.(1[0-9][0-9])$')" "1"
check "gateway took 192.168.30.1 on pa and pc" "$(for p in pa pc; do gw ip -4 -o addr show dev $p | grep -c '192.168.30.1/24'; done | tr -d '\n')" "11"
check "page reachable at 192.168.30.1" "$(pcl curl -sk -o /dev/null -w '%{http_code}' https://192.168.30.1:8443/setup)" "200"
check "foilgateway.local gives 192.168.30.1" "$(pcl ip route replace 224.0.0.0/4 dev la; pcl python3 mdnsq.py la)" "192.168.30.1"

echo "A router turns up on pc"
rt python3 dhcpd.py r0 10.10.10.50 10.10.10.1 > $ST/dhcpd.log 2>&1 &
for i in $(seq 1 30); do gw ip -4 -o addr show dev pc | grep -q 10.10.10.50 && ! gw ip -4 -o addr show dev pc | grep -q 192.168.30.1 && break; sleep 1; done
check "pc stood down and took the router's lease" "$(gw ip -4 -o addr show dev pc | grep -c 192.168.30.1)$(gw ip -4 -o addr show dev pc | grep -c 10.10.10.50)" "01"
check "still serving on pa only" "$(servers)$(gw ip -4 -o addr show dev pa | grep -c 192.168.30.1)" "11"
check "the router's DHCP server answered pc" "$(grep -c offer $ST/dhcpd.log | awk '{print ($1>0)}')" "1"

echo "Browser"
pcl env NODE_PATH=/tmp/pt/node_modules node nodhcp.js https://192.168.30.1:8443 "$SHOTS" 2>&1 | sed 's/^/  /'
check "browser walk" "${PIPESTATUS[0]}" 0

echo "After setup"
check "gateway.conf has the roles" "$(grep -E '^(lan|wan) =' $ST/gateway.conf | tr -d ' ' | tr '\n' ' ')" "lan=pa wan=pc "
check "our DHCP server is gone" "$(servers)" "0"
check "192.168.30.1 kept on the bridge, the browser used it" "$(gw ip -4 -o addr show dev br-fgw | grep -c 192.168.30.1/24)" "1"
check "nothing left on pa or pc themselves" "$(for p in pa pc; do gw ip -4 -o addr show dev $p | wc -l; done | tr -d '\n')" "00"
check "bridge has the router's lease" "$(for i in $(seq 20); do gw ip -4 -o addr show dev br-fgw | grep -q 10.10.10.50 && break; sleep 1; done; gw ip -4 -o addr show dev br-fgw | grep -c 10.10.10.50)" "1"
check "the PC now gets the router's DHCP through the bridge" "$(pcl python3 dhcpc.py la 15)" "10.10.10.50"
check "first input rule is safety" "$(gw nft list chain inet foilgateway input | grep -v hook | grep -m1 -E 'accept|drop|jump' | grep -c foilgw-safety)" "1"
echo "passed $PASS, failed $FAIL"
[ $FAIL = 0 ]
