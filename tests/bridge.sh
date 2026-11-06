#!/bin/bash
# Bridge mode against the real kernel, in throwaway network namespaces.
# Needs root, ip, nft, python3, curl. Nothing touches the host's own links.
#
#   rtr (home router)           gw                         cli (a LAN device)
#   10.10.10.1 DHCP+DNS  --  eth-wan ┐                 ┌ eth-lan  --  c-lan (DHCP)
#   1.1.1.1 9.9.9.9 8.8.8.8          br-fgw (10.10.10.x)
#                                                      └ eth-lan2 --  safe 10.10.10.42
set -u
HERE=$(realpath "$(dirname "$0")")
BIN=$(realpath "${BIN:-$HERE/../target/x86_64-unknown-linux-musl/release/foilgw}")
ST=$(mktemp -d /tmp/fgnet-br.XXXX)
NS="fgb-rtr fgb-gw fgb-cli fgb-safe"
PASS=0; FAIL=0
rtr() { ip netns exec fgb-rtr "$@"; }
gw() { ip netns exec fgb-gw "$@"; }
cli() { ip netns exec fgb-cli "$@"; }
safe() { ip netns exec fgb-safe "$@"; }
cleanup() { for n in $NS; do ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del $n 2>/dev/null; done; rm -rf /etc/netns/fgb-gw; }
[ -z "${KEEP:-}" ] && trap cleanup EXIT
cleanup
for n in $NS; do ip netns add $n; ip netns exec $n ip link set lo up; done
ip link add eth-wan netns fgb-gw type veth peer name r-lan netns fgb-rtr
ip link add eth-lan netns fgb-gw type veth peer name c-lan netns fgb-cli
ip link add eth-lan2 netns fgb-gw type veth peer name s-lan netns fgb-safe
rtr ip addr add 10.10.10.1/24 dev r-lan; rtr ip link set r-lan up
for a in 1.1.1.1 9.9.9.9 8.8.8.8; do rtr ip addr add $a/32 dev lo; done
# Before setup the gateway has a plain address on its WAN port.
gw ip addr add 10.10.10.5/24 dev eth-wan
for p in eth-wan eth-lan eth-lan2; do gw ip link set $p up; done
gw ip route add default via 10.10.10.1
cli ip link set c-lan up
safe ip addr add 10.10.10.42/24 dev s-lan; safe ip link set s-lan up; safe ip route add default via 10.10.10.1
mkdir -p /etc/netns/fgb-gw; echo "nameserver 10.10.10.1" > /etc/netns/fgb-gw/resolv.conf
sysctl -qw net.netfilter.nf_log_all_netns=1 2>/dev/null
rtr python3 -u "$HERE/router.py" r-lan 10.10.10.1 >$ST/router.log 2>&1 &
rtr python3 -m http.server 80 --bind 0.0.0.0 </dev/null >/dev/null 2>&1 &
# Ports on the router side, to try Block from LAN against.
for p in 445 5000; do rtr python3 -m http.server $p --bind 0.0.0.0 </dev/null >/dev/null 2>&1 & done
safe python3 -m http.server 80 --bind 0.0.0.0 </dev/null >/dev/null 2>&1 &
for p in 80 3389 445 5000; do cli python3 -m http.server $p --bind 0.0.0.0 </dev/null >/dev/null 2>&1 & done
# Stand-ins for the settings page and SSH on the gateway.
# A plain echo service, to hold one connection open across a policy change.
rtr python3 -c "
import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',7000));s.listen(8)
def h(c):
  while True:
    d=c.recv(64)
    if not d: break
    c.sendall(d)
while True: threading.Thread(target=h,args=(s.accept()[0],),daemon=True).start()" </dev/null >/dev/null 2>&1 &
for p in 8443 22; do gw python3 -m http.server $p --bind 0.0.0.0 </dev/null >/dev/null 2>&1 & done
sleep 1
CMAC=$(cli cat /sys/class/net/c-lan/address)

printf 'mode=bridge\nlan=eth-lan,eth-lan2\nwan=eth-wan\nsafety_hosts=10.10.10.42\nadmin_port=8443\nrollback_secs=60\n' > $ST/gateway.conf
export FOILGW_CONF=$ST/gateway.conf FOILGW_STATE=$ST FOILGW_ALLOW_NO_SYSTEMD=1
mkdir -p $ST/feeds; echo 8.8.8.8 > $ST/feeds/telemetry-windows-ips.txt

res() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1 (expected $2, got $3)"; fi; }
reach() { if "$3" curl -s -o /dev/null -m 2 "http://$4/" 2>/dev/null; then echo ok; else echo blocked; fi; }
check() { res "$1" "$2" "$(reach "$1" "$2" "$3" "$4")"; } # name expect ns-fn dest
policy() { cat > $ST/policy.json; gw $BIN apply >/dev/null 2>$ST/err || { echo "apply failed: $(cat $ST/err)"; FAIL=$((FAIL+1)); }; gw $BIN confirm >/dev/null 2>&1; }
dev() { echo "\"$CMAC\": {\"policy\": \"$1\" ${2:-}}"; }
resolve() { "$1" python3 -c "
import socket,struct,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
q=b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b''.join(bytes([len(x)])+x.encode() for x in '$2'.split('.'))+b'\x00\x00\x01\x00\x01'
s.sendto(q,('10.10.10.1',53))
try: r=s.recv(512); print(socket.inet_ntoa(r[-4:]) if r[7] else 'nx')
except Exception: print('blocked')"; }

echo "Rollback takes the bridge apart"
echo '{"mode":"normal"}' > $ST/policy.json
gw $BIN apply >/dev/null && gw $BIN bridge >/dev/null
res "bridge built" yes "$(gw ip link show br-fgw >/dev/null 2>&1 && echo yes || echo no)"
gw $BIN rollback >/dev/null 2>$ST/err
res "bridge gone after rollback" no "$(gw ip link show br-fgw >/dev/null 2>&1 && echo yes || echo no)"
res "WAN port has its address back" yes "$(gw ip -4 addr show dev eth-wan | grep -q 10.10.10.5/24 && echo yes || echo no)"
res "default route back" yes "$(gw ip route show default | grep -q 'via 10.10.10.1 dev eth-wan' && echo yes || echo no)"
res "LAN ports free again" none "$(gw ip -j link show eth-lan | python3 -c 'import json,sys; print(json.load(sys.stdin)[0].get("master","none"))')"
res "no rules left" none "$(gw nft list table inet foilgateway >/dev/null 2>&1 && echo some || echo none)"

echo "Setup in bridge mode"
gw $BIN apply >/dev/null && gw $BIN bridge >/dev/null && gw $BIN confirm >/dev/null
GWIP=$(gw python3 "$HERE/dhcpc.py" br-fgw 15)
gw ip route replace default via 10.10.10.1 dev br-fgw
res "gateway got an address from the router" yes "$(case $GWIP in 10.10.10.1[0-9][0-9]) echo yes;; *) echo no;; esac)"
policy <<<'{"mode":"normal"}'
CIP=$(cli python3 "$HERE/dhcpc.py" c-lan 15)
cli ip route replace default via 10.10.10.1
res "LAN device got DHCP through the bridge" yes "$(case $CIP in 10.10.10.1[0-9][0-9]) echo yes;; *) echo no;; esac)"
res "DNS through the bridge" 1.1.1.1 "$(resolve cli one.test)"
check "device reaches the internet" ok cli 1.1.1.1
for side in rtr cli; do
  check "settings page from $side" ok $side $GWIP:8443
  check "SSH port from $side" ok $side $GWIP:22
done

echo "Black list, with a domain"
policy <<J
{"mode":"normal","black":["nine.test"],"devices":{$(dev normal)}}
J
check "Black list stops nine.test" blocked cli 9.9.9.9
check "safety host does not bypass Black list" blocked safe 9.9.9.9
echo "Telemetry"
policy <<J
{"mode":"normal","devices":{$(dev normal ',"telemetry":true')}}
J
check "telemetry address blocked for the device" blocked cli 8.8.8.8
check "other addresses fine" ok cli 1.1.1.1
echo "Device Block all"
policy <<J
{"mode":"normal","devices":{$(dev block)}}
J
check "blocked device stopped" blocked cli 1.1.1.1
check "safety host unaffected" ok safe 1.1.1.1
echo "Device LAN only"
policy <<J
{"mode":"normal","devices":{$(dev lan_only)}}
J
check "can't go out" blocked cli 1.1.1.1
check "router's own page blocked" blocked cli 10.10.10.1
check "other LAN devices fine" ok cli 10.10.10.42
res "DNS still works" 1.1.1.1 "$(resolve cli one.test)"
CIP2=$(cli python3 "$HERE/dhcpc.py" c-lan 10)
res "DHCP still works" "$CIP" "$CIP2"
echo "Absolute LAN only"
policy <<J
{"mode":"lan_only","white":["1.1.1.1"],"devices":{$(dev trusted)}}
J
check "trusted + White list still stopped" blocked cli 1.1.1.1
check "settings page still there" ok cli $GWIP:8443
check "safety host has no internet in Local Network Only" blocked safe 1.1.1.1
echo "Block everything"
policy <<J
{"mode":"block_all","devices":{$(dev trusted)}}
J
check "trusted stopped" blocked cli 8.8.8.8
check "safety host has no internet in Block Everything" blocked safe 8.8.8.8
check "safety host still reaches FoilGateway" ok safe $GWIP:8443
check "RDP from the router side blocked" blocked rtr $CIP:3389
check "settings page from the router side" ok rtr $GWIP:8443
check "SSH from the LAN" ok cli $GWIP:22

echo "From the router side"
policy <<J
{"mode":"normal","devices":{$(dev normal)}}
J
check "new connection to a LAN device blocked" blocked rtr $CIP:80
check "RDP shut by default" blocked rtr $CIP:3389
check "SMB shut by default" blocked rtr $CIP:445
policy <<J
{"mode":"normal","inbound":[{"proto":"tcp","port":3389,"on":true},{"proto":"tcp","port":445,"on":true},{"proto":"tcp","port":5000,"on":true,"custom":true}],"devices":{$(dev normal)}}
J
check "RDP open when switched on" ok rtr $CIP:3389
check "listed port 445 open when switched on" ok rtr $CIP:445
check "custom port 5000 open" ok rtr $CIP:5000
check "port 80 still shut" blocked rtr $CIP:80
policy <<J
{"mode":"normal","inbound":[{"proto":"tcp","port":3389,"on":true},{"proto":"tcp","port":3389,"mac":"$CMAC","on":false,"own":true}],"devices":{$(dev normal)}}
J
check "global Allow beats the device's Block from WAN" ok rtr $CIP:3389
policy <<J
{"mode":"normal","inbound":[{"proto":"tcp","port":445,"on":false,"lan_off":true},{"proto":"tcp","port":445,"mac":"$CMAC","on":true,"own":true}],"devices":{$(dev normal)}}
J
check "global Block both beats the device's Allow (WAN)" blocked rtr $CIP:445
check "global Block both beats the device's Allow (LAN)" blocked cli 1.1.1.1:445

echo "Block from WAN, from LAN, both"
policy <<J
{"mode":"normal","inbound":[{"proto":"tcp","port":80,"on":true,"lan_off":true}],"devices":{$(dev normal)}}
J
check "global Block from LAN stops the device going out" blocked cli 1.1.1.1
check "global Block from LAN leaves other ports" ok cli 1.1.1.1:445
check "global Block from LAN still lets WAN in" ok rtr $CIP:80
check "safety host does not bypass Block from LAN" blocked safe 1.1.1.1
policy <<J
{"mode":"normal","inbound":[{"proto":"tcp","port":5000,"on":false}],"devices":{$(dev normal)}}
J
check "global Block from WAN" blocked rtr $CIP:5000
check "global Block from WAN leaves LAN open" ok cli 1.1.1.1:5000
policy <<J
{"mode":"normal","inbound":[{"proto":"tcp","port":5000,"on":false,"lan_off":true}],"devices":{$(dev normal)}}
J
check "global Block both (WAN)" blocked rtr $CIP:5000
check "global Block both (LAN)" blocked cli 1.1.1.1:5000
policy <<J
{"mode":"normal","inbound":[{"proto":"tcp","port":80,"mac":"$CMAC","on":false,"lan_off":true,"own":true}],"devices":{$(dev normal)}}
J
check "device Block both stops it going out" blocked cli 1.1.1.1
check "device Block both stops WAN coming in" blocked rtr $CIP:80
check "device Block both leaves others alone" ok rtr 1.1.1.1
policy <<J
{"mode":"normal","inbound":[{"proto":"tcp","port":80,"mac":"$CMAC","on":true,"lan_off":true,"own":true}],"devices":{$(dev normal)}}
J
check "device Block from LAN lets WAN in" ok rtr $CIP:80
check "device Block from LAN stops it going out" blocked cli 1.1.1.1
policy <<J
{"mode":"normal","inbound":[{"proto":"tcp","port":5000,"on":true},{"proto":"tcp","port":5000,"mac":"$CMAC","on":false,"own":true}],"devices":{$(dev normal)}}
J
check "device Block from WAN under a global Allow stays open" ok rtr $CIP:5000
policy <<J
{"mode":"block_all","inbound":[{"proto":"tcp","port":3389,"on":true}],"devices":{$(dev normal)}}
J
check "Block everything beats a port Allow" blocked rtr $CIP:3389
policy <<J
{"mode":"lan_only","inbound":[{"proto":"tcp","port":3389,"on":true}],"devices":{$(dev normal)}}
J
check "LAN only beats a port Allow" blocked rtr $CIP:3389
policy <<J
{"mode":"normal","inbound":[{"proto":"tcp","port":3389,"on":false},{"proto":"tcp","port":80,"mac":"$CMAC","on":true}],"devices":{$(dev normal)}}
J
check "per-device on opens just that device" ok rtr $CIP:80
policy <<J
{"mode":"normal","devices":{$(dev block)}}
J
check "device Block all beats RDP on" blocked rtr $CIP:3389
policy <<J
{"mode":"normal","devices":{$(dev lan_only)}}
J
check "device LAN only beats RDP on" blocked rtr $CIP:3389

echo "Audit"
dmesg -C 2>/dev/null
policy <<J
{"mode":"audit","black":["9.9.9.9"],"devices":{$(dev normal)}}
J
check "whole-network audit lets a Black list address through" ok cli 9.9.9.9
sleep 1
res "the would-be block is logged as audit" yes "$(dmesg 2>/dev/null | grep -q 'fgw:audit:black .*DST=9.9.9.9' && echo yes || echo no)"
policy <<J
{"mode":"normal","black":["9.9.9.9"],"devices":{$(dev normal ',"audit_until":9223372036854775807')}}
J
check "per-device audit lets it through" ok cli 9.9.9.9
policy <<J
{"mode":"normal","black":["9.9.9.9"],"devices":{$(dev normal ',"audit_until":1')}}
J
check "audit that ran out blocks again" blocked cli 9.9.9.9
policy <<J
{"mode":"lan_only","devices":{$(dev normal ',"audit_until":9223372036854775807')}}
J
check "device audit doesn't beat LAN only" blocked cli 1.1.1.1
echo "A connection let through is looked at again after a change"
policy <<J
{"mode":"audit","black":["9.9.9.9"],"devices":{$(dev normal)}}
J
rm -f $ST/go
cli timeout 30 python3 -c "
import socket,time,os
c=socket.create_connection(('9.9.9.9',7000),timeout=3)
c.sendall(b'a'); r1=c.recv(8)
while not os.path.exists('$ST/go'): time.sleep(0.1)
try:
  c.sendall(b'b'); r2=c.recv(8)
except Exception: r2=b''
print(('open' if r1==b'a' else 'shut')+','+('open' if r2==b'b' else 'shut'))" >$ST/flow 2>/dev/null &
FLOW=$!
sleep 1.5
policy <<J
{"mode":"normal","black":["9.9.9.9"],"devices":{$(dev normal)}}
J
touch $ST/go; wait $FLOW
res "flow passed in audit, cut once audit is off" "open,shut" "$(cat $ST/flow)"

echo "Settings page for LAN devices only"
sed -i 's/^admin_from.*//' $ST/gateway.conf; echo admin_from=lan >> $ST/gateway.conf
policy <<<'{"mode":"normal"}'
check "settings page from the LAN" ok cli $GWIP:8443
check "settings page from the router side shut" blocked rtr $GWIP:8443
check "SSH from the router side still open" ok rtr $GWIP:22
check "safety host still gets the page" ok safe $GWIP:8443
sed -i 's/^admin_from.*//' $ST/gateway.conf
policy <<<'{"mode":"normal"}'
check "both sides again" ok rtr $GWIP:8443

echo "Names devices look up (passive DNS)"
policy <<<'{"mode":"normal"}'
gw timeout 6 $BIN dns-watch eth-lan 5 > $ST/dnsw 2>&1 &
W=$!; sleep 1
resolve cli one.test >/dev/null; resolve cli eight.test >/dev/null
# A query the device sends (source port 53 is the answer only) mustn't show.
wait $W
grep -qi "$CMAC looked up one.test: 1.1.1.1 ttl 60" $ST/dnsw && res "answer seen for the device that asked" y y || res "answer seen for the device that asked" y "n: $(head -3 $ST/dnsw)"
grep -qi "looked up eight.test: 8.8.8.8" $ST/dnsw && res "second answer seen" y y || res "second answer seen" y n
res "only answers reach the watcher" 2 "$(grep -c 'looked up' $ST/dnsw)"

echo "Safety and logging"
gw nft list chain inet foilgateway input | grep -v hook | grep -m1 -E 'accept|drop|jump' | grep -q foilgw-safety && res "first input rule is safety" y y || res "first input rule is safety" y n
# Forward no longer gives safety hosts a free pass to the internet.
res "no safety free-pass in forward" 0 "$(gw nft list chain inet foilgateway forward | grep -c foilgw-safety || true)"
n=$(dmesg 2>/dev/null | grep 'fgw:' | grep -c 'PHYSIN=eth-wan')
res "blocked router-side tries logged with PHYSIN" yes "$([ "$n" -gt 0 ] && echo yes || echo no)"
echo "passed $PASS, failed $FAIL"
[ $FAIL = 0 ]
