#!/bin/bash
# Setup in bridge mode on a gateway whose ports systemd-networkd looks
# after, the way Armbian's netplan leaves it: one .network for every eth*
# doing DHCP. Runs a real networkd (and a private D-Bus for networkctl)
# in the gateway's namespace. Needs root.
#
#   pc  10.10.10.42 ┐                                  (lab PC, router side)
#   rtr 10.10.10.1  ┴ rbr -- eth3 [gw: networkd + foilgw] eth2 -- lpc (DHCP, RDP)
set -u
HERE=$(realpath "$(dirname "$0")")
BIN=$(realpath "${BIN:-$HERE/../target/x86_64-unknown-linux-musl/release/foilgw}")
ST=$(mktemp -d /tmp/fgnet-nd.XXXX)
NS="fgn-rtr fgn-gw fgn-pc fgn-lpc"
PASS=0; FAIL=0
rtr() { ip netns exec fgn-rtr "$@"; }
pc() { ip netns exec fgn-pc "$@"; }
lpc() { ip netns exec fgn-lpc "$@"; }
gw() { nsenter --net=/run/netns/fgn-gw --mount=$ST/mnt/ns env FOILGW_CONF=$ST/gateway.conf FOILGW_STATE=$ST FOILGW_ALLOW_NO_SYSTEMD=1 FOILGW_VETH_PORTS=1 "$@"; }
cleanup() {
  for n in $NS; do ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null; done
  sleep 0.3; for n in $NS; do ip netns del $n 2>/dev/null; done
  umount $ST/mnt/ns 2>/dev/null; umount $ST/mnt 2>/dev/null
}
[ -z "${KEEP:-}" ] && trap cleanup EXIT
for n in $NS; do ip netns del $n 2>/dev/null; ip netns add $n; ip netns exec $n ip link set lo up; done
rtr ip link add rbr type bridge; rtr ip link set rbr up
ip link add eth3 netns fgn-gw type veth peer name r-gw netns fgn-rtr
ip link add p-lan netns fgn-pc type veth peer name r-pc netns fgn-rtr
ip link add eth2 netns fgn-gw type veth peer name l-lan netns fgn-lpc
for p in r-gw r-pc; do rtr ip link set $p master rbr; rtr ip link set $p up; done
rtr ip addr add 10.10.10.1/24 dev rbr
pc ip addr add 10.10.10.42/24 dev p-lan; pc ip link set p-lan up
lpc ip link set l-lan up
sysctl -qw net.netfilter.nf_log_all_netns=1 2>/dev/null
rtr python3 -u "$HERE/router.py" rbr 10.10.10.1 >$ST/router.log 2>&1 &
lpc python3 -m http.server 3389 --bind 0.0.0.0 </dev/null >/dev/null 2>&1 &

# The gateway's own mount namespace: its own /sys (read-only, which is
# how networkd tells there's no udev to wait for), /run/systemd, D-Bus
# and networkd config, so nothing here touches the host.
mkdir -p $ST/mnt; mount --bind $ST/mnt $ST/mnt; mount --make-private $ST/mnt; touch $ST/mnt/ns
mkdir -p $ST/etcnet
nsenter --net=/run/netns/fgn-gw unshare --mount=$ST/mnt/ns --propagation private sh -c "
  mount -t sysfs -o ro none /sys; mkdir -p /run/systemd /run/dbus
  mount -t tmpfs none /run/systemd; mount -t tmpfs none /run/dbus; mount --bind $ST/etcnet /etc/systemd/network"
netd() {
  gw sh -c "mkdir -p /run/systemd/network /run/systemd/netif; chown -R systemd-network:systemd-network /run/systemd/netif
  printf '[Match]\nName=eth*\n\n[Network]\nDHCP=yes\nLinkLocalAddressing=ipv6\n\n[DHCP]\nRouteMetric=100\nUseMTU=true\n' > /run/systemd/network/10-netplan-all-eth-interfaces.network
  [ -S /run/dbus/system_bus_socket ] || dbus-daemon --system --fork
  /lib/systemd/systemd-networkd >>$ST/networkd.log 2>&1 &"
}
netd
up() { [ "$1" != 000 ] && echo yes || echo no; } # the page answered, page or redirect
res() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1 (expected $2, got $3)"; fi; }
wan_ip() { gw ip -4 -o addr show dev "$1" 2>/dev/null | awk '$4 ~ /^10\.10\.10\./ {sub("/.*","",$4); print $4; exit}'; }
for i in $(seq 30); do IP0=$(wan_ip eth3); [ -n "$IP0" ] && break; sleep 1; done
echo "networkd gave eth3 $IP0"
res "networkd leased the WAN port" yes "$([ -n "$IP0" ] && echo yes || echo no)"

serve() { gw $BIN serve </dev/null >> $ST/serve.log 2>&1 & }
serve; sleep 2
FLAPS0=$(lpc cat /sys/class/net/l-lan/carrier_changes)
U=https://$IP0:8443
c() { pc curl -sk -m 4 -H 'X-FG: 1' -H 'Content-Type: application/json' -c $ST/jar -b $ST/jar "$@"; }
res "page answers from the router side before setup" 200 "$(c -o /dev/null -w '%{http_code}' $U/api/setup/info)"
c -o /dev/null -d '{"user":"admin","password":"correct horse 42"}' $U/api/setup/state
c -o /dev/null -d '{"lan":["eth2"],"wan":"eth3","safety":true,"safety_hosts":"10.10.10.42","admin_port":8443,"step":"Review"}' $U/api/setup/state
cp $ST/gateway.conf $ST/gateway.conf.none 2>/dev/null
echo "Apply, and nobody confirms"
c -m 15 -o $ST/apply.json -d "{}" $U/api/setup
res "apply answered" yes "$(grep -q pending $ST/apply.json 2>/dev/null && echo yes || echo no)"
res "bridge has the address eth3 had" "$IP0" "$(for i in $(seq 20); do B=$(wan_ip br-fgw); [ -n "$B" ] && break; sleep 0.5; done; echo $B)"
res "networkd files wait in /run" 3 "$(gw sh -c 'ls /run/systemd/network | grep -c foilgw')"
for i in $(seq 200); do gw test -d /sys/class/net/br-fgw || break; sleep 1; done
res "undone after the wait" no "$(gw test -d /sys/class/net/br-fgw && echo yes || echo no)"
for i in $(seq 30); do B=$(wan_ip eth3); [ -n "$B" ] && break; sleep 1; done
res "eth3 leased by networkd again, same address" "$IP0" "$B"
res "no foilgw files left in networkd's config" 0 "$(gw sh -c 'ls /etc/systemd/network /run/systemd/network | grep -c foilgw')"
res "page back on the same address" 200 "$(c -o /dev/null -w '%{http_code}' $U/api/setup/info)"
c -o /dev/null -d '{"step":"Review"}' $U/api/setup/state

echo "Apply from the router side"
c -m 15 -o $ST/apply.json -d "{}" $U/api/setup; echo "  apply: $(cat $ST/apply.json)"
grep -q pending $ST/apply.json 2>/dev/null || { FAIL=$((FAIL+1)); echo "  FAIL apply answered"; }
# The browser keeps asking to confirm, on the address it already has.
KEPT=no
for i in $(seq 50); do
  r=$(c $U/api/setup/confirm -X POST 2>/dev/null)
  case $r in *'"kept":true'*) KEPT=yes; break;; esac
  sleep 1
done
echo "  confirm after ${i}s: $r"
res "browser on the router side confirmed on the same address" yes $KEPT
res "bridge is up" yes "$(gw test -d /sys/class/net/br-fgw/bridge && echo yes || echo no)"
res "bridge has the address eth3 had" "$IP0" "$(wan_ip br-fgw)"
res "eth3 has no address of its own" "" "$(wan_ip eth3)"
res "networkd files moved to /etc" "0 3" "$(gw sh -c 'echo $(ls /run/systemd/network | grep -c foilgw) $(ls /etc/systemd/network | grep -c foilgw)')"
res "eth3 and eth2 in the bridge" "eth2 eth3" "$(gw ls /sys/class/net/br-fgw/brif 2>/dev/null | sort | xargs)"
sleep 2
CIP=$(lpc python3 "$HERE/dhcpc.py" l-lan 15); lpc ip route replace default via 10.10.10.1 2>/dev/null
res "LAN PC got an address from the router through the bridge" yes "$(case $CIP in 10.10.10.1[0-9][0-9]) echo yes;; *) echo no;; esac)"
LMAC=$(lpc cat /sys/class/net/l-lan/address)
res "LAN PC's DHCP in the Capture Log" yes "$(python3 -c "import sqlite3,sys; c=sqlite3.connect('$ST/capture.db'); print('yes' if c.execute(\"select count(*) from events where kind='dhcp' and device=? and text like 'DHCP ACK $CIP to %'\", ('$LMAC',)).fetchone()[0] else 'no')")"
res "LAN PC's link never dropped through apply, undo and apply" "$FLAPS0" "$(lpc cat /sys/class/net/l-lan/carrier_changes)"
res "RDP from the router-side PC to the LAN PC" ok "$(pc curl -s -o /dev/null -m 3 http://$CIP:3389/ && echo ok || echo blocked)"
res "portal from the LAN PC" yes "$(up "$(lpc curl -sk -o /dev/null -m 4 -w '%{http_code}' $U/)")"
res "portal from the router side" yes "$(up "$(pc curl -sk -m 4 -o /dev/null -w '%{http_code}' $U/)")"
dash() { "$@" env NODE_PATH=/tmp/pt/node_modules node "$HERE/dash.js" $U admin "correct horse 42" 2>&1 | sed 's/^/    /'; return ${PIPESTATUS[0]}; }
res "dashboard loads on the LAN PC" 0 "$(dash lpc >&2; echo $?)"
res "dashboard loads on the router side" 0 "$(dash pc >&2; echo $?)"
# Many dashboards at once while the gateway keeps updating its device list.
lc() { lpc curl -sk -m 5 -H 'X-FG: 1' -H 'Content-Type: application/json' -c $ST/ljar -b $ST/ljar "$@"; }
lc -o /dev/null -d '{"user":"admin","password":"correct horse 42"}' $U/api/login
L=""; for j in $(seq 16); do lpc sh -c "end=\$((\$(date +%s)+25)); while [ \$(date +%s) -lt \$end ]; do curl -sk -m 5 -o /dev/null -b $ST/ljar $U/api/dashboard; done" & L="$L $!"; done; wait $L
res "dashboard still answers after 25 s of load" 200 "$(lc -o /dev/null -w '%{http_code}' $U/api/dashboard)"
# A browser that gives up mid-request must not leave sockets hanging.
H=""; for i in 1 2 3 4 5; do lpc timeout 1 openssl s_client -quiet -connect $IP0:8443 </dev/null >/dev/null 2>&1 & H="$H $!"; done
for i in 1 2 3; do lpc bash -c "exec 3<>/dev/tcp/$IP0/8443; sleep 0.5" & H="$H $!"; done; wait $H
sleep 20
res "no sockets left half closed" 0 "$(gw ss -Htn state close-wait '( sport = :8443 )' | wc -l)"
sleep 65
res "still bridged after the undo window" yes "$(gw test -d /sys/class/net/br-fgw/bridge && echo yes || echo no)"
res "networkd left the bridge's address alone" "$IP0" "$(wan_ip br-fgw)"

echo "Restart: everything on the gateway stops and comes back"
gw pkill -x foilgw; gw pkill -x systemd-network; sleep 0.5
gw ip link del br-fgw; gw ip addr flush dev eth3; gw ip addr flush dev eth2
gw sh -c 'rm -rf /run/systemd/netif/*' # /run starts empty
netd; sleep 1; serve
for i in $(seq 30); do B=$(wan_ip br-fgw); [ "$B" = "$IP0" ] && break; sleep 1; done
res "bridge back after restart" "eth2 eth3" "$(gw ls /sys/class/net/br-fgw/brif 2>/dev/null | sort | xargs)"
res "same address after restart" "$IP0" "$B"
res "RDP after restart" ok "$(pc curl -s -o /dev/null -m 3 http://$CIP:3389/ && echo ok || echo blocked)"
for i in $(seq 20); do pc curl -sk -m 1 -o /dev/null $U/ && break; sleep 0.5; done
res "portal after restart" yes "$(up "$(pc curl -sk -m 4 -o /dev/null -w '%{http_code}' $U/)")"

echo "networkd log:"; grep -iE 'br-fgw|eth3|eth2' $ST/networkd.log | tail -15 | sed 's/^/  /'
echo "serve log:"; tail -15 $ST/serve.log | sed 's/^/  /'
echo "router:"; tail -6 $ST/router.log | sed 's/^/  /'
echo "passed $PASS, failed $FAIL"
[ $FAIL = 0 ]
