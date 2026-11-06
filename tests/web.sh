#!/bin/bash
# First setup in bridge mode through the real page, then every page, in
# throwaway namespaces. The browser sits on a laptop on the router's
# network, like someone plugging the gateway in for the first time. Needs root.
#
#   lap 10.10.10.60 ┐
#   rtr 10.10.10.1  ┴ rbr  --  eth-wan [gw: foilgw serve]  eth-lan  --  cli (DHCP)
set -u
cd "$(dirname "$0")"
HERE=$(pwd)
BIN=$(realpath "${BIN:-../target/x86_64-unknown-linux-musl/release/foilgw}")
SHOTS=$(realpath -m "${SHOTS:-../_notes/shots}")
NS="fgw-rtr fgw-gw fgw-cli fgw-lap"
ST=$(mktemp -d /tmp/fgnet-web.XXXX)
rtr() { ip netns exec fgw-rtr "$@"; }
gw() { ip netns exec fgw-gw "$@"; }
cli() { ip netns exec fgw-cli "$@"; }
lap() { ip netns exec fgw-lap "$@"; }
cleanup() { for n in $NS; do ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del $n 2>/dev/null; done; rm -rf /etc/netns/fgw-gw; }
trap cleanup EXIT
cleanup
for n in $NS; do ip netns add $n; ip netns exec $n ip link set lo up; done
rtr ip link add rbr type bridge; rtr ip link set rbr up
ip link add eth-wan netns fgw-gw type veth peer name r-gw netns fgw-rtr
ip link add l-lan netns fgw-lap type veth peer name r-lap netns fgw-rtr
ip link add eth-lan netns fgw-gw type veth peer name c-lan netns fgw-cli
for p in r-gw r-lap; do rtr ip link set $p master rbr; rtr ip link set $p up; done
rtr ip addr add 10.10.10.1/24 dev rbr
for a in 1.1.1.1 9.9.9.9 8.8.8.8; do rtr ip addr add $a/32 dev lo; done
lap ip addr add 10.10.10.60/24 dev l-lan; lap ip link set l-lan up
cli ip link set c-lan up
mkdir -p /etc/netns/fgw-gw; echo "nameserver 10.10.10.1" > /etc/netns/fgw-gw/resolv.conf
sysctl -qw net.netfilter.nf_log_all_netns=1 2>/dev/null
rtr python3 -u "$HERE/router.py" rbr 10.10.10.1 >$ST/router.log 2>&1 &
rtr python3 -m http.server 80 --bind 0.0.0.0 </dev/null >/dev/null 2>&1 &
for p in 3389 445; do cli python3 -m http.server $p --bind 0.0.0.0 </dev/null >/dev/null 2>&1 & done
export FOILGW_CONF=$ST/gateway.conf FOILGW_STATE=$ST FOILGW_ALLOW_NO_SYSTEMD=1 FOILGW_VETH_PORTS=1
gw $BIN serve </dev/null > $ST/serve.log 2>&1 &
# The gateway asks the router for an address on every port.
for i in $(seq 30); do GWIP=$(gw ip -4 -o addr show dev eth-wan | awk '$4 ~ /^10\.10\.10\./ {sub("/.*","",$4); print $4}'); [ -n "$GWIP" ] && break; sleep 1; done
[ -n "$GWIP" ] || { echo "the gateway got no address from the router"; tail $ST/serve.log; exit 1; }
U=https://$GWIP:8443
echo "gateway at $U before setup"
c() { lap curl -sk -m 5 "$@"; }
echo "curl checks"
c -o /dev/null -w "  / -> %{http_code} %{redirect_url}\n" $U/
c -o /dev/null -w "  /api/dashboard before setup -> %{http_code}\n" $U/api/dashboard
c -o /dev/null -w "  POST without X-FG -> %{http_code}\n" -X POST $U/api/setup
mkdir -p "$SHOTS"; find "$SHOTS" -maxdepth 1 -name '[0-9]*.png' -delete
# A device on the LAN side, and someone on the router side knocking on it.
( for i in $(seq 600); do [ -f "$SHOTS/.ready" ] && break; sleep 0.3; done; [ -f "$SHOTS/.ready" ] || exit 0
  CIP=$(cli python3 "$HERE/dhcpc.py" c-lan 20); cli ip route replace default via 10.10.10.1
  echo "LAN device got $CIP" > $ST/device.txt
  for i in 1 2 3; do
    cli curl -s -o /dev/null -m 1 http://9.9.9.9/; cli curl -s -o /dev/null -m 1 http://1.1.1.1/
    lap curl -s -o /dev/null -m 1 http://$CIP:3389/; lap curl -s -o /dev/null -m 1 http://$CIP:445/
  done ) >/dev/null 2>&1 &
if [ -n "${NOBROWSER:-}" ]; then R=0; else lap env NODE_PATH=/tmp/pt/node_modules WAIT=12000 node browser.js $U "$SHOTS"; R=$?; fi
rm -f "$SHOTS/.ready"
# SOAK=600 keeps the gateway busy that many seconds after the browser run
# and samples its memory, open files, threads and the log's WAL.
if [ -n "${SOAK:-}" ] && [ $R = 0 ]; then
  PID=$(pgrep -f "$BIN serve" | head -1)
  CIP=$(awk '{print $NF}' $ST/device.txt)
  J=$ST/jar; lap curl -sk -c $J -H 'X-FG: 1' -H 'Content-Type: application/json' -d '{"user":"admin","password":"correct horse battery"}' $U/api/login >/dev/null
  END=$(( $(date +%s) + SOAK ))
  load() { while [ $(date +%s) -lt $END ]; do for a in ${LOAD:-dashboard devices?limit=100 firewall log?limit=200 ports settings}; do lap curl -sk -m 5 -b $J -o /dev/null "$U/api/$a"; done; done; }
  W=""; for k in 1 2 3 4; do load & W="$W $!"; done
  # New blocked lines (a new port each time) and LAN traffic, all the way through.
  [ -z "${NOTRAFFIC:-}" ] && ( n=0; while [ $(date +%s) -lt $END ]; do n=$((n+1)); cli curl -s -o /dev/null -m 0.3 http://9.9.9.9:$((1000 + n % 20000))/; cli curl -s -o /dev/null -m 1 http://1.1.1.1/; lap curl -s -o /dev/null -m 0.3 http://$CIP:$((20000 + n % 500))/; done ) >/dev/null 2>&1 & W="$W $!"
  echo "soak: sec rss_kb fds threads wal_bytes db_bytes rows"
  while [ $(date +%s) -lt $END ]; do
    echo "soak: $(( SOAK - (END - $(date +%s)) )) $(awk '/VmRSS/{print $2}' /proc/$PID/status) $(ls /proc/$PID/fd | wc -l) $(ls /proc/$PID/task | wc -l) $(stat -c %s $ST/capture.db-wal 2>/dev/null || echo 0) $(stat -c %s $ST/capture.db) $(python3 -c "import sqlite3; print(sqlite3.connect('file:$ST/capture.db?mode=ro', uri=True).execute('select count(*) from events').fetchone()[0])" 2>/dev/null)"
    sleep ${EVERY:-30}
  done
  wait $W
fi
cat $ST/device.txt 2>/dev/null
echo "after the browser run"
gw ip -br link show master br-fgw | sed 's/^/  bridge member: /'
gw ip -4 -br addr show dev br-fgw | sed 's/^/  /'
echo "  setup addresses left: $(gw ip -4 -o addr | grep -cE '192\.168\.30\.1/|169\.254\.42\.1/')"
c -o /dev/null -w "  /api/dashboard signed out -> %{http_code}\n" $U/api/dashboard
echo "serve log:"; sed 's/^/  /' $ST/serve.log | tail -20
echo "first forward rule:"; gw nft list chain inet foilgateway forward | grep -v hook | grep -m1 -E 'accept|drop|jump'
cp $ST/caplog.db /tmp/fgnet-last-caplog.db 2>/dev/null
exit $R
