#!/bin/bash
# 1.2.0 test bench, adapted from web.sh: the same throwaway namespaces, but
# kept up between steps so the gateway can be stopped and a newer build
# started on the same state (upgrade test). Needs root.
#   net120.sh up | start BIN | stop | traffic | down
#   lap 10.10.10.60-.62 ┐
#   rtr 10.10.10.1      ┴ rbr -- eth-wan [gw: foilgw serve] eth-lan -- cli (DHCP)
# rtr also runs hookrx.py on :8797 (webhook receiver for Notifications).
set -u
cd "$(dirname "$0")"
HERE=$(pwd)
ST=${ST:-/tmp/fg120-run}
NS="fgw-rtr fgw-gw fgw-cli fgw-lap"
rtr() { ip netns exec fgw-rtr "$@"; }
gw() { ip netns exec fgw-gw "$@"; }
cli() { ip netns exec fgw-cli "$@"; }
lap() { ip netns exec fgw-lap "$@"; }
down() { for n in $NS; do ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null; sleep 0.2; ip netns pids $n 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del $n 2>/dev/null; done; rm -rf /etc/netns/fgw-gw; }
case "$1" in
up)
  down
  mkdir -p $ST; chmod 700 $ST
  for n in $NS; do ip netns add $n; ip netns exec $n ip link set lo up; done
  rtr ip link add rbr type bridge; rtr ip link set rbr up
  ip link add eth-wan netns fgw-gw type veth peer name r-gw netns fgw-rtr
  ip link add l-lan netns fgw-lap type veth peer name r-lap netns fgw-rtr
  ip link add eth-lan netns fgw-gw type veth peer name c-lan netns fgw-cli
  for p in r-gw r-lap; do rtr ip link set $p master rbr; rtr ip link set $p up; done
  rtr ip addr add 10.10.10.1/24 dev rbr
  for a in 1.1.1.1 9.9.9.9 8.8.8.8; do rtr ip addr add $a/32 dev lo; done
  for a in 60 61 62 63; do lap ip addr add 10.10.10.$a/24 dev l-lan; done; lap ip link set l-lan up
  cli ip link set c-lan up
  mkdir -p /etc/netns/fgw-gw; echo "nameserver 10.10.10.1" > /etc/netns/fgw-gw/resolv.conf
  sysctl -qw net.netfilter.nf_log_all_netns=1 2>/dev/null
  rtr python3 -u "$HERE/router.py" rbr 10.10.10.1 >$ST/router.log 2>&1 &
  rtr python3 -m http.server 80 --bind 0.0.0.0 </dev/null >/dev/null 2>&1 &
  for p in 3389 445; do cli python3 -m http.server $p --bind 0.0.0.0 </dev/null >/dev/null 2>&1 & done
  rtr python3 -u "$HERE/hookrx.py" 8797 $ST/hooks.jsonl >$ST/hookrx.log 2>&1 &
  echo up ;;
start)
  BIN=$(realpath "$2")
  export FOILGW_CONF=$ST/gateway.conf FOILGW_STATE=$ST FOILGW_ALLOW_NO_SYSTEMD=1 FOILGW_VETH_PORTS=1 FOILGW_WEB=$ST/no-web-dir
  gw $BIN serve </dev/null >> $ST/serve.log 2>&1 &
  echo "$BIN" > $ST/bin
  for i in $(seq 40); do
    GWIP=$(gw ip -4 -o addr | awk '$4 ~ /^10\.10\.10\./ {sub("/.*","",$4); print $4}' | head -1)
    [ -n "$GWIP" ] && lap curl -sk -m 2 -o /dev/null https://$GWIP:8443/api/ping && break; sleep 1; done
  [ -n "$GWIP" ] || { echo "no address"; tail $ST/serve.log; exit 1; }
  echo "https://$GWIP:8443" > $ST/url; echo "gateway $(cat $ST/url) pid $(pgrep -f "$BIN serve" | head -1)" ;;
stop)
  B=$(cat $ST/bin); P=$(pgrep -f "$B serve"); [ -n "$P" ] && kill $P; for i in $(seq 50); do pgrep -f "$B serve" >/dev/null || break; sleep 0.2; done; pgrep -f "$B serve" && kill -9 $(pgrep -f "$B serve"); echo stopped ;;
traffic)
  # A device on the LAN side, and someone on the router side knocking on it.
  CIP=$(cli python3 "$HERE/dhcpc.py" c-lan 30); cli ip route replace default via 10.10.10.1
  echo "$CIP" > $ST/device.txt; echo "LAN device $CIP"
  for i in 1 2 3; do
    cli curl -s -o /dev/null -m 1 http://9.9.9.9/; cli curl -s -o /dev/null -m 1 http://1.1.1.1/
    lap curl -s -o /dev/null -m 1 http://$CIP:3389/; lap curl -s -o /dev/null -m 1 http://$CIP:445/
  done ;;
down) down; echo down ;;
esac
