#!/bin/bash
# Leak/resource soak for 1.2.0 on the bench from net120.sh (web.sh SOAK
# pattern): SOAK seconds of API traffic as admin (session) and as jarvis
# (API key), wrong-key attempts from 10.10.10.62, LAN traffic, and list
# changes that send notifications to Jarvis (reachable) and Dead End
# (unreachable). Samples RSS, fds, threads, WAL and DB size every EVERY s.
set -u
cd "$(dirname "$0")"
ST=${ST:-/tmp/fg120-run}; SOAK=${SOAK:-600}; EVERY=${EVERY:-30}
U=$(cat $ST/url); B=$(cat $ST/bin); PID=$(pgrep -f "$B serve" | head -1)
lap() { ip netns exec fgw-lap "$@"; }
cli() { ip netns exec fgw-cli "$@"; }
CIP=$(awk '{print $NF}' $ST/device.txt)
J=$ST/soak-jar; lap curl -sk -c $J -H 'X-FG: 1' -H 'Content-Type: application/json' -d '{"user":"admin","password":"correct horse battery"}' $U/api/login >/dev/null
# Key and a wrong key as curl header files, so neither is on a command line or in a log.
( umask 077; printf 'Authorization: Bearer %s\n' "$(tail -1 $ST/secrets/key-jarvis)" > $ST/secrets/h-jarvis; printf 'Authorization: Bearer fgk_%064d\n' 7 > $ST/secrets/h-wrong )
START=$(date +%s); END=$(( START + SOAK ))
W=""
load() { while [ $(date +%s) -lt $END ]; do for a in dashboard "devices?limit=100" firewall "log?limit=200" ports settings users notify status; do lap curl -sk -m 5 -b $J -o /dev/null -w "%{http_code}\n" "$U/api/$a"; done >> $ST/soak-sess-codes.txt; done; }
for k in 1 2 3; do load & W="$W $!"; done
keyload() { n=0; while [ $(date +%s) -lt $END ]; do n=$((n+1)); for a in dashboard devices firewall "log?limit=100" me; do lap curl -sk -m 5 -H @$ST/secrets/h-jarvis -o /dev/null -w "%{http_code}\n" "$U/api/$a"; done >> $ST/soak-key-codes.txt
  # A Black list change every ~20 s: a settings notification to Jarvis and Dead End.
  if [ $((n % 8)) = 0 ]; then lap curl -sk -m 5 -H @$ST/secrets/h-jarvis -H 'Content-Type: application/json' -o /dev/null -d "{\"list\":\"black\",\"add\":\"198.51.100.$((n % 200 + 1))\"}" $U/api/list; fi
  sleep 1; done; }
keyload & W="$W $!"
wrong() { while [ $(date +%s) -lt $END ]; do lap curl -sk -m 5 --interface 10.10.10.62 -H @$ST/secrets/h-wrong -o /dev/null -w "%{http_code}\n" $U/api/me >> $ST/soak-wrong-codes.txt; sleep 2; done; }
wrong & W="$W $!"
( n=0; while [ $(date +%s) -lt $END ]; do n=$((n+1)); cli curl -s -o /dev/null -m 0.3 http://9.9.9.9:$((1000 + n % 20000))/; cli curl -s -o /dev/null -m 1 http://1.1.1.1/; lap curl -s -o /dev/null -m 0.3 http://$CIP:$((20000 + n % 500))/; done ) >/dev/null 2>&1 & W="$W $!"
breakdown() { echo "  threads by name: $(cat /proc/$PID/task/*/comm | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
  echo "  threads by wait: $(for t in /proc/$PID/task/*; do cut -d' ' -f1,2 $t/syscall; done | sort | uniq -c | sort -rn | head -4 | tr -s ' ' | tr '\n' ';')"
  echo "  fds by type: $(ls -l /proc/$PID/fd | awk 'NR>1{print $NF}' | sed 's/\[[0-9]*\]//; s|^/tmp/[^ ]*/|state/|' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
  echo "  tcp on 8443: $(ip netns exec fgw-gw ss -tan | awk '$4 ~ /:8443$/ {print $1}' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"; }
echo "soak: sec rss_kb fds threads wal_bytes db_bytes rows hooks"
while [ $(date +%s) -lt $END ]; do
  echo "soak: $(( SOAK - (END - $(date +%s)) )) $(awk '/VmRSS/{print $2}' /proc/$PID/status) $(ls /proc/$PID/fd | wc -l) $(ls /proc/$PID/task | wc -l) $(stat -c %s $ST/capture.db-wal 2>/dev/null || echo 0) $(stat -c %s $ST/capture.db) $(python3 -c "import sqlite3; print(sqlite3.connect('file:$ST/capture.db?mode=ro', uri=True).execute('select count(*) from events').fetchone()[0])" 2>/dev/null) $(wc -l < $ST/hooks.jsonl) probe=$(lap curl -sk -m 5 -o /dev/null -w '%{http_code}/%{time_total}s' $U/api/status)"
  [ $(( $(date +%s) - START )) -ge 90 ] && [ -z "${BD:-}" ] && { BD=1; echo "soak: under load:"; breakdown; }
  sleep $EVERY
done
wait $W
echo "soak: end $(awk '/VmRSS/{print $2}' /proc/$PID/status) $(ls /proc/$PID/fd | wc -l) $(ls /proc/$PID/task | wc -l)"
echo "key calls: $(sort $ST/soak-key-codes.txt | uniq -c | tr '\n' ' ')"
echo "session calls: $(sort $ST/soak-sess-codes.txt | uniq -c | tr '\n' ' ')"
echo "wrong-key calls: $(sort $ST/soak-wrong-codes.txt | uniq -c | tr '\n' ' ')"
echo "soak: load stopped, waiting 60 s"; sleep 60
echo "soak: idle+60 $(awk '/VmRSS/{print $2}' /proc/$PID/status) $(ls /proc/$PID/fd | wc -l) $(ls /proc/$PID/task | wc -l) probe=$(lap curl -sk -m 5 -o /dev/null -w '%{http_code}/%{time_total}s' $U/api/status)"
breakdown
rm -f $ST/secrets/h-jarvis $ST/secrets/h-wrong $J
