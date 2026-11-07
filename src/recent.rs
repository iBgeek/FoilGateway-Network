//! Blocks from the last hour or so, kept in memory per device, address,
//! port and reason with a count per minute. The troubleshooter reads it,
//! and the blocked-attempts map reads actual stopped records. Bounded: lines
//! older than 70 minutes go, and there's a cap on how many it holds.

use std::collections::{HashMap, VecDeque};

const KEEP_SECS: i64 = 70 * 60;
const CAP: usize = 20_000;

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub mac: String,
    pub reason: String,
    pub remote: String,
    pub proto: String,
    pub port: u16,
    /// The device started it.
    pub outbound: bool,
    /// Logged by audit and let through.
    pub audit: bool,
}

#[derive(Default)]
struct Hit {
    /// (minute, count), oldest first.
    mins: VecDeque<(i64, u32)>,
    last: i64,
}

impl Hit {
    fn count_since(&self, minute: i64) -> u64 {
        self.mins.iter().rev().take_while(|m| m.0 >= minute).map(|m| m.1 as u64).sum()
    }
}

#[derive(Default)]
pub struct Recent {
    map: HashMap<Key, Hit>,
}

/// One line for the troubleshooter.
#[derive(Clone, Debug, PartialEq)]
pub struct Line {
    pub key: Key,
    pub count: u64,
    pub last: i64,
}

/// One address for the troubleshooter, all its ports together.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Merged {
    pub remote: String,
    pub outbound: bool,
    pub ports: Vec<(String, u16)>,
    pub count: u64,
    pub last: i64,
    pub audit: bool,
}

impl Recent {
    pub fn add(&mut self, key: Key, at: i64) {
        let minute = at.div_euclid(60);
        let h = self.map.entry(key).or_default();
        match h.mins.back_mut() {
            Some(m) if m.0 == minute => m.1 += 1,
            _ => h.mins.push_back((minute, 1)),
        }
        while h.mins.front().is_some_and(|m| m.0 < minute - KEEP_SECS / 60) {
            h.mins.pop_front();
        }
        h.last = h.last.max(at);
        if self.map.len() > CAP {
            self.prune(at);
        }
        if self.map.len() > CAP {
            // Still too many: drop the oldest tenth.
            let mut lasts: Vec<i64> = self.map.values().map(|h| h.last).collect();
            let nth = lasts.len() / 10;
            let (_, cut, _) = lasts.select_nth_unstable(nth);
            let cut = *cut;
            self.map.retain(|_, h| h.last > cut);
        }
    }

    pub fn prune(&mut self, at: i64) {
        let oldest = (at - KEEP_SECS).div_euclid(60);
        self.map.retain(|_, h| {
            while h.mins.front().is_some_and(|m| m.0 < oldest) {
                h.mins.pop_front();
            }
            !h.mins.is_empty()
        });
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Only actual drops, never Audit-allowed packets. Counts are minute buckets.
    pub fn stopped_since(&self, since: i64) -> Vec<Line> {
        self.map.iter().filter(|(k,h)| !k.audit && h.last >= since).map(|(k,h)| Line {key:k.clone(),count:h.count_since(since.div_euclid(60)),last:h.last}).collect()
    }

    /// One device's lines since `since`, busiest first.
    pub fn for_device(&self, mac: &str, since: i64) -> Vec<Line> {
        let minute = since.div_euclid(60);
        let mut out: Vec<Line> = self
            .map
            .iter()
            .filter(|(k, h)| k.mac == mac && h.last >= since)
            .map(|(k, h)| Line { key: k.clone(), count: h.count_since(minute), last: h.last })
            .filter(|l| l.count > 0)
            .collect();
        out.sort_by(|a, b| b.count.cmp(&a.count).then(b.last.cmp(&a.last)).then(a.key.cmp(&b.key)));
        out
    }

    /// One device's lines for one reason, one per address and outcome: every port
    /// on it merged and listed (busiest first), the count the total.
    pub fn by_address(lines: &[Line], reason: &str) -> Vec<Merged> {
        // Per address: the row, outbound hits, and hits per port.
        type Acc = (Merged, u64, Vec<(String, u16, u64)>);
        let mut per: HashMap<(&str,bool), Acc> = HashMap::new();
        for l in lines.iter().filter(|l| l.key.reason == reason) {
            let k = &l.key;
            let e = per.entry((&k.remote,k.audit)).or_insert_with(|| (Merged { remote: k.remote.clone(), audit:k.audit, ..Default::default() }, 0, Vec::new()));
            e.0.count += l.count;
            e.0.last = e.0.last.max(l.last);
            if k.outbound {
                e.1 += l.count;
            }
            match e.2.iter_mut().find(|p| p.0 == k.proto && p.1 == k.port) {
                Some(p) => p.2 += l.count,
                None => e.2.push((k.proto.clone(), k.port, l.count)),
            }
        }
        let mut out: Vec<Merged> = per
            .into_values()
            .map(|(mut m, out_n, mut ports)| {
                // Mostly started by the device: outbound.
                m.outbound = out_n * 2 >= m.count;
                ports.sort_by(|a, b| b.2.cmp(&a.2).then(a.1.cmp(&b.1)).then(a.0.cmp(&b.0)));
                m.ports = ports.into_iter().map(|p| (p.0, p.1)).collect();
                m
            })
            .collect();
        out.sort_by(|a, b| b.count.cmp(&a.count).then(b.last.cmp(&a.last)).then(a.remote.cmp(&b.remote)).then(a.audit.cmp(&b.audit)));
        out
    }


}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(mac: &str, reason: &str, remote: &str) -> Key {
        Key { mac: mac.into(), reason: reason.into(), remote: remote.into(), proto: "tcp".into(), port: 443, outbound: true, audit: false }
    }

    #[test]
    fn stopped_and_audit_at_one_address_are_not_merged_or_mislabelled() {
        let mut r=Recent::default();let k=Key{mac:"a".into(),remote:"8.8.8.8".into(),reason:"country".into(),proto:"tcp".into(),port:443,outbound:true,audit:false};
        r.add(k.clone(),100);r.add(k.clone(),101);r.add(Key{audit:true,..k},102);
        let rows=Recent::by_address(&r.for_device("a",0),"country");assert_eq!(rows.len(),2);assert_eq!(rows.iter().find(|r|!r.audit).unwrap().count,2);assert_eq!(rows.iter().find(|r|r.audit).unwrap().count,1);
    }
    #[test]
    fn map_selection_is_recent_actual_drops_including_unidentified_devices() {
        let mut r=Recent::default();let key=Key{mac:"".into(),reason:"country".into(),remote:"8.8.8.8".into(),proto:"tcp".into(),port:443,outbound:true,audit:false};
        r.add(key.clone(),100);r.add(Key{audit:true,..key.clone()},110);r.add(Key{remote:"1.1.1.1".into(),..key},10);
        let actual=r.stopped_since(60);assert_eq!(actual.len(),1);assert!(!actual[0].key.audit);assert_eq!(actual[0].key.remote,"8.8.8.8");
    }
    #[test]
    fn counts_the_last_hour_and_forgets_older() {
        let mut r = Recent::default();
        let t = 1_000_000 * 60;
        r.add(key("a", "black", "1.1.1.1"), t - 2 * 3600);
        r.add(key("a", "black", "1.1.1.1"), t - 60);
        r.add(key("a", "black", "1.1.1.1"), t);
        r.add(key("a", "country", "2.2.2.2"), t);
        let l = r.for_device("a", t - 3600);
        assert_eq!(l.len(), 2);
        assert_eq!((l[0].key.remote.as_str(), l[0].count), ("1.1.1.1", 2));
        r.prune(t + 71 * 60);
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn one_line_per_address_and_counts_add_up() {
        let mut r = Recent::default();
        let t = 3_000_000 * 60;
        let k = |remote: &str, proto: &str, port: u16| Key { proto: proto.into(), port, ..key("a", "telemetry", remote) };
        for _ in 0..3 {
            r.add(k("51.132.193.107", "tcp", 443), t);
        }
        r.add(k("51.132.193.107", "udp", 443), t - 5);
        r.add(k("51.132.193.107", "tcp", 80), t - 9);
        r.add(k("1.1.1.1", "tcp", 443), t);
        r.add(key("a", "black", "51.132.193.107"), t);
        let lines = r.for_device("a", t - 3600);
        let m = Recent::by_address(&lines, "telemetry");
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].remote, "51.132.193.107");
        assert_eq!(m[0].count, 5);
        assert_eq!(m[0].ports, vec![("tcp".into(), 443), ("tcp".into(), 80), ("udp".into(), 443)]);
        assert!(m[0].outbound);
        // The group's badge is the sum of its lines, and of the raw lines.
        let raw: u64 = lines.iter().filter(|l| l.key.reason == "telemetry").map(|l| l.count).sum();
        assert_eq!(m.iter().map(|x| x.count).sum::<u64>(), raw);
        assert_eq!(Recent::by_address(&lines, "black").len(), 1);
    }

    #[test]
    fn stays_under_the_cap() {
        let mut r = Recent::default();
        for i in 0..(CAP + 500) {
            r.add(key("a", "black", &format!("10.0.{}.{}", i / 256, i % 256)), 60_000 + i as i64);
        }
        assert!(r.len() <= CAP);
    }


}
