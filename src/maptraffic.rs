//! Fresh inet postrouting observations of bridged packets, independent of conntrack lifetime totals.
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Key {
    pub mac: String,
    pub remote: String,
    pub inbound: bool,
}
#[derive(Clone, Debug)]
pub struct Traffic {
    pub key: Key,
    pub bytes: u64,
}
#[derive(Default)]
pub struct Tracker {
    last: HashMap<Key, u64>,
    current: Vec<Traffic>,
    at: Option<Instant>,
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_broadcast()
                && !v.is_multicast()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0 && (c == 0 || c == 2))
                && !(a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] == 0x0db8 || s[1] < 0x0200))
                && !(s[0] == 0x2002)
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}
impl Tracker {
    pub fn sample(&mut self, counters: HashMap<Key, u64>, at: Instant) {
        self.current = counters
            .iter()
            .filter_map(|(k, b)| {
                let delta = match self.last.get(k) {
                    Some(old) => b.checked_sub(*old)?,
                    None if self.at.is_some() => *b,
                    None => return None,
                };
                (delta > 0 && k.remote.parse().is_ok_and(public_ip)).then(|| Traffic {
                    key: k.clone(),
                    bytes: delta,
                })
            })
            .collect();
        self.last = counters;
        self.at = Some(at);
    }
    pub fn invalidate(&mut self) {
        self.last.clear();
        self.current.clear();
        self.at = None;
    }
    pub fn current(&self, at: Instant) -> Vec<Traffic> {
        if self
            .at
            .is_some_and(|t| at.saturating_duration_since(t) <= Duration::from_secs(4))
        {
            self.current.clone()
        } else {
            Vec::new()
        }
    }
}
pub fn parse_counters(text: &str) -> HashMap<Key, u64> {
    let mut out = HashMap::new();
    let v: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    for item in v["nftables"].as_array().into_iter().flatten() {
        let name = item["set"]["name"].as_str().unwrap_or("");
        if !["map_out4", "map_in4", "map_out6", "map_in6"].contains(&name) {
            continue;
        }
        for el in item["set"]["elem"]
            .as_array()
            .into_iter()
            .flatten()
            .take(4096)
        {
            let e = &el["elem"];
            let pair = &e["val"]["concat"];
            if let (Some(mac), Some(remote), Some(bytes)) = (
                pair[0].as_str(),
                pair[1].as_str(),
                e["counter"]["bytes"].as_u64(),
            ) {
                out.insert(
                    Key {
                        mac: mac.to_lowercase(),
                        remote: remote.into(),
                        inbound: name.starts_with("map_in"),
                    },
                    bytes,
                );
            }
        }
    }
    out
}
pub fn counters() -> Option<HashMap<Key, u64>> {
    // Individual list-set reads avoid nft batch-cache bugs and large policy dumps.
    let mut all = HashMap::new();
    for name in ["map_out4", "map_in4", "map_out6", "map_in6"] {
        let text = crate::nft(
            &["-j", "list", "set", "inet", crate::rules::TABLE, name],
            None,
        )
        .ok()?;
        let _: Value = serde_json::from_str(&text).ok()?;
        all.extend(parse_counters(&text));
    }
    Some(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> Key {
        Key {
            mac: "02:00:00:00:00:01".into(),
            remote: "8.8.8.8".into(),
            inbound: false,
        }
    }
    #[test]
    fn delta_reset_quiet_and_expiry() {
        let mut t = Tracker::default();
        let at = Instant::now();
        t.sample(HashMap::from([(key(), 100)]), at);
        assert!(t.current(at).is_empty());
        t.sample(HashMap::from([(key(), 140)]), at);
        assert_eq!(t.current(at)[0].bytes, 40);
        assert!(t.current(at + Duration::from_secs(5)).is_empty());
        t.sample(HashMap::from([(key(), 140)]), at);
        assert!(t.current(at).is_empty());
        t.sample(HashMap::from([(key(), 2)]), at);
        assert!(t.current(at).is_empty());
        t.sample(HashMap::from([(key(), 4)]), at);
        assert_eq!(t.current(at)[0].bytes, 2);
        t.sample(HashMap::new(), at);
        assert!(t.current(at).is_empty());
    }
    #[test]
    fn new_short_lived_path_after_baseline_is_visible() {
        let mut t = Tracker::default();
        let at = Instant::now();
        t.sample(HashMap::new(), at);
        t.sample(HashMap::from([(key(), 64)]), at);
        assert_eq!(t.current(at).len(), 1);
        assert_eq!(t.current(at)[0].bytes, 64);
    }
    #[test]
    fn failure_recovery_seeds_without_replaying_old_totals() {
        let mut t = Tracker::default();
        let at = Instant::now();
        t.sample(HashMap::new(), at);
        t.sample(HashMap::from([(key(), 64)]), at);
        assert_eq!(t.current(at).len(), 1);
        t.invalidate();
        assert!(t.current(at).is_empty());
        t.sample(HashMap::from([(key(), 9000)]), at);
        assert!(t.current(at).is_empty());
        t.sample(HashMap::from([(key(), 9020)]), at);
        assert_eq!(t.current(at)[0].bytes, 20);
    }
    #[test]
    fn parses_only_bounded_observer_sets() {
        let j = r#"{"nftables":[{"set":{"name":"map_out6","elem":[{"elem":{"val":{"concat":["AA:BB:CC:DD:EE:FF","2606:4700::1111"]},"counter":{"bytes":123}}}]}}]}"#;
        let m = parse_counters(j);
        assert_eq!(m.values().next(), Some(&123));
        assert!(!m.keys().next().unwrap().inbound);
        assert!(parse_counters("bad").is_empty());
    }
    #[test]
    fn excludes_non_global_ips() {
        for ip in [
            "fe80::1",
            "ff02::fb",
            "ff02::1:3",
            "::ffff:8.8.8.8",
            "192.168.1.1",
            "224.0.0.251",
            "100.64.1.1",
            "2001:db8::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "2606:4700::1111"] {
            assert!(public_ip(ip.parse().unwrap()));
        }
    }
}
