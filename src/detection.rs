//! Passive, post-filter TCP metadata. No payload inspection or policy evaluator.
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::Instant,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Kind {
    Syn,
    Ack,
    Rst,
}
#[derive(Clone, Debug, Serialize)]
pub struct Signal {
    pub kind: Kind,
    pub mac: String,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub outbound: bool,
    pub audit: bool,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize)]
struct Flow(String, IpAddr, IpAddr, u16, u16, u32);
impl Signal {
    pub fn key(&self) -> String {
        serde_json::to_string(&self.flow()).unwrap()
    }
    fn response_key(&self) -> String {
        let mut f = self.flow();
        f.5 = f.5.wrapping_sub(1);
        serde_json::to_string(&f).unwrap()
    }
    fn flow(&self) -> Flow {
        Flow(
            self.mac.clone(),
            self.src,
            self.dst,
            self.sport,
            self.dport,
            self.seq,
        )
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Alert {
    pub mac: String,
    pub remote: String,
    pub outbound: bool,
    pub audit: bool,
    pub reason: String,
    pub ports: Vec<u16>,
    pub count: usize,
    pub support: Vec<Signal>,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct Subject(String, IpAddr, bool, String, u16);
#[derive(Default)]
pub struct Engine {
    pending: HashMap<Flow, (u64, Signal)>,
    seen: HashMap<Flow, u64>,
    windows: HashMap<Subject, VecDeque<(u64, Signal)>>,
    cooldown: HashMap<Subject, u64>,
    last: Option<u64>,
    fault: bool,
}
impl Engine {
    pub fn reset(&mut self) {
        *self = Self::default();
    }
    fn hit(&mut self, s: &Signal, reason: &str, t: u64, out: &mut Vec<Alert>) {
        let remote = if s.outbound { s.dst } else { s.src };
        let k = Subject(
            s.mac.clone(),
            remote,
            s.outbound,
            reason.into(),
            if reason == "tcp_failure" { s.dport } else { 0 },
        );
        if self.windows.len() >= 1024 && !self.windows.contains_key(&k) {
            self.fault = true;
            return;
        }
        let w = self.windows.entry(k.clone()).or_default();
        while w.front().is_some_and(|v| t.saturating_sub(v.0) > 60) {
            w.pop_front();
        }
        if reason == "port_sweep" && w.iter().any(|v| v.1.dport == s.dport) {
            return;
        }
        if w.len() >= 128 {
            w.pop_front();
        }
        w.push_back((t, s.clone()));
        let threshold = if reason == "port_sweep" { 12 } else { 8 };
        if w.len() >= threshold
            && self
                .cooldown
                .get(&k)
                .is_none_or(|last| t.saturating_sub(*last) >= 300)
        {
            let mut ports: Vec<_> = w.iter().map(|v| v.1.dport).collect();
            ports.sort_unstable();
            ports.dedup();
            if self.cooldown.len() >= 4096 && !self.cooldown.contains_key(&k) {
                self.fault = true;
                return;
            }
            out.push(Alert {
                mac: s.mac.clone(),
                remote: remote.to_string(),
                outbound: s.outbound,
                audit: w.iter().any(|v| v.1.audit),
                reason: reason.into(),
                ports,
                count: w.len(),
                support: w.iter().map(|v| v.1.clone()).collect(),
            });
            self.cooldown.insert(k, t);
        }
    }
    pub fn sample(&mut self, signals: Vec<Signal>, t: u64, healthy: bool) -> Vec<Alert> {
        if !healthy || self.last.is_some_and(|last| t.saturating_sub(last) > 4) {
            self.reset();
            if !healthy {
                return vec![];
            }
        }
        self.last = Some(t);
        self.seen.retain(|_, last| t.saturating_sub(*last) <= 120);
        self.cooldown
            .retain(|_, last| t.saturating_sub(*last) <= 300);
        self.windows.retain(|_, w| {
            while w.front().is_some_and(|v| t.saturating_sub(v.0) > 60) {
                w.pop_front();
            }
            !w.is_empty()
        });
        let mut out = vec![];
        for s in signals.iter().filter(|s| s.kind == Kind::Syn) {
            let k = s.flow();
            if let Some(last) = self.seen.get_mut(&k) {
                *last = t;
                continue;
            }
            if self.seen.len() >= 4096 || self.pending.len() >= 1024 {
                self.reset();
                self.fault = true;
                return vec![];
            }
            self.seen.insert(k.clone(), t);
            self.pending.insert(k, (t, s.clone()));
            self.hit(s, "port_sweep", t, &mut out);
        }
        for s in signals.iter().filter(|s| s.kind == Kind::Ack) {
            let mut k = s.flow();
            k.5 = k.5.wrapping_sub(1);
            self.pending.remove(&k);
            for (remote, outbound) in [(s.dst, true), (s.src, false)] {
                if let Some(window) = self.windows.get_mut(&Subject(
                    s.mac.clone(),
                    remote,
                    outbound,
                    "tcp_failure".into(),
                    s.dport,
                )) {
                    window.retain(|v| {
                        v.1.seq != k.5
                            || v.1.sport != k.3
                            || v.1.dport != k.4
                            || v.1.src != k.1
                            || v.1.dst != k.2
                            || v.1.mac != k.0
                    });
                }
            }
        }
        for s in signals.iter().filter(|s| s.kind == Kind::Rst) {
            let mut k = s.flow();
            k.5 = k.5.wrapping_sub(1);
            if let Some((_, original)) = self.pending.remove(&k) {
                self.hit(&original, "tcp_failure", t, &mut out);
            }
        }
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, v)| t.saturating_sub(v.0) >= 10)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            if let Some((_, s)) = self.pending.remove(&k) {
                self.hit(&s, "tcp_failure", t, &mut out);
            }
        }
        if self.fault {
            self.reset();
            self.fault = true;
            return vec![];
        }
        out
    }
}
#[derive(Clone, Serialize)]
pub struct Health {
    pub state: String,
    pub detail: String,
    pub tracked: usize,
}
pub struct Snapshot {
    pub signals: Vec<Signal>,
    pub generation: u32,
}
pub struct Detector {
    engine: Engine,
    began: Instant,
    last: Option<Instant>,
    generation: Option<u32>,
    health: Health,
    resolved: Vec<String>,
    last_replies: HashSet<String>,
}
impl Default for Detector {
    fn default() -> Self {
        Self {
            engine: Engine::default(),
            began: Instant::now(),
            last: None,
            generation: None,
            resolved: vec![],
            last_replies: HashSet::new(),
            health: Health {
                state: "off".into(),
                detail: String::new(),
                tracked: 0,
            },
        }
    }
}
impl Detector {
    pub fn storage_failed(&mut self, error: String) {
        self.engine.reset();
        self.last_replies.clear();
        self.resolved.clear();
        self.last = Some(Instant::now());
        self.health.state = "degraded".into();
        self.health.detail = format!("Could not save observation: {error}");
        self.health.tracked = 0;
    }
    pub fn take_resolved(&mut self) -> Vec<String> {
        std::mem::take(&mut self.resolved)
    }
    pub fn invalidate(&mut self) {
        self.last_replies.clear();
        self.resolved.clear();
        self.engine.reset();
        self.last = None;
        self.generation = None;
        self.health.state = "warming_up".into();
    }
    pub fn health(&self, on: bool) -> Health {
        if !on {
            return Health {
                state: "off".into(),
                detail: String::new(),
                tracked: 0,
            };
        }
        let mut h = self.health.clone();
        if self.last.is_none_or(|t| t.elapsed().as_secs() > 5) {
            h.state = "unavailable".into();
            if h.detail.is_empty() {
                h.detail = "No current observation sample.".into();
            }
        }
        h
    }
    pub fn ingest(&mut self, on: bool, snapshot: Result<Snapshot, String>) -> Vec<Alert> {
        self.resolved.clear();
        if !on {
            self.last_replies.clear();
            self.engine.reset();
            self.last = None;
            self.health.state = "off".into();
            return vec![];
        }
        match snapshot {
            Ok(s) => {
                self.last = Some(Instant::now());
                self.health.state = "watching".into();
                self.health.detail.clear();
                if self.generation != Some(s.generation) {
                    self.engine.reset();
                }
                self.generation = Some(s.generation);
                let replies: HashSet<_> = s
                    .signals
                    .iter()
                    .filter(|s| s.kind == Kind::Ack)
                    .map(Signal::response_key)
                    .collect();
                self.resolved = replies.difference(&self.last_replies).cloned().collect();
                self.last_replies = replies;
                let a = self
                    .engine
                    .sample(s.signals, self.began.elapsed().as_secs(), true);
                self.health.tracked = self.engine.pending.len();
                if std::mem::take(&mut self.engine.fault) {
                    self.resolved.clear();
                    self.last_replies.clear();
                    self.health.state = "degraded".into();
                    self.health.detail =
                        "Observation capacity reached; incomplete evidence discarded.".into();
                }
                a
            }
            Err(e) => {
                self.engine.reset();
                self.last = Some(Instant::now());
                self.health.state = "degraded".into();
                self.health.detail = e;
                self.health.tracked = 0;
                vec![]
            }
        }
    }
}
pub fn decode(name: &str, b: &[u8]) -> Result<Signal, String> {
    let v6 = name.ends_with('6');
    let iplen = if v6 { 16 } else { 4 };
    let syn = name.starts_with("syn");
    let want = 8 + 2 * iplen + if syn { 12 } else { 8 };
    if b.len() != want {
        return Err("Unexpected TCP metadata key length".into());
    }
    let mac = b[..6]
        .iter()
        .map(|n| format!("{n:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let ip = |a: usize| -> IpAddr {
        if v6 {
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&b[a..a + 16]).unwrap()).into()
        } else {
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&b[a..a + 4]).unwrap()).into()
        }
    };
    let a = 8 + 2 * iplen;
    let u16at = |n| u16::from_be_bytes([b[n], b[n + 1]]);
    let u32at = |n| u32::from_be_bytes(b[n..n + 4].try_into().unwrap());
    let (sport, dport, seq, tag) = if syn {
        (
            u16at(a),
            u16at(a + 2),
            u32at(a + 4),
            u32::from_ne_bytes(b[a + 8..a + 12].try_into().unwrap()),
        )
    } else {
        (u16at(a + 2), u16at(a), u32at(a + 4), 0)
    };
    if syn && !(1..=4).contains(&tag) {
        return Err("Unknown acceptance provenance".into());
    }
    Ok(Signal {
        kind: if syn {
            Kind::Syn
        } else if name.starts_with("ack") {
            Kind::Ack
        } else {
            Kind::Rst
        },
        mac,
        src: ip(if syn { 8 } else { 8 + iplen }),
        dst: ip(if syn { 8 + iplen } else { 8 }),
        sport,
        dport,
        seq,
        outbound: tag == 1 || tag == 3,
        audit: tag >= 3,
    })
}
// nft's JSON loses widths of raw integer concat fields. Read the documented
// nf_tables netlink key bytes directly, with strict lengths and dump checks.
fn attrs(mut b: &[u8]) -> Result<Vec<(u16, &[u8])>, String> {
    let mut out = vec![];
    while !b.is_empty() {
        if b.len() < 4 {
            return Err("Truncated netlink attribute header".into());
        }
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let ty = u16::from_ne_bytes([b[2], b[3]]) & 0x3fff;
        if len < 4 || len > b.len() {
            return Err("Truncated netlink attribute".into());
        }
        out.push((ty, &b[4..len]));
        let aligned = (len + 3) & !3;
        if aligned > b.len() {
            return Err("Missing netlink attribute padding".into());
        }
        b = &b[aligned..];
    }
    Ok(out)
}
fn attr(t: u16, value: &[u8]) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
    v.extend_from_slice(&t.to_ne_bytes());
    v.extend_from_slice(value);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}
fn kernel_sender(pid: u32, family: u16, len: libc::socklen_t) -> Result<(), String> {
    if pid != 0
        || family != libc::AF_NETLINK as u16
        || len as usize != std::mem::size_of::<libc::sockaddr_nl>()
    {
        return Err("Observation did not come from the kernel".into());
    }
    Ok(())
}
struct Reader {
    fd: OwnedFd,
    seq: u32,
    began: Instant,
}
impl Reader {
    fn open() -> Result<Self, String> {
        unsafe {
            let raw = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            );
            if raw < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let fd = OwnedFd::from_raw_fd(raw);
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as u16;
            if libc::bind(
                raw,
                &addr as *const _ as *const _,
                std::mem::size_of_val(&addr) as u32,
            ) != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let timeout = libc::timeval {
                tv_sec: 0,
                tv_usec: 250000,
            };
            if libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const _,
                std::mem::size_of_val(&timeout) as u32,
            ) != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            Ok(Self {
                fd,
                seq: 0,
                began: Instant::now(),
            })
        }
    }
    fn query(&mut self, kind: u16, body: &[u8], dump: bool) -> Result<Vec<Vec<u8>>, String> {
        self.seq += 1;
        let raw = self.fd.as_raw_fd();
        let mut req = vec![];
        req.extend_from_slice(&((body.len() + 16) as u32).to_ne_bytes());
        req.extend_from_slice(&((10u16 << 8) | kind).to_ne_bytes());
        req.extend_from_slice(&(if dump { 0x301u16 } else { 1u16 }).to_ne_bytes());
        req.extend_from_slice(&self.seq.to_ne_bytes());
        req.extend_from_slice(&0u32.to_ne_bytes());
        req.extend_from_slice(body);
        if unsafe { libc::send(raw, req.as_ptr() as *const _, req.len(), 0) } != req.len() as isize
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut parts = vec![];
        let mut bytes = 0;
        loop {
            if self.began.elapsed().as_millis() >= 2000 {
                return Err("Observation dump exceeded its deadline".into());
            }
            let mut buf = [0u8; 65536];
            let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut senderlen = std::mem::size_of_val(&sender) as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    raw,
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    libc::MSG_TRUNC,
                    &mut sender as *mut _ as *mut _,
                    &mut senderlen,
                )
            };
            if n < 0 {
                return Err(format!(
                    "Observation unavailable: {}",
                    std::io::Error::last_os_error()
                ));
            }
            kernel_sender(sender.nl_pid, sender.nl_family, senderlen)?;
            if n == 0 || n as usize > buf.len() {
                return Err("Observation truncated".into());
            }
            let mut off = 0;
            let mut done = false;
            while off < n as usize {
                if off + 16 > n as usize {
                    return Err("Truncated observation header".into());
                }
                let h = &buf[off..];
                let length = u32::from_ne_bytes(h[..4].try_into().unwrap()) as usize;
                let ty = u16::from_ne_bytes(h[4..6].try_into().unwrap());
                let flags = u16::from_ne_bytes(h[6..8].try_into().unwrap());
                let got = u32::from_ne_bytes(h[8..12].try_into().unwrap());
                if length < 16 || off + length > n as usize || got != self.seq || flags & 0x10 != 0
                {
                    return Err("Interrupted or invalid observation dump".into());
                }
                let b = &buf[off + 16..off + length];
                off += (length + 3) & !3;
                if ty == 3 {
                    if b.len() >= 4 && i32::from_ne_bytes(b[..4].try_into().unwrap()) != 0 {
                        return Err("Kernel interrupted observation dump".into());
                    }
                    done = true;
                    continue;
                }
                if ty == 2 {
                    return Err("Kernel rejected observation query".into());
                }
                if ty != (10u16 << 8) | if dump { 12 } else { 15 } {
                    return Err("Unexpected observation response type".into());
                }
                if b.len() < 4 {
                    return Err("Missing observation header".into());
                }
                bytes += b.len();
                if bytes > 524288 {
                    return Err("Observation response capacity reached".into());
                }
                parts.push(b.to_vec());
            }
            if done || !dump {
                return Ok(parts);
            }
        }
    }
    fn generation(&mut self) -> Result<u32, String> {
        let parts = self.query(16, &[0, 0, 0, 0], false)?;
        for b in parts {
            for (ty, value) in attrs(&b[4..])? {
                if ty == 1 && value.len() == 4 {
                    return Ok(u32::from_be_bytes(value.try_into().unwrap()));
                }
            }
        }
        Err("Missing ruleset generation".into())
    }
}
pub fn snapshot() -> Result<Snapshot, String> {
    snapshot_between(|| {})
}
fn snapshot_between(before_finish: impl FnOnce()) -> Result<Snapshot, String> {
    let mut reader = Reader::open()?;
    let generation = reader.generation()?;
    let mut signals = vec![];
    for kind in ["eligible", "syn", "ack", "rst"] {
        for family in [4, 6] {
            let name = format!("{kind}{family}");
            let set = format!("dd_{name}\0");
            let mut body = vec![1, 0, 0, 0];
            body.extend(attr(1, b"foilgateway\0"));
            body.extend(attr(2, set.as_bytes()));
            let mut count = 0;
            for b in reader.query(13, &body, true)? {
                for (t, list) in attrs(&b[4..])? {
                    if t != 3 {
                        continue;
                    }
                    for (_, element) in attrs(list)? {
                        for (t, key) in attrs(element)? {
                            if t != 1 {
                                continue;
                            }
                            for (t, value) in attrs(key)? {
                                if t != 1 {
                                    continue;
                                }
                                count += 1;
                                if count >= 512 {
                                    return Err("Observation capacity reached; incomplete evidence discarded".into());
                                }
                                if kind != "eligible" {
                                    signals.push(decode(&name, value)?);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    before_finish();
    if reader.generation()? != generation {
        return Err("Rules changed during observation; incomplete evidence discarded".into());
    }
    Ok(Snapshot {
        signals,
        generation,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn syn(port: u16, seq: u32) -> Signal {
        Signal {
            kind: Kind::Syn,
            mac: "02:00:00:00:00:02".into(),
            src: "8.8.8.9".parse().unwrap(),
            dst: "8.8.8.8".parse().unwrap(),
            sport: 40000 + port,
            dport: port,
            seq,
            outbound: true,
            audit: false,
        }
    }
    #[test]
    fn sweep_counts_unique_ports_not_retries() {
        let mut e = Engine::default();
        let mut alerts = vec![];
        for p in 1..=12 {
            let s = syn(p, p as u32);
            alerts.extend(e.sample(vec![s.clone(), s], p as u64, true));
        }
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].reason, "port_sweep");
    }
    #[test]
    fn failures_need_distinct_attempts_and_healthy_time() {
        let mut e = Engine::default();
        let mut v = vec![];
        for p in 1..=8 {
            let mut s = syn(443, p);
            s.sport = 40000 + p as u16;
            v.push(s);
        }
        assert!(e.sample(v, 0, true).is_empty());
        for t in [2, 4, 6, 8] {
            assert!(e.sample(vec![], t, true).is_empty());
        }
        let a = e.sample(vec![], 10, true);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].reason, "tcp_failure");
    }
    #[test]
    fn response_prevents_failure_and_established_reset_is_not_failure() {
        let mut e = Engine::default();
        for p in 1..=8 {
            let mut s = syn(443, p);
            s.sport += p as u16;
            let mut ack = s.clone();
            ack.kind = Kind::Ack;
            ack.seq = s.seq.wrapping_add(1);
            let mut rst = ack.clone();
            rst.kind = Kind::Rst;
            assert!(e.sample(vec![s, ack, rst], p as u64, true).is_empty());
        }
        assert!(e.sample(vec![], 30, true).is_empty());
    }
    #[test]
    fn loss_and_off_never_manufacture_timeouts() {
        let mut e = Engine::default();
        let v = (1..=8)
            .map(|p| {
                let mut s = syn(443, p);
                s.sport += p as u16;
                s
            })
            .collect();
        e.sample(v, 0, true);
        assert!(e.sample(vec![], 11, false).is_empty());
        assert!(e.sample(vec![], 22, true).is_empty());
    }
    #[test]
    fn parse_kernel_bytes_keeps_sequence_and_provenance() {
        let bytes = hex("02000000000200000808080908080808969e1f92d858ee0d01000000");
        let s = decode("syn4", &bytes).unwrap();
        assert_eq!(s.sport, 38558);
        assert_eq!(s.dport, 8082);
        assert_eq!(s.seq, 0xd858ee0d);
        assert!(s.outbound && !s.audit);
    }
    #[test]
    fn reply_wire_addresses_are_normalized_to_original_tuple() {
        for name in ["ack4", "rst4"] {
            let b = hex("020000000002000008080808080808091f92969e00000002");
            let s = decode(name, &b).unwrap();
            assert_eq!(s.src.to_string(), "8.8.8.9");
            assert_eq!(s.dst.to_string(), "8.8.8.8");
            assert_eq!((s.sport,s.dport,s.seq), (38558,8082,2));
        }
    }
    #[test]
    fn observer_capacity_must_report_degraded() {
        let mut d = Detector::default();
        let signals = (0..1025).map(|seq| syn(443, seq)).collect();
        assert!(d
            .ingest(
                true,
                Ok(Snapshot {
                    signals,
                    generation: 1
                })
            )
            .is_empty());
        assert_eq!(d.health(true).state, "degraded");
        assert_eq!(d.health(true).tracked, 0);
    }
    #[test]
    fn malformed_attribute_tails_are_rejected() {
        assert!(attrs(&[1]).is_err());
        assert!(attrs(&[4, 0, 1, 0, 9, 9]).is_err());
    }
    #[test]
    fn only_kernel_netlink_senders_are_accepted() {
        let n = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        assert!(kernel_sender(0, libc::AF_NETLINK as u16, n).is_ok());
        assert!(kernel_sender(7, libc::AF_NETLINK as u16, n).is_err());
        assert!(kernel_sender(0, libc::AF_INET as u16, n).is_err());
        assert!(kernel_sender(0, libc::AF_NETLINK as u16, n - 1).is_err());
    }
    #[test]
    fn generation_change_discards_pending_failure_evidence() {
        let mut d = Detector::default();
        let signals = (1..=8).map(|seq| syn(443, seq)).collect();
        assert!(d
            .ingest(
                true,
                Ok(Snapshot {
                    signals,
                    generation: 1
                })
            )
            .is_empty());
        assert_eq!(d.health(true).tracked, 8);
        assert!(d
            .ingest(
                true,
                Ok(Snapshot {
                    signals: vec![],
                    generation: 2
                })
            )
            .is_empty());
        assert_eq!(d.health(true).tracked, 0);
    }
    #[test]
    #[ignore]
    fn isolated_kernel_snapshot() {
        let parent = std::env::var("FOILGW_TEST_PARENT_NETNS").expect("isolated launcher required");
        let current = std::fs::read_link("/proc/self/ns/net")
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_ne!(parent, current, "refusing host network observation");
        let mapping = std::fs::read_to_string("/proc/self/uid_map").unwrap();
        let map: Vec<_> = mapping.split_whitespace().collect();
        assert_eq!(map.len(), 3);
        assert_eq!(map[0], "0");
        assert_eq!(map[2], "1");
        let mode = std::env::var("FOILGW_DD_CASE").unwrap();
        let mut detector = Detector::default();
        let mut alerts = vec![];
        if mode == "permission" {
            #[repr(C)]
            struct Header {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            #[derive(Clone, Copy)]
            struct Caps {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let mut h = Header {
                version: 0x20080522,
                pid: 0,
            };
            let mut caps = [Caps {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            }; 2];
            unsafe {
                assert_eq!(libc::syscall(libc::SYS_capget, &mut h, &mut caps), 0);
            }
            let original = caps;
            caps[0].effective &= !(1 << 12);
            unsafe {
                assert_eq!(libc::syscall(libc::SYS_capset, &h, &caps), 0);
            }
            let result = snapshot();
            unsafe {
                assert_eq!(libc::syscall(libc::SYS_capset, &h, &original), 0);
            }
            assert!(result.is_err(), "metadata access must require NET_ADMIN");
            assert!(detector.ingest(true, result).is_empty());
            assert_eq!(detector.health(true).state, "degraded");
            assert!(detector.ingest(true, snapshot()).is_empty());
            assert_eq!(detector.health(true).state, "watching");
            return;
        }
        if mode == "off" {
            assert!(snapshot().is_err());
            assert!(detector
                .ingest(false, Err("must stay off".into()))
                .is_empty());
            assert_eq!(detector.health(false).state, "off");
            return;
        }
        if mode == "overflow" {
            let error = snapshot()
                .err()
                .expect("full sets must not be complete evidence");
            assert!(error.contains("capacity"), "{error}");
            assert!(detector.ingest(true, Err(error)).is_empty());
            assert_eq!(detector.health(true).state, "degraded");
            return;
        }
        if mode == "generation" {
            let error = snapshot_between(|| {
                crate::nft(&["add", "table", "inet", "epoch_test"], None).unwrap();
                crate::nft(&["delete", "table", "inet", "epoch_test"], None).unwrap();
            })
            .err()
            .expect("mixed epoch must fail");
            assert!(error.contains("Rules changed"), "{error}");
            assert!(detector.ingest(true, Err(error)).is_empty());
            assert!(detector.ingest(true, snapshot()).is_empty());
            assert_eq!(detector.health(true).state, "watching");
            return;
        }
        if mode == "late-success" {
            use std::io::BufRead;
            let log = crate::caplog::Log::open(":memory:").unwrap();
            for round in 0..=5 {
                if round > 0 {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
                let alerts = detector.ingest(true, snapshot());
                for a in alerts {
                    log.pattern(&a, crate::caplog::now(), "TCP failures")
                        .unwrap();
                }
            }
            let rows = log.rows("alert", "", 0, 100);
            assert_eq!(rows.len(), 2);
            assert!(rows.iter().all(|r| r.count == 8));
            println!("DD_LATE_READY");
            let mut stdin = std::io::stdin().lock();
            let mut line = String::new();
            stdin.read_line(&mut line).unwrap();
            assert!(detector.ingest(true, snapshot()).is_empty());
            log.resolve_tcp(&detector.take_resolved()).unwrap();
            let rows = log.rows("alert", "", 0, 100);
            assert_eq!(rows.len(), 2);
            assert!(rows.iter().all(|r| r.count == 5));
            assert!(log.rows("", "", 0, 100).iter().all(|r| r.count == 8));
            println!("DD_LATE_PARTIAL");
            line.clear();
            stdin.read_line(&mut line).unwrap();
            assert!(detector.ingest(true, snapshot()).is_empty());
            log.resolve_tcp(&detector.take_resolved()).unwrap();
            assert!(log.rows("alert", "", 0, 100).is_empty());
            let raw = log.rows("", "", 0, 100);
            assert_eq!(raw.len(), 2);
            assert!(raw.iter().all(|r| r.handled && r.count == 8));
            println!("DD_LATE_RESOLVED raw preserved");
            return;
        }
        let rounds = if mode == "timeout" { 7 } else { 1 };
        for round in 0..rounds {
            if round > 0 {
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
            let snap = snapshot().expect("production netlink reader must return actual metadata");
            let after = std::fs::read_dir("/proc/self/fd").unwrap().count();
            assert_eq!(before, after, "snapshot must close its netlink socket");
            let syns = snap.signals.iter().filter(|s| s.kind == Kind::Syn).count();
            println!(
                "round={round} generation={} SYN={syns} replies={}",
                snap.generation,
                snap.signals.len() - syns
            );
            if let Ok(expected) = std::env::var("FOILGW_DD_EXPECT_SYN") {
                assert_eq!(syns, expected.parse::<usize>().unwrap());
            }
            alerts.extend(detector.ingest(true, Ok(snap)));
            assert_eq!(detector.health(true).state, "watching");
        }
        println!("alerts={}", serde_json::to_string(&alerts).unwrap());
        if mode.starts_with("incoming-") {
            assert!(alerts.iter().all(|a| !a.outbound && a.audit));
        }
        if mode == "sweep" || mode == "incoming-sweep" {
            assert_eq!(
                alerts.iter().filter(|a| a.reason == "port_sweep").count(),
                2
            );
        } else if mode == "refused"
            || mode == "timeout"
            || mode == "incoming-refused"
            || mode == "distinct-isn"
        {
            assert_eq!(
                alerts.iter().filter(|a| a.reason == "tcp_failure").count(),
                2
            );
        } else {
            assert!(alerts.is_empty(), "unexpected alert in {mode}");
        }
    }
    #[test]
    fn sequence_wrap_and_service_scope() {
        let mut e = Engine::default();
        let mut v = vec![];
        for n in 0..8 {
            let mut s = syn(if n < 4 { 443 } else { 80 }, u32::MAX);
            s.sport = 30000 + n;
            let mut reply = s.clone();
            reply.kind = Kind::Ack;
            reply.seq = 0;
            v.extend([s, reply]);
        }
        assert!(e.sample(v, 0, true).is_empty());
        for t in (2..=12).step_by(2) {
            assert!(e.sample(vec![], t, true).is_empty());
        }
    }
    #[test]
    fn windows_expire_and_cooldown_is_scoped() {
        let mut e = Engine::default();
        let ports = |base: u32| (1..=12).map(|p| syn(p, base + p as u32)).collect();
        assert_eq!(e.sample(ports(0), 0, true).len(), 1);
        assert!(e.sample(ports(100), 2, true).is_empty());
        for t in (4..=302).step_by(2) {
            e.sample(vec![], t, true);
        }
        assert_eq!(e.sample(ports(200), 302, true).len(), 1);
    }
    #[test]
    fn distinct_devices_and_directions_do_not_combine() {
        let mut e = Engine::default();
        let mut v = vec![];
        for p in 1..=12 {
            let mut s = syn(p, p as u32);
            if p > 6 {
                s.mac = "02:00:00:00:00:03".into();
                s.outbound = false;
            }
            v.push(s);
        }
        assert!(e.sample(v, 0, true).is_empty());
    }
    #[test]
    fn continuously_observed_retransmits_never_become_new_attempts() {
        let mut e = Engine::default();
        let signals: Vec<_> = (0..8).map(|seq| syn(443, seq)).collect();
        let mut alerts = vec![];
        for t in (0..=400).step_by(2) {
            alerts.extend(e.sample(signals.clone(), t, true));
        }
        assert_eq!(alerts.len(), 1);
    }
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
