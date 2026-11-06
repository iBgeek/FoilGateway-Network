//! Who an address belongs to: the names devices looked up (passive DNS)
//! and, failing that, the address's own reverse name.
//!
//! DNS answers are copied out of the kernel by a socket per LAN port with
//! a classic BPF filter attached, so only UDP packets from port 53 ever
//! reach this process; every other packet stays in the kernel. Nothing in
//! the firewall rules changes for it.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

/// Answers are kept at least this long past their TTL: a device keeps a
/// connection open (and gets blocked on retries) long after the answer
/// itself has expired.
pub const GRACE: i64 = 3600;
/// And never longer than a day.
pub const MAX_KEEP: i64 = 86400;
/// One line per device and address. At about 120 bytes each, the default
/// caps stay under 5 MB for hundreds of devices.
pub const DEV_CAP: usize = 32768;
pub const IP_CAP: usize = 8192;

/// A map with a size cap that drops the least recently used entry, and
/// entries that expire. Both operations are O(log n).
pub struct Lru<K: Eq + Hash + Clone + Ord, V> {
    map: HashMap<K, (V, i64, u64)>,
    order: BTreeMap<u64, K>,
    tick: u64,
    cap: usize,
}

impl<K: Eq + Hash + Clone + Ord, V: Clone> Lru<K, V> {
    pub fn new(cap: usize) -> Self {
        Lru { map: HashMap::new(), order: BTreeMap::new(), tick: 0, cap: cap.max(1) }
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    /// Sets the value, good until `expires`; newest goes to the back.
    pub fn put(&mut self, k: K, v: V, expires: i64) {
        self.tick += 1;
        if let Some((_, _, old)) = self.map.insert(k.clone(), (v, expires, self.tick)) {
            self.order.remove(&old);
        }
        self.order.insert(self.tick, k);
        while self.map.len() > self.cap {
            let Some((_, oldest)) = self.order.pop_first() else { break };
            self.map.remove(&oldest);
        }
    }
    /// The value if it hasn't expired. Reading counts as use.
    pub fn get(&mut self, k: &K, now: i64) -> Option<V> {
        let (v, exp, t) = self.map.get_mut(k)?;
        if *exp < now {
            let t = *t;
            self.map.remove(k);
            self.order.remove(&t);
            return None;
        }
        self.tick += 1;
        self.order.remove(t);
        *t = self.tick;
        self.order.insert(self.tick, k.clone());
        Some(v.clone())
    }
    pub fn prune(&mut self, now: i64) {
        let gone: Vec<(K, u64)> = self.map.iter().filter(|(_, (_, e, _))| *e < now).map(|(k, (_, _, t))| (k.clone(), *t)).collect();
        for (k, t) in gone {
            self.map.remove(&k);
            self.order.remove(&t);
        }
    }
}

pub type Mac = [u8; 6];

/// Names looked up, per device and address, plus the latest name for an
/// address whoever asked.
pub struct Pdns {
    by_dev: Lru<(Mac, IpAddr), Arc<str>>,
    by_ip: Lru<IpAddr, Arc<str>>,
    pub answers: u64,
}

impl Default for Pdns {
    fn default() -> Self {
        Pdns::with_caps(DEV_CAP, IP_CAP)
    }
}

pub fn keep_until(now: i64, ttl: u32) -> i64 {
    now + (ttl as i64 + GRACE).min(MAX_KEEP)
}

impl Pdns {
    pub fn with_caps(dev: usize, ip: usize) -> Self {
        Pdns { by_dev: Lru::new(dev), by_ip: Lru::new(ip), answers: 0 }
    }
    pub fn len(&self) -> (usize, usize) {
        (self.by_dev.len(), self.by_ip.len())
    }
    pub fn record(&mut self, dev: Mac, a: &Answer, now: i64) {
        self.answers += 1;
        let name: Arc<str> = Arc::from(a.name.as_str());
        for (ip, ttl) in &a.ips {
            let until = keep_until(now, *ttl);
            self.by_dev.put((dev, *ip), name.clone(), until);
            self.by_ip.put(*ip, name.clone(), until);
        }
    }
    /// The name this device looked up for the address, else the latest
    /// name anyone looked up for it.
    pub fn name_for(&mut self, dev: Option<Mac>, ip: IpAddr, now: i64) -> Option<String> {
        if let Some(d) = dev {
            if let Some(n) = self.by_dev.get(&(d, ip), now) {
                return Some(n.to_string());
            }
        }
        self.by_ip.get(&ip, now).map(|n| n.to_string())
    }
    pub fn prune(&mut self, now: i64) {
        self.by_dev.prune(now);
        self.by_ip.prune(now);
    }
}

pub fn parse_mac(s: &str) -> Option<Mac> {
    let mut m = [0u8; 6];
    let mut it = s.split(':');
    for b in m.iter_mut() {
        *b = u8::from_str_radix(it.next()?, 16).ok()?;
    }
    it.next().is_none().then_some(m)
}

pub fn mac_text(m: &Mac) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// One DNS response: the name asked for and the addresses it got, with
/// their TTLs. CNAME chains end at the name the device asked for.
#[derive(Debug, PartialEq)]
pub struct Answer {
    pub name: String,
    pub ips: Vec<(IpAddr, u32)>,
}

fn read_name(m: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end = None;
    let mut hops = 0;
    loop {
        let len = *m.get(i)? as usize;
        if len & 0xc0 == 0xc0 {
            let p = ((len & 0x3f) << 8) | *m.get(i + 1)? as usize;
            end.get_or_insert(i + 2);
            hops += 1;
            if hops > 16 {
                return None;
            }
            i = p;
            continue;
        }
        if len == 0 {
            return Some((out.to_ascii_lowercase(), end.unwrap_or(i + 1)));
        }
        let label = m.get(i + 1..i + 1 + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.extend(label.iter().map(|&c| if c.is_ascii_graphic() { c as char } else { '?' }));
        if out.len() > 253 {
            return None;
        }
        i += 1 + len;
    }
}

/// Parses a DNS response message (from the UDP payload on).
pub fn parse_dns(m: &[u8]) -> Option<Answer> {
    if m.len() < 12 || m[2] & 0x80 == 0 || m[3] & 0x0f != 0 {
        return None;
    }
    let qd = u16::from_be_bytes([m[4], m[5]]);
    let an = u16::from_be_bytes([m[6], m[7]]) as usize;
    if qd != 1 || an == 0 {
        return None;
    }
    let (name, mut i) = read_name(m, 12)?;
    i += 4;
    let mut ips = Vec::new();
    for _ in 0..an.min(64) {
        let (_, j) = read_name(m, i)?;
        let h = m.get(j..j + 10)?;
        let (ty, ttl, len) = (u16::from_be_bytes([h[0], h[1]]), u32::from_be_bytes([h[4], h[5], h[6], h[7]]), u16::from_be_bytes([h[8], h[9]]) as usize);
        let data = m.get(j + 10..j + 10 + len)?;
        match (ty, len) {
            (1, 4) => ips.push((IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])), ttl)),
            (28, 16) => ips.push((IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?)), ttl)),
            _ => {}
        }
        i = j + 10 + len;
    }
    (!ips.is_empty() && !name.is_empty()).then_some(Answer { name, ips })
}

/// An Ethernet frame carrying a DNS answer: (the device it went to, the answer).
pub fn parse_frame(f: &[u8]) -> Option<(Mac, Answer)> {
    let dst: Mac = f.get(0..6)?.try_into().ok()?;
    let et = u16::from_be_bytes([*f.get(12)?, *f.get(13)?]);
    let udp = match et {
        0x0800 => {
            let ihl = (*f.get(14)? & 0x0f) as usize * 4;
            if *f.get(23)? != 17 {
                return None;
            }
            14 + ihl
        }
        0x86dd if *f.get(20)? == 17 => 54,
        _ => return None,
    };
    if u16::from_be_bytes([*f.get(udp)?, *f.get(udp + 1)?]) != 53 {
        return None;
    }
    Some((dst, parse_dns(f.get(udp + 8..)?)?))
}

// Classic BPF: IPv4 or IPv6, UDP, source port 53, not a later fragment.
// Everything else is dropped in the kernel.
#[cfg(target_os = "linux")]
fn filter() -> Vec<libc::sock_filter> {
    let s = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    const LDH: u16 = 0x28;
    const LDB: u16 = 0x30;
    const JEQ: u16 = 0x15;
    const JSET: u16 = 0x45;
    const LDXB_MSH: u16 = 0xb1;
    const LDH_X: u16 = 0x48;
    const RET: u16 = 0x06;
    vec![
        s(LDH, 0, 0, 12),          // 0 ethertype
        s(JEQ, 0, 7, 0x0800),      // 1 v4 ? 2 : 9
        s(LDB, 0, 0, 23),          // 2 protocol
        s(JEQ, 0, 11, 17),         // 3 udp ? 4 : drop
        s(LDH, 0, 0, 20),          // 4 flags and fragment offset
        s(JSET, 9, 0, 0x1fff),     // 5 a later fragment: drop
        s(LDXB_MSH, 0, 0, 14),     // 6 x = IP header length
        s(LDH_X, 0, 0, 14),        // 7 UDP source port
        s(JEQ, 5, 6, 53),          // 8 53 ? accept : drop
        s(JEQ, 0, 5, 0x86dd),      // 9 v6 ? 10 : drop
        s(LDB, 0, 0, 20),          // 10 next header
        s(JEQ, 0, 3, 17),          // 11 udp ? 12 : drop
        s(LDH, 0, 0, 54),          // 12 UDP source port
        s(JEQ, 0, 1, 53),          // 13 53 ? accept : drop
        s(RET, 0, 0, 0x0000_ffff), // 14 accept
        s(RET, 0, 0, 0),           // 15 drop
    ]
}

/// Watches one port for DNS answers until the socket fails. `on` gets
/// each one.
#[cfg(target_os = "linux")]
pub fn watch(ifname: &str, on: &mut dyn FnMut(Mac, Answer)) -> Result<(), String> {
    let mut prog = filter();
    unsafe {
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, (libc::ETH_P_ALL as u16).to_be() as i32);
        if fd < 0 {
            return Err(format!("can't open a packet socket: {}", std::io::Error::last_os_error()));
        }
        let close = |e: String| {
            libc::close(fd);
            Err(e)
        };
        let fp = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_mut_ptr() };
        if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &fp as *const _ as *const libc::c_void, std::mem::size_of::<libc::sock_fprog>() as u32) != 0 {
            return close(format!("can't attach the DNS filter: {}", std::io::Error::last_os_error()));
        }
        let name = std::ffi::CString::new(ifname).map_err(|e| e.to_string())?;
        let idx = libc::if_nametoindex(name.as_ptr());
        if idx == 0 {
            return close(format!("no port called {ifname}"));
        }
        let mut sa: libc::sockaddr_ll = std::mem::zeroed();
        sa.sll_family = libc::AF_PACKET as u16;
        sa.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sa.sll_ifindex = idx as i32;
        if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32) != 0 {
            return close(format!("can't watch {ifname}: {}", std::io::Error::last_os_error()));
        }
        // Anything queued before the filter went on.
        let mut buf = vec![0u8; 4096];
        while libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_DONTWAIT) > 0 {}
        loop {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return close(format!("watching {ifname} stopped: {e}"));
            }
            if let Some((mac, a)) = parse_frame(&buf[..n as usize]) {
                on(mac, a);
            }
        }
    }
}

// ---- reverse names, looked up in the background and kept ----

/// Reverse names for addresses, one lookup at a time in the background.
/// A page asks and gets what is known now; the answer shows on its next
/// refresh.
#[derive(Default)]
pub struct Owners {
    cache: Mutex<Option<Lru<IpAddr, String>>>,
    queue: Mutex<VecDeque<IpAddr>>,
}

pub const OWNER_CAP: usize = 4096;
const QUEUE_CAP: usize = 256;

impl Owners {
    /// The owner if known ("" when the address has no reverse name), None
    /// when not looked up yet (it is queued).
    pub fn get(&self, ip: IpAddr, now: i64) -> Option<String> {
        if !is_public(ip) {
            return Some(String::new());
        }
        let mut c = self.cache.lock().unwrap();
        let c = c.get_or_insert_with(|| Lru::new(OWNER_CAP));
        if let Some(v) = c.get(&ip, now) {
            return Some(v);
        }
        let mut q = self.queue.lock().unwrap();
        if q.len() < QUEUE_CAP && !q.contains(&ip) {
            q.push_back(ip);
        }
        None
    }
    pub fn next(&self) -> Option<IpAddr> {
        self.queue.lock().unwrap().pop_front()
    }
    pub fn put(&self, ip: IpAddr, owner: String, until: i64) {
        self.cache.lock().unwrap().get_or_insert_with(|| Lru::new(OWNER_CAP)).put(ip, owner, until);
    }
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => !(a.is_private() || a.is_loopback() || a.is_link_local() || a.is_multicast() || a.is_broadcast() || a.is_unspecified() || a.octets()[0] == 100 && a.octets()[1] & 0xc0 == 64),
        IpAddr::V6(a) => !(a.is_loopback() || a.is_multicast() || a.is_unspecified() || a.segments()[0] & 0xfe00 == 0xfc00 || a.segments()[0] & 0xffc0 == 0xfe80),
    }
}

/// The part of a host name its owner registered: "ec2-1-2-3-4.compute-1.amazonaws.com"
/// gives "amazonaws.com", "host.example.co.uk" gives "example.co.uk".
pub fn registered(host: &str) -> String {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let l: Vec<&str> = h.split('.').filter(|x| !x.is_empty()).collect();
    if l.len() < 2 {
        return h;
    }
    let tld = l[l.len() - 1];
    let second = l[l.len() - 2];
    let take = if tld.len() == 2 && l.len() >= 3 && ["co", "com", "net", "org", "ac", "gov", "edu", "ne", "or", "go"].contains(&second) { 3 } else { 2 };
    l[l.len() - take..].join(".")
}

pub fn ptr_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let mut s = String::new();
            for b in a.octets().iter().rev() {
                s += &format!("{:x}.{:x}.", b & 0xf, b >> 4);
            }
            s + "ip6.arpa"
        }
    }
}

/// One PTR query to the system's first name server.
pub fn reverse(ip: IpAddr) -> Result<Option<(String, u32)>, String> {
    let ns = std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.trim().strip_prefix("nameserver").and_then(|a| a.trim().parse::<IpAddr>().ok()))
        .ok_or("no name server")?;
    let sock = std::net::UdpSocket::bind(if ns.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok();
    let mut id = [0u8; 2];
    let _ = getrandom::getrandom(&mut id);
    let mut q = vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in ptr_name(ip).split('.') {
        q.push(l.len() as u8);
        q.extend(l.as_bytes());
    }
    q.extend([0, 0, 12, 0, 1]);
    sock.send_to(&q, (ns, 53)).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 1500];
    let n = sock.recv(&mut buf).map_err(|e| e.to_string())?;
    let m = &buf[..n];
    if n < 12 || m[0..2] != id {
        return Err("bad answer".into());
    }
    let rcode = m[3] & 0x0f;
    if rcode == 3 {
        return Ok(None);
    }
    if rcode != 0 {
        return Err(format!("name server said {rcode}"));
    }
    let an = u16::from_be_bytes([m[6], m[7]]);
    let (_, mut i) = read_name(m, 12).ok_or("bad answer")?;
    i += 4;
    for _ in 0..an {
        let (_, j) = read_name(m, i).ok_or("bad answer")?;
        let h = m.get(j..j + 10).ok_or("bad answer")?;
        let (ty, ttl, len) = (u16::from_be_bytes([h[0], h[1]]), u32::from_be_bytes([h[4], h[5], h[6], h[7]]), u16::from_be_bytes([h[8], h[9]]) as usize);
        if ty == 12 {
            let (name, _) = read_name(m, j + 10).ok_or("bad answer")?;
            return Ok(Some((name, ttl)));
        }
        i = j + 10 + len;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(name: &str, ips: &[(&str, u32)]) -> Answer {
        Answer { name: name.into(), ips: ips.iter().map(|(a, t)| (a.parse().unwrap(), *t)).collect() }
    }

    #[test]
    fn lru_drops_the_least_recently_used() {
        let mut l: Lru<u32, u32> = Lru::new(3);
        for k in 0..3 {
            l.put(k, k, 100);
        }
        // Reading 0 makes 1 the oldest.
        assert_eq!(l.get(&0, 0), Some(0));
        l.put(3, 3, 100);
        assert_eq!(l.len(), 3);
        assert_eq!(l.get(&1, 0), None);
        assert_eq!(l.get(&0, 0), Some(0));
        // Expired entries read as gone and are pruned.
        l.put(9, 9, 5);
        assert_eq!(l.get(&9, 6), None);
        l.put(8, 8, 5);
        l.prune(6);
        assert_eq!(l.get(&8, 0), None);
        // Many more than the cap: stays at the cap, keeps the newest.
        for k in 100..10_100 {
            l.put(k, k, 100);
        }
        assert_eq!(l.len(), 3);
        assert_eq!(l.order.len(), 3);
        assert_eq!(l.get(&10_099, 0), Some(10_099));
    }

    #[test]
    fn names_per_device_with_ttl_and_eviction() {
        let mut p = Pdns::with_caps(4, 2);
        let tv = [1, 2, 3, 4, 5, 6];
        let pc = [9, 9, 9, 9, 9, 9];
        let ip: IpAddr = "51.132.193.107".parse().unwrap();
        p.record(tv, &answer("v10.events.data.microsoft.com", &[("51.132.193.107", 60)]), 1000);
        p.record(pc, &answer("other.example", &[("51.132.193.107", 60)]), 1001);
        // Each device sees the name it asked for; others get the latest.
        assert_eq!(p.name_for(Some(tv), ip, 1002).as_deref(), Some("v10.events.data.microsoft.com"));
        assert_eq!(p.name_for(Some([0; 6]), ip, 1002).as_deref(), Some("other.example"));
        // Kept for TTL + grace, then gone.
        assert!(p.name_for(Some(tv), ip, 1000 + 60 + GRACE).is_some());
        assert!(p.name_for(Some(tv), ip, 1000 + 61 + GRACE + 1).is_none());
        // A huge TTL is capped at a day.
        assert_eq!(keep_until(0, u32::MAX), MAX_KEEP);
        // Over the cap the oldest answers go first.
        let mut p = Pdns::with_caps(4, 2);
        for i in 0..10u8 {
            p.record(tv, &answer(&format!("n{i}.test"), &[(&format!("1.1.1.{i}"), 300)]), 0);
        }
        assert_eq!(p.len(), (4, 2));
        assert!(p.name_for(Some(tv), "1.1.1.0".parse().unwrap(), 1).is_none());
        assert_eq!(p.name_for(Some(tv), "1.1.1.9".parse().unwrap(), 1).as_deref(), Some("n9.test"));
    }

    // A real answer: www.example.com CNAME to a host with two A records.
    fn sample() -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        for l in ["www", "example", "com"] {
            m.push(l.len() as u8);
            m.extend(l.as_bytes());
        }
        m.extend([0, 0, 1, 0, 1]);
        // CNAME -> edge.cdn.test
        m.extend([0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30]);
        let target: Vec<u8> = [4u8].iter().copied().chain(*b"edge").chain([3]).chain(*b"cdn").chain([4]).chain(*b"test").chain([0]).collect();
        m.extend((target.len() as u16).to_be_bytes());
        let at = m.len();
        m.extend(&target);
        for last in [10u8, 11] {
            m.extend([0xc0, at as u8, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, last]);
        }
        m
    }

    #[test]
    fn parses_answers_and_frames() {
        let a = parse_dns(&sample()).unwrap();
        assert_eq!(a.name, "www.example.com");
        assert_eq!(a.ips, vec![("93.184.216.10".parse().unwrap(), 300), ("93.184.216.11".parse().unwrap(), 300)]);
        let mut f = vec![0xaa, 0xbb, 0xcc, 0, 0, 1, 2, 2, 2, 2, 2, 2, 8, 0];
        f.extend([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 1, 1, 1, 1, 10, 0, 0, 2]);
        f.extend([0, 53, 0xc0, 0x00, 0, 0, 0, 0]);
        f.extend(sample());
        let (mac, a) = parse_frame(&f).unwrap();
        assert_eq!(mac_text(&mac), "aa:bb:cc:00:00:01");
        assert_eq!(a.ips.len(), 2);
        // A question, not an answer.
        let mut q = sample();
        q[2] = 0x01;
        assert!(parse_dns(&q).is_none());
        // Garbage and loops don't panic.
        assert!(parse_dns(&[0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xc0, 12]).is_none());
        for n in 0..f.len() {
            let _ = parse_frame(&f[..n]);
        }
    }

    // Runs the kernel filter over frames, the way the kernel would.
    fn bpf(prog: &[libc::sock_filter], p: &[u8]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let h = |i: usize| p.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]) as u32);
        loop {
            let i = &prog[pc];
            pc += 1;
            match i.code {
                0x28 => match h(i.k as usize) { Some(v) => a = v, None => return 0 },
                0x30 => match p.get(i.k as usize) { Some(v) => a = *v as u32, None => return 0 },
                0x48 => match h(x as usize + i.k as usize) { Some(v) => a = v, None => return 0 },
                0xb1 => match p.get(i.k as usize) { Some(v) => x = 4 * (*v as u32 & 0xf), None => return 0 },
                0x15 => pc += if a == i.k { i.jt } else { i.jf } as usize,
                0x45 => pc += if a & i.k != 0 { i.jt } else { i.jf } as usize,
                0x06 => return i.k,
                c => panic!("unknown op {c:#x}"),
            }
        }
    }

    #[test]
    fn kernel_filter_passes_only_dns_answers() {
        let prog = filter();
        let mut v4 = vec![0u8; 12];
        v4.extend([8, 0, 0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 1, 1, 1, 1, 10, 0, 0, 2, 0, 53, 0x30, 0x39, 0, 0, 0, 0]);
        assert!(bpf(&prog, &v4) > 0);
        let mut q = v4.clone();
        (q[34], q[35]) = (0x30, 0x39); // from a high port: a question or other UDP
        assert_eq!(bpf(&prog, &q), 0);
        let mut tcp = v4.clone();
        tcp[23] = 6;
        assert_eq!(bpf(&prog, &tcp), 0);
        let mut frag = v4.clone();
        frag[21] = 5;
        assert_eq!(bpf(&prog, &frag), 0);
        let mut v6 = vec![0u8; 12];
        v6.extend([0x86, 0xdd, 0x60, 0, 0, 0, 0, 8, 17, 64]);
        v6.extend([0u8; 32]);
        v6.extend([0, 53, 0x30, 0x39, 0, 8, 0, 0]);
        assert!(bpf(&prog, &v6) > 0);
        v6[55] = 54;
        assert_eq!(bpf(&prog, &v6), 0);
        assert_eq!(bpf(&prog, &[0u8; 8]), 0);
    }

    #[test]
    fn owner_names() {
        assert_eq!(registered("ec2-1-2-3-4.compute-1.amazonaws.com."), "amazonaws.com");
        assert_eq!(registered("host.example.co.uk"), "example.co.uk");
        assert_eq!(registered("lhr25s34-in-f14.1e100.net"), "1e100.net");
        assert_eq!(ptr_name("1.2.3.4".parse().unwrap()), "4.3.2.1.in-addr.arpa");
        assert!(!is_public("10.1.2.3".parse().unwrap()));
        assert!(is_public("51.132.193.107".parse().unwrap()));
    }
}
