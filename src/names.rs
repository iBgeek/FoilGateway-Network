//! Finding a device's host name when DHCP didn't tell us: reverse DNS on
//! the router, then the device itself over mDNS, then NetBIOS.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Sends `q` to each of `to` from one socket and returns the first reply
/// that comes from `from` with the same id. Other packets (a second
/// responder, a late answer to an earlier question) are skipped instead of
/// ending the wait, which 0.5.2 did.
fn ask(to: &[SocketAddr], from: Ipv4Addr, q: &[u8]) -> Option<Vec<u8>> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = s.set_multicast_loop_v4(false);
    for t in to {
        let _ = s.send_to(q, t);
    }
    let end = Instant::now() + Duration::from_millis(800);
    let mut buf = [0u8; 1500];
    loop {
        let left = end.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())?;
        s.set_read_timeout(Some(left)).ok()?;
        let (n, src) = s.recv_from(&mut buf).ok()?;
        if src.ip() == from && n >= 2 && buf[..2] == q[..2] {
            return Some(buf[..n].to_vec());
        }
    }
}

pub fn ptr_query(ip: Ipv4Addr, id: u16) -> Vec<u8> {
    let o = ip.octets();
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for part in [o[3].to_string(), o[2].to_string(), o[1].to_string(), o[0].to_string(), "in-addr".into(), "arpa".into()] {
        q.push(part.len() as u8);
        q.extend_from_slice(part.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 12, 0, 1]);
    q
}

/// A name at `at`, following compression pointers. Returns it and where
/// the name ended in the message.
fn name_at(m: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let n = *m.get(at)? as usize;
        if n == 0 {
            return Some((parts.join("."), end.unwrap_or(at + 1)));
        }
        if n & 0xc0 == 0xc0 {
            end.get_or_insert(at + 2);
            at = ((n & 0x3f) << 8) | *m.get(at + 1)? as usize;
            continue;
        }
        parts.push(String::from_utf8_lossy(m.get(at + 1..at + 1 + n)?).into_owned());
        at += 1 + n;
    }
    None
}

/// The first PTR answer in a DNS reply.
pub fn parse_ptr(m: &[u8]) -> Option<String> {
    if m.len() < 12 || m[3] & 0x0f != 0 {
        return None;
    }
    let (qd, an) = (u16::from_be_bytes([m[4], m[5]]), u16::from_be_bytes([m[6], m[7]]));
    let mut at = 12;
    for _ in 0..qd {
        at = name_at(m, at)?.1 + 4;
    }
    for _ in 0..an {
        let next = name_at(m, at)?.1;
        let kind = u16::from_be_bytes([*m.get(next)?, *m.get(next + 1)?]);
        let len = u16::from_be_bytes([*m.get(next + 8)?, *m.get(next + 9)?]) as usize;
        if kind == 12 {
            return name_at(m, next + 10).map(|n| n.0);
        }
        at = next + 10 + len;
    }
    None
}

pub fn nbstat_query() -> Vec<u8> {
    let mut q = vec![0x4e, 0x42, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20];
    // "*" padded with zeros, in NetBIOS half-byte encoding.
    let mut raw = [0u8; 16];
    raw[0] = b'*';
    for b in raw {
        q.push(b'A' + (b >> 4));
        q.push(b'A' + (b & 0x0f));
    }
    q.extend_from_slice(&[0, 0, 0x21, 0, 1]);
    q
}

/// The machine's own name from a NetBIOS node status reply.
pub fn parse_nbstat(m: &[u8]) -> Option<String> {
    let at = 12 + 34 + 4 + 4 + 2; // question name, type/class, ttl, length
    let count = *m.get(at)? as usize;
    for i in 0..count {
        let e = m.get(at + 1 + i * 18..at + 1 + i * 18 + 18)?;
        let group = e[16] & 0x80 != 0;
        if e[15] == 0 && !group {
            let name = String::from_utf8_lossy(&e[..15]).trim_end().to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// "laptop.lan." becomes "laptop"; addresses and junk come back empty.
pub fn tidy(name: &str) -> String {
    let n = name.trim_end_matches('.');
    let first = n.split('.').next().unwrap_or("");
    let local = [".local", ".lan", ".home", ".localdomain", ".home.arpa", ".internal"].iter().any(|s| n.to_lowercase().ends_with(s));
    let n = if local { first } else { n };
    if n.is_empty() || n.eq_ignore_ascii_case("localhost") || n.ends_with("in-addr.arpa") || n.parse::<Ipv4Addr>().is_ok() || n.chars().all(|c| c.is_ascii_digit() || c == '-' || c == '.') {
        return String::new();
    }
    n.chars().filter(|c| !c.is_control()).take(63).collect()
}

/// Tries the router's DNS, then the device over mDNS (sent to the device
/// and to 224.0.0.251, as a legacy unicast question so the answer comes
/// back to our port), then NetBIOS.
pub fn lookup(ip: Ipv4Addr, dns: &[Ipv4Addr]) -> String {
    for d in dns {
        if let Some(n) = ask(&[SocketAddr::from((*d, 53))], *d, &ptr_query(ip, 0x4642)).and_then(|r| parse_ptr(&r)) {
            let n = tidy(&n);
            if !n.is_empty() {
                return n;
            }
        }
    }
    let mut q = ptr_query(ip, 0x4643);
    q[2] = 0; // mDNS: no recursion
    if let Some(n) = ask(&[SocketAddr::from((ip, 5353)), SocketAddr::from((MDNS, 5353))], ip, &q).and_then(|r| parse_ptr(&r)) {
        let n = tidy(&n);
        if !n.is_empty() {
            return n;
        }
    }
    ask(&[SocketAddr::from((ip, 137))], ip, &nbstat_query()).and_then(|r| parse_nbstat(&r)).map(|n| tidy(&n)).unwrap_or_default()
}

const MDNS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_ptr_reply() {
        let mut r = ptr_query(Ipv4Addr::new(10, 10, 10, 7), 1);
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 1;
        r.extend_from_slice(&[0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 60, 0, 13, 7]);
        r.extend_from_slice(b"klanker");
        r.extend_from_slice(&[3]);
        r.extend_from_slice(b"lan");
        r.push(0);
        assert_eq!(parse_ptr(&r).as_deref(), Some("klanker.lan"));
        assert_eq!(tidy("klanker.lan."), "klanker");
        assert_eq!(tidy("10-10-10-7"), "");
        assert_eq!(tidy("host.example.com"), "host.example.com");
        r[3] = 0x83; // NXDOMAIN
        assert_eq!(parse_ptr(&r), None);
    }

    #[test]
    fn reads_a_netbios_reply() {
        let mut r = nbstat_query();
        r[2] = 0x84;
        r.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        r.push(2);
        let e = |name: &str, suffix: u8, flags: u8| {
            let mut n = format!("{name:<15}").into_bytes();
            n.push(suffix);
            n.extend_from_slice(&[flags, 0]);
            n
        };
        let mut body = e("WORKGROUP", 0, 0x80);
        body.extend(e("DESKTOP-7", 0, 0x04));
        r.extend(body);
        assert_eq!(parse_nbstat(&r).as_deref(), Some("DESKTOP-7"));
    }

    fn labels(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for p in name.split('.') {
            v.push(p.len() as u8);
            v.extend_from_slice(p.as_bytes());
        }
        v.push(0);
        v
    }

    /// dnsmasq on a router answering a PTR for a lease: RA+AA flags, the
    /// question echoed, the answer name a pointer to it, then an authority
    /// record. Shape as captured from dnsmasq 2.89.
    #[test]
    fn reads_dnsmasq_ptr() {
        let mut r = ptr_query(Ipv4Addr::new(10, 10, 10, 3), 0x4642);
        r[2] = 0x85;
        r[3] = 0x80;
        r[7] = 1;
        r[9] = 1;
        let host = labels("raspberrypi.lan");
        r.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 0, 0, host.len() as u8]);
        r.extend_from_slice(&host);
        // authority: 10.10.10.in-addr.arpa SOA (contents skipped)
        r.extend_from_slice(&[0xc0, 0x0e, 0, 6, 0, 1, 0, 0, 0, 0, 0, 2, 0xc0, 0x0c]);
        assert_eq!(tidy(&parse_ptr(&r).unwrap()), "raspberrypi");
    }

    /// Avahi answering a legacy unicast question (source port not 5353):
    /// question echoed, class without the cache-flush bit, TTL capped at 10.
    #[test]
    fn reads_avahi_legacy_unicast() {
        let mut r = ptr_query(Ipv4Addr::new(10, 10, 10, 3), 0x4643);
        r[2] = 0x84;
        r[3] = 0;
        r[7] = 1;
        let host = labels("raspberrypi.local");
        r.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 10, 0, host.len() as u8]);
        r.extend_from_slice(&host);
        assert_eq!(tidy(&parse_ptr(&r).unwrap()), "raspberrypi");
    }

    /// A multicast-style mDNS answer: no question, cache-flush class,
    /// an A record before the PTR.
    #[test]
    fn reads_mdns_without_question() {
        let mut r = vec![0x46, 0x43, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        let host = labels("DESKTOP-ABC.local");
        r.extend_from_slice(&host);
        r.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 10, 10, 10, 42]);
        r.extend_from_slice(&labels("42.10.10.10.in-addr.arpa"));
        r.extend_from_slice(&[0, 12, 0x80, 1, 0, 0, 0, 120, 0, 2, 0xc0, 12]);
        assert_eq!(tidy(&parse_ptr(&r).unwrap()), "DESKTOP-ABC");
    }

    /// Windows NBSTAT reply as sent on the wire: no question section, one
    /// answer, six names (workstation, group, server, browser...), then the MAC.
    #[test]
    fn reads_windows_nbstat() {
        let q = nbstat_query();
        let mut r = vec![0x4e, 0x42, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        r.extend_from_slice(&q[12..12 + 34]);
        r.extend_from_slice(&[0, 0x21, 0, 1, 0, 0, 0, 0]);
        let names: [(&str, u8, u8); 4] = [("ASUS-PC", 0x00, 0x04), ("WORKGROUP", 0x00, 0x84), ("ASUS-PC", 0x20, 0x04), ("WORKGROUP", 0x1e, 0x84)];
        let len = 1 + names.len() * 18 + 6;
        r.extend_from_slice(&(len as u16).to_be_bytes());
        r.push(names.len() as u8);
        for (n, s, f) in names {
            r.extend_from_slice(format!("{n:<15}").as_bytes());
            r.extend_from_slice(&[s, f, 0]);
        }
        r.extend_from_slice(&[0xbc, 0xfc, 0xe7, 0x71, 0x82, 0x0d]);
        assert_eq!(parse_nbstat(&r).as_deref(), Some("ASUS-PC"));
    }

    /// A stray packet first (wrong id) no longer ends the wait.
    #[test]
    fn ask_skips_strays() {
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let at = srv.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, from) = srv.recv_from(&mut b).unwrap();
            srv.send_to(&[0xff, 0xff, 0], from).unwrap();
            let mut r = b[..n].to_vec();
            r[2] = 0x84;
            r[7] = 1;
            let host = labels("pi.local");
            r.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 10, 0, host.len() as u8]);
            r.extend_from_slice(&host);
            srv.send_to(&r, from).unwrap();
        });
        let r = ask(&[at], Ipv4Addr::LOCALHOST, &ptr_query(Ipv4Addr::new(10, 0, 0, 1), 7)).unwrap();
        assert_eq!(parse_ptr(&r).as_deref(), Some("pi.local"));
    }
}
