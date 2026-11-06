//! Notes every DHCP exchange that crosses the bridge, so a LAN device
//! changing address can be explained later. Listens on the WAN port with
//! a packet socket; the router's DHCP server is on that side.

use std::net::Ipv4Addr;

#[derive(Debug, PartialEq)]
pub struct Dhcp {
    pub kind: &'static str,
    pub mac: String,
    pub ip: Option<Ipv4Addr>,
    pub server: Option<Ipv4Addr>,
    pub lease: Option<u32>,
    pub host: String,
}

fn kind(t: u8) -> &'static str {
    match t {
        1 => "DISCOVER",
        2 => "OFFER",
        3 => "REQUEST",
        4 => "DECLINE",
        5 => "ACK",
        6 => "NAK",
        7 => "RELEASE",
        8 => "INFORM",
        _ => "?",
    }
}

/// An ethernet frame, untagged or with one VLAN tag.
pub fn parse(f: &[u8]) -> Option<Dhcp> {
    let mut o = 12;
    if f.get(o..o + 2)? == [0x81, 0x00] {
        o += 4;
    }
    if f.get(o..o + 2)? != [0x08, 0x00] {
        return None;
    }
    let ip = &f[o + 2..];
    let ihl = (*ip.first()? & 0x0f) as usize * 4;
    if *ip.get(9)? != 17 {
        return None;
    }
    let udp = ip.get(ihl..)?;
    let (sp, dp) = (u16::from_be_bytes([udp[0], udp[1]]), u16::from_be_bytes([*udp.get(2)?, *udp.get(3)?]));
    if !matches!((sp, dp), (67, 68) | (68, 67)) {
        return None;
    }
    let b = udp.get(8..)?;
    if b.len() < 240 || b[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let mac = b[28..34].iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":");
    let yiaddr = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
    let ciaddr = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
    let (mut t, mut server, mut req, mut lease, mut host) = (0, None, None, None, String::new());
    let mut i = 240;
    while i < b.len() {
        let c = b[i];
        if c == 0 {
            i += 1;
            continue;
        }
        if c == 255 {
            break;
        }
        let n = *b.get(i + 1)? as usize;
        let v = b.get(i + 2..i + 2 + n)?;
        match (c, n) {
            (53, 1) => t = v[0],
            (54, 4) => server = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            (50, 4) => req = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            (51, 4) => lease = Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
            (12, _) => host = String::from_utf8_lossy(v).chars().filter(|c| !c.is_control()).collect(),
            _ => {}
        }
        i += 2 + n;
    }
    let set = |a: Ipv4Addr| (!a.is_unspecified()).then_some(a);
    let ip = set(yiaddr).or(req).or(set(ciaddr));
    Some(Dhcp { kind: kind(t), mac, ip, server, lease, host })
}

pub fn text(d: &Dhcp) -> String {
    let ip = d.ip.map(|a| a.to_string());
    let host = if d.host.is_empty() { String::new() } else { format!(" ({})", d.host) };
    let from = d.server.map(|s| format!(" from {s}")).unwrap_or_default();
    match d.kind {
        "OFFER" | "ACK" | "NAK" => {
            let lease = d.lease.map(|l| format!(", lease {}", lease_words(l))).unwrap_or_default();
            format!("DHCP {} {} to {}{from}{lease}", d.kind, ip.unwrap_or_default(), d.mac).replace("  ", " ")
        }
        _ => format!("DHCP {} from {}{host}{}", d.kind, d.mac, ip.map(|a| format!(" for {a}")).unwrap_or_default()),
    }
}

fn lease_words(s: u32) -> String {
    match s {
        s if s >= 7200 && s % 3600 == 0 => format!("{} h", s / 3600),
        s if s >= 120 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}

/// A packet socket on one port, giving up every 2 s so the caller can
/// notice the port changed.
pub struct Watch {
    fd: i32,
}

impl Watch {
    pub fn open(port: &str) -> Option<Watch> {
        let name = std::ffi::CString::new(port).ok()?;
        unsafe {
            let idx = libc::if_nametoindex(name.as_ptr());
            if idx == 0 {
                return None;
            }
            let proto = (libc::ETH_P_ALL as u16).to_be();
            let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto as i32);
            if fd < 0 {
                return None;
            }
            let mut sa: libc::sockaddr_ll = std::mem::zeroed();
            sa.sll_family = libc::AF_PACKET as u16;
            sa.sll_protocol = proto;
            sa.sll_ifindex = idx as i32;
            let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32);
            if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32) < 0 {
                libc::close(fd);
                return None;
            }
            Some(Watch { fd })
        }
    }

    pub fn next(&self) -> Option<Dhcp> {
        let mut buf = [0u8; 1600];
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            return None;
        }
        parse(&buf[..n as usize])
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(t: u8, yi: [u8; 4], opts: &[u8]) -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend([4, 0x7b, 0xcb, 0xa9, 0x90, 0xbe, 0x08, 0x00]);
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 10, 10, 1, 255, 255, 255, 255];
        let mut b = vec![0u8; 240];
        b[0] = 2;
        b[16..20].copy_from_slice(&yi);
        b[28..34].copy_from_slice(&[4, 0x7b, 0xcb, 0xa9, 0x90, 0xbe]);
        b[236..240].copy_from_slice(&[99, 130, 83, 99]);
        b.extend([53, 1, t]);
        b.extend(opts);
        b.push(255);
        let mut udp = vec![0, 67, 0, 68, 0, 0, 0, 0];
        udp.extend(b);
        ip.extend(udp);
        f.extend(ip);
        f
    }

    #[test]
    fn reads_an_ack() {
        let d = parse(&frame(5, [10, 10, 10, 67], &[54, 4, 10, 10, 10, 1, 51, 4, 0, 1, 0x51, 0x80])).unwrap();
        assert_eq!(text(&d), "DHCP ACK 10.10.10.67 to 04:7b:cb:a9:90:be from 10.10.10.1, lease 24 h");
    }

    #[test]
    fn reads_a_request() {
        let d = parse(&frame(3, [0; 4], &[50, 4, 10, 10, 10, 67, 12, 7, b'C', b'l', b'u', b'n', b'k', b'e', b'r'])).unwrap();
        assert_eq!(text(&d), "DHCP REQUEST from 04:7b:cb:a9:90:be (Clunker) for 10.10.10.67");
    }

    #[test]
    fn skips_other_traffic() {
        let mut f = frame(5, [0; 4], &[]);
        f[14 + 20 + 1] = 80;
        assert!(parse(&f).is_none());
    }
}
