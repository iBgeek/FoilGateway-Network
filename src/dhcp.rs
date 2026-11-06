//! A small DHCP client for setup, used when nothing else on the system
//! (systemd-networkd, NetworkManager, dhclient) looks after a port.
//! It asks with the broadcast flag set, so it works before the port has
//! an address, and puts the lease in with `ip`, which marks it dynamic.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::fd::FromRawFd;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub router: Option<Ipv4Addr>,
    pub server: Ipv4Addr,
    pub secs: u32,
    pub dns: Vec<Ipv4Addr>,
}

const COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Our own fallback server's address. The client never takes a lease from it.
pub const FALLBACK: Ipv4Addr = Ipv4Addr::new(192, 168, 30, 1);

fn socket_on(iface: &str) -> Result<UdpSocket, String> {
    socket_port(iface, 68)
}

fn socket_port(iface: &str, port: u16) -> Result<UdpSocket, String> {
    // SAFETY: plain socket calls on a descriptor we own; it goes into a
    // UdpSocket straight after, which closes it.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err("can't open a socket".into());
        }
        let sock = UdpSocket::from_raw_fd(fd);
        let one: libc::c_int = 1;
        let p = &one as *const _ as *const libc::c_void;
        let n = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, p, n);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BROADCAST, p, n);
        if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, iface.as_ptr() as *const libc::c_void, iface.len() as libc::socklen_t) != 0 {
            return Err(format!("can't bind to {iface}"));
        }
        let addr = libc::sockaddr_in { sin_family: libc::AF_INET as libc::sa_family_t, sin_port: port.to_be(), sin_addr: libc::in_addr { s_addr: 0 }, sin_zero: [0; 8] };
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t) != 0 {
            return Err(format!("port {port} is taken"));
        }
        Ok(sock)
    }
}

pub fn packet(kind: u8, xid: u32, mac: &[u8; 6], want: Option<(Ipv4Addr, Ipv4Addr)>) -> Vec<u8> {
    let mut p = vec![0u8; 236];
    p[0] = 1; // request
    p[1] = 1; // ethernet
    p[2] = 6;
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    p[10] = 0x80; // answer by broadcast, we have no address yet
    p[28..34].copy_from_slice(mac);
    p.extend_from_slice(&COOKIE);
    p.extend_from_slice(&[53, 1, kind]);
    p.extend_from_slice(&[61, 7, 1]);
    p.extend_from_slice(mac);
    if let Some((ip, server)) = want {
        p.extend_from_slice(&[50, 4]);
        p.extend_from_slice(&ip.octets());
        p.extend_from_slice(&[54, 4]);
        p.extend_from_slice(&server.octets());
    }
    p.extend_from_slice(&[12, 11]);
    p.extend_from_slice(b"foilgateway");
    p.extend_from_slice(&[55, 4, 1, 3, 51, 54, 255]);
    p
}

/// (message type, offered address, lease) from a server's answer to `xid`.
pub fn parse(buf: &[u8], xid: u32) -> Option<(u8, Lease)> {
    if buf.len() < 240 || buf[0] != 2 || buf[4..8] != xid.to_be_bytes() || buf[236..240] != COOKIE {
        return None;
    }
    let ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let (mut kind, mut prefix, mut router, mut server, mut secs) = (0, 24, None, Ipv4Addr::UNSPECIFIED, 3600);
    let mut dns = Vec::new();
    let mut i = 240;
    while i < buf.len() {
        let code = buf[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = *buf.get(i + 1)? as usize;
        let v = buf.get(i + 2..i + 2 + len)?;
        let v4 = || (len >= 4).then(|| Ipv4Addr::new(v[0], v[1], v[2], v[3]));
        match code {
            53 if len == 1 => kind = v[0],
            1 => prefix = v4().map(|m| u32::from(m).count_ones() as u8).unwrap_or(24),
            3 => router = v4(),
            6 => dns = v.as_chunks::<4>().0.iter().map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3])).collect(),
            54 => server = v4().unwrap_or(server),
            51 if len == 4 => secs = u32::from_be_bytes([v[0], v[1], v[2], v[3]]),
            _ => {}
        }
        i += 2 + len;
    }
    Some((kind, Lease { ip, prefix, router, server, secs, dns }))
}

fn wait(sock: &UdpSocket, xid: u32, want: &[u8], until: Instant) -> Option<(u8, Lease)> {
    let mut buf = [0u8; 1500];
    while Instant::now() < until {
        sock.set_read_timeout(Some(until.saturating_duration_since(Instant::now()).max(Duration::from_millis(10)))).ok();
        let Ok((n, _)) = sock.recv_from(&mut buf) else { continue };
        if let Some(got) = parse(&buf[..n], xid).filter(|g| want.contains(&g.0) && g.1.server != FALLBACK) {
            return Some(got);
        }
    }
    None
}

/// Discover, offer, request, ack. Gives up after `secs`.
pub fn obtain(iface: &str, mac: &[u8; 6], secs: u64) -> Result<Lease, String> {
    let sock = socket_on(iface)?;
    let to = SocketAddrV4::new(Ipv4Addr::BROADCAST, 67);
    let until = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < until {
        let mut r = [0u8; 4];
        getrandom::getrandom(&mut r).map_err(|e| e.to_string())?;
        let xid = u32::from_ne_bytes(r);
        sock.send_to(&packet(1, xid, mac, None), to).map_err(|e| format!("can't send on {iface}: {e}"))?;
        let Some((_, offer)) = wait(&sock, xid, &[2], (Instant::now() + Duration::from_secs(3)).min(until)) else { continue };
        sock.send_to(&packet(3, xid, mac, Some((offer.ip, offer.server))), to).map_err(|e| e.to_string())?;
        match wait(&sock, xid, &[5, 6], (Instant::now() + Duration::from_secs(3)).min(until)) {
            Some((5, ack)) => return Ok(ack),
            _ => continue,
        }
    }
    Err(format!("no DHCP answer on {iface}"))
}

/// A tiny DHCP server for setup on a network with no router handing out
/// addresses: 192.168.30.100-199, no gateway, no DNS. It stops as soon as
/// `stop` is set, or by itself when another server's answer shows up on
/// the port (then it returns true).
pub fn serve(iface: &str, own_mac: &[u8; 6], stop: &std::sync::atomic::AtomicBool) -> Result<bool, String> {
    use std::sync::atomic::Ordering;
    let sock = socket_port(iface, 67)?;
    // Answers from other servers go to port 68; watch for them there.
    let watch = socket_on(iface).ok();
    if let Some(w) = &watch {
        w.set_nonblocking(true).ok();
    }
    sock.set_read_timeout(Some(Duration::from_millis(300))).ok();
    let mut given: Vec<[u8; 6]> = Vec::new();
    let mut buf = [0u8; 1500];
    while !stop.load(Ordering::Relaxed) {
        if let Some(w) = &watch {
            while let Ok((n, _)) = w.recv_from(&mut buf) {
                if let Some((k, l)) = parse_any(&buf[..n]) {
                    if (k == 2 || k == 5) && l.server != FALLBACK && !l.server.is_unspecified() {
                        return Ok(true);
                    }
                }
            }
        }
        let Ok((n, _)) = sock.recv_from(&mut buf) else { continue };
        let Some(reply) = answer(&buf[..n], own_mac, &mut given) else { continue };
        let _ = sock.send_to(&reply, SocketAddrV4::new(Ipv4Addr::BROADCAST, 68));
    }
    Ok(false)
}

fn parse_any(buf: &[u8]) -> Option<(u8, Lease)> {
    if buf.len() < 8 {
        return None;
    }
    parse(buf, u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]))
}

/// Our answer to one client packet, if it gets one.
pub fn answer(req: &[u8], own_mac: &[u8; 6], given: &mut Vec<[u8; 6]>) -> Option<Vec<u8>> {
    if req.len() < 240 || req[0] != 1 || req[236..240] != COOKIE || req[28..34] == own_mac[..] {
        return None;
    }
    let mac: [u8; 6] = req[28..34].try_into().ok()?;
    let (mut kind, mut asked, mut server) = (0, None, None);
    let mut i = 240;
    while i + 1 < req.len() && req[i] != 255 {
        if req[i] == 0 {
            i += 1;
            continue;
        }
        let len = req[i + 1] as usize;
        let v = req.get(i + 2..i + 2 + len)?;
        match (req[i], len) {
            (53, 1) => kind = v[0],
            (50, 4) => asked = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            (54, 4) => server = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            _ => {}
        }
        i += 2 + len;
    }
    let slot = match given.iter().position(|m| *m == mac) {
        Some(n) => n,
        None if given.len() < 100 => {
            given.push(mac);
            given.len() - 1
        }
        None => return None,
    };
    let ip = Ipv4Addr::new(192, 168, 30, 100 + slot as u8);
    let reply = match kind {
        1 => 2,
        3 if server.is_some_and(|s| s != FALLBACK) => return None, // took another server's offer
        3 => {
            let ci = Ipv4Addr::new(req[12], req[13], req[14], req[15]);
            if asked.unwrap_or(ci) == ip { 5 } else { 6 }
        }
        _ => return None,
    };
    let mut p = req[..236].to_vec();
    p[0] = 2;
    p[16..20].copy_from_slice(&if reply == 6 { [0; 4] } else { ip.octets() });
    p.extend_from_slice(&COOKIE);
    p.extend_from_slice(&[53, 1, reply, 54, 4]);
    p.extend_from_slice(&FALLBACK.octets());
    if reply != 6 {
        p.extend_from_slice(&[1, 4, 255, 255, 255, 0, 51, 4]);
        // Short, so computers move to the real router soon after setup.
        p.extend_from_slice(&300u32.to_be_bytes());
    }
    p.push(255);
    Some(p)
}

pub fn mac_bytes(mac: &str) -> Option<[u8; 6]> {
    let v: Vec<u8> = mac.split(':').filter_map(|x| u8::from_str_radix(x, 16).ok()).collect();
    v.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_parses() {
        let mac = [2, 0, 0, 0, 0, 1];
        let mut p = packet(5, 77, &mac, None);
        p[0] = 2;
        p[16..20].copy_from_slice(&[10, 10, 10, 234]);
        p.truncate(240);
        p.extend_from_slice(&[53, 1, 5, 1, 4, 255, 255, 255, 0, 3, 4, 10, 10, 10, 1, 51, 4, 0, 0, 0x0e, 0x10, 54, 4, 10, 10, 10, 1, 6, 8, 10, 10, 10, 1, 9, 9, 9, 9, 255]);
        let (k, l) = parse(&p, 77).unwrap();
        assert_eq!(k, 5);
        assert_eq!(l, Lease { ip: Ipv4Addr::new(10, 10, 10, 234), prefix: 24, router: Some(Ipv4Addr::new(10, 10, 10, 1)), server: Ipv4Addr::new(10, 10, 10, 1), secs: 3600, dns: vec![Ipv4Addr::new(10, 10, 10, 1), Ipv4Addr::new(9, 9, 9, 9)] });
        assert!(parse(&p, 78).is_none());
        assert_eq!(mac_bytes("02:00:00:00:00:01"), Some(mac));
    }

    #[test]
    fn fallback_server_hands_out_addresses() {
        let us = [2, 0, 0, 0, 0, 9];
        let them = [2, 0, 0, 0, 0, 1];
        let mut given = Vec::new();
        let offer = answer(&packet(1, 5, &them, None), &us, &mut given).unwrap();
        let (k, l) = parse(&offer, 5).unwrap();
        assert_eq!((k, l.ip, l.server, l.router), (2, Ipv4Addr::new(192, 168, 30, 100), FALLBACK, None));
        let ack = answer(&packet(3, 5, &them, Some((l.ip, FALLBACK))), &us, &mut given).unwrap();
        assert_eq!(parse(&ack, 5).unwrap().0, 5);
        let nak = answer(&packet(3, 6, &them, Some((Ipv4Addr::new(192, 168, 30, 150), FALLBACK))), &us, &mut given).unwrap();
        assert_eq!(parse(&nak, 6).unwrap().0, 6);
        // Our own client and requests meant for another server get nothing.
        assert!(answer(&packet(1, 7, &us, None), &us, &mut given).is_none());
        assert!(answer(&packet(3, 8, &them, Some((l.ip, Ipv4Addr::new(10, 0, 0, 1)))), &us, &mut given).is_none());
    }
}
