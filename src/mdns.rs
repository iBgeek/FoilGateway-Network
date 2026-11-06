//! Answers "foilgateway.local" on the local network (multicast DNS), with
//! the gateway's address on the port the question came in on. Only A
//! records, only that one name. If something else holds port 5353 and
//! won't share it, avahi-publish is used instead when it's installed.

use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::net::UdpSocket;
use std::os::fd::FromRawFd;

pub const NAME: &str = "foilgateway.local";
const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// The A question for our name in a query, if it's asked. Returns the
/// question bytes (for legacy unicast answers) and whether it was QU.
pub fn asks_for_us(q: &[u8]) -> Option<Vec<u8>> {
    if q.len() < 12 || q[2] & 0x80 != 0 {
        return None; // too short, or an answer
    }
    let count = u16::from_be_bytes([q[4], q[5]]);
    let mut i = 12;
    for _ in 0..count {
        let start = i;
        let mut labels = Vec::new();
        loop {
            let len = *q.get(i)? as usize;
            if len == 0 {
                i += 1;
                break;
            }
            if len & 0xc0 != 0 {
                return None; // compressed names in questions: not from anyone we serve
            }
            labels.push(String::from_utf8_lossy(q.get(i + 1..i + 1 + len)?).to_ascii_lowercase());
            i += 1 + len;
        }
        let kind = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
        let end = i + 4;
        q.get(i + 2..end)?;
        i = end;
        if labels.join(".") == NAME && (kind == 1 || kind == 255) {
            return Some(q[start..end].to_vec());
        }
    }
    None
}

fn name_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    for l in NAME.split('.') {
        out.push(l.len() as u8);
        out.extend_from_slice(l.as_bytes());
    }
    out.push(0);
    out
}

/// An answer with one A record. `legacy` is a plain DNS-style reply to a
/// one-shot resolver (it carries the question and the asker's id).
pub fn answer(addr: Ipv4Addr, legacy: Option<(u16, &[u8])>) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&legacy.map(|l| l.0).unwrap_or(0).to_be_bytes());
    p.extend_from_slice(&[0x84, 0x00]);
    p.extend_from_slice(&[0, if legacy.is_some() { 1 } else { 0 }, 0, 1, 0, 0, 0, 0]);
    if let Some((_, q)) = legacy {
        p.extend_from_slice(q);
    }
    p.extend_from_slice(&name_bytes());
    p.extend_from_slice(&[0, 1]);
    // Cache-flush bit only on real multicast answers.
    p.extend_from_slice(if legacy.is_some() { &[0x00, 0x01] } else { &[0x80, 0x01] });
    p.extend_from_slice(&(if legacy.is_some() { 10u32 } else { 120u32 }).to_be_bytes());
    p.extend_from_slice(&[0, 4]);
    p.extend_from_slice(&addr.octets());
    p
}

fn opt(fd: i32, level: i32, name: i32, val: &impl Sized) -> i32 {
    // SAFETY: val outlives the call and its size is passed along.
    unsafe { libc::setsockopt(fd, level, name, val as *const _ as *const libc::c_void, std::mem::size_of_val(val) as libc::socklen_t) }
}

pub fn ifindex(name: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex")).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

fn open() -> Result<UdpSocket, String> {
    // SAFETY: a fresh descriptor, handed to UdpSocket which owns it from here.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err("can't open a socket".into());
    }
    let sock = unsafe { UdpSocket::from_raw_fd(fd) };
    let one: libc::c_int = 1;
    opt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one);
    opt(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, &one);
    let ttl: libc::c_int = 255;
    opt(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, &ttl);
    let zero: libc::c_int = 0;
    opt(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, &zero);
    let addr = libc::sockaddr_in { sin_family: libc::AF_INET as libc::sa_family_t, sin_port: 5353u16.to_be(), sin_addr: libc::in_addr { s_addr: 0 }, sin_zero: [0; 8] };
    // SAFETY: addr is a valid sockaddr_in for the length given.
    if unsafe { libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t) } != 0 {
        return Err("port 5353 is in use by a program that doesn't share it".into());
    }
    Ok(sock)
}

fn mreq(index: u32) -> libc::ip_mreqn {
    libc::ip_mreqn { imr_multiaddr: libc::in_addr { s_addr: u32::from(GROUP).to_be() }, imr_address: libc::in_addr { s_addr: 0 }, imr_ifindex: index as i32 }
}

/// Receives one datagram with the index of the port it came in on.
fn recv(sock: &UdpSocket, buf: &mut [u8]) -> Option<(usize, Ipv4Addr, u16, u32)> {
    let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
    let mut ctl = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut from as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctl.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = ctl.len() as _;
    // SAFETY: every pointer in msg points at a live buffer of the stated size.
    let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
    if n <= 0 {
        return None;
    }
    let mut index = 0;
    // SAFETY: walking the control messages the kernel just filled in.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::IPPROTO_IP && (*c).cmsg_type == libc::IP_PKTINFO {
                let info = libc::CMSG_DATA(c) as *const libc::in_pktinfo;
                index = (*info).ipi_ifindex as u32;
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    Some((n as usize, Ipv4Addr::from(u32::from_be(from.sin_addr.s_addr)), u16::from_be(from.sin_port), index))
}

/// Runs forever. `ports` says which ports to answer on right now, and
/// `addr_for(port, asker)` which address to give out there.
pub fn run(ports: impl Fn() -> Vec<String>, addr_for: impl Fn(&str, Ipv4Addr) -> Option<Ipv4Addr>, note: impl Fn(&str)) {
    let sock = match open() {
        Ok(s) => s,
        Err(e) => {
            note(&format!("foilgateway.local isn't answered by FoilGateway itself: {e}."));
            return avahi(&ports, &addr_for, &note);
        }
    };
    sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok();
    let fd = sock.as_raw_fd();
    let mut joined: Vec<u32> = Vec::new();
    let mut buf = [0u8; 1500];
    loop {
        let want: Vec<(String, u32)> = ports().into_iter().map(|p| { let i = ifindex(&p); (p, i) }).filter(|p| p.1 > 0).collect();
        for (_, i) in &want {
            // Joining again after a port went down and up is harmless.
            opt(fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &mreq(*i));
            if !joined.contains(i) {
                joined.push(*i);
            }
        }
        for i in joined.clone() {
            if !want.iter().any(|w| w.1 == i) {
                opt(fd, libc::IPPROTO_IP, libc::IP_DROP_MEMBERSHIP, &mreq(i));
                joined.retain(|x| *x != i);
            }
        }
        let Some((n, from, sport, index)) = recv(&sock, &mut buf) else { continue };
        let Some((port, _)) = want.iter().find(|w| w.1 == index) else { continue };
        let Some(question) = asks_for_us(&buf[..n]) else { continue };
        let Some(addr) = addr_for(port, from) else { continue };
        if sport != 5353 {
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            let _ = sock.send_to(&answer(addr, Some((id, &question))), (from, sport));
        } else {
            opt(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &mreq(index));
            let _ = sock.send_to(&answer(addr, None), (GROUP, 5353));
        }
    }
}

/// Fallback: have avahi publish the name with the setup address, which
/// every port has during setup. Restarted if it stops.
fn avahi(ports: &impl Fn() -> Vec<String>, addr_for: &impl Fn(&str, Ipv4Addr) -> Option<Ipv4Addr>, note: &impl Fn(&str)) {
    let mut said = false;
    loop {
        let addr = ports().first().and_then(|p| addr_for(p, Ipv4Addr::UNSPECIFIED));
        if let Some(a) = addr {
            match std::process::Command::new("avahi-publish").args(["-a", "-R", NAME, &a.to_string()]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status() {
                Ok(_) => {}
                Err(_) if !said => {
                    note("avahi-publish isn't installed either, so foilgateway.local won't resolve. Use the address instead.");
                    said = true;
                }
                Err(_) => {}
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, kind: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&kind.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    #[test]
    fn answers_only_our_name() {
        assert!(asks_for_us(&query("FoilGateway.local", 1)).is_some());
        assert!(asks_for_us(&query("foilgateway.local", 28)).is_none());
        assert!(asks_for_us(&query("printer.local", 1)).is_none());
        let q = query("foilgateway.local", 1);
        let a = answer(Ipv4Addr::new(169, 254, 42, 1), Some((0x1234, &q[12..])));
        assert_eq!(&a[..2], &[0x12, 0x34]);
        assert_eq!(&a[a.len() - 4..], &[169, 254, 42, 1]);
    }
}
