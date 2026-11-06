//! Until setup has given the ports their roles, the gateway answers on
//! every ethernet port: each one gets the setup address 169.254.42.1/16,
//! a DHCP client runs on any port with a cable that nothing else looks
//! after, and foilgateway.local is answered (see mdns.rs). What we add is
//! written to anyport.json so it can be taken back after a restart.
//!
//! 169.254.42.1 is never shown to the user; it's only a last address for
//! the page to try. When no router hands out addresses on a cabled port
//! for a while, the gateway takes 192.168.30.1/24 there and hands out
//! 192.168.30.100-199 itself, and stops the moment another server answers.

use crate::{dhcp, net};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const SETUP_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 42, 1);
const SETUP_CIDR: &str = "169.254.42.1/16";
const LINK_LOCAL: &str = "169.254.0.0/16";
pub const FALLBACK: Ipv4Addr = dhcp::FALLBACK;
const FALLBACK_CIDR: &str = "192.168.30.1/24";
/// How long a cabled port waits for a router's DHCP before we serve our own.
const FALLBACK_AFTER: Duration = Duration::from_secs(15);

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct Owned {
    /// Ports that carry the setup address.
    pub setup: Vec<String>,
    /// Leases we got: port -> "ip/prefix".
    pub leases: HashMap<String, String>,
    /// Default routes we added: port -> router.
    pub routes: HashMap<String, String>,
    /// rp_filter values before setup, put back afterwards.
    pub rp_filter: HashMap<String, String>,
    /// After setup: DHCP stays on for these ports (the WAN, if we were its client).
    pub keep_dhcp: Vec<String>,
    /// Ports where we put 192.168.30.1 and serve DHCP.
    #[serde(default)]
    pub fallback: Vec<String>,
    /// DNS servers each lease named.
    #[serde(default)]
    pub dns: HashMap<String, Vec<String>>,
}

struct Client {
    stop: Arc<AtomicBool>,
}

pub struct AnyPort {
    path: String,
    owned: Mutex<Owned>,
    clients: Mutex<HashMap<String, Client>>,
    /// port -> why Blink doesn't work there
    no_blink: Mutex<HashMap<String, String>>,
    blinking: Mutex<HashMap<String, Instant>>,
    /// port -> when its cable went in
    link_since: Mutex<HashMap<String, Instant>>,
    servers: Mutex<HashMap<String, Client>>,
    /// Ports where another DHCP server answered: we never serve there.
    router_seen: Mutex<std::collections::HashSet<String>>,
    pub notes: Mutex<Vec<String>>,
}

fn ip(args: &[&str]) -> bool {
    Command::new("ip").args(args).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

fn sysctl_path(port: &str) -> String {
    format!("/proc/sys/net/ipv4/conf/{port}/rp_filter")
}

/// Does systemd-networkd or NetworkManager look after this port?
fn managed(port: &str) -> bool {
    let out = |cmd: &str, args: &[&str]| Command::new(cmd).args(args).stderr(Stdio::null()).output().ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    let networkd = out("networkctl", &["list", "--no-legend", "--no-pager"]).lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.get(1) == Some(&port) && f.get(4).is_some_and(|s| *s != "unmanaged")
    });
    let nm = out("nmcli", &["-t", "-f", "DEVICE,STATE", "device"]).lines().any(|l| l.split_once(':').is_some_and(|(d, s)| d == port && s != "unmanaged"));
    networkd || nm
}

impl AnyPort {
    pub fn open(dir: &str) -> AnyPort {
        let path = format!("{dir}/anyport.json");
        let owned = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        AnyPort { path, owned: Mutex::new(owned), clients: Mutex::new(HashMap::new()), no_blink: Mutex::new(HashMap::new()), blinking: Mutex::new(HashMap::new()), link_since: Mutex::new(HashMap::new()), servers: Mutex::new(HashMap::new()), router_seen: Mutex::new(Default::default()), notes: Mutex::new(Vec::new()) }
    }

    fn save(&self, o: &Owned) {
        let _ = std::fs::write(&self.path, serde_json::to_string_pretty(o).unwrap_or_default());
    }

    fn note(&self, text: String) {
        self.notes.lock().unwrap().push(text);
    }

    pub fn owned(&self) -> Owned {
        self.owned.lock().unwrap().clone()
    }

    /// One round of setup mode: every port up, with the setup address, a
    /// route to link-local clients through the ports with a cable, and DHCP.
    pub fn tick(self: &Arc<Self>) {
        // Bridge members answer through the bridge, not on their own.
        let ports: Vec<net::Port> = net::ports().into_iter().filter(|p| !net::enslaved(&p.name)).chain(net::bridge_port()).collect();
        let gone: Vec<String> = self.clients.lock().unwrap().keys().filter(|k| !ports.iter().any(|p| &p.name == *k)).cloned().collect();
        for g in gone {
            self.stop_dhcp(&g);
            self.stop_fallback(&g);
        }
        let mut o = self.owned.lock().unwrap().clone();
        // Reverse-path checks would drop setup traffic on the "wrong" port
        // while all ports share one address, and DHCP answers that come
        // before there is any route back. The kernel uses the larger of
        // "all" and the port's own value, so both go to 0 for now.
        let names: Vec<&str> = std::iter::once("all").chain(ports.iter().map(|p| p.name.as_str())).collect();
        for name in names {
            if !o.rp_filter.contains_key(name) {
                let old = std::fs::read_to_string(sysctl_path(name)).unwrap_or_default().trim().to_string();
                if !old.is_empty() {
                    let _ = std::fs::write(sysctl_path(name), "0");
                    o.rp_filter.insert(name.to_string(), old);
                }
            }
        }
        for p in &ports {
            if !p.up {
                ip(&["link", "set", &p.name, "up"]);
            }
            ip(&["addr", "replace", SETUP_CIDR, "dev", &p.name, "scope", "link", "noprefixroute"]);
            if !o.setup.contains(&p.name) {
                o.setup.push(p.name.clone());
            }
            if p.link {
                ip(&["route", "replace", LINK_LOCAL, "dev", &p.name, "src", &SETUP_ADDR.to_string(), "metric", "4242"]);
            } else {
                ip(&["route", "del", LINK_LOCAL, "dev", &p.name, "metric", "4242"]);
            }
        }
        // A link-local client is wherever its neighbour entry says; pin it
        // there so answers don't leave through another port.
        let ours: Vec<&str> = ports.iter().filter(|p| p.link).map(|p| p.name.as_str()).collect();
        for n in net::neighbours() {
            if n.ip.starts_with("169.254.") && ours.contains(&n.dev.as_str()) {
                ip(&["route", "replace", &format!("{}/32", n.ip), "dev", &n.dev, "src", &SETUP_ADDR.to_string(), "metric", "4242"]);
            }
        }
        // Clients that moved to another port, or whose cable came out.
        let neigh = net::neighbours();
        let pinned = Command::new("ip").args(["-o", "-4", "route", "show", "metric", "4242"]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
        for line in pinned.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (Some(dst), Some(dev)) = (f.first(), f.iter().position(|x| *x == "dev").and_then(|i| f.get(i + 1))) else { continue };
            if dst.starts_with("169.254.") && !dst.contains('/') && !(ours.contains(dev) && neigh.iter().any(|n| n.ip == *dst && n.dev == *dev)) {
                ip(&["route", "del", dst, "dev", dev, "metric", "4242"]);
            }
        }
        self.save(&o);
        *self.owned.lock().unwrap() = o;
        let fallback = self.owned().fallback;
        for p in &ports {
            let has_ours = self.clients.lock().unwrap().contains_key(&p.name);
            let other_ips = p.ips.iter().any(|i| i != FALLBACK_CIDR);
            if p.link && !has_ours && !other_ips && !managed(&p.name) {
                self.start_dhcp(&p.name, &p.mac);
            } else if !p.link && has_ours {
                self.stop_dhcp(&p.name);
            }
            let mut since = self.link_since.lock().unwrap();
            if !p.link {
                since.remove(&p.name);
                self.router_seen.lock().unwrap().remove(&p.name);
            }
            let waited = p.link && since.entry(p.name.clone()).or_insert_with(Instant::now).elapsed() >= FALLBACK_AFTER;
            drop(since);
            let serving = self.servers.lock().unwrap().contains_key(&p.name);
            let leased = self.owned().leases.contains_key(&p.name);
            let quiet = !self.router_seen.lock().unwrap().contains(&p.name);
            let want = p.link && has_ours && !leased && !other_ips && quiet && (waited || fallback.contains(&p.name));
            if want && !serving {
                self.start_fallback(&p.name, &p.mac);
            } else if !want && (serving || fallback.contains(&p.name)) {
                self.stop_fallback(&p.name);
            }
        }
    }

    fn start_fallback(self: &Arc<Self>, port: &str, mac: &str) {
        let Some(mac) = dhcp::mac_bytes(mac) else { return };
        ip(&["addr", "replace", FALLBACK_CIDR, "dev", port]);
        let stop = Arc::new(AtomicBool::new(false));
        self.servers.lock().unwrap().insert(port.into(), Client { stop: stop.clone() });
        let mut o = self.owned.lock().unwrap();
        let fresh = !o.fallback.contains(&port.to_string());
        if fresh {
            o.fallback.push(port.into());
        }
        let snapshot = o.clone();
        drop(o);
        self.save(&snapshot);
        if fresh {
            self.note(format!("No router handed out addresses on {port}, so the gateway took {FALLBACK} there and hands out 192.168.30.100-199 until setup is done."));
        }
        let (me, port) = (self.clone(), port.to_string());
        std::thread::spawn(move || match dhcp::serve(&port, &mac, &stop) {
            Ok(true) => {
                me.router_seen.lock().unwrap().insert(port.clone());
                me.note(format!("Another DHCP server answered on {port}; the gateway stopped handing out addresses there."));
                me.stop_fallback(&port);
            }
            Ok(false) => {}
            Err(e) => {
                me.note(format!("Couldn't hand out addresses on {port}: {e}."));
                me.servers.lock().unwrap().remove(&port);
            }
        });
    }

    pub fn stop_fallback(&self, port: &str) {
        if let Some(c) = self.servers.lock().unwrap().remove(port) {
            c.stop.store(true, Ordering::Relaxed);
        }
        let mut o = self.owned.lock().unwrap();
        if o.fallback.contains(&port.to_string()) {
            ip(&["addr", "del", FALLBACK_CIDR, "dev", port]);
            o.fallback.retain(|p| p != port);
        }
        let snapshot = o.clone();
        drop(o);
        self.save(&snapshot);
    }

    pub fn start_dhcp(self: &Arc<Self>, port: &str, mac: &str) {
        if port == crate::bridge::NAME && crate::bridge::FIXED.lock().unwrap().is_some() {
            return;
        }
        let Some(mac) = dhcp::mac_bytes(mac) else { return };
        let stop = Arc::new(AtomicBool::new(false));
        self.clients.lock().unwrap().insert(port.into(), Client { stop: stop.clone() });
        let (me, port) = (self.clone(), port.to_string());
        std::thread::spawn(move || {
            let mut wait;
            while !stop.load(Ordering::Relaxed) {
                match dhcp::obtain(&port, &mac, 12) {
                    Ok(l) if !stop.load(Ordering::Relaxed) => {
                        me.router_seen.lock().unwrap().insert(port.clone());
                        me.stop_fallback(&port);
                        me.put_lease(&port, &l);
                        wait = (l.secs as u64 / 2).clamp(30, 12 * 3600);
                    }
                    Ok(_) => break,
                    Err(_) => wait = 10,
                }
                for _ in 0..wait {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        });
    }

    fn put_lease(&self, port: &str, l: &dhcp::Lease) {
        let cidr = format!("{}/{}", l.ip, l.prefix);
        let life = l.secs.to_string();
        let mut o = self.owned.lock().unwrap();
        if let Some(old) = o.leases.get(port).filter(|c| **c != cidr) {
            ip(&["addr", "del", old, "dev", port]);
        }
        ip(&["addr", "replace", &cidr, "dev", port, "valid_lft", &life, "preferred_lft", &life]);
        let fresh = !o.leases.contains_key(port);
        o.leases.insert(port.into(), cidr.clone());
        o.dns.insert(port.into(), l.dns.iter().map(|d| d.to_string()).collect());
        if let Some(r) = l.router {
            let has_default = net::ports().iter().any(|p| p.default_route);
            if !has_default || o.routes.contains_key(port) {
                ip(&["route", "replace", "default", "via", &r.to_string(), "dev", port, "metric", "1024"]);
                o.routes.insert(port.into(), r.to_string());
            }
        }
        let snapshot = o.clone();
        drop(o);
        self.save(&snapshot);
        if fresh {
            self.note(format!("{port} got {cidr} by DHCP from {}.", l.server));
        }
    }

    pub fn stop_dhcp(&self, port: &str) {
        if let Some(c) = self.clients.lock().unwrap().remove(port) {
            c.stop.store(true, Ordering::Relaxed);
        }
        let mut o = self.owned.lock().unwrap();
        if let Some(cidr) = o.leases.remove(port) {
            ip(&["addr", "del", &cidr, "dev", port]);
        }
        o.dns.remove(port);
        if let Some(r) = o.routes.remove(port) {
            ip(&["route", "del", "default", "via", &r, "dev", port, "metric", "1024"]);
        }
        let snapshot = o.clone();
        drop(o);
        self.save(&snapshot);
    }

    fn drop_setup_addr(&self, port: &str, o: &mut Owned) {
        ip(&["addr", "del", SETUP_CIDR, "dev", port]);
        ip(&["route", "del", LINK_LOCAL, "dev", port, "metric", "4242"]);
        // Host routes we pinned to link-local clients on this port.
        let out = Command::new("ip").args(["-o", "-4", "route", "show", "dev", port, "metric", "4242"]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
        for line in out.lines() {
            if let Some(dst) = line.split_whitespace().next().filter(|d| d.starts_with("169.254.")) {
                ip(&["route", "del", dst, "dev", port, "metric", "4242"]);
            }
        }
        o.setup.retain(|p| p != port);
    }

    /// Addresses setup put on these ports, so the bridge doesn't save them
    /// as the ports' own.
    pub fn ours(&self) -> Vec<String> {
        let o = self.owned();
        let mut out: Vec<String> = o.leases.values().cloned().collect();
        out.push("192.168.30.1/24".into());
        out.push("169.254.42.1/16".into());
        out
    }

    /// The ports went into the bridge: their own DHCP and setup addresses
    /// are done with, and the next tick starts over on the bridge.
    pub fn serving_fallback(&self, members: &[String]) -> bool {
        self.owned().fallback.iter().any(|p| members.contains(p))
    }

    /// Call with what `serving_fallback` said before the bridge went up.
    pub fn bridged(self: &Arc<Self>, members: &[String], had_fallback: bool) {
        // A browser on 192.168.30.1 keeps it: the address moves to the
        // bridge, without the DHCP server.
        for m in members {
            self.stop_dhcp(m);
            self.stop_fallback(m);
            let mut o = self.owned.lock().unwrap();
            o.setup.retain(|p| p != m);
            let snapshot = o.clone();
            drop(o);
            self.save(&snapshot);
        }
        if had_fallback {
            let br = crate::bridge::NAME.to_string();
            ip(&["addr", "replace", FALLBACK_CIDR, "dev", &br]);
            let mut o = self.owned.lock().unwrap();
            o.fallback.retain(|p| !members.contains(p));
            if !o.fallback.contains(&br) {
                o.fallback.push(br);
            }
            let snapshot = o.clone();
            drop(o);
            self.save(&snapshot);
        }
    }

    /// Setup is done. The WAN loses the setup address; so do unused ports
    /// and LAN ports, except a LAN port whose address `kept` the browser
    /// used to confirm. Our DHCP stays only where it's still needed: the
    /// WAN, and the LAN address the browser came in on.
    pub fn finish(self: &Arc<Self>, lan: &[String], wan: &str, via: Option<(String, Ipv4Addr)>) {
        let kept = via.as_ref().map(|v| v.1);
        let via_port = via.as_ref().map(|v| v.0.clone());
        let mut o = self.owned.lock().unwrap().clone();
        let kept_cidr = |port: &str, o: &Owned| kept.is_some_and(|k| o.leases.get(port).is_some_and(|c| c.split('/').next() == Some(&k.to_string())));
        for port in o.setup.clone() {
            let keep = lan.contains(&port) && kept == Some(SETUP_ADDR) && via_port.as_deref() == Some(port.as_str());
            if !keep {
                self.drop_setup_addr(&port, &mut o);
            }
        }
        // Our DHCP server never outlives setup. 192.168.30.1 stays only on
        // the LAN port the browser confirmed through, so the page keeps working.
        for port in o.fallback.clone() {
            if let Some(c) = self.servers.lock().unwrap().remove(&port) {
                c.stop.store(true, Ordering::Relaxed);
            }
            let keep = lan.contains(&port) && kept == Some(FALLBACK) && via_port.as_deref() == Some(port.as_str());
            if !keep {
                ip(&["addr", "del", FALLBACK_CIDR, "dev", &port]);
            }
        }
        o.fallback.clear();
        // The bridge always keeps asking the router, lease or not yet.
        let mut keep_dhcp = if wan == crate::bridge::NAME && !managed(wan) { vec![wan.to_string()] } else { Vec::new() };
        for port in o.leases.keys().cloned().collect::<Vec<_>>() {
            if keep_dhcp.contains(&port) {
                continue;
            }
            if port == wan || (lan.contains(&port) && via_port.as_deref() == Some(port.as_str()) && kept_cidr(&port, &o)) {
                keep_dhcp.push(port);
            }
        }
        for (port, old) in std::mem::take(&mut o.rp_filter) {
            if o.setup.contains(&port) || (port == "all" && !o.setup.is_empty()) {
                o.rp_filter.insert(port, old); // still serving the setup address here
            } else {
                let _ = std::fs::write(sysctl_path(&port), old);
            }
        }
        o.keep_dhcp = keep_dhcp.clone();
        self.save(&o);
        *self.owned.lock().unwrap() = o.clone();
        let running: Vec<String> = self.clients.lock().unwrap().keys().cloned().collect();
        for port in running.iter().chain(o.leases.keys()).cloned().collect::<Vec<_>>() {
            if !keep_dhcp.contains(&port) {
                self.stop_dhcp(&port);
            }
        }
        let left: Vec<String> = self.owned().setup;
        self.note(format!(
            "Temporary setup addresses taken off{}. DHCP client by FoilGateway {}.",
            if left.is_empty() { String::new() } else { format!(" except on {} (you confirmed through it)", left.join(", ")) },
            if keep_dhcp.is_empty() { "is off".to_string() } else { format!("stays on for {}", keep_dhcp.join(", ")) }
        ));
    }

    /// After a restart outside setup: keep the WAN lease going if it was ours.
    pub fn resume(self: &Arc<Self>) {
        let o = self.owned();
        for port in &o.keep_dhcp {
            if let Some(p) = net::port(port) {
                if !self.clients.lock().unwrap().contains_key(port) {
                    self.start_dhcp(port, &p.mac);
                }
            }
        }
    }

    /// Identify a port with `ethtool -p <port> 5`. A driver that can't
    /// blink fails at once; one that can keeps running for the 5 seconds.
    pub fn blink(&self, port: &str) -> Result<(), String> {
        if let Some(why) = self.no_blink.lock().unwrap().get(port) {
            return Err(why.clone());
        }
        let mut child = match Command::new("ethtool").args(["-p", port, "5"]).stdout(Stdio::null()).stderr(Stdio::piped()).spawn() {
            Ok(c) => c,
            Err(_) => {
                let why = "ethtool isn't installed, so ports can't blink.".to_string();
                self.no_blink.lock().unwrap().insert(port.into(), why.clone());
                return Err(why);
            }
        };
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(1200) {
            if let Ok(Some(s)) = child.try_wait() {
                if s.success() {
                    return Ok(());
                }
                let mut err = String::new();
                use std::io::Read;
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut err);
                }
                let why = if err.contains("not supported") || err.contains("Operation not supported") { "This port's driver can't blink its lights.".to_string() } else { format!("Blink didn't work here: {}", err.trim()) };
                self.no_blink.lock().unwrap().insert(port.into(), why.clone());
                return Err(why);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        self.blinking.lock().unwrap().insert(port.into(), Instant::now());
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }

    pub fn blink_state(&self, port: &str) -> (bool, Option<String>) {
        let on = self.blinking.lock().unwrap().get(port).is_some_and(|t| t.elapsed() < Duration::from_secs(5));
        (on, self.no_blink.lock().unwrap().get(port).cloned())
    }
}
