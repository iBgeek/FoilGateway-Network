//! What a connection or block is about, in one plain line: the device,
//! the name it looked up, who runs the address, what the port is for,
//! which way the data goes, and which list stopped it.

use crate::app::App;
use crate::pdns;
use crate::policy::{parse_entry, Entry};
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// What a downloaded list covers and, only where the list's own page says
/// so, what tends to stop working when it blocks something.
pub struct ListDoc {
    pub id: &'static str,
    pub name: &'static str,
    pub covers: &'static str,
    pub breaks: Option<&'static str>,
    pub doc: &'static str,
}

pub const NO_EFFECT: &str = "No known effect";

pub const LIST_DOCS: &[ListDoc] = &[
    ListDoc { id: "telemetry-windows", name: "WindowsSpyBlocker spy list", covers: "addresses Windows uses to send usage and diagnostic data (telemetry) to Microsoft", breaks: None, doc: "https://crazymax.dev/WindowsSpyBlocker/blocking-rules/" },
    ListDoc { id: "telemetry-windows-ips", name: "WindowsSpyBlocker spy list", covers: "addresses Windows uses to send usage and diagnostic data (telemetry) to Microsoft", breaks: None, doc: "https://crazymax.dev/WindowsSpyBlocker/blocking-rules/" },
    ListDoc { id: "telemetry-nvidia", name: "NVIDIA telemetry blocklist", covers: "NVIDIA's telemetry, update and analytics servers", breaks: Some("NVIDIA apps may lose sign-in, automatic updates or account management"), doc: "https://github.com/ravetank/nvidia-telemetry-blocklist" },
    ListDoc { id: "telemetry-smarttv", name: "Perflyst Smart TV list", covers: "tracking and ad servers used by smart TVs", breaks: None, doc: "https://github.com/Perflyst/PiHoleBlocklist" },
    ListDoc { id: "spamhaus-drop", name: "Spamhaus DROP", covers: "networks taken over or run by criminals", breaks: None, doc: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/" },
    ListDoc { id: "spamhaus-dropv6", name: "Spamhaus DROPv6", covers: "IPv6 networks taken over or run by criminals", breaks: None, doc: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/" },
    ListDoc { id: "feodo-c2", name: "abuse.ch Feodo Tracker", covers: "servers that control banking-malware botnets", breaks: None, doc: "https://feodotracker.abuse.ch/blocklist/" },
];

pub fn doc(id: &str) -> Option<&'static ListDoc> {
    LIST_DOCS.iter().find(|d| d.id == id)
}

/// Which list stopped something, in plain words.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct Which {
    /// "WindowsSpyBlocker spy list", "your Blacklist (example.com)", ...
    pub list: String,
    pub covers: String,
    /// Always set: the list's own warning, or "No known effect".
    pub breaks: String,
    pub link: String,
    /// The host name on the list, when it was a host list.
    pub host: String,
}

/// Per request: telemetry addresses back to the host and list they came from.
pub struct Index {
    tele_hosts: HashMap<String, (String, &'static str)>,
}

fn has(net: &str, ip: IpAddr) -> bool {
    crate::web::net_has(net, ip)
}

impl App {
    pub fn list_index(&self) -> Index {
        let f = self.feeds.read().unwrap();
        let seen = self.seen.lock().unwrap();
        let mut tele_hosts = HashMap::new();
        for (h, feed) in &f.host_feed {
            for a in seen.of(h) {
                tele_hosts.entry(a).or_insert((h.clone(), *feed));
            }
        }
        Index { tele_hosts }
    }

    pub fn which_list(&self, ix: &Index, reason: &str, mac: &str, remote: &str) -> Which {
        let ip: Option<IpAddr> = remote.parse().ok();
        let from_doc = |d: &ListDoc, host: String| Which { list: d.name.into(), covers: d.covers.into(), breaks: d.breaks.unwrap_or(NO_EFFECT).into(), link: d.doc.into(), host };
        let plain = |list: String, covers: &str| Which { list, covers: covers.into(), breaks: NO_EFFECT.into(), ..Default::default() };
        let entry_of = |list: &[String]| -> Option<String> {
            let ip = ip?;
            let seen = self.seen.lock().unwrap();
            list.iter().find(|e| match parse_entry(e) {
                Ok(Entry::Net(n)) => has(&n, ip),
                Ok(Entry::Site(s)) => seen.of(&s).contains(&ip.to_string()),
                _ => false,
            }).cloned()
        };
        match reason {
            "telemetry" | "threat" => {
                let f = self.feeds.read().unwrap();
                if let Some(ip) = ip {
                    for (id, nets) in &f.addr_feeds {
                        if nets.iter().any(|n| has(n, ip)) {
                            if let Some(d) = doc(id) {
                                return from_doc(d, String::new());
                            }
                        }
                    }
                }
                if let Some((host, id)) = ix.tele_hosts.get(remote) {
                    if let Some(d) = doc(id) {
                        return from_doc(d, host.clone());
                    }
                }
                plain(if reason == "threat" { "a threat list".into() } else { "a telemetry list".into() }, "")
            }
            "black" => {
                let p = self.policy.read().unwrap();
                match entry_of(&p.black) {
                    Some(e) => plain(format!("your Blacklist ({e})"), "addresses and websites you chose to block for every device"),
                    None => plain("your Blacklist".into(), "addresses and websites you chose to block for every device"),
                }
            }
            "devdeny" => {
                let p = self.policy.read().unwrap();
                let e = p.devices.get(mac).and_then(|d| entry_of(&d.deny));
                plain(e.map(|e| format!("this device's block list ({e})")).unwrap_or("this device's block list".into()), "websites and addresses you chose to block for this device")
            }
            "country" => {
                let cc = ip.and_then(|ip| self.geo.read().unwrap().locate(ip)).map(|p| p.country).unwrap_or_default();
                let name = crate::geo::countries().get(cc.as_str()).copied().unwrap_or(cc.as_str()).to_string();
                plain("Geo-Blocking".into(), &if name.is_empty() { "countries you chose to block".into() } else { format!("everything in {name}, a country you chose to block") })
            }
            "devblock" => plain("this device's policy: Block all".into(), "everything this device does outside your network"),
            "devlan" => plain("this device's policy: LAN only".into(), "everything this device does outside your network"),
            "wan" => plain("router-side protection".into(), "new connections from the internet side to a device"),
            "lanport" => plain("the Ports page (blocked from the LAN side)".into(), "this port, for devices on your network"),
            "mode" => plain("Protection mode: Block everything".into(), "all traffic"),
            "lanonly" => plain("Protection mode: LAN only".into(), "all traffic to and from the internet"),
            _ => plain("the firewall".into(), ""),
        }
    }

    /// The name the device looked up for the address, if seen.
    pub fn domain_of(&self, mac: &str, remote: &str) -> String {
        let Ok(ip) = remote.parse::<IpAddr>() else { return String::new() };
        self.pdns.lock().unwrap().name_for(pdns::parse_mac(mac), ip, crate::caplog::now()).unwrap_or_default()
    }

    /// Who runs the address, from its reverse name ("" until looked up or
    /// when it has none).
    pub fn owner_of(&self, remote: &str) -> String {
        let Ok(ip) = remote.parse::<IpAddr>() else { return String::new() };
        self.owners.get(ip, crate::caplog::now()).unwrap_or_default()
    }

    /// Watches every LAN port for DNS answers, and looks up owners in
    /// the background. A port that comes and goes gets its watcher again.
    pub fn start_name_jobs(self: &Arc<Self>) {
        let a = self.clone();
        std::thread::spawn(move || {
            let mut running: HashMap<String, std::sync::mpsc::Receiver<String>> = HashMap::new();
            let mut said = std::collections::HashSet::new();
            loop {
                let lan = a.cfg.read().unwrap().as_ref().map(|c| c.lan.clone()).unwrap_or_default();
                running.retain(|port, rx| match rx.try_recv() {
                    Ok(e) => {
                        if said.insert(port.clone()) {
                            a.log.note("alert", &format!("Can't see name lookups on {port}, so blocks show addresses only: {e}"));
                        }
                        false
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => false,
                    Err(_) => true,
                });
                for port in lan {
                    if running.contains_key(&port) {
                        continue;
                    }
                    let (tx, rx) = std::sync::mpsc::channel();
                    let b = a.clone();
                    let p = port.clone();
                    std::thread::spawn(move || {
                        let r = pdns::watch(&p, &mut |mac, ans| b.pdns.lock().unwrap().record(mac, &ans, crate::caplog::now()));
                        let _ = tx.send(r.err().unwrap_or_default());
                    });
                    running.insert(port, rx);
                }
                a.pdns.lock().unwrap().prune(crate::caplog::now());
                std::thread::sleep(Duration::from_secs(30));
            }
        });
        let a = self.clone();
        std::thread::spawn(move || loop {
            let Some(ip) = a.owners.next() else {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            };
            let t = crate::caplog::now();
            match pdns::reverse(ip) {
                Ok(Some((name, ttl))) => a.owners.put(ip, pdns::registered(&name), t + (ttl as i64).clamp(3600, 86400)),
                Ok(None) => a.owners.put(ip, String::new(), t + 6 * 3600),
                // The name server didn't answer: try again in ten minutes.
                Err(_) => a.owners.put(ip, String::new(), t + 600),
            }
            std::thread::sleep(Duration::from_millis(50));
        });
    }
}

/// One plain line about a connection or a block.
pub struct Line<'a> {
    pub device: &'a str,
    /// "in" or "out", from map_dir.
    pub dir: &'a str,
    pub remote: &'a str,
    pub domain: &'a str,
    pub owner: &'a str,
    pub country: &'a str,
    /// (proto, port); port 0 for none.
    pub ports: &'a [(String, u16)],
}

pub fn port_text(proto: &str, port: u16) -> String {
    if port == 0 {
        return proto.to_string();
    }
    format!("{proto} {port}, {}", crate::ports::purpose(proto, port))
}

pub fn describe(l: &Line) -> String {
    let verb = if l.dir == "in" { "receiving from" } else { "sending to" };
    let mut extra: Vec<String> = Vec::new();
    let target = if l.domain.is_empty() {
        l.remote.to_string()
    } else {
        extra.push(l.remote.to_string());
        l.domain.to_string()
    };
    let same_site = !l.domain.is_empty() && (l.domain == l.owner || l.domain.ends_with(&format!(".{}", l.owner)));
    if !l.owner.is_empty() && !same_site {
        extra.push(format!("run by {}", l.owner));
    }
    if !l.country.is_empty() {
        extra.push(l.country.to_string());
    }
    let place = if extra.is_empty() { String::new() } else { format!(" ({})", extra.join(", ")) };
    let ports = l.ports.iter().map(|(p, n)| port_text(p, *n)).collect::<Vec<_>>();
    let ports = if ports.is_empty() { String::new() } else { format!(" on {}", ports.join("; ")) };
    format!("{} {verb} {target}{place}{ports}", l.device)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_lines() {
        let ports = vec![("tcp".to_string(), 443), ("udp".to_string(), 31337)];
        let l = Line { device: "Clunker", dir: "out", remote: "51.132.193.107", domain: "v10.events.data.microsoft.com", owner: "microsoft.com", country: "United Kingdom", ports: &ports };
        assert_eq!(describe(&l), "Clunker sending to v10.events.data.microsoft.com (51.132.193.107, United Kingdom) on tcp 443, secure web (HTTPS); udp 31337, Unknown use");
        let l = Line { device: "Cam", dir: "in", remote: "3.3.3.3", domain: "", owner: "amazonaws.com", country: "", ports: &ports[..1] };
        assert_eq!(describe(&l), "Cam receiving from 3.3.3.3 (run by amazonaws.com) on tcp 443, secure web (HTTPS)");
        for d in LIST_DOCS {
            assert!(!d.covers.is_empty() && d.doc.starts_with("https://"));
        }
        assert!(crate::lists::TELEMETRY.iter().chain(crate::lists::THREATS).all(|f| doc(f.id).is_some()));
    }
}
