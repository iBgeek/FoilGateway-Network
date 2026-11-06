//! What the gateway can see right now: ports, neighbours, leases,
//! connections and its own health. Everything is read live from the system.

use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Clone, Debug, Serialize)]
pub struct Port {
    pub name: String,
    pub mac: String,
    pub up: bool,
    pub link: bool,
    /// Link speed now, when there's a cable.
    pub speed: String,
    /// Fastest mode the port says it supports, from ethtool.
    pub max_speed: String,
    /// "PCIe", "USB" or "built-in", from where the device sits in sysfs.
    pub bus: String,
    pub ips: Vec<String>,
    /// Addresses handed out by a DHCP server (the kernel marks them dynamic).
    pub leased: Vec<String>,
    /// The default route goes out of this port.
    pub default_route: bool,
    /// The bridge it's part of, if any.
    pub master: String,
}

fn sys(path: &str) -> String {
    fs::read_to_string(path).map(|s| s.trim().to_string()).unwrap_or_default()
}

fn ip_json(args: &[&str]) -> Vec<Value> {
    Command::new("ip")
        .args(args)
        .output()
        .ok()
        .and_then(|o| serde_json::from_slice::<Vec<Value>>(&o.stdout).ok())
        .unwrap_or_default()
}

/// A real ethernet port: has a device behind it and isn't wireless, a
/// bridge or a bond. FOILGW_VETH_PORTS=1 counts veth pairs too, for tests.
pub fn is_physical(name: &str) -> bool {
    let base = format!("/sys/class/net/{name}");
    let has = |x: &str| std::path::Path::new(&format!("{base}/{x}")).exists();
    if has("wireless") || has("phy80211") || has("bridge") || has("bonding") {
        return false;
    }
    if has("device") {
        return true;
    }
    std::env::var("FOILGW_VETH_PORTS").as_deref() == Ok("1") && fs::read_link(&base).map(|l| l.to_string_lossy().contains("/virtual/")).unwrap_or(false) && sys(&format!("{base}/type")) == "1" && !name.starts_with("lo")
}

fn bus(name: &str) -> String {
    let dev = fs::canonicalize(format!("/sys/class/net/{name}/device")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    if dev.is_empty() {
        String::new()
    } else if dev.contains("/usb") {
        "USB".into()
    } else if dev.contains("/pci") {
        "PCIe".into()
    } else {
        "built-in".into()
    }
}

/// Highest speed in ethtool's "Supported link modes", e.g. 2500baseT/Full -> 2.5 Gb/s.
pub fn parse_max_speed(ethtool: &str) -> String {
    let mut best = 0u64;
    let mut inside = false;
    for line in ethtool.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Supported link modes:") {
            inside = true;
            best = best.max(modes_max(rest));
        } else if inside {
            if t.contains(':') {
                inside = false;
            } else {
                best = best.max(modes_max(t));
            }
        }
    }
    speed_text(best)
}

fn modes_max(text: &str) -> u64 {
    text.split_whitespace().filter_map(|m| m.split("base").next()?.parse::<u64>().ok()).max().unwrap_or(0)
}

fn speed_text(mbs: u64) -> String {
    match mbs {
        0 => String::new(),
        m if m >= 1000 && m % 1000 == 0 => format!("{} Gb/s", m / 1000),
        m if m >= 1000 => format!("{:.1} Gb/s", m as f64 / 1000.0),
        m => format!("{m} Mb/s"),
    }
}

/// ethtool output is cached: supported modes don't change while we run.
fn max_speed(name: &str, mac: &str) -> String {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    let key = format!("{name} {mac}");
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(v) = cache.lock().unwrap().get(&key) {
        return v.clone();
    }
    let v = Command::new("ethtool").arg(name).output().map(|o| parse_max_speed(&String::from_utf8_lossy(&o.stdout))).unwrap_or_default();
    cache.lock().unwrap().insert(key, v.clone());
    v
}

/// Physical ethernet ports, sorted by name, bridge members included.
pub fn ports() -> Vec<Port> {
    scan(is_physical)
}

/// The gateway's bridge as a port, once there is one.
pub fn bridge_port() -> Option<Port> {
    scan(|n| n == crate::bridge::NAME).into_iter().next()
}

/// A port that's in a bridge can't carry addresses of its own.
pub fn enslaved(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}/master")).exists()
}

fn scan(want: impl Fn(&str) -> bool) -> Vec<Port> {
    let addrs = ip_json(&["-j", "addr", "show"]);
    let default_devs: Vec<String> = ip_json(&["-j", "-4", "route", "show", "default"]).iter().filter_map(|r| r["dev"].as_str().map(String::from)).collect();
    let mut out = Vec::new();
    for a in &addrs {
        let name = a["ifname"].as_str().unwrap_or("").to_string();
        if name.is_empty() || name == "lo" || a["link_type"].as_str() != Some("ether") || !want(&name) {
            continue;
        }
        let info: Vec<&Value> = a["addr_info"].as_array().map(|v| v.iter().filter(|i| i["scope"] != "link").collect()).unwrap_or_default();
        let cidr = |i: &&Value| format!("{}/{}", i["local"].as_str().unwrap_or(""), i["prefixlen"]);
        let ips = info.iter().map(cidr).collect();
        let leased = info.iter().filter(|i| i["dynamic"].as_bool() == Some(true) && i["family"] == "inet").map(cidr).collect();
        let base = format!("/sys/class/net/{name}");
        let speed = sys(&format!("{base}/speed"));
        let link = sys(&format!("{base}/carrier")) == "1";
        let mac = sys(&format!("{base}/address"));
        out.push(Port {
            max_speed: max_speed(&name, &mac),
            bus: bus(&name),
            mac,
            up: a["flags"].as_array().map(|f| f.iter().any(|x| x == "UP")).unwrap_or(false),
            speed: if !link || speed.starts_with('-') || speed.is_empty() { String::new() } else { speed_text(speed.parse().unwrap_or(0)) },
            link,
            ips,
            leased,
            default_route: default_devs.contains(&name),
            master: a["master"].as_str().unwrap_or("").to_string(),
            name,
        });
    }
    out.sort_by_key(|a| natural(&a.name));
    out
}

/// eth2 before eth10.
fn natural(name: &str) -> (String, u64) {
    let digits: String = name.chars().rev().take_while(|c| c.is_ascii_digit()).collect::<Vec<_>>().into_iter().rev().collect();
    (name[..name.len() - digits.len()].to_string(), digits.parse().unwrap_or(0))
}

/// Every ethernet-type interface, read at most every 2 seconds. For the
/// pages that ask on each refresh; setup reads fresh with `ports()`.
pub fn all_ports_cached() -> std::sync::Arc<Vec<Port>> {
    use std::sync::{Arc, Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<Cached<Port>>> = OnceLock::new();
    let c = CACHE.get_or_init(|| Mutex::new(None));
    let mut g = c.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, v)) = g.as_ref() {
        if at.elapsed() < std::time::Duration::from_secs(2) {
            return v.clone();
        }
    }
    let v = Arc::new(scan(|_| true));
    *g = Some((std::time::Instant::now(), v.clone()));
    v
}

pub fn port_cached(name: &str) -> Option<Port> {
    all_ports_cached().iter().find(|p| p.name == name).cloned()
}

pub fn port(name: &str) -> Option<Port> {
    if name == crate::bridge::NAME {
        return bridge_port();
    }
    ports().into_iter().find(|p| p.name == name)
}

/// The port a client's packets come in on: its neighbour entry if we have
/// one on a port with a cable (a fresh one before a stale one), otherwise
/// the route to it.
pub fn port_of(ip: &str) -> Option<String> {
    let linked = |d: &str| sys(&format!("/sys/class/net/{d}/carrier")) == "1";
    let mut best: Option<(bool, String)> = None;
    for n in ip_json(&["-j", "-4", "neigh", "show", "to", ip]) {
        let state: Vec<String> = n["state"].as_array().map(|s| s.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        let Some(dev) = n["dev"].as_str() else { continue };
        if state.iter().any(|x| x == "FAILED" || x == "INCOMPLETE") || !linked(dev) {
            continue;
        }
        let fresh = !state.iter().any(|x| x == "STALE");
        // Behind the bridge, the bridge's own table knows the real port.
        let dev = match n["lladdr"].as_str() {
            Some(mac) if dev == crate::bridge::NAME => crate::bridge::port_of_mac(mac).unwrap_or(dev.to_string()),
            _ => dev.to_string(),
        };
        if best.as_ref().is_none_or(|b| fresh && !b.0) {
            best = Some((fresh, dev));
        }
    }
    best.map(|b| b.1).or_else(|| ip_json(&["-j", "route", "get", ip]).first().and_then(|r| r["dev"].as_str().map(String::from))).filter(|d| d != "lo")
}

#[derive(Clone, Debug)]
pub struct Neighbour {
    pub ip: String,
    pub mac: String,
    pub dev: String,
}

pub fn neighbours() -> Vec<Neighbour> {
    ip_json(&["-j", "-4", "neigh", "show"])
        .iter()
        .filter_map(|n| {
            let mac = n["lladdr"].as_str()?.to_ascii_lowercase();
            let state: Vec<String> = n["state"].as_array().map(|s| s.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            if state.iter().any(|s| s == "FAILED" || s == "INCOMPLETE") {
                return None;
            }
            Some(Neighbour {
                ip: n["dst"].as_str()?.to_string(),
                mac,
                dev: n["dev"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect()
}

/// MAC -> (ip, hostname) from dnsmasq or ISC dhcpd leases, if either runs here.
pub fn leases() -> HashMap<String, (String, String)> {
    let mut out = HashMap::new();
    for path in ["/var/lib/misc/dnsmasq.leases", "/var/lib/dnsmasq/dnsmasq.leases"] {
        out.extend(parse_dnsmasq(&sys(path)));
    }
    out.extend(parse_dhcpd(&sys("/var/lib/dhcp/dhcpd.leases")));
    out
}

pub fn parse_dnsmasq(text: &str) -> HashMap<String, (String, String)> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let host = f.get(3).filter(|h| **h != "*").map(|h| h.to_string()).unwrap_or_default();
            Some((crate::policy::normal_mac(f.get(1)?)?, (f.get(2)?.to_string(), host)))
        })
        .collect()
}

pub fn parse_dhcpd(text: &str) -> HashMap<String, (String, String)> {
    let mut out = HashMap::new();
    for block in text.split("lease ").skip(1) {
        let ip = block.split_whitespace().next().unwrap_or("").to_string();
        let field = |k: &str| block.lines().find_map(|l| l.trim().strip_prefix(k).map(|v| v.trim().trim_end_matches(';').trim_matches('"').to_string()));
        if let Some(mac) = field("hardware ethernet").and_then(|m| crate::policy::normal_mac(&m)) {
            out.insert(mac, (ip, field("client-hostname").unwrap_or_default()));
        }
    }
    out
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Conn {
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
    pub state: String,
    pub bytes: u64,
    /// Bytes the starter sent (original direction) and got back (reply).
    pub orig_bytes: u64,
    pub reply_bytes: u64,
}

/// Connections the kernel tracks. Reads /proc/net/nf_conntrack, or the
/// `conntrack` tool where that file isn't there.
pub fn connections() -> Vec<Conn> {
    // FOILGW_CONNTRACK points at a saved table, for load tests.
    let file = std::env::var("FOILGW_CONNTRACK").unwrap_or_else(|_| "/proc/net/nf_conntrack".into());
    let text = fs::read_to_string(file).ok().filter(|t| !t.is_empty()).or_else(|| {
        Command::new("conntrack").args(["-L", "-o", "extended"]).output().ok().map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    });
    text.map(|t| t.lines().filter_map(parse_conntrack).collect()).unwrap_or_default()
}

/// The connection table, read at most once a second: several open pages
/// and the poll loop share one read.
pub fn connections_cached() -> std::sync::Arc<Vec<Conn>> {
    use std::sync::{Arc, Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<Cached<Conn>>> = OnceLock::new();
    let c = CACHE.get_or_init(|| Mutex::new(None));
    let mut g = c.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, v)) = g.as_ref() {
        if at.elapsed() < std::time::Duration::from_secs(1) {
            return v.clone();
        }
    }
    let v = Arc::new(connections());
    *g = Some((std::time::Instant::now(), v.clone()));
    v
}

pub fn parse_conntrack(line: &str) -> Option<Conn> {
    let f: Vec<&str> = line.split_whitespace().collect();
    let proto = f.get(2)?.to_string();
    // Every protocol counts (icmpv6, gre, esp, sctp...), not only tcp/udp/icmp.
    if !proto.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let first = |k: &str| f.iter().find_map(|x| x.strip_prefix(k)).map(String::from);
    let state = if proto == "tcp" { f.get(5).filter(|s| s.chars().all(|c| c.is_ascii_uppercase() || c == '_')).map(|s| s.to_string()).unwrap_or_default() } else { String::new() };
    let mut counts = f.iter().filter_map(|x| x.strip_prefix("bytes=")).filter_map(|b| b.parse::<u64>().ok());
    let (orig_bytes, reply_bytes) = (counts.next().unwrap_or(0), counts.next().unwrap_or(0));
    let bytes = orig_bytes + reply_bytes;
    Some(Conn {
        src: first("src=")?,
        dst: first("dst=")?,
        sport: first("sport=").and_then(|p| p.parse().ok()).unwrap_or(0),
        dport: first("dport=").and_then(|p| p.parse().ok()).unwrap_or(0),
        proto,
        state,
        bytes,
        orig_bytes,
        reply_bytes,
    })
}

/// Bridged traffic only reaches the rules with br_netfilter on.
pub fn bridge_filtering() -> bool {
    sys("/proc/sys/net/bridge/bridge-nf-call-iptables") == "1"
}

/// Nameservers in resolv.conf, for when DHCP didn't name any.
pub fn default_gateways() -> Vec<String> {
    let out = Command::new("ip").args(["-4", "route", "show", "default"]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    out.lines().filter_map(|l| l.split_whitespace().skip_while(|w| *w != "via").nth(1).map(String::from)).collect()
}

/// Next hops of the default routes; the router usually answers DNS too.
pub fn gateways() -> Vec<std::net::Ipv4Addr> {
    ip_json(&["-j", "-4", "route", "show", "default"]).iter().filter_map(|r| r["gateway"].as_str()?.parse().ok()).collect()
}

pub fn resolvers() -> Vec<String> {
    sys("/etc/resolv.conf").lines().filter_map(|l| l.trim().strip_prefix("nameserver")).map(|a| a.trim().to_string()).filter(|a| a.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| !ip.is_loopback())).collect()
}

pub fn uptime_secs() -> u64 {
    sys("/proc/uptime").split('.').next().and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// The CPU or SoC temperature in °C, if the board has a sensor for it.
pub fn temperature() -> Option<f64> {
    cpu_temp_in(Path::new(&std::env::var("FOILGW_THERMAL").unwrap_or_else(|_| "/sys/class/thermal".into())))
}

/// The hottest zone whose type names the CPU or SoC: cluster0_thermal and
/// cluster1_thermal on the R2S, soc-thermal, cpu-thermal, x86_pkg_temp or
/// any *-thermal elsewhere. Without one, a board with a single zone uses that.
pub fn cpu_temp_in(root: &Path) -> Option<f64> {
    let mut zones: Vec<(String, f64)> = Vec::new();
    for e in fs::read_dir(root).ok()?.flatten() {
        if !e.file_name().to_string_lossy().starts_with("thermal_zone") {
            continue;
        }
        let kind = sys(&format!("{}/type", e.path().display())).trim().to_lowercase();
        if let Ok(t) = sys(&format!("{}/temp", e.path().display())).trim().parse::<f64>() {
            let c = t / 1000.0;
            if c > -40.0 && c < 150.0 {
                zones.push((kind, c));
            }
        }
    }
    let cpu = |k: &str| !k.contains("gpu") && (["soc", "cpu", "cluster", "x86_pkg", "package", "coretemp", "k10temp"].iter().any(|n| k.contains(n)) || k.ends_with("-thermal") || k.ends_with("_thermal"));
    let hottest = zones.iter().filter(|z| cpu(&z.0)).map(|z| z.1).fold(None, |m: Option<f64>, c| Some(m.map_or(c, |m| m.max(c))));
    hottest.or_else(|| (zones.len() == 1).then(|| zones[0].1))
}

/// MAC to IPv4 address, from the seen4 set the rules fill from each
/// device's own packets. A private address wins over a link-local one.
pub fn learned() -> HashMap<String, String> {
    let out = Command::new("nft").args(["-j", "list", "set", "inet", "foilgateway", "seen4"]).output();
    out.ok().map(|o| parse_seen(&String::from_utf8_lossy(&o.stdout))).unwrap_or_default()
}

pub fn parse_seen(json: &str) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = HashMap::new();
    let v: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    let sets = v["nftables"].as_array().cloned().unwrap_or_default();
    for e in sets.iter().filter_map(|x| x["set"]["elem"].as_array()).flatten() {
        let c = if e["elem"].is_object() { &e["elem"]["val"]["concat"] } else { &e["concat"] };
        let (Some(mac), Some(ip)) = (c[0].as_str(), c[1].as_str()) else { continue };
        let keep = m.get(mac).is_some_and(|old| !old.starts_with("169.254.") && ip.starts_with("169.254."));
        if !keep {
            m.insert(mac.to_lowercase(), ip.to_string());
        }
    }
    m
}

/// (used, total) bytes on the filesystem holding path, the way df counts
/// it: used is everything not free, total what an ordinary user could fill.
pub fn disk(path: &str) -> (u64, u64) {
    let Ok(c) = std::ffi::CString::new(path) else { return (0, 0) };
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return (0, 0);
    }
    let f = st.f_frsize as u64;
    let used = (st.f_blocks as u64).saturating_sub(st.f_bfree as u64) * f;
    (used, used + st.f_bavail as u64 * f)
}

/// (used, total) in bytes.
pub fn memory() -> (u64, u64) {
    let text = sys("/proc/meminfo");
    let kb = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok()).unwrap_or(0) * 1024;
    let total = kb("MemTotal:");
    (total.saturating_sub(kb("MemAvailable:")), total)
}

/// (busy, total) jiffies so far; CPU use is the change between two reads.
pub fn cpu_ticks() -> (u64, u64) {
    let text = sys("/proc/stat");
    let v: Vec<u64> = text.lines().next().unwrap_or("").split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    let total: u64 = v.iter().sum();
    let idle = v.get(3).copied().unwrap_or(0) + v.get(4).copied().unwrap_or(0);
    (total - idle, total)
}

/// Bytes per device address from the gateway's own counting sets.
/// Bytes received and sent on a port so far, from its counters.
pub fn port_bytes(name: &str) -> (u64, u64) {
    let read = |f: &str| fs::read_to_string(format!("/sys/class/net/{name}/statistics/{f}")).ok().and_then(|t| t.trim().parse().ok()).unwrap_or(0);
    (read("rx_bytes"), read("tx_bytes"))
}

pub fn device_bytes(set: &str) -> HashMap<String, u64> {
    let out = Command::new("nft").args(["-j", "list", "set", "inet", crate::rules::TABLE, set]).output();
    let Ok(out) = out else { return HashMap::new() };
    parse_set_counters(&String::from_utf8_lossy(&out.stdout))
}

pub fn parse_set_counters(json: &str) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    let v: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    for item in v["nftables"].as_array().into_iter().flatten() {
        for e in item["set"]["elem"].as_array().into_iter().flatten() {
            let el = &e["elem"];
            if let (Some(ip), Some(b)) = (el["val"].as_str(), el["counter"]["bytes"].as_u64()) {
                map.insert(ip.to_string(), b);
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conntrack_line() {
        let l = "ipv4     2 tcp      6 431999 ESTABLISHED src=10.10.10.42 dst=10.10.10.50 sport=50522 dport=8443 packets=12 bytes=1800 src=10.10.10.50 dst=10.10.10.42 sport=8443 dport=50522 packets=10 bytes=9000 [ASSURED] mark=0 use=1";
        let c = parse_conntrack(l).unwrap();
        assert_eq!((c.src.as_str(), c.dport, c.state.as_str(), c.bytes), ("10.10.10.42", 8443, "ESTABLISHED", 10800));
        let u = "ipv4     2 udp      17 20 src=10.10.10.5 dst=1.1.1.1 sport=5353 dport=53 src=1.1.1.1 dst=10.10.10.5 sport=53 dport=5353 mark=0 use=1";
        assert_eq!(parse_conntrack(u).unwrap().state, "");
        assert_eq!((c.orig_bytes, c.reply_bytes), (1800, 9000));
        let g = "ipv6     10 icmpv6   58 29 src=2001:db8::5 dst=2606:4700::1111 type=128 code=0 id=7 packets=3 bytes=312 src=2606:4700::1111 dst=2001:db8::5 type=129 code=0 id=7 packets=3 bytes=312 mark=0 use=1";
        assert_eq!(parse_conntrack(g).unwrap().proto, "icmpv6");
        assert!(parse_conntrack("garbage").is_none());
    }

    #[test]
    fn lease_files() {
        let d = parse_dnsmasq("1730000000 AA:BB:CC:00:11:22 10.10.10.50 printer *\n1730000000 aa:bb:cc:00:11:23 10.10.10.51 * *\n");
        assert_eq!(d["aa:bb:cc:00:11:22"], ("10.10.10.50".to_string(), "printer".to_string()));
        assert_eq!(d["aa:bb:cc:00:11:23"].1, "");
        let i = parse_dhcpd("lease 10.0.0.9 {\n  hardware ethernet 00:11:22:33:44:55;\n  client-hostname \"cam\";\n}\n");
        assert_eq!(i["00:11:22:33:44:55"], ("10.0.0.9".to_string(), "cam".to_string()));
    }

    #[test]
    fn counters() {
        let j = r#"{"nftables":[{"metainfo":{}},{"set":{"name":"dev_up","elem":[{"elem":{"val":"10.10.10.42","counter":{"packets":3,"bytes":420}}}]}}]}"#;
        assert_eq!(parse_set_counters(j)["10.10.10.42"], 420);
    }
}

#[cfg(test)]
mod temp_tests {
    use super::*;

    #[test]
    fn seen_addresses() {
        let j = r#"{"nftables":[{"metainfo":{}},{"set":{"name":"seen4","elem":[{"elem":{"val":{"concat":["02:00:00:00:00:01","169.254.3.4"]},"expires":10}},{"elem":{"val":{"concat":["02:00:00:00:00:01","10.10.10.9"]}}},{"concat":["02:00:00:00:00:02","10.10.10.7"]}]}}]}"#;
        let m = parse_seen(j);
        assert_eq!(m["02:00:00:00:00:01"], "10.10.10.9");
        assert_eq!(m["02:00:00:00:00:02"], "10.10.10.7");
        assert!(parse_seen("").is_empty());
    }

    fn zone(root: &Path, n: u32, kind: &str, milli: &str) {
        let d = root.join(format!("thermal_zone{n}"));
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("type"), kind).unwrap();
        fs::write(d.join("temp"), milli).unwrap();
    }

    #[test]
    fn picks_the_cpu_zone() {
        let root = std::env::temp_dir().join(format!("fg-thermal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        assert_eq!(cpu_temp_in(&root), None);
        zone(&root, 0, "soc-thermal\n", "47200\n");
        assert_eq!(cpu_temp_in(&root), Some(47.2));
        zone(&root, 1, "acpitz", "80000");
        zone(&root, 2, "gpu-thermal", "90000");
        assert_eq!(cpu_temp_in(&root), Some(47.2));
        fs::remove_dir_all(root.join("thermal_zone0")).unwrap();
        assert_eq!(cpu_temp_in(&root), None);
        fs::remove_dir_all(root.join("thermal_zone2")).unwrap();
        assert_eq!(cpu_temp_in(&root), Some(80.0));
        let _ = fs::remove_dir_all(&root);
        // The R2S: two CPU clusters, the hotter one wins.
        fs::create_dir_all(&root).unwrap();
        zone(&root, 0, "cluster0_thermal\n", "62000\n");
        zone(&root, 1, "cluster1_thermal\n", "64500\n");
        zone(&root, 2, "gpu-thermal", "90000");
        zone(&root, 3, "acpitz", "95000");
        assert_eq!(cpu_temp_in(&root), Some(64.5));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn disk_reads_the_root() {
        let (used, total) = disk("/");
        assert!(total > 0 && used <= total);
        assert_eq!(disk("/no/such/place"), (0, 0));
    }
}

/// A list read from the system and when it was read.
type Cached<T> = Option<(std::time::Instant, std::sync::Arc<Vec<T>>)>;
