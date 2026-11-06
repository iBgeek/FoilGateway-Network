//! Downloaded lists (telemetry hosts, threat lists) and the addresses of
//! websites named on the lists. Nothing downloads unless its feature is on.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;

pub struct Feed {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub hosts: bool,
}

// Same lists as the Windows edition, plus the smart TV one since a gateway
// mostly sees TVs, speakers and cameras.
pub const TELEMETRY: &[Feed] = &[
    Feed { id: "telemetry-windows", name: "WindowsSpyBlocker spy hosts", url: "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt", hosts: true },
    Feed { id: "telemetry-windows-ips", name: "WindowsSpyBlocker spy addresses", url: "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt", hosts: false },
    Feed { id: "telemetry-nvidia", name: "NVIDIA telemetry blocklist", url: "https://raw.githubusercontent.com/ravetank/nvidia-telemetry-blocklist/main/nvidia_telemetry_blocklist.hosts", hosts: true },
    Feed { id: "telemetry-smarttv", name: "Perflyst Smart TV list", url: "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt", hosts: true },
];

pub const THREATS: &[Feed] = &[
    Feed { id: "spamhaus-drop", name: "Spamhaus DROP", url: "https://www.spamhaus.org/drop/drop.txt", hosts: false },
    Feed { id: "spamhaus-dropv6", name: "Spamhaus DROPv6", url: "https://www.spamhaus.org/drop/dropv6.txt", hosts: false },
    Feed { id: "feodo-c2", name: "abuse.ch Feodo C2", url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", hosts: false },
];

// Hosts on telemetry lists that also carry sign-in or downloads.
const SKIP: &[&str] = &["login.", "accounts.", "img.", "images.", "assets.", ".edgesuite.net", ".akamaized.net"];

pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout_connect(std::time::Duration::from_secs(15)).timeout(std::time::Duration::from_secs(600)).user_agent(concat!("FoilGateway/", env!("CARGO_PKG_VERSION"))).build()
}

/// Downloads to a file, reporting (done, total) as it goes. Total is 0 when
/// the server doesn't say.
pub fn download_to(url: &str, path: &Path, cap: u64, on: &dyn Fn(u64, u64)) -> Result<u64, String> {
    let resp = agent().get(url).call().map_err(|e| format!("download failed: {e}"))?;
    let total = resp.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut r = resp.into_reader();
    let tmp = path.with_extension("part");
    let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut done = 0u64;
    loop {
        let n = r.read(&mut buf).map_err(|e| format!("download cut off: {e}"))?;
        if n == 0 {
            break;
        }
        done += n as u64;
        if done > cap {
            return Err("download was far bigger than expected, stopped".into());
        }
        std::io::Write::write_all(&mut f, &buf[..n]).map_err(|e| e.to_string())?;
        on(done, total);
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(done)
}

pub fn fetch_text(url: &str) -> Result<String, String> {
    let resp = agent().get(url).call().map_err(|e| format!("download failed: {e}"))?;
    let mut s = String::new();
    resp.into_reader().take(30_000_000).read_to_string(&mut s).map_err(|e| e.to_string())?;
    if s.trim().is_empty() {
        return Err("the list came back empty".into());
    }
    Ok(s)
}

/// Addresses and networks in a list file. Comments start with ; or #.
pub fn parse_addresses(text: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let token = line.split(';').next().unwrap_or("").split_whitespace().next().unwrap_or("");
        if let Some(n) = crate::policy::parse_net(token) {
            seen.insert(n);
        }
    }
    seen.into_iter().collect()
}

/// Host names in a hosts-style file ("0.0.0.0 host" or one name per line).
pub fn parse_hosts(text: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for line in text.lines().map(|l| l.split('#').next().unwrap_or("").trim()) {
        let name = line.split_whitespace().last().unwrap_or("");
        if let Some(d) = crate::policy::domain_of(name) {
            if !SKIP.iter().any(|s| d.starts_with(s) || d.ends_with(s)) {
                seen.insert(d);
            }
        }
    }
    seen.into_iter().collect()
}

pub fn resolve(name: &str) -> Vec<IpAddr> {
    (name, 443).to_socket_addrs().map(|a| a.map(|s| s.ip()).filter(|ip| !ip.is_loopback() && !ip.is_unspecified()).collect()).unwrap_or_default()
}

/// Every address a site has used since it was added. Big sites rotate
/// addresses, so old ones stay. Saved so a restart doesn't forget them.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct SeenAddrs {
    pub sites: BTreeMap<String, BTreeSet<String>>,
}

impl SeenAddrs {
    pub fn load(path: &str) -> SeenAddrs {
        std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }
    pub fn save(&self, path: &str) {
        let _ = std::fs::write(path, serde_json::to_string(self).unwrap_or_default());
    }
    /// Looks the site up now and adds what it finds. True when anything was new.
    pub fn refresh(&mut self, site: &str) -> bool {
        let mut names = vec![site.to_string()];
        if !site.starts_with("www.") {
            names.push(format!("www.{site}"));
        }
        let entry = self.sites.entry(site.to_string()).or_default();
        let before = entry.len();
        for n in names {
            entry.extend(resolve(&n).into_iter().map(|ip| ip.to_string()));
        }
        entry.len() != before
    }
    pub fn of(&self, site: &str) -> Vec<String> {
        self.sites.get(site).map(|s| s.iter().cloned().collect()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_and_feodo_samples() {
        let drop = "; Spamhaus DROP List 2026/10/01 - (c) 2026 The Spamhaus Project\n; Last-Modified: Wed, 01 Oct 2026\n1.10.16.0/20 ; SBL256894\n2.56.192.0/22 ; SBL459831\n";
        assert_eq!(parse_addresses(drop), vec!["1.10.16.0/20", "2.56.192.0/22"]);
        let feodo = "# abuse.ch Feodo Tracker\n#\n162.243.103.246\n50.16.16.211\n";
        assert_eq!(parse_addresses(feodo).len(), 2);
    }

    #[test]
    fn hosts_files() {
        let t = "# comment\n0.0.0.0 vortex.data.microsoft.com\n0.0.0.0 login.live.com\nsamsungads.com\n127.0.0.1 localhost\n";
        assert_eq!(parse_hosts(t), vec!["samsungads.com", "vortex.data.microsoft.com"]);
    }
}
