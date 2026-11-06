//! What the owner chose: modes, lists, devices. Kept in
//! /var/lib/foilgateway/policy.json. The rules are built from this.

use crate::rules::Mode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePolicy {
    Trusted,
    #[default]
    Normal,
    LanOnly,
    Block,
}

impl DevicePolicy {
    pub fn label(self) -> &'static str {
        match self {
            DevicePolicy::Trusted => "Trusted",
            DevicePolicy::Normal => "Normal",
            DevicePolicy::LanOnly => "Local Network Only",
            DevicePolicy::Block => "Block All",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Device {
    pub name: String,
    pub ip: String,
    pub vendor: String,
    pub policy: DevicePolicy,
    pub telemetry: bool,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    /// When an allow entry expires (unix). Missing or 0 = permanent.
    #[serde(default)]
    pub allow_until: BTreeMap<String, i64>,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Still waiting for the owner to look at it.
    pub new: bool,
    pub hostname: String,
    /// Audit for this device until this time (0 = off, i64::MAX = until
    /// turned off): what would be blocked is logged and let through.
    pub audit_until: i64,
}

/// Default lifetime for auto-learned allows when whitelist expiry is on.
pub const WHITE_AUTO_SECS: i64 = 30 * 86400;

impl Device {
    pub fn auditing(&self, now: i64) -> bool {
        self.audit_until > now
    }

    /// True when this allow entry is still in force (permanent or not yet due).
    pub fn allow_live(&self, entry: &str, now: i64) -> bool {
        match self.allow_until.get(entry) {
            Some(&u) if u > 0 => u > now,
            _ => true,
        }
    }
}

/// A port that devices on the LAN side can be reached on from the router
/// side. The list fills itself from what the gateway sees: blocked tries
/// from the router side and connections that came in. `mac` empty means
/// every LAN device. The entry for everybody beats a device's own entry,
/// which only counts on ports that have none.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct InPort {
    pub proto: String,
    pub port: u16,
    pub mac: String,
    /// New connections from the router side get through.
    pub on: bool,
    /// New connections from the LAN side to this port are stopped.
    pub lan_off: bool,
    /// A device's entry that just shows what it got from the entry for
    /// everybody. Turning it on or off by hand makes it its own.
    pub follow: bool,
    /// Seen but not looked at yet.
    pub new: bool,
    /// Added by hand rather than seen.
    pub custom: bool,
    pub hits: u64,
    pub last_seen: i64,
    /// Who tried last, for the list.
    pub from: String,
    /// A device entry the owner set by hand.
    pub own: bool,
}

/// The four ways a port can be set.
pub const CHOICES: &[&str] = &["allow", "block_wan", "block_lan", "block_both"];

impl InPort {
    /// A device's own setting, as opposed to one that follows everybody's
    /// or was only seen. Older files had no `own`, so an entry opened or
    /// added by hand counts too.
    pub fn is_own(&self) -> bool {
        !self.mac.is_empty() && !self.follow && (self.own || self.custom || self.on || self.lan_off)
    }

    pub fn choice(&self) -> &'static str {
        match (self.on, self.lan_off) {
            (true, false) => "allow",
            (false, false) => "block_wan",
            (true, true) => "block_lan",
            (false, true) => "block_both",
        }
    }

    pub fn set_choice(&mut self, c: &str) -> bool {
        let (on, lan_off) = match c {
            "allow" => (true, false),
            "block_wan" => (false, false),
            "block_lan" => (true, true),
            "block_both" => (false, true),
            _ => return false,
        };
        self.on = on;
        self.lan_off = lan_off;
        true
    }

    pub fn same(&self, proto: &str, port: u16, mac: &str) -> bool {
        self.proto == proto && self.port == port && self.mac == mac
    }
}

/// RDP is listed so Ports can warn. External (router side) stays Off; LAN stays
/// allowed until FortNox (or the owner) turns LAN Off too.
pub fn default_inbound() -> Vec<InPort> {
    vec![InPort { proto: "tcp".into(), port: 3389, on: false, lan_off: false, ..Default::default() }]
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Policy {
    pub mode: Mode,
    pub telemetry_all: bool,
    pub white: Vec<String>,
    pub black: Vec<String>,
    pub countries: Vec<String>,
    pub threats: bool,
    pub new_devices: DevicePolicy,
    pub geo: bool,
    pub timezone: String,
    /// MAC address, lower case with colons.
    pub devices: BTreeMap<String, Device>,
    pub inbound: Vec<InPort>,
    /// "tcp 443" -> when a LAN device last started a connection to it.
    pub out_seen: BTreeMap<String, i64>,
    /// Days of Capture Log kept.
    pub log_days: i64,
    /// Dashboard top cards the owner turned on or off (Settings > View), by
    /// card id. A card not listed shows (the page's card list has the
    /// defaults); the server only uses this to skip work for cards set off.
    pub dash_cards: BTreeMap<String, bool>,
    /// 12-hour clock on the pages when true; 24-hour when false.
    #[serde(default = "default_hour12")]
    pub hour12: bool,
    /// Date layout: ymd | mdy | dmy.
    #[serde(default = "default_date_fmt")]
    pub date_fmt: String,
    /// Unix time when this install first wrote a policy. Used to quiet
    /// attack-style warnings while a baseline is learned (about a week).
    /// 0 means unknown (upgrades): treat as past the quiet window.
    #[serde(default)]
    pub installed_at: i64,
    /// Last named protection preset applied, if any. Drift shows as Custom.
    #[serde(default)]
    pub preset: Option<crate::presets::Preset>,
    /// Fail-closed new outbound (Strict). Off by default; On in FortNox.
    #[serde(default)]
    pub strict_outbound: bool,
    /// When true, no IPv6 traffic passes the gateway onto the LAN (except
    /// neighbour / router discovery so the link stays usable). Default Off.
    /// Legacy `ipv6_enabled` (through) migrates in Policy::load:
    /// through=true → block_ipv6=false.
    #[serde(default)]
    pub block_ipv6: bool,
    /// Block common VPN / WireGuard ports (e.g. 51820). Off by default.
    #[serde(default)]
    pub block_vpn: bool,
    /// Block DoT on TCP/UDP 853 so host lists are harder to skip. On with lists in Normal+.
    #[serde(default)]
    pub block_dot: bool,
    /// Time-box auto-learned whitelist entries. Permanent stays available.
    #[serde(default)]
    pub white_expiry: bool,
    /// Expiry times for global white-list entries (unix). Missing or 0 = permanent.
    #[serde(default)]
    pub white_until: BTreeMap<String, i64>,
    /// Owner chose Keep Both on the admin WAN nudge; stop showing the banner.
    #[serde(default)]
    pub admin_keep_both: bool,
    /// Best Practices suggestion ids the owner dismissed.
    #[serde(default)]
    pub coach_dismissed: Vec<String>,
    /// Wave D: hold ordinary DNS so name lists stick. Default Off.
    #[serde(default)]
    pub dns_proxy: bool,
    /// Wave I: stronger identity beyond soft MAC sticky. Default Off.
    #[serde(default)]
    pub sticky_identity: bool,
    /// Wave Det: deeper detection than volume heuristics. Default Off.
    #[serde(default)]
    pub deep_detect: bool,
    /// Wave R: want device-to-device filter when topology allows. Default Off.
    /// Bridge placements refuse to enable this even if the flag is set.
    #[serde(default)]
    pub peer_filter: bool,
}

fn default_hour12() -> bool { true }
fn default_date_fmt() -> String { "ymd".into() }

/// Days after install when Blocked Today stays calm while learning usual.
pub const QUIET_DAYS: i64 = 6;

impl Default for Policy {
    fn default() -> Self {
        Policy {
            mode: Mode::Normal,
            telemetry_all: false,
            white: vec![],
            black: vec![],
            countries: vec![],
            threats: false,
            new_devices: DevicePolicy::Normal,
            geo: false,
            timezone: "UTC".into(),
            devices: BTreeMap::new(),
            inbound: default_inbound(),
            out_seen: BTreeMap::new(),
            log_days: 90,
            dash_cards: BTreeMap::new(),
            hour12: true,
            date_fmt: "ymd".into(),
            installed_at: 0,
            preset: None,
            strict_outbound: false,
            block_ipv6: false,
            block_vpn: false,
            block_dot: false,
            white_expiry: false,
            white_until: BTreeMap::new(),
            admin_keep_both: false,
            coach_dismissed: vec![],
            dns_proxy: false,
            sticky_identity: false,
            deep_detect: false,
            peer_filter: false,
        }
    }
}

impl Policy {
    /// Whether a dashboard card is shown. Unlisted cards show.
    pub fn card_on(&self, id: &str) -> bool {
        self.dash_cards.get(id).copied().unwrap_or(true)
    }

    pub fn load(path: &str) -> Policy {
        let Ok(text) = std::fs::read_to_string(path) else { return Policy::default() };
        let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&text) else { return Policy::default() };
        if let Some(obj) = v.as_object_mut() {
            // 0.7.6: Block IPv6 replaces IPv6 Through Gateway (inverted).
            if !obj.contains_key("block_ipv6") {
                if let Some(through) = obj.remove("ipv6_enabled").and_then(|x| x.as_bool()) {
                    obj.insert("block_ipv6".into(), serde_json::Value::Bool(!through));
                }
            } else {
                obj.remove("ipv6_enabled");
            }
        }
        serde_json::from_value(v).unwrap_or_default()
    }

    /// A brand new install starts in Audit, so nothing breaks while the
    /// owner sees what would be blocked. Saved settings keep their mode:
    /// files from before Audit existed load as whatever they say (Normal
    /// when the field is missing). `installed` is true when there's any
    /// sign of an earlier install, such as a gateway config.
    pub fn open(path: &str, installed: bool) -> Policy {
        if installed || std::path::Path::new(path).exists() {
            let mut p = Policy::load(path);
            // Upgrades with no stamp: already past quiet (don't re-alarm-suppress).
            if p.installed_at == 0 {
                p.installed_at = crate::caplog::now().saturating_sub((QUIET_DAYS + 1) * 86400);
            }
            return p;
        }
        let p = Policy {
            mode: Mode::Audit,
            installed_at: crate::caplog::now(),
            ..Policy::default()
        };
        let _ = p.save(path);
        p
    }

    /// True for the first QUIET_DAYS after a fresh install: still log blocks,
    /// but don't paint Blocked Today red/yellow or fire surge attack alerts.
    pub fn alarm_quiet(&self, now: i64) -> bool {
        self.installed_at > 0 && now.saturating_sub(self.installed_at) < QUIET_DAYS * 86400
    }

    /// True when a global white entry is still in force.
    pub fn white_live(&self, entry: &str, now: i64) -> bool {
        match self.white_until.get(entry) {
            Some(&u) if u > 0 => u > now,
            _ => true,
        }
    }

    /// Drop expired white / device-allow entries. Returns labels of what was removed.
    pub fn expire_allows(&mut self, now: i64) -> Vec<String> {
        let mut gone = Vec::new();
        let dead_white: Vec<String> = self.white.iter().filter(|e| !self.white_live(e, now)).cloned().collect();
        if !dead_white.is_empty() {
            self.white.retain(|e| !dead_white.contains(e));
            for e in &dead_white {
                self.white_until.remove(e);
            }
            gone.push(format!(
                "{} white-list {}",
                dead_white.len(),
                if dead_white.len() == 1 { "entry" } else { "entries" }
            ));
        }
        self.white_until.retain(|e, _| self.white.iter().any(|x| x == e));
        let macs: Vec<String> = self.devices.keys().cloned().collect();
        for mac in macs {
            let Some(d) = self.devices.get_mut(&mac) else { continue };
            let dead: Vec<String> = d.allow.iter().filter(|e| !d.allow_live(e, now)).cloned().collect();
            if dead.is_empty() {
                continue;
            }
            d.allow.retain(|e| !dead.contains(e));
            for e in &dead {
                d.allow_until.remove(e);
            }
            let label = if d.name.is_empty() { mac.as_str() } else { d.name.as_str() };
            gone.push(format!(
                "{} allow {} on {label}",
                dead.len(),
                if dead.len() == 1 { "entry" } else { "entries" }
            ));
        }
        gone
    }

    /// Ports that only ever show up once (games, calls) would make the
    /// list grow for ever: keep 30 days and at most 2000, newest first.
    pub fn trim_out_seen(&mut self, now: i64) {
        self.out_seen.retain(|_, t| now - *t < 30 * 86400);
        if self.out_seen.len() > 2000 {
            let mut v: Vec<(i64, String)> = std::mem::take(&mut self.out_seen).into_iter().map(|(k, t)| (t, k)).collect();
            v.sort_unstable_by(|a, b| b.cmp(a));
            v.truncate(2000);
            self.out_seen = v.into_iter().map(|(t, k)| (k, t)).collect();
        }
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let tmp = format!("{path}.new");
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, text).and_then(|_| std::fs::rename(&tmp, path)).map_err(|e| format!("can't save settings: {e}"))
    }
}

/// One line of an allow/deny list, checked when it's typed in.
#[derive(Clone, Debug, PartialEq)]
pub enum Entry {
    Net(String),
    Site(String),
    Port(&'static str, u16),
}

pub fn parse_entry(text: &str) -> Result<Entry, String> {
    let t = text.trim();
    let lower = t.to_ascii_lowercase();
    for (pre, proto) in [("tcp/", "tcp"), ("udp/", "udp"), ("port ", "tcp")] {
        if let Some(p) = lower.strip_prefix(pre) {
            return p.trim().parse::<u16>().ok().filter(|p| *p > 0).map(|p| Entry::Port(proto, p)).ok_or(format!("{t}: not a port"));
        }
    }
    if let Some(net) = parse_net(t) {
        return Ok(Entry::Net(net));
    }
    if let Some(d) = domain_of(t) {
        return Ok(Entry::Site(d));
    }
    Err(format!("{t}: not an address, network, website or port (try tcp/443)"))
}

/// "10.0.0.0/8", "1.2.3.4", "2001:db8::/32" in nft's form, or None.
pub fn parse_net(text: &str) -> Option<String> {
    let (addr, prefix) = match text.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
        None => (text, None),
    };
    let ip: std::net::IpAddr = addr.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    match prefix {
        Some(p) if p > max => None,
        Some(p) if p < max => {
            // nft refuses host bits in a prefix, so clear them.
            Some(match ip {
                std::net::IpAddr::V4(v) => {
                    let m = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                    format!("{}/{p}", std::net::Ipv4Addr::from(u32::from(v) & m))
                }
                std::net::IpAddr::V6(v) => {
                    let m = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                    format!("{}/{p}", std::net::Ipv6Addr::from(u128::from(v) & m))
                }
            })
        }
        _ => Some(ip.to_string()),
    }
}

/// The site a list entry names. "https://www.example.com/page?x=1" gives
/// "www.example.com". HTTPS hides the page, so a link only stands for its site.
pub fn domain_of(text: &str) -> Option<String> {
    let mut rest = text.trim();
    if let Some((_, after)) = rest.split_once("://") {
        rest = after;
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = host.split(':').next().unwrap_or("").trim_end_matches('.').to_ascii_lowercase();
    let host = host.strip_prefix("*.").unwrap_or(&host).to_string();
    let label_ok = |l: &str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    let labels: Vec<&str> = host.split('.').collect();
    let tld = labels.last().copied().unwrap_or("");
    if host.len() > 253 || labels.len() < 2 || !labels.iter().all(|l| label_ok(l)) || tld.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(host)
}

pub fn normal_mac(text: &str) -> Option<String> {
    let hex: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_lowercase();
    if hex.len() != 12 || text.chars().any(|c| !(c.is_ascii_hexdigit() || c == ':' || c == '-')) {
        return None;
    }
    Some(hex.as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_cards_default_on_and_old_files_load() {
        // A 0.5.7 policy file has no card choices: every card shows.
        let p: Policy = serde_json::from_str(r#"{"mode":"lan_only","log_days":30}"#).unwrap();
        assert_eq!(p.mode, Mode::LanOnly);
        assert!(p.card_on("cpu") && p.card_on("some_future_card"));
        let mut p = p;
        p.dash_cards.insert("cpu".into(), false);
        let back: Policy = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert!(!back.card_on("cpu") && back.card_on("disk"));
    }

    #[test]
    fn fresh_install_starts_in_audit_and_upgrades_keep_their_mode() {
        let dir = std::env::temp_dir().join(format!("fgw-open-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("policy.json");
        let path = path.to_str().unwrap();
        let _ = std::fs::remove_file(path);
        // Nothing there at all: Audit, and it's saved so a restart keeps it.
        let fresh = Policy::open(path, false);
        assert_eq!(fresh.mode, Mode::Audit);
        assert!(fresh.installed_at > 0);
        assert!(fresh.alarm_quiet(crate::caplog::now()));
        assert_eq!(Policy::load(path).mode, Mode::Audit);
        // An install from before Audit existed: no mode field means Normal.
        std::fs::write(path, r#"{"telemetry_all":true}"#).unwrap();
        let up = Policy::open(path, true);
        assert_eq!(up.mode, Mode::Normal);
        assert!(!up.alarm_quiet(crate::caplog::now()), "upgrades skip the quiet week");
        std::fs::write(path, r#"{"mode":"lan_only"}"#).unwrap();
        assert_eq!(Policy::open(path, false).mode, Mode::LanOnly);
        // A gateway config but no policy file yet is an upgrade too.
        std::fs::remove_file(path).unwrap();
        assert_eq!(Policy::open(path, true).mode, Mode::Normal);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn alarm_quiet_covers_the_first_week_only() {
        let mut p = Policy::default();
        p.installed_at = 1_700_000_000;
        assert!(p.alarm_quiet(1_700_000_000 + 3 * 86400));
        assert!(!p.alarm_quiet(1_700_000_000 + QUIET_DAYS * 86400));
        p.installed_at = 0;
        assert!(!p.alarm_quiet(1_700_000_000));
    }

    #[test]
    fn audit_until_runs_out() {
        let d = Device { audit_until: 100, ..Default::default() };
        assert!(d.auditing(99) && !d.auditing(100));
        assert!(Device { audit_until: i64::MAX, ..Default::default() }.auditing(i64::MAX - 1));
        assert!(!Device::default().auditing(0));
    }

    #[test]
    fn white_expiry_drops_due_entries() {
        let mut p = Policy::default();
        p.white_expiry = true;
        p.white.push("1.2.3.4".into());
        p.white_until.insert("1.2.3.4".into(), 100);
        p.white.push("9.9.9.9".into()); // permanent
        let mut d = Device::default();
        d.allow.push("8.8.8.8".into());
        d.allow_until.insert("8.8.8.8".into(), 50);
        d.allow.push("8.8.4.4".into());
        p.devices.insert("aa:bb:cc:00:00:01".into(), d);
        let gone = p.expire_allows(100);
        assert!(!gone.is_empty());
        assert_eq!(p.white, vec!["9.9.9.9".to_string()]);
        let d = p.devices.get("aa:bb:cc:00:00:01").unwrap();
        assert_eq!(d.allow, vec!["8.8.4.4".to_string()]);
    }

    #[test]
    fn fresh_policy_keeps_rdp_off() {
        let p = Policy::default();
        assert_eq!(p.inbound.len(), 1);
        assert_eq!((p.inbound[0].port, p.inbound[0].on, p.inbound[0].lan_off), (3389, false, false));
        assert!(!p.block_ipv6);
        assert!(!p.strict_outbound && !p.block_vpn && !p.block_dot);
    }

    #[test]
    fn block_ipv6_migrates_from_ipv6_enabled() {
        let dir = std::env::temp_dir().join(format!("fgw-pol-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("policy.json");
        std::fs::write(&path, r#"{"ipv6_enabled":true}"#).unwrap();
        let p = Policy::load(path.to_str().unwrap());
        assert!(!p.block_ipv6, "through=true → block_ipv6=false");
        std::fs::write(&path, r#"{"ipv6_enabled":false}"#).unwrap();
        let p = Policy::load(path.to_str().unwrap());
        assert!(p.block_ipv6, "through=false → block_ipv6=true");
        std::fs::write(&path, r#"{"block_ipv6":true,"ipv6_enabled":true}"#).unwrap();
        let p = Policy::load(path.to_str().unwrap());
        assert!(p.block_ipv6, "new field wins");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn entries() {
        assert_eq!(parse_entry("tcp/443"), Ok(Entry::Port("tcp", 443)));
        assert_eq!(parse_entry("UDP/53"), Ok(Entry::Port("udp", 53)));
        assert!(parse_entry("tcp/0").is_err());
        assert_eq!(parse_entry("10.1.2.3/8"), Ok(Entry::Net("10.0.0.0/8".into())));
        assert_eq!(parse_entry("1.2.3.4"), Ok(Entry::Net("1.2.3.4".into())));
        assert_eq!(parse_entry("1.2.3.4/32"), Ok(Entry::Net("1.2.3.4".into())));
        assert_eq!(parse_entry("2001:db8::1/32"), Ok(Entry::Net("2001:db8::/32".into())));
        assert_eq!(parse_entry("https://www.Example.com/a?b"), Ok(Entry::Site("www.example.com".into())));
        assert!(parse_entry("1.2.3.4/40").is_err());
        assert!(parse_entry("rm -rf /").is_err());
        assert!(parse_entry("a.com; flush ruleset").is_err());
    }

    #[test]
    fn sites_like_windows() {
        assert_eq!(domain_of("http://user@site.org:8080/x").as_deref(), Some("site.org"));
        assert_eq!(domain_of("*.baidu.com").as_deref(), Some("baidu.com"));
        assert_eq!(domain_of("1.2.3.4"), None);
        assert_eq!(domain_of("localhost"), None);
    }

    #[test]
    fn macs() {
        assert_eq!(normal_mac("AA-BB-CC-00-11-22").as_deref(), Some("aa:bb:cc:00:11:22"));
        assert_eq!(normal_mac("aa:bb:cc:00:11"), None);
        assert_eq!(normal_mac("aa:bb:cc:00:11:2z"), None);
    }

    #[test]
    fn old_files_still_load() {
        let p: Policy = serde_json::from_str(r#"{"mode":"lan_only"}"#).unwrap();
        assert_eq!(p.mode, Mode::LanOnly);
        assert_eq!(p.new_devices, DevicePolicy::Normal);
        assert!(!p.geo);
        assert_eq!((p.inbound[0].port, p.inbound[0].on), (3389, false));
    }
}
