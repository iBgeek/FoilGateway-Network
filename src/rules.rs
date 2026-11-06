use crate::config::Config;

pub const TABLE: &str = "foilgateway";
// Every safety rule carries this comment so a loaded ruleset can be checked.
pub const SAFETY_TAG: &str = "foilgw-safety";

fn set(items: impl IntoIterator<Item = String>) -> String {
    format!("{{ {} }}", items.into_iter().collect::<Vec<_>>().join(", "))
}

/// Safety rules for one chain. They go first, ahead of every block rule.
fn safety(cfg: &Config, chain: &str) -> Vec<String> {
    if !cfg.safety {
        return Vec::new();
    }
    let v4: Vec<String> = cfg.safety_hosts.iter().filter(|h| h.is_ipv4()).map(|h| h.to_string()).collect();
    let v6: Vec<String> = cfg.safety_hosts.iter().filter(|h| h.is_ipv6()).map(|h| h.to_string()).collect();
    let ports = set(cfg.safety_ports.iter().map(|p| p.to_string()));
    let tag = format!("comment \"{SAFETY_TAG}\"");
    let mut r = Vec::new();
    match chain {
        "input" => {
            if !v4.is_empty() {
                let hosts = set(v4.iter().cloned());
                r.push(format!("ip saddr {hosts} tcp dport {ports} accept {tag}"));
                r.push(format!("ip saddr {hosts} icmp type echo-request accept {tag}"));
            }
            if !v6.is_empty() {
                let hosts = set(v6.iter().cloned());
                r.push(format!("ip6 saddr {hosts} tcp dport {ports} accept {tag}"));
                r.push(format!("ip6 saddr {hosts} icmpv6 type echo-request accept {tag}"));
            }
        }
        "output" => {
            if !v4.is_empty() {
                let hosts = set(v4.iter().cloned());
                r.push(format!("ip daddr {hosts} tcp sport {ports} accept {tag}"));
                r.push(format!("ip daddr {hosts} icmp type echo-reply accept {tag}"));
            }
            if !v6.is_empty() {
                let hosts = set(v6.iter().cloned());
                r.push(format!("ip6 daddr {hosts} tcp sport {ports} accept {tag}"));
                r.push(format!("ip6 daddr {hosts} icmpv6 type echo-reply accept {tag}"));
            }
        }
        // Safety hosts reach the gateway only (input/output above).
        // They do not get a free pass through forward: in Block Everything
        // or Local Network Only they stay cut off from the internet, which
        // is what you want on a compromised network.
        "forward" => {}
        _ => {}
    }
    r
}

/// Builds the full table. `blocks` holds the rest of the rules per chain.
pub fn ruleset(cfg: &Config, blocks: &[(&str, Vec<String>)]) -> String {
    let mut out = format!("table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{\n");
    for chain in ["input", "forward", "output"] {
        out += &format!("  chain {chain} {{\n    type filter hook {chain} priority filter; policy accept;\n");
        for r in safety(cfg, chain) {
            out += &format!("    {r}\n");
        }
        for (c, rules) in blocks {
            if *c == chain {
                for r in rules {
                    out += &format!("    {r}\n");
                }
            }
        }
        out += "  }\n";
    }
    out + "}\n"
}

/// Checks a loaded table (output of `nft -a list table inet foilgateway`):
/// with safety on, each chain must start with its safety rules.
pub fn safety_first(cfg: &Config, listed: &str) -> Result<(), String> {
    if !cfg.safety {
        return Ok(());
    }
    let mut chain = "";
    let mut seen_other = false;
    let mut found = std::collections::HashMap::new();
    for line in listed.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("chain ") {
            chain = rest.split_whitespace().next().unwrap_or("");
            seen_other = false;
            continue;
        }
        if line.is_empty() || line == "}" || line.starts_with("type ") || line.starts_with("table ") {
            continue;
        }
        if line.contains(SAFETY_TAG) {
            if seen_other {
                return Err(format!("{chain}: a rule sits ahead of the safety rules"));
            }
            *found.entry(chain.to_string()).or_insert(0) += 1;
        } else {
            seen_other = true;
        }
    }
    for c in ["input", "forward", "output"] {
        let want = safety(cfg, c).len();
        if found.get(c).copied().unwrap_or(0) != want {
            return Err(format!("{c}: safety rules missing"));
        }
    }
    Ok(())
}


/// Whole-network modes. The two blocking ones are absolute: only the
/// safety rules above them get through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Normal,
    LanOnly,
    BlockAll,
    /// Like Normal, but what would be blocked is logged and let through.
    Audit,
}

/// Addresses split by family, as nft wants them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Nets {
    pub v4: Vec<String>,
    pub v6: Vec<String>,
}

/// Set elements written once, as nft wants them ("a-b, c-d"), with how
/// many ranges each family has. `hidden` leaves them out of the text shown
/// on the Rules page.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Elems {
    pub v4: String,
    pub v6: String,
    pub n4: usize,
    pub n6: usize,
    pub hidden: bool,
}

impl Nets {
    /// Duplicates are dropped when the set is written, so adding stays
    /// cheap for long lists.
    pub fn add(&mut self, net: &str) {
        let list = if net.contains(':') { &mut self.v6 } else { &mut self.v4 };
        list.push(net.to_string());
    }
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

/// One entry on a device's own allow or deny list, already resolved.
#[derive(Clone, Debug, PartialEq)]
pub enum Match {
    Nets(Nets),
    Port(&'static str, u16),
}

/// Devices are known by MAC: in bridge mode that's what every packet
/// carries, whatever address the router handed out.
#[derive(Clone, Debug, Default)]
pub struct DeviceRules {
    pub mac: String,
    pub policy: crate::policy::DevicePolicy,
    pub telemetry: bool,
    pub allow: Vec<Match>,
    pub deny: Vec<Match>,
}

/// One port that may (or may not) be reached from the router side.
/// `mac` None means every LAN device.
#[derive(Clone, Debug, PartialEq)]
pub struct Inbound {
    pub proto: &'static str,
    pub port: u16,
    pub mac: Option<String>,
    pub on: bool,
    pub lan_off: bool,
}

/// Everything the rules are built from, with names already turned into
/// addresses.
#[derive(Clone, Debug)]
pub struct Plan {
    pub mode: Mode,
    pub telemetry_all: bool,
    pub white: Nets,
    pub black: Nets,
    pub telemetry: Nets,
    pub threats: Nets,
    /// Country ranges, already merged and written out, shared and cached.
    pub countries: std::sync::Arc<Elems>,
    pub devices: Vec<DeviceRules>,
    /// The network the bridge is on (what the router hands out).
    pub local: Nets,
    /// The router itself, and the DNS servers its DHCP names.
    pub router: Nets,
    pub dns: Nets,
    pub inbound: Vec<Inbound>,
    /// Devices in audit right now (MACs).
    pub audit: Vec<String>,
    /// Fail-closed new outbound from the LAN side.
    pub strict_outbound: bool,
    /// When false, drop IPv6 forward (except ND / DHCPv6) so v6 cannot bypass.
    pub ipv6_enabled: bool,
    /// Block WireGuard / common VPN UDP ports.
    pub block_vpn: bool,
    /// Block DoT on TCP+UDP 853.
    pub block_dot: bool,
    /// Wave D: DNS proxy intercept armed (ordinary DNS). Default Off.
    /// When On, LAN DNS is marked for the local forwarder hook. Full DoH
    /// on 443 is still not solved by this flag alone.
    pub dns_proxy: bool,
}

impl Default for Plan {
    fn default() -> Self {
        Plan {
            mode: Mode::Normal,
            telemetry_all: false,
            white: Nets::default(),
            black: Nets::default(),
            telemetry: Nets::default(),
            threats: Nets::default(),
            countries: std::sync::Arc::default(),
            devices: vec![],
            local: Nets::default(),
            router: Nets::default(),
            dns: Nets::default(),
            inbound: vec![],
            audit: vec![],
            strict_outbound: false,
            ipv6_enabled: true,
            block_vpn: false,
            block_dot: false,
            dns_proxy: false,
        }
    }
}

// Why a packet was dropped. Each has its own chain that logs (rate limited)
// and drops, so the daemon can tell blocks apart in the kernel log.
pub const REASONS: &[(&str, &str)] = &[
    ("mode", "Block everything is on"),
    ("lanonly", "LAN only is on"),
    ("devblock", "device is set to Block all"),
    ("devlan", "device is set to LAN only"),
    ("devdeny", "on this device's deny list"),
    ("telemetry", "telemetry"),
    ("black", "on the Black list"),
    ("threat", "on a threat list"),
    ("country", "blocked country"),
    ("wan", "new connection from the router side"),
    ("lanport", "port blocked on the LAN side"),
    ("dot", "encrypted DNS on port 853"),
    ("vpn", "VPN / WireGuard port"),
    ("strict", "strict outbound"),
];
pub const LOG_PREFIX: &str = "fgw:";
/// Reasons that are never audited: the whole-network modes are absolute.
const NOT_AUDITED: &[&str] = &["mode", "lanonly"];

/// In audit, a block jumps to chk_<reason> instead of drop_<reason>: the
/// device (or everybody, in whole-network Audit) goes to audit_<reason>,
/// which logs once per connection and lets it through; others still drop.
/// With no audit on, the rules are exactly as before.
fn audited(rules: Vec<String>, plan: &Plan) -> Vec<String> {
    if plan.mode != Mode::Audit && plan.audit.is_empty() {
        return rules;
    }
    rules
        .into_iter()
        .map(|r| {
            for (reason, _) in REASONS {
                if NOT_AUDITED.contains(reason) {
                    continue;
                }
                let from = format!("jump drop_{reason}");
                if r.ends_with(&from) {
                    return format!("{}jump chk_{reason}", &r[..r.len() - from.len()]);
                }
            }
            r
        })
        .collect()
}

fn audit_chains(plan: &Plan) -> String {
    if plan.mode != Mode::Audit && plan.audit.is_empty() {
        return String::new();
    }
    let macs = set(plan.audit.iter().cloned());
    let mut out = String::new();
    for (reason, _) in REASONS.iter().filter(|(r, _)| !NOT_AUDITED.contains(r)) {
        out += &format!("  chain chk_{reason} {{
");
        if plan.mode == Mode::Audit {
            out += &format!("    goto audit_{reason}
");
        } else {
            out += &format!("    ether saddr {macs} goto audit_{reason}
    ether daddr {macs} goto audit_{reason}
    goto drop_{reason}
");
        }
        out += "  }
";
        // Logged on the connection's first direction only; the connection
        // then takes the fast path until the policy changes.
        out += &format!(
            "  chain audit_{reason} {{
    ct direction original limit rate 20/second burst 40 packets log prefix \"{LOG_PREFIX}audit:{reason} \" level info
    goto pass
  }}
"
        );
    }
    out
}

// Set at ingress on each bridge port so the inet rules know which side a
// bridged packet came from (inside the bridge every packet is on br-fgw).
pub const MARK_WAN: &str = "0x00466710";
pub const MARK_LAN: &str = "0x00466720";
const FROM_WAN: &str = "meta mark 0x00466710";
const FROM_LAN: &str = "meta mark 0x00466720";

/// When the bridge has no address yet, "local" means the private ranges.
const PRIVATE4: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

fn q(name: &str) -> String {
    format!("\"{name}\"")
}

fn ipset(name: &str, kind: &str, items: &[String]) -> String {
    let mut items: Vec<&str> = items.iter().map(String::as_str).collect();
    items.sort_unstable();
    items.dedup();
    raw_set(name, kind, &items.join(", "), items.len(), false)
}

fn raw_set(name: &str, kind: &str, elems: &str, n: usize, hidden: bool) -> String {
    let mut out = format!("  set {name} {{\n    type {kind}; flags interval; auto-merge;\n");
    if hidden && n > 0 {
        out += &format!("    # {n} ranges from Geo-Blocking, not listed here\n");
    } else if !elems.is_empty() {
        out += &format!("    elements = {{ {elems} }}\n");
    }
    out + "  }\n"
}

fn sets(name: &str, nets: &Nets) -> String {
    ipset(&format!("{name}4"), "ipv4_addr", &nets.v4) + &ipset(&format!("{name}6"), "ipv6_addr", &nets.v6)
}

/// Rules matching traffic to or from any address in a set pair, both ways.
fn both_ways(set: &str, verdict: &str, only: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (fam, f) in [("ip", "4"), ("ip6", "6")] {
        out.push(format!("{only}{fam} daddr @{set}{f} {verdict}"));
        out.push(format!("{only}{fam} saddr @{set}{f} {verdict}"));
    }
    out.into_iter().map(|r| r.trim().to_string()).collect()
}

fn match_rules(mac: &str, m: &Match, verdict: &str) -> Vec<String> {
    match m {
        Match::Port(proto, port) => vec![
            format!("ether saddr {mac} {proto} dport {port} {verdict}"),
            format!("ether daddr {mac} {proto} sport {port} {verdict}"),
        ],
        Match::Nets(n) => {
            let mut out = Vec::new();
            for (fam, list) in [("ip", &n.v4), ("ip6", &n.v6)] {
                if !list.is_empty() {
                    let s = set(list.iter().cloned());
                    out.push(format!("ether saddr {mac} {fam} daddr {s} {verdict}"));
                    out.push(format!("ether daddr {mac} {fam} saddr {s} {verdict}"));
                }
            }
            out
        }
    }
}

/// LAN only, for everybody (`who` empty) or for some devices: only the
/// local network, and from the router only DHCP (always let through) and
/// DNS. DNS to the servers the router names works too, so names resolve.
fn lan_only(who_s: &str, who_d: &str, verdict: &str) -> Vec<String> {
    let (s, d) = (format!("{who_s} ").trim_start().to_string(), format!("{who_d} ").trim_start().to_string());
    vec![
        format!("{s}ip daddr @dns4 meta l4proto {{ tcp, udp }} th dport 53 accept"),
        format!("{d}ip saddr @dns4 meta l4proto {{ tcp, udp }} th sport 53 accept"),
        format!("{s}ip6 daddr @dns6 meta l4proto {{ tcp, udp }} th dport 53 accept"),
        format!("{d}ip6 saddr @dns6 meta l4proto {{ tcp, udp }} th sport 53 accept"),
        format!("{s}ip daddr @router4 {verdict}"),
        format!("{d}ip saddr @router4 {verdict}"),
        format!("{s}ip6 daddr @router6 {verdict}"),
        format!("{d}ip6 saddr @router6 {verdict}"),
        format!("{s}ip daddr != @local4 {verdict}"),
        format!("{d}ip saddr != @local4 {verdict}"),
        format!("{s}ip6 daddr != @local6 {verdict}"),
        format!("{d}ip6 saddr != @local6 {verdict}"),
    ]
}

/// New connections to a port, from either side. A port with an entry for
/// everybody goes by that entry alone; devices' own entries only count for
/// ports without one. From the router side only open ports get in, and
/// devices set to Block all or LAN only never get any (their own rules
/// come later, and an accept here would skip them). From the LAN side
/// everything passes unless a port says otherwise.
fn inbound_rules(plan: &Plan) -> Vec<String> {
    use crate::policy::DevicePolicy as P;
    let shut: Vec<&str> = plan.devices.iter().filter(|d| matches!(d.policy, P::Block | P::LanOnly)).map(|d| d.mac.as_str()).collect();
    let global = |proto: &str, port: u16| plan.inbound.iter().any(|g| g.mac.is_none() && g.proto == proto && g.port == port);
    let new = format!("{FROM_WAN} ct state new");
    let lan = format!("{FROM_LAN} ct state new");
    let mut r = Vec::new();
    for i in plan.inbound.iter().filter(|i| i.mac.is_some() && !global(i.proto, i.port)) {
        let mac = i.mac.as_deref().unwrap();
        if i.lan_off {
            r.push(format!("{lan} ether saddr {mac} {} dport {} jump drop_lanport", i.proto, i.port));
            r.push(format!("{lan} ether daddr {mac} {} dport {} jump drop_lanport", i.proto, i.port));
        }
        if !i.on {
            r.push(format!("{new} ether daddr {mac} {} dport {} jump drop_wan", i.proto, i.port));
        } else if !shut.contains(&mac) {
            r.push(format!("{new} ether daddr {mac} {} dport {} accept", i.proto, i.port));
        }
    }
    for proto in ["tcp", "udp"] {
        let mine = |f: fn(&Inbound) -> bool| plan.inbound.iter().filter(|i| i.mac.is_none() && i.proto == proto && f(i)).map(|i| i.port.to_string()).collect::<Vec<_>>();
        let off = mine(|i| i.lan_off);
        if !off.is_empty() {
            r.push(format!("{lan} {proto} dport {} jump drop_lanport", set(off)));
        }
        let ports = mine(|i| i.on);
        if ports.is_empty() {
            continue;
        }
        let not = if shut.is_empty() { String::new() } else { format!(" ether daddr != {}", set(shut.iter().map(|m| m.to_string()))) };
        r.push(format!("{new}{not} {proto} dport {} accept", set(ports)));
    }
    // Broadcasts and multicast from the router side stay there, quietly.
    r.push(format!("{new} meta pkttype {{ broadcast, multicast }} drop"));
    r.push(format!("{new} jump drop_wan"));
    r
}

/// The forward rules (traffic crossing the bridge) in the order that makes
/// the precedence work. Each line's position is the policy, so keep it:
/// DHCP and neighbour discovery, absolute modes, device deny, new
/// connections from the router side, device allow, device Block all /
/// LAN only, White list, telemetry, Trusted, Black list, threat lists,
/// countries.
pub fn forward_rules(_cfg: &Config, plan: &Plan) -> Vec<String> {
    use crate::policy::DevicePolicy as P;
    // The router's DHCP passes untouched, and IPv6 can't find anybody
    // without neighbour discovery. Neither carries anybody's data.
    let mut r = vec![
        "udp sport { 67, 68 } udp dport { 67, 68 } accept".to_string(),
        "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept".to_string(),
        "udp sport { 546, 547 } udp dport { 546, 547 } accept".to_string(),
    ];
    // IPv6 Off: after ND/DHCPv6, drop the rest of IPv6 so it cannot bypass IPv4 policy.
    if !plan.ipv6_enabled {
        r.push("meta nfproto ipv6 jump drop_mode".to_string());
    }
    match plan.mode {
        Mode::BlockAll => r.push("jump drop_mode".to_string()),
        Mode::LanOnly => r.extend(lan_only("", "", "jump drop_lanonly")),
        Mode::Normal | Mode::Audit => {}
    }
    let devs = &plan.devices;
    for d in devs {
        for m in &d.deny {
            r.extend(match_rules(&d.mac, m, "jump drop_devdeny"));
        }
    }
    r.extend(inbound_rules(plan));
    for d in devs {
        for m in &d.allow {
            r.extend(match_rules(&d.mac, m, "accept"));
        }
    }
    let pick = |p: P| set(devs.iter().filter(|d| d.policy == p).map(|d| d.mac.clone()));
    if devs.iter().any(|d| d.policy == P::Block) {
        let s = pick(P::Block);
        r.push(format!("ether saddr {s} jump drop_devblock"));
        r.push(format!("ether daddr {s} jump drop_devblock"));
    }
    if devs.iter().any(|d| d.policy == P::LanOnly) {
        let s = pick(P::LanOnly);
        r.extend(lan_only(&format!("ether saddr {s}"), &format!("ether daddr {s}"), "jump drop_devlan"));
    }
    r.extend(both_ways("white", "accept", ""));
    if plan.telemetry_all {
        r.extend(both_ways("telemetry", "jump drop_telemetry", ""));
    } else if devs.iter().any(|d| d.telemetry) {
        let s = set(devs.iter().filter(|d| d.telemetry).map(|d| d.mac.clone()));
        for (fam, f) in [("ip", "4"), ("ip6", "6")] {
            r.push(format!("ether saddr {s} {fam} daddr @telemetry{f} jump drop_telemetry"));
            r.push(format!("ether daddr {s} {fam} saddr @telemetry{f} jump drop_telemetry"));
        }
    }
    if devs.iter().any(|d| d.policy == P::Trusted) {
        let s = pick(P::Trusted);
        r.push(format!("ether saddr {s} accept"));
        r.push(format!("ether daddr {s} accept"));
    }
    r.extend(both_ways("black", "jump drop_black", ""));
    r.extend(both_ways("threat", "jump drop_threat", ""));
    r.extend(both_ways("country", "jump drop_country", ""));
    if plan.block_dot {
        r.push(format!("{FROM_LAN} meta l4proto {{ tcp, udp }} th dport 853 jump drop_dot"));
        r.push(format!("{FROM_WAN} meta l4proto {{ tcp, udp }} th sport 853 jump drop_dot"));
    }
    // Wave D: when DNS Proxy is On, mark ordinary DNS from the LAN so a
    // local forwarder (or a later redirect) can hold name lists. Packets
    // still pass today — DoH on 443 is not claimed solved.
    if plan.dns_proxy {
        r.push(format!("{FROM_LAN} meta l4proto {{ tcp, udp }} th dport 53 jump dns_proxy"));
    }

    if plan.block_vpn {
        // WireGuard default and a few common VPN UDP ports.
        r.push(format!("{FROM_LAN} udp dport {{ 51820, 1194, 500, 4500 }} jump drop_vpn"));
        r.push(format!("{FROM_WAN} udp sport {{ 51820, 1194, 500, 4500 }} jump drop_vpn"));
    }
    if plan.strict_outbound {
        // Fail-closed: new outbound from the LAN side that nothing above accepted.
        r.push(format!("{FROM_LAN} ct state new jump drop_strict"));
    }
    r
}

/// Input rules after the safety ones: traffic to the gateway itself. SSH
/// and the settings page answer from both sides in every mode, as do
/// DHCP, mDNS and ping. Nothing else new comes in from the router side.
/// With admin_from = lan the page only answers your devices; SSH still
/// answers both sides. Safety computers reach the gateway via the input rules above.
pub fn input_rules(cfg: &Config, plan: &Plan) -> Vec<String> {
    let admin = if cfg.admin_from_wan { format!("tcp dport {{ 22, {} }} accept", cfg.admin_port) } else { format!("tcp dport 22 accept\n{FROM_LAN} tcp dport {} accept", cfg.admin_port) };
    let mut r = vec![
        admin,
        "udp dport { 67, 68 } accept".into(),
        "udp dport 5353 accept".into(),
        "icmp type echo-request accept".into(),
    ];
    if plan.ipv6_enabled {
        // Narrow ICMPv6: echo + neighbour/router discovery (not every icmpv6 type).
        r.push("icmpv6 type { echo-request, echo-reply, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept".into());
    }
    r.push("ct state established,related accept".into());
    r.push(format!("{FROM_WAN} ct state new jump drop_wan"));
    r
}

/// Marks each bridge port's packets with its side as they arrive.
pub fn side_table(cfg: &Config) -> String {
    format!(
        "table netdev {TABLE}\ndelete table netdev {TABLE}\ntable netdev {TABLE} {{\n  chain wan_side {{\n    type filter hook ingress devices = {{ {} }} priority -500; policy accept;\n    meta mark set {MARK_WAN}\n  }}\n  chain lan_side {{\n    type filter hook ingress devices = {{ {} }} priority -500; policy accept;\n    meta mark set {MARK_LAN}\n  }}\n}}\n",
        q(&cfg.wan),
        cfg.lan.iter().map(|l| q(l)).collect::<Vec<_>>().join(", ")
    )
}

/// The full rules for a plan: the port marks, then the inet table with
/// safety rules first in every base chain, then the policy. Drop chains
/// and traffic counters sit beside them.
pub fn policy_ruleset(cfg: &Config, plan: &Plan) -> String {
    let blocks = vec![("input", input_rules(cfg, plan)), ("forward", fast_forward(audited(forward_rules(cfg, plan), plan))), ("output", vec![])];
    let mut out = ruleset(cfg, &blocks);
    out.truncate(out.len() - 2); // reopen the table
    out += &sets("white", &plan.white);
    out += &sets("black", &plan.black);
    out += &sets("telemetry", &plan.telemetry);
    out += &sets("threat", &plan.threats);
    let c = &plan.countries;
    out += &raw_set("country4", "ipv4_addr", &c.v4, c.n4, c.hidden);
    out += &raw_set("country6", "ipv6_addr", &c.v6, c.n6, c.hidden);
    let mut local = plan.local.clone();
    if local.v4.is_empty() {
        PRIVATE4.iter().for_each(|n| local.add(n));
    }
    local.add("fe80::/10");
    local.add("fc00::/7"); // ULA
    local.add("ff00::/8");
    out += &sets("local", &local);
    out += &sets("router", &plan.router);
    out += &sets("dns", &plan.dns);
    for name in ["dev_up", "dev_down"] {
        // Entries go after an hour without traffic, so MACs that came and
        // went (private addresses change) don't pile up until a reload.
        out += &format!("  set {name} {{\n    type ether_addr; size 65535; flags dynamic, timeout; timeout 1h;\n  }}\n");
    }
    // Which addresses each device uses, learned from its own packets.
    out += "  set seen4 {\n    type ether_addr . ipv4_addr; size 65535; flags dynamic, timeout; timeout 1h;\n  }\n";
    out += "  set seen6 {\n    type ether_addr . ipv6_addr; size 65535; flags dynamic, timeout; timeout 1h;\n  }\n";
    for (reason, _) in REASONS {
        out += &format!(
            "  chain drop_{reason} {{\n    limit rate 20/second burst 40 packets log prefix \"{LOG_PREFIX}{reason} \" level info\n    drop\n  }}\n"
        );
    }
    // Wave D hook: jump target when dns_proxy is On. Returns so ordinary DNS
    // still flows until a local forwarder claims these packets. DoH on 443
    // is not solved by this chain alone.
    out += "  chain dns_proxy {\n    return\n  }\n";
    // Counting only, never a verdict, so it can't get ahead of the safety rules.
    // Byte counters stay per packet (they are the in/out totals); learning
    // a device's addresses only needs a connection's first packet.
    out += &format!(
        "  chain acct_fwd {{\n    type filter hook forward priority -10; policy accept;\n    {FROM_LAN} update @dev_up {{ ether saddr counter }}\n    {FROM_WAN} update @dev_down {{ ether daddr counter }}\n    {FROM_LAN} ct state new ip saddr != 0.0.0.0 update @seen4 {{ ether saddr . ip saddr }}\n    {FROM_LAN} ct state new ip6 saddr != :: update @seen6 {{ ether saddr . ip6 saddr }}\n  }}\n"
    );
    out += &format!("  chain acct_in {{\n    type filter hook input priority -10; policy accept;\n    {FROM_LAN} update @dev_up {{ ether saddr counter }}\n    {FROM_LAN} ct state new ip saddr != 0.0.0.0 update @seen4 {{ ether saddr . ip saddr }}\n  }}\n");
    out += &audit_chains(plan);
    out += "  chain pass {\n    ct mark and 0xfffffffc != @@GEN@@ ct mark set @@GEN@@\n    ct direction original ct mark set ct mark or 0x1 accept\n    ct mark set ct mark or 0x2 accept\n  }\n";
    out += "}\n";
    let full = side_table(cfg) + &out;
    let g = generation(&full);
    full.replace("@@GEN1@@", &format!("0x{:08x}", g | 1)).replace("@@GEN2@@", &format!("0x{:08x}", g | 2)).replace("@@GEN@@", &format!("0x{g:08x}"))
}

/// The policy's fingerprint, as a ct mark with the two low bits free.
fn generation(text: &str) -> u32 {
    let h = text.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3));
    ((h ^ (h >> 32)) as u32 & 0xfffffffc).max(4)
}

/// Remembers, per connection and direction, that its packets passed the
/// whole policy, so the rest of that connection's packets in that
/// direction skip the set lookups. The mark carries the policy's
/// fingerprint: any change to the rules or the lists re-checks every
/// connection on its next packet. Accepts that depend on `ct state new`
/// aren't remembered, because the connection's later packets used to go
/// on down the list and must still do so.
fn fast_forward(rules: Vec<String>) -> Vec<String> {
    let mut out = vec![
        "ct direction original ct mark and 0xfffffffd == @@GEN1@@ accept".to_string(),
        "ct direction reply ct mark and 0xfffffffe == @@GEN2@@ accept".to_string(),
    ];
    out.extend(rules.into_iter().map(|r| match r.strip_suffix(" accept") {
        Some(m) if !r.contains("ct state new") => format!("{m} goto pass"),
        _ => r,
    }));
    out.push("goto pass".into());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::DevicePolicy;

    fn cfg() -> Config {
        Config::parse("lan=eth3\nwan=eth2\nsafety_hosts=10.10.10.42\nsafety_ports=22,8443").unwrap()
    }

    fn dev(mac: &str, policy: DevicePolicy) -> DeviceRules {
        DeviceRules { mac: mac.into(), policy, ..Default::default() }
    }

    fn pos(rules: &[String], needle: &str) -> usize {
        rules.iter().position(|r| r.contains(needle)).unwrap_or_else(|| panic!("no rule with {needle}"))
    }

    fn rdp() -> Inbound {
        Inbound { proto: "tcp", port: 3389, mac: None, on: true, lan_off: false }
    }

    const A: &str = "02:00:00:00:00:0a";
    const B: &str = "02:00:00:00:00:0b";

    #[test]
    fn safety_comes_before_blocks() {
        let r = ruleset(&cfg(), &[("input", vec!["drop".into()])]);
        let input = r.split("chain input").nth(1).unwrap();
        assert!(input.find(SAFETY_TAG).unwrap() < input.find("    drop").unwrap());
    }

    #[test]
    fn safety_first_in_full_policy() {
        let plan = Plan { mode: Mode::BlockAll, devices: vec![dev(A, DevicePolicy::Trusted)], ..Default::default() };
        let text = policy_ruleset(&cfg(), &plan);
        let input = text.split("chain input").nth(1).unwrap().split("\n  }").next().unwrap();
        assert!(input.contains(SAFETY_TAG), "safety hosts still reach the gateway");
        let fwd = text.split("chain forward").nth(1).unwrap().split("\n  }").next().unwrap();
        assert!(!fwd.contains(SAFETY_TAG), "safety must not get a free pass through forward");
        assert!(fwd.contains("jump drop_mode"));
        safety_first(&cfg(), &text).unwrap();
    }

    #[test]
    fn audit_logs_instead_of_dropping() {
        let mut plan = Plan { devices: vec![dev(A, DevicePolicy::Normal)], inbound: vec![rdp()], ..Default::default() };
        plan.black.add("9.9.9.9");
        // Off: the drop chains are used straight away and no audit chain exists.
        let off = policy_ruleset(&cfg(), &plan);
        assert!(off.contains("jump drop_black") && !off.contains("chk_") && !off.contains("audit:"));
        // The whole network: every list block becomes a logged pass, but
        // the modes and safety rules don't.
        plan.mode = Mode::Audit;
        let all = policy_ruleset(&cfg(), &plan);
        let fwd = all.split("chain forward").nth(1).unwrap().split("
  }").next().unwrap();
        assert!(fwd.contains("jump chk_black") && !fwd.contains("jump drop_black"));
        assert!(all.contains("chain chk_black {
    goto audit_black
"));
        assert!(all.contains("log prefix \"fgw:audit:black \"") && all.contains("chain audit_black {"));
        assert!(!all.contains("chk_mode") && !all.contains("chk_lanonly"));
        safety_first(&cfg(), &all).unwrap();
        // One device: only its traffic, either way, is let through.
        plan.mode = Mode::Normal;
        plan.audit = vec![A.into()];
        let one = policy_ruleset(&cfg(), &plan);
        let chk = one.split("chain chk_black {").nth(1).unwrap().split("
  }").next().unwrap();
        assert!(chk.contains(&format!("ether saddr {{ {A} }} goto audit_black")) && chk.contains(&format!("ether daddr {{ {A} }} goto audit_black")));
        assert!(chk.trim_end().ends_with("goto drop_black"));
        // Audit on or off is a new policy version, so connections let
        // through while auditing are looked at again afterwards.
        let gen = |t: &str| t.lines().find(|l| l.contains("ct mark set 0x")).map(String::from);
        assert_ne!(gen(&off), gen(&one));
        assert_ne!(gen(&one), gen(&all));
        // Lock-down modes still drop with audit on.
        plan.mode = Mode::BlockAll;
        let blk = policy_ruleset(&cfg(), &plan);
        assert!(blk.contains("jump drop_mode"));
    }

    #[test]
    fn connections_skip_the_lists_until_the_policy_changes() {
        let mut plan = Plan { devices: vec![dev(A, DevicePolicy::Trusted)], inbound: vec![rdp()], ..Default::default() };
        plan.black.add("9.9.9.9");
        let text = policy_ruleset(&cfg(), &plan);
        let fwd = text.split("chain forward").nth(1).unwrap().split("\n  }").next().unwrap();
        assert!(!text.contains("@@GEN"));
        // Fast path before any list; remembered accepts go through `pass`.
        // (Safety hosts no longer get a forward free-pass.)
        assert!(fwd.find("ct direction original ct mark").unwrap() < fwd.find("@black4").unwrap());
        assert!(fwd.find("ct direction reply ct mark").unwrap() < fwd.find("@black4").unwrap());
        assert!(fwd.contains(&format!("ether saddr {{ {A} }} goto pass")) && fwd.trim_end().ends_with("goto pass"));
        // An accept that only holds for a connection's first packet isn't remembered.
        assert!(fwd.contains("ct state new tcp dport { 3389 } accept"));
        safety_first(&cfg(), &text).unwrap();
        // Any change to the lists is a new fingerprint.
        plan.black.add("8.8.4.4");
        let gen = |t: &str| t.lines().find(|l| l.contains("ct mark set 0x")).map(String::from);
        assert_ne!(gen(&text), gen(&policy_ruleset(&cfg(), &plan)));
        if let Ok(path) = std::env::var("FGW_DUMP_RULES") {
            std::fs::write(path, policy_ruleset(&cfg(), &plan)).unwrap();
        }
    }

    #[test]
    fn ipv6_off_drops_non_nd() {
        let plan = Plan { ipv6_enabled: false, ..Default::default() };
        let r = forward_rules(&cfg(), &plan);
        assert!(r.iter().any(|x| x.contains("meta nfproto ipv6") && x.contains("drop_mode")));
        assert!(r.iter().any(|x| x.contains("nd-neighbor-solicit")));
    }

    #[test]
    fn strict_and_dot_and_vpn_rules() {
        let plan = Plan { strict_outbound: true, block_dot: true, block_vpn: true, ..Default::default() };
        let r = forward_rules(&cfg(), &plan);
        assert!(r.iter().any(|x| x.contains("dport 853") && x.contains("drop_dot")));
        assert!(r.iter().any(|x| x.contains("51820") && x.contains("drop_vpn")));
        assert!(r.iter().any(|x| x.contains("drop_strict")));
    }

    
    #[test]
    fn dns_proxy_hook_off_by_default_and_jumps_when_on() {
        let off = forward_rules(&cfg(), &Plan::default());
        assert!(!off.iter().any(|x| x.contains("jump dns_proxy")));
        let on = forward_rules(&cfg(), &Plan { dns_proxy: true, ..Default::default() });
        assert!(on.iter().any(|x| x.contains("dport 53") && x.contains("jump dns_proxy")));
        let full = policy_ruleset(&cfg(), &Plan { dns_proxy: true, ..Default::default() });
        assert!(full.contains("chain dns_proxy"), "hook chain must exist so nft apply stays valid");
    }

#[test]
    fn ports_get_their_side() {
        let two = Config::parse("lan=eth0,eth1\nwan=eth3\nsafety=off").unwrap();
        let t = side_table(&two);
        assert!(t.contains("devices = { \"eth3\" }"));
        assert!(t.contains("devices = { \"eth0\", \"eth1\" }"));
    }

    #[test]
    fn absolute_modes_beat_trusted_white_list_and_open_ports() {
        let mut plan = Plan { devices: vec![dev(A, DevicePolicy::Trusted)], inbound: vec![rdp()], ..Default::default() };
        plan.white.add("1.1.1.1");
        for mode in [Mode::BlockAll, Mode::LanOnly] {
            plan.mode = mode;
            let r = forward_rules(&cfg(), &plan);
            let first = if mode == Mode::BlockAll { "jump drop_mode" } else { "jump drop_lanonly" };
            assert!(pos(&r, first) < pos(&r, "@white4"));
            assert!(pos(&r, first) < pos(&r, "tcp dport { 3389 } accept"));
            assert!(pos(&r, first) < pos(&r, &format!("ether saddr {{ {A} }} accept")));
        }
        plan.mode = Mode::Normal;
        assert!(!forward_rules(&cfg(), &plan).iter().any(|r| r.contains("drop_mode") || r.contains("drop_lanonly")));
    }

    #[test]
    fn dhcp_passes_before_everything() {
        let r = forward_rules(&cfg(), &Plan { mode: Mode::BlockAll, ..Default::default() });
        assert!(r[0].contains("udp dport { 67, 68 } accept"));
        assert_eq!(pos(&r, "drop_mode"), 3);
    }

    #[test]
    fn management_from_both_sides_in_every_mode() {
        for mode in [Mode::Normal, Mode::LanOnly, Mode::BlockAll] {
            let r = input_rules(&cfg(), &Plan { mode, ..Default::default() });
            assert_eq!(r[0], "tcp dport { 22, 8443 } accept");
            assert!(pos(&r, "tcp dport") < pos(&r, "drop_wan"));
        }
    }

    #[test]
    fn lan_only_allows_dns_to_the_router() {
        let r = forward_rules(&cfg(), &Plan { mode: Mode::LanOnly, ..Default::default() });
        assert!(pos(&r, "@dns4 meta l4proto { tcp, udp } th dport 53 accept") < pos(&r, "ip daddr @router4 jump drop_lanonly"));
        assert!(pos(&r, "ip daddr @router4") < pos(&r, "ip daddr != @local4"));
    }

    #[test]
    fn new_from_router_side_only_to_open_ports() {
        let mut plan = Plan { inbound: vec![rdp(), Inbound { proto: "tcp", port: 22, mac: None, on: false, lan_off: false }], ..Default::default() };
        let r = forward_rules(&cfg(), &plan);
        assert!(r.iter().any(|x| x == &format!("{FROM_WAN} ct state new tcp dport {{ 3389 }} accept")));
        assert!(pos(&r, "dport { 3389 } accept") < pos(&r, "ct state new jump drop_wan"));
        assert!(!r.iter().any(|x| x.contains("dport 22")));
        // one device keeps RDP shut, another gets SSH
        plan.inbound.push(Inbound { proto: "tcp", port: 3389, mac: Some(A.into()), on: false, lan_off: false });
        plan.inbound.push(Inbound { proto: "tcp", port: 22, mac: Some(B.into()), on: true, lan_off: false });
        let r = forward_rules(&cfg(), &plan);
        // RDP has an entry for everybody, so A's own one doesn't count.
        assert!(!r.iter().any(|x| x.contains(&format!("ether daddr {A} tcp dport 3389"))));
        // SSH has one too (shut), so B's doesn't open it either.
        assert!(!r.iter().any(|x| x.contains(&format!("ether daddr {B} tcp dport 22"))));
        plan.inbound.retain(|i| !(i.mac.is_none() && i.port == 22));
        let r = forward_rules(&cfg(), &plan);
        assert!(r.iter().any(|x| x.contains(&format!("ether daddr {B} tcp dport 22 accept"))));
        plan.inbound.clear();
        assert_eq!(inbound_rules(&plan).len(), 2);
    }

    #[test]
    fn ports_blocked_from_the_lan_side() {
        let both = Inbound { proto: "tcp", port: 445, mac: None, on: false, lan_off: true };
        let mine = Inbound { proto: "udp", port: 5000, mac: Some(A.into()), on: true, lan_off: true };
        // Global block on 445 wins over B's own allow.
        let over = Inbound { proto: "tcp", port: 445, mac: Some(B.into()), on: true, lan_off: false };
        let plan = Plan { inbound: vec![rdp(), both, mine, over], ..Default::default() };
        let r = forward_rules(&cfg(), &plan);
        assert!(r.iter().any(|x| x == &format!("{FROM_LAN} ct state new tcp dport {{ 445 }} jump drop_lanport")));
        assert!(r.iter().any(|x| x == &format!("{FROM_LAN} ct state new ether saddr {A} udp dport 5000 jump drop_lanport")));
        assert!(r.iter().any(|x| x == &format!("{FROM_LAN} ct state new ether daddr {A} udp dport 5000 jump drop_lanport")));
        assert!(r.iter().any(|x| x == &format!("{FROM_WAN} ct state new ether daddr {A} udp dport 5000 accept")));
        assert!(!r.iter().any(|x| x.contains(&format!("ether daddr {B}"))));
        assert!(!r.iter().any(|x| x.contains("dport { 3389, 445 }") || x.contains("445 } accept")));
        // The LAN side stops come before anything that could accept.
        assert!(pos(&r, "drop_lanport") < pos(&r, "ct state new jump drop_wan"));
    }

    #[test]
    fn blocked_devices_get_no_open_ports() {
        let plan = Plan { devices: vec![dev(A, DevicePolicy::Block), dev(B, DevicePolicy::LanOnly)], inbound: vec![rdp(), Inbound { proto: "tcp", port: 80, mac: Some(A.into()), on: true, lan_off: false }], ..Default::default() };
        let r = forward_rules(&cfg(), &plan);
        assert!(r.iter().any(|x| x.contains(&format!("ether daddr != {{ {A}, {B} }} tcp dport {{ 3389 }} accept"))));
        assert!(!r.iter().any(|x| x.contains("dport 80 accept")));
    }

    #[test]
    fn trusted_beats_black_list_and_countries_not_telemetry() {
        let mut plan = Plan { telemetry_all: true, devices: vec![dev(A, DevicePolicy::Trusted)], ..Default::default() };
        plan.black.add("9.9.9.0/24");
        let r = forward_rules(&cfg(), &plan);
        let trusted = pos(&r, &format!("ether saddr {{ {A} }} accept"));
        assert!(trusted < pos(&r, "@black4"));
        assert!(trusted < pos(&r, "@country4"));
        assert!(trusted < pos(&r, "@threat4"));
        assert!(pos(&r, "@telemetry4") < trusted);
    }

    #[test]
    fn device_lists_and_policies_ordered() {
        let mut d = dev(A, DevicePolicy::Block);
        let mut n = Nets::default();
        n.add("8.8.8.8");
        d.allow.push(Match::Nets(n));
        d.deny.push(Match::Port("tcp", 23));
        let plan = Plan { devices: vec![d, dev(B, DevicePolicy::LanOnly)], ..Default::default() };
        let r = forward_rules(&cfg(), &plan);
        assert!(pos(&r, "tcp dport 23 jump drop_devdeny") < pos(&r, "ip daddr { 8.8.8.8 } accept"));
        assert!(pos(&r, "ip daddr { 8.8.8.8 } accept") < pos(&r, "drop_devblock"));
        assert!(r.iter().any(|x| x == &format!("ether saddr {{ {B} }} ip daddr != @local4 jump drop_devlan")));
    }

    #[test]
    fn lan_only_page_keeps_ssh_on_both_sides() {
        let c = Config::parse("lan=eth3\nwan=eth2\nsafety_hosts=10.10.10.42\nadmin_from=lan").unwrap();
        let r = input_rules(&c, &Plan::default()).join("\n");
        assert!(r.starts_with("tcp dport 22 accept\nmeta mark 0x00466720 tcp dport 8443 accept"));
        assert!(c.to_text().contains("admin_from = lan"));
    }

    #[test]
    fn safety_hosts_ipv6_on_input() {
        let c = Config::parse("lan=eth3\nwan=eth2\nsafety_hosts=10.10.10.42,2001:db8::1\nsafety_ports=22,8443").unwrap();
        let plan = Plan::default();
        let text = policy_ruleset(&c, &plan);
        assert!(text.contains("ip6 saddr"), "{text}");
        assert!(text.contains("2001:db8::1"), "{text}");
        assert!(text.contains(SAFETY_TAG));
    }

    #[test]
    fn lan_only_allows_dns6() {
        let r = lan_only("", "", "jump drop_lanonly");
        assert!(r.iter().any(|x| x.contains("@dns6") && x.contains("dport 53")));
        assert!(r.iter().any(|x| x.contains("@router6")));
    }

    #[test]
    fn local_includes_ula() {
        let c = Config::parse("lan=eth3\nwan=eth2\nsafety_hosts=10.10.10.42").unwrap();
        let plan = Plan::default();
        let text = policy_ruleset(&c, &plan);
        assert!(text.contains("fc00::/7"), "{text}");
    }


    #[test]
    fn rule_ahead_of_safety_is_caught() {
        let listed = "table inet foilgateway {\n chain input {\n type filter hook input priority filter; policy accept;\n drop # handle 9\n ip saddr 10.10.10.42 tcp dport { 22, 8443 } accept comment \"foilgw-safety\" # handle 2\n }\n}";
        assert!(safety_first(&cfg(), listed).is_err());
    }
}
