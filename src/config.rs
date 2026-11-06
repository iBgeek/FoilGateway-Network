use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};

pub const PATH: &str = "/etc/foilgateway/gateway.conf";

/// How the gateway sits in the network. Only bridge mode exists so far:
/// the gateway is a filtering switch between the router and the LAN.
/// Router mode (own subnet, DHCP, NAT) is planned and gets its own arm
/// wherever this is matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetMode {
    #[default]
    Bridge,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub mode: NetMode,
    /// Where the bridge sits in the cable path (not Router mode).
    pub placement: crate::presets::Placement,
    /// One or more LAN ports: bridge members toward the switch or wifi.
    pub lan: Vec<String>,
    pub wan: String,
    pub safety: bool,
    pub safety_hosts: Vec<IpAddr>,
    pub safety_ports: Vec<u16>,
    pub rollback_secs: u64,
    pub admin_port: u16,
    /// The settings page answers from the router side too, unless this is off.
    /// SSH and the safety computers aren't affected.
    pub admin_from_wan: bool,
    /// The gateway's own address on the bridge. None: DHCP from the router.
    pub fixed: Option<Fixed>,
}

/// A fixed address for the gateway instead of DHCP.
#[derive(Clone, Debug, PartialEq)]
pub struct Fixed {
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

impl Fixed {
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.ip, self.prefix)
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("can't read {path}: {e}"))?;
        Config::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let mut kv = HashMap::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap().trim();
            if line.is_empty() {
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or(format!("line {}: expected name = value", n + 1))?;
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
        let get = |k: &str| kv.get(k).cloned().unwrap_or_default();
        let list = |k: &str| get(k).split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>();
        let iface = |k: &str, v: String| -> Result<String, String> {
            if v.is_empty() || v.len() > 15 || !v.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_') {
                return Err(format!("{k}: not a valid interface name"));
            }
            Ok(v)
        };

        let safety = match get("safety").as_str() {
            "on" | "" => true,
            "off" => false,
            v => return Err(format!("safety: expected on or off, got {v}")),
        };
        let safety_hosts = list("safety_hosts")
            .iter()
            .map(|s| s.parse::<IpAddr>().map_err(|_| format!("safety_hosts: {s} is not an IP address")))
            .collect::<Result<Vec<IpAddr>, String>>()?;
        if safety && safety_hosts.is_empty() {
            return Err("safety is on but safety_hosts is empty".into());
        }
        let mut safety_ports = list("safety_ports")
            .iter()
            .map(|s| s.parse().map_err(|_| format!("safety_ports: {s} is not a port")))
            .collect::<Result<Vec<u16>, String>>()?;
        if !safety_ports.contains(&22) {
            safety_ports.insert(0, 22);
        }
        let rollback_secs = match get("rollback_secs").as_str() {
            "" => 180,
            v => v.parse().map_err(|_| format!("rollback_secs: {v} is not a number"))?,
        };
        let admin_port = match get("admin_port").as_str() {
            "" => 8443,
            v => v.parse().ok().filter(|p| *p > 0).ok_or(format!("admin_port: {v} is not a port"))?,
        };
        // The settings page has to stay reachable for the safety hosts too.
        if !safety_ports.contains(&admin_port) {
            safety_ports.push(admin_port);
        }
        let admin_from_wan = match get("admin_from").as_str() {
            "" | "both" => true,
            "lan" => false,
            v => return Err(format!("admin_from: expected both or lan, got {v}")),
        };
        let mode = match get("mode").as_str() {
            "" | "bridge" => NetMode::Bridge,
            "router" => return Err("mode: router mode isn't available yet, use mode = bridge".into()),
            v => return Err(format!("mode: expected bridge, got {v}")),
        };
        let placement = match get("placement").as_str() {
            "" => crate::presets::Placement::RouterSwitch,
            v => crate::presets::Placement::parse(v).ok_or_else(|| {
                format!("placement: expected internet_switch or router_switch, got {v}")
            })?,
        };
        let wan = iface("wan", get("wan"))?;
        let mut lan = Vec::new();
        for l in list("lan") {
            let l = iface("lan", l)?;
            if l == wan {
                return Err(format!("{l} can't be both LAN and WAN"));
            }
            if !lan.contains(&l) {
                lan.push(l);
            }
        }
        if lan.is_empty() {
            return Err("lan: not a valid interface name".into());
        }
        let fixed = match get("address").as_str() {
            "" | "dhcp" => None,
            v => {
                let (ip, prefix) = v.split_once('/').ok_or(format!("address: expected dhcp or an address like 10.10.10.5/24, got {v}"))?;
                let ip: Ipv4Addr = ip.parse().map_err(|_| format!("address: {ip} is not an IPv4 address"))?;
                let prefix: u8 = prefix.parse().ok().filter(|p| (1..=32).contains(p)).ok_or(format!("address: /{prefix} is not a network size"))?;
                let gateway = match get("gateway").as_str() {
                    "" => None,
                    g => Some(g.parse().map_err(|_| format!("gateway: {g} is not an IPv4 address"))?),
                };
                let mut dns = Vec::new();
                for d in list("dns") {
                    dns.push(d.parse().map_err(|_| format!("dns: {d} is not an IPv4 address"))?);
                }
                Some(Fixed { ip, prefix, gateway, dns })
            }
        };
        Ok(Config { mode, placement, lan, wan, safety, safety_hosts, safety_ports, rollback_secs, admin_port, admin_from_wan, fixed })
    }

    /// The file as written by setup and the settings page.
    pub fn to_text(&self) -> String {
        let join = |v: Vec<String>| v.join(", ");
        format!(
            "# FoilGateway network edition settings. Written by the settings page;\n# hand edits are fine, then run `foilgw apply`.\n\n# bridge: the gateway sits between two network sides.\nmode = bridge\n# Where the box sits: internet_switch or router_switch (not Router mode).\nplacement = {}\n# wan goes toward the internet/router side, lan toward the switch or wifi.\nlan = {}\nwan = {}\n\n# While on, these computers can always reach the gateway (settings page and SSH),\n# never a free pass to the internet.\nsafety = {}\nsafety_hosts = {}\nsafety_ports = {}\n\nadmin_port = {}\n# both: the settings page answers from the router side too. lan: only from\n# your devices (SSH and the safety computers still work from both).\nadmin_from = {}\nrollback_secs = {}\n\n# The gateway's own address: dhcp, or fixed with gateway and dns.\naddress = {}\n{}",
            self.placement.conf_value(),
            self.lan.join(", "),
            self.wan,
            if self.safety { "on" } else { "off" },
            join(self.safety_hosts.iter().map(|h| h.to_string()).collect()),
            join(self.safety_ports.iter().map(|p| p.to_string()).collect()),
            self.admin_port,
            if self.admin_from_wan { "both" } else { "lan" },
            self.rollback_secs,
            self.fixed.as_ref().map(|f| f.cidr()).unwrap_or("dhcp".into()),
            self.fixed.as_ref().map(|f| format!("gateway = {}\ndns = {}\n", f.gateway.map(|g| g.to_string()).unwrap_or_default(), join(f.dns.iter().map(|d| d.to_string()).collect()))).unwrap_or_default()
        )
    }

    pub fn is_lan(&self, port: &str) -> bool {
        self.lan.iter().any(|l| l == port)
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let text = self.to_text();
        // Never write something we can't read back.
        Config::parse(&text)?;
        if let Some(dir) = std::path::Path::new(path).parent() {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let tmp = format!("{path}.new");
        fs::write(&tmp, text).and_then(|_| fs::rename(&tmp, path)).map_err(|e| format!("can't write {path}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_parses() {
        let c = Config::parse(include_str!("../gateway.conf.example")).unwrap();
        assert_eq!(c.lan, vec!["eth3".to_string()]);
        assert!(c.safety);
        assert_eq!(c.safety_hosts, vec![IpAddr::V4(Ipv4Addr::new(10, 10, 10, 42))]);
        assert_eq!(c.safety_ports, vec![22, 8443]);
    }

    #[test]
    fn safety_hosts_accept_ipv6() {
        let c = Config::parse("lan=eth3\nwan=eth2\nsafety_hosts=10.10.10.42, 2001:db8::1\nsafety_ports=22,8443").unwrap();
        assert_eq!(c.safety_hosts.len(), 2);
        assert!(c.safety_hosts.iter().any(|h| h.is_ipv6()));
        assert!(c.to_text().contains("2001:db8::1"));
    }

    #[test]
    fn ssh_is_always_kept() {
        let c = Config::parse("lan=eth3\nwan=eth2\nsafety_hosts=10.0.0.5\nsafety_ports=8443").unwrap();
        assert_eq!(c.safety_ports, vec![22, 8443]);
    }

    #[test]
    fn safety_needs_a_host() {
        assert!(Config::parse("lan=eth3\nwan=eth2\nsafety=on").is_err());
    }

    #[test]
    fn admin_port_is_kept_open() {
        let c = Config::parse("lan=eth3\nwan=eth2\nsafety_hosts=10.0.0.5\nadmin_port=9443").unwrap();
        assert_eq!(c.admin_port, 9443);
        assert_eq!(c.safety_ports, vec![22, 9443]);
    }

    #[test]
    fn written_file_reads_back_the_same() {
        let c = Config::parse("lan=eth3\nwan=eth2\nsafety_hosts=10.0.0.5, 10.0.0.6\nrollback_secs=60").unwrap();
        assert_eq!(Config::parse(&c.to_text()).unwrap(), c);
    }

    #[test]
    fn bad_port_rejected() {
        assert!(Config::parse("lan=eth3\nwan=eth2\nsafety=off\nadmin_port=0").is_err());
        assert!(Config::parse("lan=eth3\nwan=eth2\nsafety=off\nadmin_port=99999").is_err());
    }

    #[test]
    fn several_lan_ports() {
        let c = Config::parse("lan=eth0, eth1\nwan=eth3\nsafety=off").unwrap();
        assert_eq!(c.lan, vec!["eth0".to_string(), "eth1".to_string()]);
        assert_eq!(Config::parse(&c.to_text()).unwrap(), c);
        assert!(Config::parse("lan=eth0, eth3\nwan=eth3\nsafety=off").is_err());
    }

    #[test]
    fn placement_round_trips() {
        let c = Config::parse("lan=eth3\nwan=eth2\nsafety=off\nplacement=internet_switch").unwrap();
        assert_eq!(c.placement, crate::presets::Placement::InternetSwitch);
        assert_eq!(Config::parse(&c.to_text()).unwrap().placement, crate::presets::Placement::InternetSwitch);
        let d = Config::parse("lan=eth3\nwan=eth2\nsafety=off").unwrap();
        assert_eq!(d.placement, crate::presets::Placement::RouterSwitch);
        assert!(Config::parse("lan=eth3\nwan=eth2\nsafety=off\nplacement=router_mode").is_err());
    }

    #[test]
    fn router_mode_not_yet() {
        assert!(Config::parse("mode=router\nlan=eth3\nwan=eth2\nsafety=off").is_err());
        assert_eq!(Config::parse("mode=bridge\nlan=eth3\nwan=eth2\nsafety=off").unwrap().mode, NetMode::Bridge);
    }

    #[test]
    fn bad_interface_rejected() {
        assert!(Config::parse("lan=eth3; flush ruleset\nwan=eth2\nsafety=off").is_err());
    }
}

#[cfg(test)]
mod fixed_tests {
    use super::*;

    #[test]
    fn fixed_address_round_trips() {
        let c = Config::parse("lan=eth2\nwan=eth3\nsafety=off\naddress=10.10.10.5/24\ngateway=10.10.10.1\ndns=10.10.10.1, 9.9.9.9").unwrap();
        let f = c.fixed.clone().unwrap();
        assert_eq!((f.cidr(), f.gateway, f.dns.len()), ("10.10.10.5/24".into(), Some(Ipv4Addr::new(10, 10, 10, 1)), 2));
        assert_eq!(Config::parse(&c.to_text()).unwrap(), c);
        assert!(Config::parse("lan=eth2\nwan=eth3\nsafety=off\naddress=10.10.10.5").is_err());
        assert_eq!(Config::parse("lan=eth2\nwan=eth3\nsafety=off").unwrap().fixed, None);
    }
}
