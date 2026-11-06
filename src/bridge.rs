//! Bridge mode: the WAN port and the LAN ports become members of one
//! bridge, br-fgw. The router keeps handing out addresses and answering
//! DNS for everything behind us; the gateway itself gets its address on
//! the bridge, by DHCP like any other device.
//!
//! What the member ports had before is written to bridge.json, so an
//! unconfirmed setup (or `foilgw rollback`) puts them back as they were.
//!
//! When systemd-networkd looks after the ports (Armbian's netplan does
//! DHCP on every eth*), we don't build the bridge behind its back: it would
//! keep configuring the members. networkd builds it from our own files
//! instead. They go in /run until the change is confirmed, so a reboot
//! before then is an undo too, and move to /etc once it is.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::{Command, Stdio};

pub const NAME: &str = "br-fgw";

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Saved {
    /// port -> addresses ("ip/len") it had, minus the ones setup put there.
    pub addrs: Vec<(String, Vec<String>)>,
    /// port -> default route gateway it had.
    pub routes: Vec<(String, String)>,
    /// networkd built the bridge from our files.
    #[serde(default)]
    pub networkd: bool,
    /// Ports we told NetworkManager to leave alone.
    #[serde(default)]
    pub nm: Vec<String>,
}

fn ip(args: &[&str]) -> Result<(), String> {
    let out = Command::new("ip").args(args).stdout(Stdio::null()).stderr(Stdio::piped()).output().map_err(|e| format!("can't run ip: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn ip_json(args: &[&str]) -> Vec<Value> {
    Command::new("ip").args(args).output().ok().and_then(|o| serde_json::from_slice(&o.stdout).ok()).unwrap_or_default()
}

fn path(dir: &str) -> String {
    format!("{dir}/bridge.json")
}

pub fn exists() -> bool {
    std::path::Path::new(&format!("/sys/class/net/{NAME}/bridge")).exists()
}

/// Ports currently in the bridge.
pub fn members() -> Vec<String> {
    let Ok(dir) = std::fs::read_dir(format!("/sys/class/net/{NAME}/brif")) else { return vec![] };
    let mut out: Vec<String> = dir.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    out.sort();
    out
}

/// Bridged IPv4 and IPv6 go through the inet rules only with br_netfilter.
fn filtering_on() -> Result<(), String> {
    let _ = Command::new("modprobe").arg("br_netfilter").stdout(Stdio::null()).stderr(Stdio::null()).status();
    for f in ["bridge-nf-call-iptables", "bridge-nf-call-ip6tables"] {
        std::fs::write(format!("/proc/sys/net/bridge/{f}"), "1").map_err(|_| "the kernel has no br_netfilter, so bridged traffic can't be filtered".to_string())?;
    }
    Ok(())
}

/// Builds the bridge from `wan` and `lan`. Addresses in `ours` were put
/// there by setup and aren't saved; everything else on a member is saved
/// and taken off (a bridge member can't have its own addresses).
pub fn up(dir: &str, wan: &str, lan: &[String], ours: &[String]) -> Result<(), String> {
    filtering_on()?;
    let ports: Vec<String> = std::iter::once(wan.to_string()).chain(lan.iter().cloned()).collect();
    if !exists() && ports.iter().any(|p| networkd_manages(p)) {
        let saved = Saved { networkd: true, ..Default::default() };
        std::fs::write(path(dir), serde_json::to_string_pretty(&saved).unwrap_or_default()).map_err(|e| format!("can't save the port state: {e}"))?;
        return networkd_up(wan, lan);
    }
    if !exists() {
        let mut saved = Saved::default();
        for p in &ports {
            let addrs: Vec<String> = ip_json(&["-j", "addr", "show", "dev", p])
                .iter()
                .flat_map(|a| a["addr_info"].as_array().cloned().unwrap_or_default())
                .filter(|i| i["scope"] == "global")
                .filter_map(|i| Some(format!("{}/{}", i["local"].as_str()?, i["prefixlen"])))
                .filter(|c| !ours.contains(c))
                .collect();
            saved.addrs.push((p.clone(), addrs));
            for r in ip_json(&["-j", "-4", "route", "show", "default", "dev", p]) {
                if let Some(g) = r["gateway"].as_str() {
                    saved.routes.push((p.clone(), g.to_string()));
                }
            }
        }
        // NetworkManager would take the members' addresses back otherwise.
        for p in ports.iter().filter(|p| nm_manages(p)) {
            nmcli_managed(p, false);
            saved.nm.push(p.clone());
        }
        std::fs::write(path(dir), serde_json::to_string_pretty(&saved).unwrap_or_default()).map_err(|e| format!("can't save the port state: {e}"))?;
        // Same MAC as the WAN port, so the router hands us the same lease.
        let mac = std::fs::read_to_string(format!("/sys/class/net/{wan}/address")).unwrap_or_default();
        ip(&["link", "add", NAME, "type", "bridge", "stp_state", "0", "forward_delay", "0"])?;
        if !mac.trim().is_empty() {
            let _ = ip(&["link", "set", NAME, "address", mac.trim()]);
        }
    }
    for p in &ports {
        if !members().contains(p) {
            let _ = ip(&["addr", "flush", "dev", p, "scope", "global"]);
            let _ = ip(&["addr", "flush", "dev", p, "scope", "link"]);
            ip(&["link", "set", p, "master", NAME])?;
        }
        let _ = ip(&["link", "set", p, "up"]);
    }
    ip(&["link", "set", NAME, "up"])
}

/// Takes the bridge apart and gives the ports back what they had.
pub fn down(dir: &str) -> Result<(), String> {
    let saved: Saved = std::fs::read_to_string(path(dir)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let had: Vec<String> = members();
    if saved.networkd || networkd_files().iter().any(|f| std::path::Path::new(f).exists()) {
        for f in networkd_files() {
            let _ = std::fs::remove_file(f);
        }
        networkctl(&["reload"]);
        // networkd doesn't delete a bridge whose file went away.
        if exists() {
            let _ = ip(&["link", "del", NAME]);
        }
        // The ports go back to whatever networkd's other files say.
        if !had.is_empty() {
            let mut again = vec!["reconfigure"];
            again.extend(had.iter().map(String::as_str));
            networkctl(&again);
        }
        let _ = std::fs::remove_file(path(dir));
        return Ok(());
    }
    for p in &had {
        let _ = ip(&["link", "set", p, "nomaster"]);
    }
    if exists() {
        ip(&["link", "del", NAME])?;
    }
    for (p, addrs) in &saved.addrs {
        // Brings back the port's own IPv6 link address without dropping
        // the link, which would make devices on it ask DHCP again.
        let v6 = format!("/proc/sys/net/ipv6/conf/{p}/disable_ipv6");
        let _ = std::fs::write(&v6, "1");
        let _ = std::fs::write(&v6, "0");
        for a in addrs {
            let _ = ip(&["addr", "replace", a, "dev", p]);
        }
    }
    for (p, g) in &saved.routes {
        let _ = ip(&["route", "replace", "default", "via", g, "dev", p]);
    }
    for p in &saved.nm {
        nmcli_managed(p, true);
    }
    let _ = std::fs::remove_file(nm_conf());
    let _ = std::fs::remove_file(path(dir));
    Ok(())
}

/// Which member port a MAC was last seen on, from the bridge's own table.
pub fn port_of_mac(mac: &str) -> Option<String> {
    let mac = mac.to_ascii_lowercase();
    ip_json_bridge(&["-j", "fdb", "show", "br", NAME]).iter().find(|e| e["mac"].as_str().is_some_and(|m| m.eq_ignore_ascii_case(&mac)) && e["flags"].as_array().is_none_or(|f| !f.iter().any(|x| x == "self"))).and_then(|e| e["ifname"].as_str().map(String::from))
}

fn ip_json_bridge(args: &[&str]) -> Vec<Value> {
    Command::new("bridge").args(args).output().ok().and_then(|o| serde_json::from_slice(&o.stdout).ok()).unwrap_or_default()
}

fn flag(dir: &str) -> String {
    format!("{dir}/bridge-pending")
}

/// The bridge was built by a change that isn't confirmed yet: an undo takes it apart.
pub fn mark_pending(dir: &str) {
    let _ = std::fs::write(flag(dir), "");
}

pub fn clear_pending(dir: &str) {
    let _ = std::fs::remove_file(flag(dir));
}

pub fn pending(dir: &str) -> bool {
    std::path::Path::new(&flag(dir)).exists()
}

/// MACs the bridge has learned on these ports (not its own).
pub fn macs_on(ports: &[String]) -> Vec<String> {
    let mut out: Vec<String> = ip_json_bridge(&["-j", "fdb", "show", "br", NAME])
        .iter()
        .filter(|e| e["state"].as_str() != Some("permanent") && e["flags"].as_array().is_none_or(|f| !f.iter().any(|x| x == "self")))
        .filter(|e| e["ifname"].as_str().is_some_and(|i| ports.iter().any(|p| p == i)))
        .filter_map(|e| crate::policy::normal_mac(e["mac"].as_str()?))
        .filter(|m| !m.starts_with("33:33") && !m.starts_with("01:"))
        .collect();
    out.sort();
    out.dedup();
    out
}

fn prev_path(dir: &str) -> String {
    format!("{dir}/bridge-prev.json")
}

/// Changes which ports are in the bridge after setup. The old set is kept
/// until the change is confirmed, so an undo can put it back.
pub fn reshape(dir: &str, wan: &str, lan: &[String]) -> Result<(), String> {
    let want: Vec<String> = std::iter::once(wan.to_string()).chain(lan.iter().cloned()).collect();
    let had = members();
    if !std::path::Path::new(&prev_path(dir)).exists() {
        let _ = std::fs::write(prev_path(dir), serde_json::to_string(&had).unwrap_or_default());
    }
    set_members(&had, &want)
}

fn set_members(had: &[String], want: &[String]) -> Result<(), String> {
    for p in had.iter().filter(|p| !want.contains(p)) {
        let _ = ip(&["link", "set", p, "nomaster"]);
    }
    for p in want.iter().filter(|p| !had.contains(p)) {
        let _ = ip(&["addr", "flush", "dev", p, "scope", "global"]);
        ip(&["link", "set", p, "master", NAME])?;
        let _ = ip(&["link", "set", p, "up"]);
    }
    Ok(())
}

/// Undo of `reshape`.
pub fn unshape(dir: &str) {
    if let Some(old) = std::fs::read_to_string(prev_path(dir)).ok().and_then(|t| serde_json::from_str::<Vec<String>>(&t).ok()) {
        if exists() {
            let _ = set_members(&members(), &old);
        }
    }
    let _ = std::fs::remove_file(prev_path(dir));
}

pub fn keep_shape(dir: &str) {
    let _ = std::fs::remove_file(prev_path(dir));
}

const RUN_NET: &str = "/run/systemd/network";
const ETC_NET: &str = "/etc/systemd/network";
/// Sorts ahead of netplan's 10-*, and networkd uses the first file that matches.
const FILES: [&str; 3] = ["05-foilgw-bridge.netdev", "05-foilgw-bridge.network", "05-foilgw-ports.network"];

fn networkd_files() -> Vec<String> {
    [RUN_NET, ETC_NET].iter().flat_map(|d| FILES.iter().map(move |f| format!("{d}/{f}"))).collect()
}

fn networkctl(args: &[&str]) -> bool {
    Command::new("networkctl").args(args).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

fn listed(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd).args(args).stderr(Stdio::null()).output().ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

pub fn networkd_manages(port: &str) -> bool {
    listed("networkctl", &["list", "--no-legend", "--no-pager"]).lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.get(1) == Some(&port) && f.get(4).is_some_and(|s| *s != "unmanaged" && *s != "unlinked")
    })
}

pub fn nm_manages(port: &str) -> bool {
    listed("nmcli", &["-t", "-f", "DEVICE,STATE", "device"]).lines().any(|l| l.split_once(':').is_some_and(|(d, s)| d == port && !s.starts_with("unmanaged")))
}

fn nmcli_managed(port: &str, on: bool) {
    let _ = Command::new("nmcli").args(["device", "set", port, "managed", if on { "yes" } else { "no" }]).stdout(Stdio::null()).stderr(Stdio::null()).status();
}

fn nm_conf() -> String {
    "/etc/NetworkManager/conf.d/90-foilgw.conf".into()
}

/// The DHCP client id networkd used on the WAN port, from its lease file:
/// 01 + MAC, or ff + IAID + DUID. The bridge asks with the same one, so
/// the router hands it the address the WAN port had.
fn wan_client_id(wan: &str) -> Option<String> {
    let idx = std::fs::read_to_string(format!("/sys/class/net/{wan}/ifindex")).ok()?;
    let lease = std::fs::read_to_string(format!("/run/systemd/netif/leases/{}", idx.trim())).ok()?;
    lease.lines().find_map(|l| l.strip_prefix("CLIENTID=")).map(|c| c.trim().to_ascii_lowercase())
}

/// What goes in the bridge's [DHCPv4] section for that client id.
pub fn dhcp_section(client_id: Option<&str>) -> String {
    match client_id {
        Some(c) if c.starts_with("ff") && c.len() >= 10 => match u32::from_str_radix(&c[2..10], 16) {
            Ok(iaid) => format!("ClientIdentifier=duid\nIAID={iaid}\n"),
            Err(_) => "ClientIdentifier=mac\n".into(),
        },
        _ => "ClientIdentifier=mac\n".into(),
    }
}

/// A fixed address for the bridge, when the owner set one. Read when
/// networkd's files are written.
pub static FIXED: std::sync::Mutex<Option<crate::config::Fixed>> = std::sync::Mutex::new(None);

/// The bridge's own .network: DHCP (with the client id the WAN port used)
/// or the fixed address.
pub fn bridge_network(dhcp: &str, fixed: Option<&crate::config::Fixed>) -> String {
    let head = format!("[Match]\nName={NAME}\n\n[Network]\n");
    let common = "LinkLocalAddressing=ipv6\nIPv6AcceptRA=yes\nConfigureWithoutCarrier=yes\n";
    match fixed {
        None => format!("{head}DHCP=yes\n{common}\n[DHCPv4]\n{dhcp}RouteMetric=100\nUseMTU=yes\n"),
        Some(f) => {
            let gw = f.gateway.map(|g| format!("Gateway={g}\n")).unwrap_or_default();
            let dns: String = f.dns.iter().map(|d| format!("DNS={d}\n")).collect();
            // The DHCP client id stays in the file for going back to DHCP.
            let keep: String = dhcp.lines().map(|l| format!("# {l}\n")).collect();
            format!("{head}DHCP=no\nAddress={}\n{gw}{dns}{common}\n{keep}", f.cidr())
        }
    }
}

/// The client id lines from the bridge's current .network, so a change of
/// address keeps asking the router the same way.
fn current_dhcp() -> Option<String> {
    let f = FILES[1];
    let t = std::fs::read_to_string(format!("{RUN_NET}/{f}")).or_else(|_| std::fs::read_to_string(format!("{ETC_NET}/{f}"))).ok()?;
    let lines: String = t.lines().map(|l| l.trim_start_matches("# ")).filter(|l| l.starts_with("ClientIdentifier=") || l.starts_with("IAID=")).map(|l| format!("{l}\n")).collect();
    (!lines.is_empty()).then_some(lines)
}

/// Gives a networkd-built bridge a new address setting. The file goes in
/// /run, ahead of the confirmed one in /etc, until the change is kept.
/// False when networkd doesn't own the bridge.
pub fn networkd_address(fixed: Option<&crate::config::Fixed>) -> Result<bool, String> {
    if !networkd_owned() {
        return Ok(false);
    }
    let dhcp = current_dhcp().unwrap_or_else(|| dhcp_section(None));
    std::fs::create_dir_all(RUN_NET).map_err(|e| format!("can't write networkd files: {e}"))?;
    std::fs::write(format!("{RUN_NET}/{}", FILES[1]), bridge_network(&dhcp, fixed)).map_err(|e| format!("can't write networkd files: {e}"))?;
    networkctl(&["reload"]);
    networkctl(&["reconfigure", NAME]);
    Ok(true)
}

pub fn networkd_text(wan: &str, lan: &[String], mac: &str, client_id: Option<&str>) -> [String; 3] {
    let mac = if mac.is_empty() { String::new() } else { format!("MACAddress={mac}\n") };
    let ports: Vec<&str> = std::iter::once(wan).chain(lan.iter().map(String::as_str)).collect();
    [
        format!("# FoilGateway bridge mode.\n[NetDev]\nName={NAME}\nKind=bridge\n{mac}\n[Bridge]\nSTP=no\nForwardDelaySec=0\n"),
        bridge_network(&dhcp_section(client_id), FIXED.lock().unwrap().as_ref()),
        format!("[Match]\nName={}\n\n[Network]\nBridge={NAME}\nLinkLocalAddressing=no\nDHCP=no\nIPv6AcceptRA=no\n", ports.join(" ")),
    ]
}

fn networkd_up(wan: &str, lan: &[String]) -> Result<(), String> {
    let mac = std::fs::read_to_string(format!("/sys/class/net/{wan}/address")).unwrap_or_default();
    let text = networkd_text(wan, lan, mac.trim(), wan_client_id(wan).as_deref());
    std::fs::create_dir_all(RUN_NET).map_err(|e| format!("can't write networkd files: {e}"))?;
    for (f, t) in FILES.iter().zip(text.iter()) {
        std::fs::write(format!("{RUN_NET}/{f}"), t).map_err(|e| format!("can't write networkd files: {e}"))?;
    }
    if !networkctl(&["reload"]) {
        return Err("networkctl reload failed".into());
    }
    let ports: Vec<String> = std::iter::once(wan.to_string()).chain(lan.iter().cloned()).collect();
    let mut again = vec!["reconfigure"];
    again.extend(ports.iter().map(String::as_str));
    networkctl(&again);
    for _ in 0..50 {
        let m = members();
        if ports.iter().all(|p| m.contains(p)) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Err(format!("networkd didn't put {} in {NAME}", ports.join(", ")))
}

/// The bridge is confirmed: networkd's files move to /etc so it comes back
/// after a reboot, and NetworkManager is told to leave the ports alone for good.
pub fn persist(dir: &str) {
    let saved: Saved = std::fs::read_to_string(path(dir)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    for f in FILES {
        let from = format!("{RUN_NET}/{f}");
        if let Ok(t) = std::fs::read_to_string(&from) {
            let _ = std::fs::create_dir_all(ETC_NET);
            if std::fs::write(format!("{ETC_NET}/{f}"), t).is_ok() {
                let _ = std::fs::remove_file(&from);
            }
        }
    }
    if !saved.nm.is_empty() {
        let mut names: Vec<String> = saved.nm.iter().map(|p| format!("interface-name:{p}")).collect();
        names.push(format!("interface-name:{NAME}"));
        let _ = std::fs::write(nm_conf(), format!("# FoilGateway bridge mode.\n[keyfile]\nunmanaged-devices={}\n", names.join(";")));
    }
}

/// networkd builds this bridge itself, at boot too.
pub fn networkd_owned() -> bool {
    networkd_files().iter().any(|f| std::path::Path::new(f).exists())
}

/// Turns br_netfilter on, which a reboot loses.
pub fn filtering() -> Result<(), String> {
    filtering_on()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_asks_with_the_wan_ports_client_id() {
        assert_eq!(dhcp_section(Some("ffebb18c4900020000ab11acdbe9ec0cbafbfd")), "ClientIdentifier=duid\nIAID=3954281545\n");
        assert_eq!(dhcp_section(Some("0162f884709c72")), "ClientIdentifier=mac\n");
        assert_eq!(dhcp_section(None), "ClientIdentifier=mac\n");
    }

    #[test]
    fn networkd_files_name_the_ports() {
        let t = networkd_text("eth3", &["eth2".into()], "aa:bb:cc:dd:ee:ff", None);
        assert!(t[0].contains("MACAddress=aa:bb:cc:dd:ee:ff"));
        assert!(t[2].contains("Name=eth3 eth2") && t[2].contains("Bridge=br-fgw"));
    }

    #[test]
    fn fixed_address_keeps_the_client_id() {
        let f = crate::config::Fixed { ip: "10.10.10.5".parse().unwrap(), prefix: 24, gateway: Some("10.10.10.1".parse().unwrap()), dns: vec!["9.9.9.9".parse().unwrap()] };
        let t = bridge_network("ClientIdentifier=duid\nIAID=7\n", Some(&f));
        assert!(t.contains("DHCP=no\nAddress=10.10.10.5/24\nGateway=10.10.10.1\nDNS=9.9.9.9\n"));
        assert!(t.contains("# IAID=7"));
        assert!(bridge_network("ClientIdentifier=mac\n", None).contains("DHCP=yes"));
    }
}
