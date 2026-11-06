//! Named protection bundles. Owner can fine-tune any toggle after Apply.
//! UI labels are Title Case exactly as shown in the UI.
//!
//! 0.7.2: named levels are Normal · FortNox only. Custom is the chip when
//! settings drift. Legacy "home_user" / Office / Lab in saved policy map to
//! Normal (same former Home User bundle).

use crate::policy::Policy;
use crate::rules::Mode;
use serde::{Deserialize, Serialize};

/// Named levels shown in Protection Levels. Serde ids stay snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    /// Everyday protection (former Home User).
    #[serde(alias = "home_user")]
    Normal,
    FortNox,
}

impl Preset {
    pub const ALL: [Preset; 2] = [Preset::Normal, Preset::FortNox];

    /// Exact UI label (Title Case as shown in the UI).
    pub fn label(self) -> &'static str {
        match self {
            Preset::Normal => "Normal",
            Preset::FortNox => "FortNox",
        }
    }

    pub fn one_line(self) -> &'static str {
        match self {
            Preset::Normal => "Everyday protection without locking the house down.",
            Preset::FortNox => "Strongest recommended bundle; some devices may need Allow.",
        }
    }

    pub fn parse(s: &str) -> Option<Preset> {
        match s {
            // Current ids + legacy Home User names.
            "normal" | "Normal" | "home_user" | "Home User" | "HomeUser" => Some(Preset::Normal),
            // Retired Office / Lab used the same bundle as Home User; treat as Normal.
            "office" | "Office" | "lab" | "Lab" => Some(Preset::Normal),
            "fortnox" | "FortNox" | "fort_nox" => Some(Preset::FortNox),
            _ => None,
        }
    }

    /// Bundle values this preset wants. Does not change Audit/Normal mode
    /// except Leave-Audit → Normal forces Normal mode.
    pub fn bundle(self) -> Bundle {
        match self {
            Preset::Normal => Bundle {
                mode: Mode::Normal,
                threats: true,
                telemetry_all: false,
                block_dot: false,
                strict_outbound: false,
                block_vpn: false,
                block_ipv6: false,
                prefer_admin_lan: true,
                white_expiry: true,
                rdp_block_lan: false, // External blocked; LAN Remote Desktop still works
            },
            Preset::FortNox => Bundle {
                mode: Mode::Normal,
                threats: true,
                telemetry_all: true,
                block_dot: true,
                strict_outbound: true,
                block_vpn: false, // VPN block OFF inside FortNox
                block_ipv6: false,
                prefer_admin_lan: true,
                white_expiry: true,
                rdp_block_lan: true, // FortNox: block 3389 on the home network too
            },
        }
    }

    /// Apply this preset onto a policy. RDP stays off (new default). Mode
    /// becomes Normal when leaving Audit via Normal.
    pub fn apply(self, pol: &mut Policy) {
        let b = self.bundle();
        pol.mode = b.mode;
        pol.threats = b.threats;
        pol.telemetry_all = b.telemetry_all;
        pol.block_dot = b.block_dot;
        pol.strict_outbound = b.strict_outbound;
        pol.block_vpn = b.block_vpn;
        pol.block_ipv6 = b.block_ipv6;
        pol.white_expiry = b.white_expiry;
        pol.preset = Some(self);
        // RDP 3389: external (router side) always Off in presets.
        // Normal keeps LAN Remote Desktop allowed.
        // FortNox also blocks 3389 on the home network.
        if let Some(p) = pol.inbound.iter_mut().find(|i| i.mac.is_empty() && i.proto == "tcp" && i.port == 3389) {
            p.on = false;
            p.lan_off = b.rdp_block_lan;
        }
        let _ = b.prefer_admin_lan; // applied via config/coach, not policy
    }

    /// Human-readable lines of what would change vs current policy, with why-text.
    pub fn diff(self, pol: &Policy) -> Vec<DiffLine> {
        let b = self.bundle();
        let mut out = Vec::new();
        let push = |out: &mut Vec<DiffLine>, label: &str, from: bool, to: bool, why: &str| {
            if from != to {
                out.push(DiffLine {
                    label: label.into(),
                    from: if from { "On" } else { "Off" }.into(),
                    to: if to { "On" } else { "Off" }.into(),
                    why: why.into(),
                });
            }
        };
        if pol.mode != b.mode {
            out.push(DiffLine {
                label: "Protection Mode".into(),
                from: mode_label(pol.mode).into(),
                to: mode_label(b.mode).into(),
                why: "How strictly FoilGateway filters traffic overall.".into(),
            });
        }
        push(&mut out, "Threat Lists", pol.threats, b.threats,
            "Blocks connections to known bad networks many scanners use.");
        push(&mut out, "Block All Telemetry", pol.telemetry_all, b.telemetry_all,
            "Stops a lot of silent phone-home traffic. A few gadgets may need Allow.");
        push(&mut out, "Block Encrypted DNS (Port 853)", pol.block_dot, b.block_dot,
            "Keeps name-based blocks from being skipped by DNS over TLS. While On, devices set to require DNS over TLS (for example Android Private DNS set to a provider name) cannot look up names.");
        push(&mut out, "Strict Outbound", pol.strict_outbound, b.strict_outbound,
            "Only allows new outbound that matches your rules. Unusual apps may need Allow.");
        push(&mut out, "Block VPN Ports", pol.block_vpn, b.block_vpn,
            "Stops common VPN / WireGuard ports. Off by default, including in FortNox.");
        push(&mut out, "Block IPv6", pol.block_ipv6, b.block_ipv6,
            "On: no IPv6 traffic passes the gateway onto the LAN. Off: IPv6 is allowed with the same hardening as IPv4.");
        push(&mut out, "Whitelist Expiry For Auto Allows", pol.white_expiry, b.white_expiry,
            "Auto Allows from Audit expire after 30 days so old exceptions do not linger. Allow · Permanent stays available.");
        let rdp = pol.inbound.iter().find(|i| i.mac.is_empty() && i.proto == "tcp" && i.port == 3389);
        let rdp_wan = rdp.map(|i| i.on).unwrap_or(false);
        let rdp_lan_off = rdp.map(|i| i.lan_off).unwrap_or(false);
        if rdp_wan {
            out.push(DiffLine {
                label: "Remote Desktop From Outside (3389)".into(),
                from: "Allowed".into(),
                to: "Blocked".into(),
                why: "Stops strangers on the router / internet side from reaching Remote Desktop. Port 3389 is scanned constantly.".into(),
            });
        }
        if rdp_lan_off != b.rdp_block_lan {
            out.push(DiffLine {
                label: "Remote Desktop On Home Network (3389)".into(),
                from: if rdp_lan_off { "Blocked" } else { "Allowed" }.into(),
                to: if b.rdp_block_lan { "Blocked" } else { "Allowed" }.into(),
                why: if b.rdp_block_lan {
                    "FortNox also blocks Remote Desktop between your own devices. Turn on per device on Ports only if you need it.".into()
                } else {
                    "Keeps Remote Desktop working between devices on your home network. Outside access stays blocked.".into()
                },
            });
        }
        out
    }

    /// True when every bundled toggle still matches this preset.
    pub fn matches(self, pol: &Policy) -> bool {
        self.diff(pol).is_empty()
    }
}

fn mode_label(m: Mode) -> &'static str {
    match m {
        Mode::Normal => "Normal",
        Mode::LanOnly => "Local Network Only",
        Mode::BlockAll => "Block Everything",
        Mode::Audit => "Audit",
    }
}

/// Diff for a mode-only change. Mode Normal is the Normal protection-level lever,
/// so callers should use Preset::Normal.diff instead when activating Normal.
pub fn mode_diff(pol: &Policy, to: Mode) -> Vec<DiffLine> {
    if to == Mode::Normal {
        return Preset::Normal.diff(pol);
    }
    if pol.mode == to {
        return Vec::new();
    }
    vec![DiffLine {
        label: "Protection Mode".into(),
        from: mode_label(pol.mode).into(),
        to: mode_label(to).into(),
        why: String::new(),
    }]
}

#[derive(Clone, Debug, PartialEq)]
pub struct Bundle {
    pub mode: Mode,
    pub threats: bool,
    pub telemetry_all: bool,
    pub block_dot: bool,
    pub strict_outbound: bool,
    pub block_vpn: bool,
    pub block_ipv6: bool,
    pub prefer_admin_lan: bool,
    pub white_expiry: bool,
    /// When true (FortNox), also block TCP 3389 from the LAN side.
    pub rdp_block_lan: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DiffLine {
    pub label: String,
    pub from: String,
    pub to: String,
    /// Plain why-text shown in Review And Apply.
    pub why: String,
}

/// Leave-Audit lands on Normal.
pub fn leave_audit(pol: &mut Policy) {
    Preset::Normal.apply(pol);
}

/// Active chip: named preset if it still matches, else Custom.
pub fn chip(pol: &Policy) -> &'static str {
    match pol.preset {
        Some(p) if p.matches(pol) => p.label(),
        Some(_) | None => {
            // Infer if an unnamed policy happens to match a bundle.
            for p in Preset::ALL {
                if p.matches(pol) {
                    return p.label();
                }
            }
            "Custom"
        }
    }
}

/// Placement of the bridge in the cable path (not Router mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Placement {
    /// Modem / ONT → FoilGateway → switch.
    InternetSwitch,
    /// Modem → router → FoilGateway → switch. Default for existing homes.
    #[default]
    RouterSwitch,
}

impl Placement {
    pub fn label(self) -> &'static str {
        match self {
            Placement::InternetSwitch => "Between Internet And Switch",
            Placement::RouterSwitch => "Between Router And Switch",
        }
    }

    pub fn plain(self) -> &'static str {
        match self {
            Placement::InternetSwitch => "Modem / ONT → FoilGateway → switch (and Wi-Fi access points).",
            Placement::RouterSwitch => "Modem / ONT → existing router → FoilGateway → switch / Wi-Fi.",
        }
    }

    pub fn when(self) -> &'static str {
        match self {
            Placement::InternetSwitch => "You want FoilGateway to see nearly everything before it hits your home switch.",
            Placement::RouterSwitch => "You already have a home router for Wi-Fi, DHCP, and NAT, and want FoilGateway as a silent filter.",
        }
    }

    pub fn can_see(self) -> &'static str {
        match self {
            Placement::InternetSwitch => "Everything downstream of the LAN port: switches, Wi-Fi, and all devices behind FoilGateway.",
            Placement::RouterSwitch => "Everything downstream of the LAN port: switches, Wi-Fi, and all devices behind FoilGateway.",
        }
    }

    pub fn cannot_see(self) -> &'static str {
        match self {
            Placement::InternetSwitch => "Anything upstream of the WAN port.",
            Placement::RouterSwitch => "Anything upstream of the WAN port (including the router and its own upstream).",
        }
    }

    pub fn parse(s: &str) -> Option<Placement> {
        match s {
            "internet_switch" | "InternetSwitch" | "a" => Some(Placement::InternetSwitch),
            "router_switch" | "RouterSwitch" | "b" | "" => Some(Placement::RouterSwitch),
            _ => None,
        }
    }

    pub fn conf_value(self) -> &'static str {
        match self {
            Placement::InternetSwitch => "internet_switch",
            Placement::RouterSwitch => "router_switch",
        }
    }
}

/// Best Practices coach suggestion (Accept / Dismiss).
#[derive(Clone, Debug, Serialize)]
pub struct Suggestion {
    pub id: String,
    pub title: String,
    pub why: String,
    /// Key/value patch for /api/firewall when Apply is pressed.
    pub patch: serde_json::Value,
    pub risky: bool,
    /// When set, Apply is disabled — feature needs a different placement / mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placement_block: Option<String>,
}

/// One wizard question with novice explanation. Skipped when already answered
/// by current settings (skip=true).
#[derive(Clone, Debug, Serialize)]
pub struct CoachQuestion {
    pub id: String,
    pub text: String,
    pub explain: String,
    pub yesno: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_yes: Option<bool>,
    /// When true, UI should skip (settings already settle this).
    pub skip: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

/// Build wizard questions. Skip ones already settled by mode / settings.
pub fn coach_questions(pol: &Policy, admin_from_wan: bool) -> Vec<CoachQuestion> {
    let chip = chip(pol);
    vec![
        CoachQuestion {
            id: "cables_done".into(),
            text: "Have you finished placing the cables?".into(),
            explain: "FoilGateway only filters traffic that crosses it. Two placements are supported today: Between Internet And Switch (modem / ONT → FoilGateway → switch), or Between Router And Switch (modem → your router → FoilGateway → switch / Wi-Fi). Until the WAN cable faces the internet or router side and the LAN cable(s) face your devices, the map and blocks can look wrong. Answer Yes once those cables are in the right ports. Answer No if you are still moving cables — we will not change protection until you are ready.".into(),
            yesno: true,
            default_yes: None,
            skip: false,
            skip_reason: None,
        },
        CoachQuestion {
            id: "admin_outside".into(),
            text: "Do you still need to open FoilGateway settings from outside your home network?".into(),
            explain: "Outside means from the router or internet side of FoilGateway — not from a phone or laptop already on your own Wi-Fi. Leaving the settings page open from outside lets strangers on that side try the sign-in page. Most homes only need Local Network Only (phones and PCs behind FoilGateway). Say Yes only if you truly manage FoilGateway from away. Say No and we will suggest switching settings to Local Network Only at the end — you still choose Apply yourself.".into(),
            yesno: true,
            default_yes: None,
            skip: !admin_from_wan,
            skip_reason: (!admin_from_wan).then(|| "Settings already answer from your home network only.".into()),
        },
        CoachQuestion {
            id: "rdp_needed".into(),
            text: "Does anyone Remote Desktop in from the internet (outside your home)?".into(),
            explain: "Remote Desktop (port 3389) is scanned constantly on the public internet. FoilGateway blocks it from outside by default so strangers cannot try your PCs. Devices already on your home network can still use Remote Desktop to each other unless you pick FortNox (which also blocks it on the LAN). Say Yes only if someone must reach a PC from outside your house — that is unusual and risky. Say No if you only use Remote Desktop inside the house, or not at all.".into(),
            yesno: true,
            default_yes: None,
            skip: !pol.inbound.iter().any(|i| i.mac.is_empty() && i.proto == "tcp" && i.port == 3389 && i.on),
            skip_reason: Some("Remote Desktop from outside is already Off.".into()),
        },
        CoachQuestion {
            id: "ok_with_allows".into(),
            text: "Are you okay if a few unusual devices need an Allow the first week?".into(),
            explain: format!(
                "An Allow is a one-time exception you grant so one device can reach something FoilGateway blocked (for example a smart TV calling home, or a printer talking to a cloud service). You make an Allow from the Troubleshooter (Devices → Troubleshooter) or from an Audit row — it is not automatic. You are on the {chip} protection level. FortNox turns on Strict Outbound: new outbound traffic must match your rules, so a gadget may need one or two Allows the first week while you learn what it needs. Normal is gentler and rarely needs that. Say Yes if you are willing to open the Troubleshooter a few times for odd devices. Say No to stay on softer Normal defaults and skip the FortNox suggestion."
            ),
            yesno: true,
            default_yes: None,
            skip: pol.strict_outbound || chip == "FortNox",
            skip_reason: (pol.strict_outbound || chip == "FortNox").then(|| "Strict Outbound is already On (FortNox-style).".into()),
        },
        CoachQuestion {
            id: "need_ipv6".into(),
            text: "Do you need IPv6 on this network?".into(),
            explain: "IPv6 is a second kind of internet address beside ordinary IPv4. Many home ISPs and gadgets never use it. With Block IPv6 Off, IPv6 may pass the gateway onto the LAN and is hardened like IPv4. With Block IPv6 On, no IPv6 traffic passes the gateway onto the LAN (neighbour discovery still works). Say Yes if your ISP handed you IPv6, or a device needs it. Say No if you want Block IPv6 On — you still choose Apply at the end.".into(),
            yesno: true,
            default_yes: Some(true),
            skip: pol.block_ipv6,
            skip_reason: pol.block_ipv6.then(|| "Block IPv6 is already On.".into()),
        },
        CoachQuestion {
            id: "uses_vpn".into(),
            text: "Do you use a VPN app on phones or PCs?".into(),
            explain: "A VPN app wraps a device's traffic so it can leave your network through an encrypted tunnel. That can skip some name-based blocks FoilGateway applies. FoilGateway can block common VPN / WireGuard ports, but that breaks those apps on purpose. FortNox leaves Block VPN Ports Off so work and travel VPNs keep working. Say Yes if someone in the house relies on a VPN — we will not suggest blocking VPN ports. Say No only if nobody uses a VPN and you want that door closed; we will suggest Block VPN Ports at the end for you to Apply or Skip.".into(),
            yesno: true,
            default_yes: None,
            skip: pol.block_vpn,
            skip_reason: pol.block_vpn.then(|| "Block VPN Ports is already On.".into()),
        },
    ]
}

/// Build suggestions from current policy + answers. Respects Normal / FortNox /
/// Custom and skips tips already covered by what is On.
pub fn coach_suggestions(pol: &Policy, admin_from_wan: bool, answers: &serde_json::Value) -> Vec<Suggestion> {
    let mut out = Vec::new();
    let chip_now = chip(pol);
    if !pol.threats {
        out.push(Suggestion {
            id: "threats".into(),
            title: "Turn On Threat Lists".into(),
            why: "Blocks connections to known bad networks many scanners use.".into(),
            patch: serde_json::json!({ "threats": true }),
            risky: false,
            placement_block: None,
        });
    }
    if !pol.telemetry_all {
        out.push(Suggestion {
            id: "telemetry".into(),
            title: "Turn On Telemetry Block".into(),
            why: "Stops a lot of silent phone-home traffic. A few gadgets may need Allow.".into(),
            patch: serde_json::json!({ "telemetry_all": true }),
            risky: false,
            placement_block: None,
        });
    }
    if admin_from_wan && answers.get("admin_outside").and_then(|v| v.as_bool()) != Some(true) {
        out.push(Suggestion {
            id: "admin_lan".into(),
            title: "Switch Settings To Local Network Only".into(),
            why: "Stops strangers on the internet side from opening your FoilGateway pages.".into(),
            patch: serde_json::json!({ "admin_from": "lan" }),
            risky: true,
            placement_block: None,
        });
    }
    let rdp_on = pol.inbound.iter().any(|i| i.mac.is_empty() && i.proto == "tcp" && i.port == 3389 && i.on);
    if rdp_on && answers.get("rdp_needed").and_then(|v| v.as_bool()) != Some(true) {
        out.push(Suggestion {
            id: "rdp_off".into(),
            title: "Keep Remote Desktop Off".into(),
            why: "Blocks Remote Desktop from the router / internet side. Your devices on the home network can still use it unless you pick FortNox.".into(),
            patch: serde_json::json!({ "rdp_off": true }),
            risky: false,
            placement_block: None,
        });
    }
    if (pol.threats || pol.telemetry_all) && !pol.block_dot {
        out.push(Suggestion {
            id: "block_dot".into(),
            title: "Block Encrypted DNS On Port 853".into(),
            why: "Keeps name-based blocks from being skipped by DNS over TLS on port 853. While On, devices set to require DNS over TLS (for example Android Private DNS set to a provider name) cannot look up names. Some apps use encrypted DNS on port 443, so FoilGateway may not learn those names from DNS; names already on your lists still become address blocks.".into(),
            patch: serde_json::json!({ "block_dot": true }),
            risky: false,
            placement_block: None,
        });
    }
    // Offer FortNox only when not already there and the owner said Yes to Allows.
    if chip_now != "FortNox" && !pol.strict_outbound && answers.get("ok_with_allows").and_then(|v| v.as_bool()) == Some(true) {
        out.push(Suggestion {
            id: "strict".into(),
            title: "Apply FortNox".into(),
            why: format!("You are on {chip_now}. FortNox turns on Block All Telemetry and Strict Outbound, and also blocks Remote Desktop on the home network. Unusual apps may need Allow."),
            patch: serde_json::json!({ "preset": "fortnox" }),
            risky: true,
            placement_block: None,
        });
    }
    if !pol.block_ipv6 && answers.get("need_ipv6").and_then(|v| v.as_bool()) == Some(false) {
        out.push(Suggestion {
            id: "block_ipv6".into(),
            title: "Turn On Block IPv6".into(),
            why: "No IPv6 traffic passes the gateway onto the LAN. Neighbour discovery still works.".into(),
            patch: serde_json::json!({ "block_ipv6": true }),
            risky: true,
            placement_block: None,
        });
    }
    // VPN block only when they said they do NOT use a VPN, and it is Off.
    if !pol.block_vpn && answers.get("uses_vpn").and_then(|v| v.as_bool()) == Some(false) {
        out.push(Suggestion {
            id: "block_vpn".into(),
            title: "Block VPN Ports".into(),
            why: "Stops common VPN / WireGuard ports. Skip this if anyone still needs a VPN app.".into(),
            patch: serde_json::json!({ "block_vpn": true }),
            risky: true,
            placement_block: None,
        });
    }
    if !pol.white_expiry {
        out.push(Suggestion {
            id: "white_expiry".into(),
            title: "Turn On Whitelist Expiry".into(),
            why: "Auto Allows from Audit expire after 30 days so old exceptions do not linger. Allow · Permanent stays available.".into(),
            patch: serde_json::json!({ "white_expiry": true }),
            risky: false,
            placement_block: None,
        });
    }
    if pol.mode == Mode::Audit {
        out.push(Suggestion {
            id: "leave_audit".into(),
            title: "Leave Audit And Apply Normal".into(),
            why: "Turns on everyday protection: threat lists, telemetry block, and related Normal defaults.".into(),
            patch: serde_json::json!({ "preset": "normal" }),
            risky: false,
            placement_block: None,
        });
    }

    // Wave I — stronger identity (opt-in).
    if !pol.sticky_identity {
        out.push(Suggestion {
            id: "sticky_identity".into(),
            title: "Turn On Stronger Device Identity".into(),
            why: "Remembers hostname and DHCP fingerprint hints when a phone rotates its private MAC, so it looks less like a brand-new device. Soft sticky already runs; this is the stronger opt-in. Default Off.".into(),
            patch: serde_json::json!({ "sticky_identity": true }),
            risky: false,
            placement_block: None,
        });
    }
    // Wave Det — deeper detection (opt-in).
    if !pol.deep_detect {
        out.push(Suggestion {
            id: "deep_detect".into(),
            title: "Turn On Deeper Detection".into(),
            why: "Adds quieter pattern checks beyond volume spikes (odd port sweeps, repeated soft fails). Can raise more alerts. Default Off — Apply only if you want a sharper eye.".into(),
            patch: serde_json::json!({ "deep_detect": true }),
            risky: false,
            placement_block: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_match_ui() {
        assert_eq!(Preset::Normal.label(), "Normal");
        assert_eq!(Preset::FortNox.label(), "FortNox");
        assert_eq!(Preset::ALL.len(), 2);
    }

    #[test]
    fn parse_accepts_legacy_home_user() {
        assert_eq!(Preset::parse("home_user"), Some(Preset::Normal));
        assert_eq!(Preset::parse("Home User"), Some(Preset::Normal));
        assert_eq!(Preset::parse("normal"), Some(Preset::Normal));
        assert_eq!(Preset::parse("office"), Some(Preset::Normal));
        assert_eq!(Preset::parse("lab"), Some(Preset::Normal));
        assert_eq!(Preset::parse("fortnox"), Some(Preset::FortNox));
    }

    #[test]
    fn serde_alias_home_user() {
        let p: Preset = serde_json::from_str("\"home_user\"").unwrap();
        assert_eq!(p, Preset::Normal);
        let p2: Preset = serde_json::from_str("\"normal\"").unwrap();
        assert_eq!(p2, Preset::Normal);
        assert_eq!(serde_json::to_string(&Preset::Normal).unwrap(), "\"normal\"");
    }

    #[test]
    fn leave_audit_lands_normal() {
        let mut p = Policy { mode: Mode::Audit, ..Policy::default() };
        leave_audit(&mut p);
        assert_eq!(p.preset, Some(Preset::Normal));
        assert_eq!(p.mode, Mode::Normal);
        assert!(p.threats && !p.telemetry_all && !p.block_dot && p.white_expiry);
        assert!(!p.strict_outbound && !p.block_vpn && !p.block_ipv6);
    }

    #[test]
    fn normal_non_disruptive_defaults() {
        let b = Preset::Normal.bundle();
        assert!(b.threats && !b.telemetry_all && !b.block_dot && b.white_expiry && b.prefer_admin_lan && !b.block_ipv6);
        assert!(!b.strict_outbound && !b.block_vpn && !b.rdp_block_lan);
    }

    #[test]
    fn fortnox_strict_on_vpn_off() {
        let b = Preset::FortNox.bundle();
        assert!(b.strict_outbound);
        assert!(b.telemetry_all);
        assert!(!b.block_vpn);
        assert!(b.rdp_block_lan);
    }

    #[test]
    fn normal_block_dot_off_fortnox_on() {
        assert!(!Preset::Normal.bundle().block_dot);
        assert!(Preset::FortNox.bundle().block_dot);
        let mut p = Policy::default();
        Preset::Normal.apply(&mut p);
        assert!(!p.block_dot);
        assert_eq!(chip(&p), "Normal");
        Preset::FortNox.apply(&mut p);
        assert!(p.block_dot);
        assert_eq!(chip(&p), "FortNox");
        // Turning block_dot off while on FortNox drifts to Custom.
        p.block_dot = false;
        assert_eq!(chip(&p), "Custom");
    }

    #[test]
    fn normal_rdp_blocks_outside_allows_lan() {
        let mut p = Policy::default();
        if let Some(i) = p.inbound.iter_mut().find(|i| i.port == 3389) {
            i.on = true;
            i.lan_off = false;
        }
        Preset::Normal.apply(&mut p);
        let r = p.inbound.iter().find(|i| i.port == 3389).unwrap();
        assert!(!r.on, "external RDP blocked");
        assert!(!r.lan_off, "LAN RDP still allowed in Normal");
        Preset::FortNox.apply(&mut p);
        let r = p.inbound.iter().find(|i| i.port == 3389).unwrap();
        assert!(!r.on && r.lan_off, "FortNox blocks RDP both sides");
        let d = Preset::Normal.diff(&p);
        assert!(d.iter().any(|x| x.label.contains("Home Network") && x.to == "Allowed"), "{d:?}");
        assert!(d.iter().all(|x| !x.why.is_empty()), "every diff line needs why-text");
    }

    #[test]
    fn custom_when_drifted() {
        let mut p = Policy::default();
        Preset::Normal.apply(&mut p);
        assert_eq!(chip(&p), "Normal");
        p.threats = false;
        assert_eq!(chip(&p), "Custom");
    }

    #[test]
    fn diff_lists_flips() {
        let p = Policy { mode: Mode::Audit, ..Policy::default() };
        let d = Preset::Normal.diff(&p);
        assert!(d.iter().any(|x| x.label == "Protection Mode"));
        assert!(d.iter().any(|x| x.label == "Threat Lists" && x.to == "On"));
    }

    #[test]
    fn mode_normal_uses_preset_diff() {
        let p = Policy { mode: Mode::Audit, ..Policy::default() };
        let d = mode_diff(&p, Mode::Normal);
        assert!(d.iter().any(|x| x.label == "Protection Mode" && x.to == "Normal"));
        assert!(d.iter().any(|x| x.label == "Threat Lists" && x.to == "On"));
        assert!(d.iter().all(|x| x.label != "Block IPv6"), "default and Normal both leave Block IPv6 Off");
        let mut blocked = p.clone();
        blocked.block_ipv6 = true;
        let d_b = mode_diff(&blocked, Mode::Normal);
        assert!(d_b.iter().any(|x| x.label == "Block IPv6" && x.from == "On" && x.to == "Off"));
        let d2 = mode_diff(&p, Mode::BlockAll);
        assert_eq!(d2.len(), 1);
        assert_eq!(d2[0].label, "Protection Mode");
        assert_eq!(d2[0].to, "Block Everything");
    }

    #[test]
    fn coach_skips_settled_and_respects_preset() {
        let mut p = Policy::default();
        Preset::Normal.apply(&mut p);
        let qs = coach_questions(&p, false);
        assert!(qs.iter().any(|q| q.id == "admin_outside" && q.skip));
        let sug = coach_suggestions(&p, false, &serde_json::json!({ "ok_with_allows": true }));
        assert!(sug.iter().any(|s| s.id == "strict"), "Normal + ok_with_allows offers FortNox");
        Preset::FortNox.apply(&mut p);
        let sug2 = coach_suggestions(&p, false, &serde_json::json!({ "ok_with_allows": true }));
        assert!(sug2.iter().all(|s| s.id != "strict"), "already FortNox");
    }
}
