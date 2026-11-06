//! Known kinds of device and what they need from the router side, taken
//! only from what the maker publishes. A profile opens the device's own
//! ports to connections from the router side (phones and computers on the
//! router's Wi-Fi), and lets the matching discovery messages (mDNS, SSDP)
//! through for every device, since those go to a group address and not to
//! one device.

pub struct Profile {
    pub id: &'static str,
    pub name: &'static str,
    /// What it's for, in a sentence.
    pub what: &'static str,
    /// The maker's page the ports come from.
    pub source: &'static str,
    /// Ports on the device itself, opened from the router side.
    pub ports: &'static [(&'static str, u16)],
    /// Discovery ports opened for every device.
    pub discovery: &'static [(&'static str, u16)],
    /// What it doesn't cover, when there's something.
    pub note: &'static str,
    detect: fn(&str, &str) -> bool,
}

fn has(s: &str, words: &[&str]) -> bool {
    words.iter().any(|w| s.contains(w))
}

pub const ALL: &[Profile] = &[
    Profile {
        id: "cast",
        name: "Google Cast (Chromecast, Google TV, Nest speakers and displays)",
        what: "Lets phones and computers on the router's network find it and cast to it.",
        source: "https://support.google.com/chrome/a/answer/12256492 and https://support.google.com/googlenest/answer/9216542",
        ports: &[("tcp", 8008), ("tcp", 8009), ("tcp", 8443)],
        discovery: &[("udp", 5353)],
        note: "Screen mirroring also sends video on UDP ports Google gives as 1 to 65535. Those aren't opened; mirroring from the router side may still be blocked.",
        detect: |vendor, host| (vendor.contains("google") && !has(host, &["pixel", "android"])) || has(host, &["chromecast", "google-home", "googlehome", "google-nest", "nest-audio", "nest-hub", "nest-mini", "google-tv"]),
    },
    Profile {
        id: "sonos",
        name: "Sonos speaker",
        what: "Lets the Sonos app, Spotify Connect and AirPlay on the router's network find and control it.",
        source: "https://support.sonos.com/en-us/article/configure-your-firewall-to-work-with-sonos",
        ports: &[
            ("tcp", 1400),
            ("tcp", 1443),
            ("tcp", 1500),
            ("tcp", 1543),
            ("tcp", 1600),
            ("tcp", 1643),
            ("tcp", 1700),
            ("tcp", 1743),
            ("tcp", 1843),
            ("tcp", 1943),
            ("tcp", 2043),
            ("tcp", 2143),
            ("tcp", 3400),
            ("tcp", 3401),
            ("tcp", 3500),
            ("tcp", 4070),
            ("tcp", 7000),
            ("tcp", 7001),
            ("tcp", 7002),
            ("tcp", 7003),
            ("udp", 1901),
            ("udp", 6969),
        ],
        discovery: &[("udp", 1900), ("udp", 5353)],
        note: "",
        detect: |vendor, host| vendor.contains("sonos") || host.contains("sonos"),
    },
    Profile {
        id: "printer",
        name: "Network printer",
        what: "Lets computers on the router's network print to it and open its settings page.",
        source: "https://support.hp.com/us-en/document/c02480766",
        ports: &[("tcp", 9100), ("tcp", 631), ("tcp", 515), ("tcp", 80), ("tcp", 443), ("udp", 161), ("udp", 427)],
        discovery: &[],
        note: "",
        detect: |vendor, host| {
            has(vendor, &["brother", "seiko epson", "kyocera", "lexmark", "xerox", "ricoh"])
                || has(host, &["printer", "laserjet", "officejet", "deskjet", "epson", "canon"])
                || host.starts_with("brw")
                || host.starts_with("npi")
                || (has(vendor, &["hewlett", "hp inc"]) && host.starts_with("hp"))
        },
    },
    Profile {
        id: "roku",
        name: "Roku",
        what: "Lets the Roku app and other remotes on the router's network find and control it.",
        source: "https://developer.roku.com/docs/developer-program/dev-tools/external-control-api.md",
        ports: &[("tcp", 8060)],
        discovery: &[("udp", 1900)],
        note: "",
        detect: |vendor, host| vendor.contains("roku") || host.contains("roku"),
    },
];

pub fn get(id: &str) -> Option<&'static Profile> {
    ALL.iter().find(|p| p.id == id)
}

/// Profiles that fit a device, from its maker (MAC vendor) and the name it
/// gave (DHCP, DNS or mDNS).
pub fn for_device(vendor: &str, hostname: &str) -> Vec<&'static Profile> {
    let (v, h) = (vendor.to_lowercase(), hostname.to_lowercase());
    ALL.iter().filter(|p| (p.detect)(&v, &h)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spots_known_devices() {
        let ids = |v: &str, h: &str| for_device(v, h).iter().map(|p| p.id).collect::<Vec<_>>();
        assert_eq!(ids("Google, Inc.", "Chromecast-Ultra"), vec!["cast"]);
        assert_eq!(ids("Sonos, Inc.", ""), vec!["sonos"]);
        assert_eq!(ids("", "BRW0080927AFBCE"), vec!["printer"]);
        assert_eq!(ids("HP Inc.", "HP-Laptop-7"), vec!["printer"]);
        assert!(ids("HP Inc.", "DESKTOP-1").is_empty());
        assert_eq!(ids("Roku, Inc", ""), vec!["roku"]);
        assert!(ids("Apple, Inc.", "Admins-iPhone").is_empty());
        assert!(ids("Google, Inc.", "Pixel-8").is_empty());
    }

    #[test]
    fn every_profile_has_a_source_and_ports() {
        for p in ALL {
            assert!(p.source.starts_with("https://"), "{}", p.id);
            assert!(!p.ports.is_empty(), "{}", p.id);
        }
    }
}
