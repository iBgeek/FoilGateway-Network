//! What a port is usually for, in plain words. Every line comes from the
//! IANA service name registry or from the maker's own port list; a port
//! that isn't here is "Unknown use", never a guess.
//!
//! IANA: https://www.iana.org/assignments/service-names-port-numbers/
//! The IANA name for each line is kept so a test can check it against a
//! copy of the registry (tests/iana-ports.csv).

pub const IANA: &str = "https://www.iana.org/assignments/service-names-port-numbers/";
pub const APPLE: &str = "https://support.apple.com/en-us/103229";
pub const PLEX: &str = "https://support.plex.tv/articles/201543147-what-network-ports-do-i-need-to-allow-through-my-firewall/";

pub struct Use {
    /// "tcp", "udp", or "" for both.
    pub proto: &'static str,
    pub port: u16,
    pub what: &'static str,
    /// The IANA service name, or "" for a maker's port.
    pub iana: &'static str,
    pub source: &'static str,
}

const fn u(proto: &'static str, port: u16, what: &'static str, iana: &'static str) -> Use {
    Use { proto, port, what, iana, source: IANA }
}

pub const TABLE: &[Use] = &[
    u("tcp", 21, "file transfer (FTP)", "ftp"),
    u("", 22, "remote login (SSH)", "ssh"),
    u("tcp", 23, "old unencrypted remote login (Telnet)", "telnet"),
    u("tcp", 25, "sending email between servers (SMTP)", "smtp"),
    u("", 53, "name lookups (DNS)", "domain"),
    u("udp", 67, "getting a network address (DHCP server)", "bootps"),
    u("udp", 68, "getting a network address (DHCP client)", "bootpc"),
    u("udp", 69, "simple file transfer (TFTP)", "tftp"),
    u("tcp", 80, "web (HTTP)", "http"),
    u("tcp", 110, "fetching email (POP3)", "pop3"),
    u("udp", 123, "clock sync (NTP)", "ntp"),
    u("udp", 137, "Windows network names (NetBIOS)", "netbios-ns"),
    u("udp", 138, "Windows network browsing (NetBIOS)", "netbios-dgm"),
    u("tcp", 139, "old Windows file sharing (NetBIOS)", "netbios-ssn"),
    u("tcp", 143, "reading email (IMAP)", "imap"),
    u("udp", 161, "device monitoring (SNMP)", "snmp"),
    u("", 389, "directory lookups (LDAP)", "ldap"),
    u("tcp", 443, "secure web (HTTPS)", "https"),
    u("udp", 443, "secure web over QUIC (HTTPS)", "https"),
    u("tcp", 445, "Windows file sharing (SMB)", "microsoft-ds"),
    u("tcp", 465, "sending email, encrypted (SMTP)", "submissions"),
    u("udp", 500, "VPN setup (IPsec IKE)", "isakmp"),
    u("udp", 514, "device logs (syslog)", "syslog"),
    u("tcp", 515, "printing (LPD)", "printer"),
    u("", 554, "camera and video streams (RTSP)", "rtsp"),
    u("tcp", 587, "sending email (SMTP submission)", "submission"),
    u("tcp", 631, "printing (IPP)", "ipp"),
    u("", 636, "directory lookups, encrypted (LDAPS)", "ldaps"),
    u("", 853, "encrypted name lookups (DNS over TLS)", "domain-s"),
    u("tcp", 873, "file sync (rsync)", "rsync"),
    u("tcp", 993, "reading email, encrypted (IMAP)", "imaps"),
    u("tcp", 995, "fetching email, encrypted (POP3)", "pop3s"),
    u("", 1194, "VPN (OpenVPN)", "openvpn"),
    u("", 1701, "VPN (L2TP)", "l2tp"),
    u("tcp", 1723, "old VPN (PPTP)", "pptp"),
    u("tcp", 1883, "smart-home messages (MQTT)", "mqtt"),
    u("udp", 1900, "finding devices on the network (SSDP/UPnP)", "ssdp"),
    u("", 3074, "Xbox online play", "xbox"),
    u("", 3389, "Windows Remote Desktop", "ms-wbt-server"),
    u("", 3478, "setting up calls and video chat (STUN/TURN)", "stun"),
    u("udp", 4500, "VPN (IPsec)", "ipsec-nat-t"),
    u("", 5060, "internet phone calls (SIP)", "sip"),
    u("", 5061, "internet phone calls, encrypted (SIP)", "sips"),
    u("tcp", 5222, "chat messages (XMPP)", "xmpp-client"),
    Use { proto: "tcp", port: 5223, what: "Apple push notifications, iMessage and FaceTime", iana: "", source: APPLE },
    u("udp", 5353, "finding devices on the network (mDNS/Bonjour)", "mdns"),
    u("udp", 5355, "Windows local name lookups (LLMNR)", "llmnr"),
    u("udp", 5683, "smart-home device control (CoAP)", "coap"),
    u("tcp", 5900, "remote screen sharing (VNC)", "rfb"),
    u("tcp", 8080, "web, second port (HTTP)", "http-alt"),
    u("tcp", 8883, "smart-home messages, encrypted (MQTT)", "secure-mqtt"),
    u("tcp", 9100, "printing (raw print port)", "pdl-datastream"),
    Use { proto: "tcp", port: 32400, what: "Plex media server", iana: "", source: PLEX },
];

pub const UNKNOWN: &str = "Unknown use";

pub fn lookup(proto: &str, port: u16) -> Option<&'static Use> {
    let p = proto.to_ascii_lowercase();
    TABLE.iter().find(|u| u.port == port && (u.proto.is_empty() || u.proto == p))
}

/// "secure web (HTTPS)", or "Unknown use".
pub fn purpose(proto: &str, port: u16) -> &'static str {
    lookup(proto, port).map(|u| u.what).unwrap_or(UNKNOWN)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every IANA line names the service IANA lists for that port and
    // protocol (tests/iana-ports.csv is cut from the registry's CSV).
    #[test]
    fn table_matches_the_registry() {
        let csv = include_str!("../tests/iana-ports.csv");
        let has = |name: &str, port: u16, proto: &str| csv.lines().any(|l| {
            let f: Vec<&str> = l.split(',').collect();
            f.len() >= 3 && f[0] == name && f[1] == port.to_string() && f[2] == proto
        });
        for u in TABLE {
            if u.iana.is_empty() {
                assert_ne!(u.source, IANA, "{} has no IANA name but cites IANA", u.port);
                continue;
            }
            for p in if u.proto.is_empty() { vec!["tcp", "udp"] } else { vec![u.proto] } {
                assert!(has(u.iana, u.port, p), "{} {} is not {} at IANA", p, u.port, u.iana);
            }
        }
        // No port listed twice for the same protocol.
        for (i, a) in TABLE.iter().enumerate() {
            for b in &TABLE[i + 1..] {
                assert!(!(a.port == b.port && (a.proto.is_empty() || b.proto.is_empty() || a.proto == b.proto)), "{} twice", a.port);
            }
        }
        assert_eq!(purpose("tcp", 443), "secure web (HTTPS)");
        assert_eq!(purpose("udp", 443), "secure web over QUIC (HTTPS)");
        assert_eq!(purpose("tcp", 31337), UNKNOWN);
        assert_eq!(purpose("udp", 465), UNKNOWN);
    }
}
