//! Maker names from the IEEE MA-L list, bundled gzipped (about 370 KB).

use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

static LIST: &[u8] = include_bytes!("../assets/oui.txt.gz");
static MAP: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Locally administered / privacy MAC (U/L bit set). Soft sticky-name hint uses this.
pub fn is_private(mac: &str) -> bool {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).take(2).collect::<String>();
    u8::from_str_radix(&hex, 16).map(|b| b & 2 != 0).unwrap_or(false)
}

pub fn vendor(mac: &str) -> String {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).take(6).collect::<String>().to_ascii_uppercase();
    if hex.len() < 6 {
        return String::new();
    }
    // Phones and laptops make up a random address per network for privacy.
    if is_private(mac) {
        return "Private address (random)".into();
    }
    let map = MAP.get_or_init(|| {
        let mut text = String::new();
        let _ = flate2::read::GzDecoder::new(LIST).read_to_string(&mut text);
        text.lines().filter_map(|l| l.split_once('\t')).map(|(a, b)| (a.to_string(), b.to_string())).collect()
    });
    map.get(&hex).map(|v| tidy(v)).unwrap_or_default()
}

/// The maker's name without the list's stray punctuation:
/// "Universal Global Scientific Industrial.," becomes
/// "Universal Global Scientific Industrial"; "ASUSTek COMPUTER INC." keeps its dot.
pub fn tidy(v: &str) -> String {
    let mut s = v.split_whitespace().collect::<Vec<_>>().join(" ");
    loop {
        let t = s.trim_end_matches([',', ';', ':', ' ', '-', '/']).to_string();
        let t = match t.strip_suffix('.') {
            Some(base) => {
                let word = base.rsplit([' ', ',']).next().unwrap_or("").to_ascii_lowercase();
                const ABBR: [&str; 22] = ["inc", "ltd", "co", "corp", "llc", "plc", "bv", "b.v", "ag", "sa", "s.a", "ab", "oy", "pte", "pty", "srl", "spa", "kg", "nv", "n.v", "a.s", "gmbh"];
                if ABBR.contains(&word.as_str()) { t } else { base.to_string() }
            }
            None => t,
        };
        if t == s {
            return s;
        }
        s = t;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn known_makers() {
        assert!(super::vendor("b8:27:eb:00:00:01").contains("Raspberry"));
        assert!(super::is_private("da:00:00:00:00:01"));
        assert!(!super::is_private("b8:27:eb:00:00:01"));
        assert_eq!(super::vendor("da:00:00:00:00:01"), "Private address (random)");
        assert_eq!(super::vendor("zz"), "");
        assert_eq!(super::tidy("Universal Global Scientific Industrial.,"), "Universal Global Scientific Industrial");
        assert_eq!(super::tidy("ASUSTek COMPUTER INC."), "ASUSTek COMPUTER INC.");
        assert_eq!(super::tidy("Foo Co.,Ltd."), "Foo Co.,Ltd.");
        assert_eq!(super::tidy("  silicom  "), "silicom");
        assert!(!super::vendor("04:7b:cb:a9:90:be").ends_with(','), "{}", super::vendor("04:7b:cb:a9:90:be"));
    }
}
