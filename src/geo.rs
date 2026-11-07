//! Offline locations from DB-IP City Lite (CC BY 4.0). Off until the owner
//! turns it on; then it downloads once (about 86 MB) and again each month.
//! The CSV is boiled down to ranges of (country, rough place), so the file
//! kept on disk and in memory is a few MB.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicU8, Ordering};

pub const SIZE_NOTE: &str = "about 86 MB";
pub const SOURCE: &str = "download.db-ip.com";

// 0 idle, 1 downloading, 2 building, 3 failed. Shown where the map goes.
pub static PHASE: AtomicU8 = AtomicU8::new(0);
pub static DONE: AtomicU64 = AtomicU64::new(0);
pub static TOTAL: AtomicU64 = AtomicU64::new(0);
/// When the next try after a failed download is due, and how many failed in a row.
pub static NEXT_TRY: AtomicI64 = AtomicI64::new(0);
pub static FAILS: AtomicU32 = AtomicU32::new(0);
/// Only one download at a time.
pub static BUSY: AtomicBool = AtomicBool::new(false);

/// Wait after the nth failure in a row: 1, 5, 15, then 60 minutes.
pub fn backoff(fails: u32) -> i64 {
    [60, 300, 900, 3600][(fails.max(1) as usize - 1).min(3)]
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Span {
    start: u128,
    end: u128,
    cc: [u8; 2],
    lat: i16, // tenths of a degree
    lon: i16,
}

/// IPv4 spans kept in 16 bytes instead of 48: the database has about two
/// million of them.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Span4 {
    start: u32,
    end: u32,
    cc: [u8; 2],
    lat: i16,
    lon: i16,
}

#[derive(Default)]
pub struct Db {
    v4: Vec<Span4>,
    v6: Vec<Span>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Place {
    pub country: String,
    pub lat: f64,
    pub lon: f64,
}

fn key(ip: IpAddr) -> (bool, u128) {
    match ip {
        IpAddr::V4(v) => (true, u32::from(v) as u128),
        IpAddr::V6(v) => (false, u128::from(v)),
    }
}

fn place(cc: [u8; 2], lat: i16, lon: i16) -> Option<Place> {
    (&cc != b"ZZ").then(|| Place { country: String::from_utf8_lossy(&cc).into(), lat: lat as f64 / 10.0, lon: lon as f64 / 10.0 })
}

/// Index of a two-letter code in a 26x26 table.
fn slot(cc: [u8; 2]) -> Option<usize> {
    let (a, b) = (cc[0].wrapping_sub(b'A') as usize, cc[1].wrapping_sub(b'A') as usize);
    (a < 26 && b < 26).then_some(a * 26 + b)
}

/// Joins sorted ranges that touch or overlap.
fn merge(it: impl Iterator<Item = (u128, u128)>) -> Vec<(u128, u128)> {
    let mut out: Vec<(u128, u128)> = Vec::new();
    for (a, b) in it {
        match out.last_mut() {
            Some(l) if a <= l.1.saturating_add(1) => l.1 = l.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

fn write_ranges(list: &[(u128, u128)], four: bool) -> String {
    let ip = |x: u128| if four { std::net::Ipv4Addr::from(x as u32).to_string() } else { std::net::Ipv6Addr::from(x).to_string() };
    let mut out = String::with_capacity(list.len() * if four { 32 } else { 48 });
    for (i, &(a, b)) in list.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&ip(a));
        if b != a {
            out.push('-');
            out.push_str(&ip(b));
        }
    }
    out
}

impl Db {
    pub fn loaded(&self) -> bool {
        !self.v4.is_empty() || !self.v6.is_empty()
    }

    pub fn locate(&self, ip: IpAddr) -> Option<Place> {
        if !crate::maptraffic::public_ip(ip) { return None; }
        let (four, k) = key(ip);
        if four {
            let k = k as u32;
            let i = self.v4.partition_point(|s| s.start <= k);
            let s = self.v4.get(i.checked_sub(1)?)?;
            (k <= s.end).then(|| place(s.cc, s.lat, s.lon)).flatten()
        } else {
            let i = self.v6.partition_point(|s| s.start <= k);
            let s = self.v6.get(i.checked_sub(1)?)?;
            (k <= s.end).then(|| place(s.cc, s.lat, s.lon)).flatten()
        }
    }

    /// Every address in the chosen countries as merged ranges, ready for an
    /// nft interval set. One pass over the database whatever the number of
    /// countries. Neighbouring ranges of different chosen countries join,
    /// so blocking all but one country leaves about as many ranges as an
    /// allow list of that one would, while unlisted and private space
    /// (never in a country) stays open.
    pub fn block_ranges(&self, codes: &[String]) -> crate::rules::Elems {
        let mut on = [false; 676];
        for c in codes {
            if let Some(i) = c.as_bytes().get(..2).and_then(|b| slot([b[0], b[1]])) {
                on[i] = true;
            }
        }
        let pick = |cc: [u8; 2]| slot(cc).is_some_and(|i| on[i]);
        let r4 = merge(self.v4.iter().filter(|s| pick(s.cc)).map(|s| (s.start as u128, s.end as u128)));
        let r6 = merge(self.v6.iter().filter(|s| pick(s.cc)).map(|s| (s.start, s.end)));
        crate::rules::Elems { v4: write_ranges(&r4, true), v6: write_ranges(&r6, false), n4: r4.len(), n6: r6.len(), hidden: false }
    }

    pub fn open(dir: &Path) -> Db {
        let mut db = Db::default();
        for (name, four) in [("geo4.bin", true), ("geo6.bin", false)] {
            if let Ok(bytes) = std::fs::read(dir.join(name)) {
                for c in bytes.as_chunks::<38>().0 {
                    let s = Span {
                        start: u128::from_le_bytes(c[0..16].try_into().unwrap()),
                        end: u128::from_le_bytes(c[16..32].try_into().unwrap()),
                        cc: [c[32], c[33]],
                        lat: i16::from_le_bytes([c[34], c[35]]),
                        lon: i16::from_le_bytes([c[36], c[37]]),
                    };
                    if four {
                        db.v4.push(Span4 { start: s.start as u32, end: s.end as u32, cc: s.cc, lat: s.lat, lon: s.lon });
                    } else {
                        db.v6.push(s);
                    }
                }
                db.v4.shrink_to_fit();
                db.v6.shrink_to_fit();
            }
        }
        db
    }
}

/// Reads the DB-IP CSV (start,end,continent,country,region,city,lat,lon)
/// and merges neighbouring rows that land in the same country and place.
pub fn build(csv: impl Read, dir: &Path) -> Result<usize, String> {
    let mut v4: Vec<Span> = Vec::new();
    let mut v6: Vec<Span> = Vec::new();
    let mut rows = 0usize;
    for line in BufReader::new(csv).lines() {
        let line = line.map_err(|e| format!("location file unreadable: {e}"))?;
        let f = split_csv(&line);
        if f.len() < 8 {
            continue;
        }
        let (Ok(a), Ok(b)) = (f[0].parse::<IpAddr>(), f[1].parse::<IpAddr>()) else { continue };
        let cc = f[3].as_bytes();
        if cc.len() != 2 {
            continue;
        }
        rows += 1;
        let deg = |s: &str| (s.parse::<f64>().unwrap_or(0.0) * 10.0).round() as i16;
        let (four, start) = key(a);
        let span = Span { start, end: key(b).1, cc: [cc[0], cc[1]], lat: deg(&f[6]), lon: deg(&f[7]) };
        let list = if four { &mut v4 } else { &mut v6 };
        match list.last_mut() {
            // Same country, within about a degree: one span is plenty for a map dot.
            Some(l) if l.cc == span.cc && l.end.saturating_add(1) == span.start && (l.lat - span.lat).abs() <= 10 && (l.lon - span.lon).abs() <= 10 => l.end = span.end,
            _ => list.push(span),
        }
    }
    if rows < 1000 {
        return Err("the location file looked wrong, kept the old one".into());
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    for (name, list) in [("geo4.bin", &v4), ("geo6.bin", &v6)] {
        let mut out = Vec::with_capacity(list.len() * 38);
        for s in list.iter() {
            out.extend_from_slice(&s.start.to_le_bytes());
            out.extend_from_slice(&s.end.to_le_bytes());
            out.extend_from_slice(&s.cc);
            out.extend_from_slice(&s.lat.to_le_bytes());
            out.extend_from_slice(&s.lon.to_le_bytes());
        }
        let tmp = dir.join(format!("{name}.new"));
        std::fs::File::create(&tmp).and_then(|mut f| f.write_all(&out)).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, dir.join(name)).map_err(|e| e.to_string())?;
    }
    Ok(v4.len() + v6.len())
}

fn split_csv(line: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(String::new()),
            _ => out.last_mut().unwrap().push(c),
        }
    }
    out
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct Meta {
    pub month: String,
    pub fetched_at: i64,
    pub url: String,
    pub bytes: u64,
    pub error: String,
}

pub fn meta(dir: &Path) -> Meta {
    std::fs::read_to_string(dir.join("geo.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

/// Downloads this month's file (or last month's, DB-IP posts a little late)
/// unless the copy on disk is already this month's. Returns the log line.
pub fn refresh(dir: &Path, month: &str, prev: &str, first: bool) -> Option<Result<String, String>> {
    let base = std::env::var("FOILGW_GEO_URL").unwrap_or_else(|_| format!("https://{SOURCE}"));
    refresh_from(dir, month, prev, first, &base)
}

pub fn refresh_from(dir: &Path, month: &str, prev: &str, first: bool, base: &str) -> Option<Result<String, String>> {
    let old = meta(dir);
    if old.month == month && dir.join("geo4.bin").exists() {
        return None;
    }
    // The folder isn't there on a fresh install; without it the download had
    // nowhere to go and failed before a byte came in.
    if let Err(e) = std::fs::create_dir_all(dir) {
        let err = format!("Location database can't be saved in {}: {e}", dir.display());
        eprintln!("foilgw: {err}");
        PHASE.store(if first { 3 } else { 0 }, Ordering::Relaxed);
        return Some(Err(err));
    }
    let mut err = String::new();
    for m in [month, prev] {
        if m == old.month && dir.join("geo4.bin").exists() {
            return None;
        }
        let url = format!("{base}/free/dbip-city-lite-{m}.csv.gz");
        if first {
            PHASE.store(1, Ordering::Relaxed);
        }
        DONE.store(0, Ordering::Relaxed);
        TOTAL.store(0, Ordering::Relaxed);
        let gz = dir.join("dbip.csv.gz");
        eprintln!("foilgw: location database download starting: {url} -> {}", gz.display());
        let step = std::sync::atomic::AtomicU64::new(0);
        let got = crate::lists::download_to(&url, &gz, 400_000_000, &|d, t| {
            DONE.store(d, Ordering::Relaxed);
            TOTAL.store(t, Ordering::Relaxed);
            // A journal line every 10% (every 10 MB when the size is unknown).
            let s = (d * 10).checked_div(t).unwrap_or(d / 10_000_000);
            if s > step.load(Ordering::Relaxed) {
                step.store(s, Ordering::Relaxed);
                eprintln!("foilgw: location database {:.1} of {} MB", d as f64 / 1e6, if t > 0 { format!("{:.1}", t as f64 / 1e6) } else { "?".into() });
            }
        });
        if let Ok(b) = &got {
            eprintln!("foilgw: location database downloaded, {:.1} MB, building lookups", *b as f64 / 1e6);
        }
        let res = got.and_then(|bytes| {
            PHASE.store(if first { 2 } else { 0 }, Ordering::Relaxed);
            let f = std::fs::File::open(&gz).map_err(|e| e.to_string())?;
            build(flate2::read::GzDecoder::new(f), dir).map(|_| bytes)
        });
        let _ = std::fs::remove_file(&gz);
        match res {
            Ok(bytes) => {
                let m = Meta { month: m.into(), fetched_at: crate::caplog::now(), url: url.clone(), bytes, error: String::new() };
                let _ = std::fs::write(dir.join("geo.json"), serde_json::to_string(&m).unwrap());
                PHASE.store(0, Ordering::Relaxed);
                eprintln!("foilgw: location database ready ({})", m.month);
                return Some(Ok(format!("Location database downloaded from {url}, {:.1} MB.", bytes as f64 / 1e6)));
            }
            Err(e) => {
                err = format!("Location database download from {url} failed: {e}");
                eprintln!("foilgw: {err}");
            }
        }
    }
    PHASE.store(if first { 3 } else { 0 }, Ordering::Relaxed);
    let _ = std::fs::write(dir.join("geo.json"), serde_json::to_string(&Meta { error: err.clone(), ..old }).unwrap());
    Some(Err(err))
}

/// Two-letter code to name, for the country checkboxes.
/// Country code -> name, read once.
pub fn countries() -> &'static BTreeMap<&'static str, &'static str> {
    static MAP: std::sync::OnceLock<BTreeMap<&'static str, &'static str>> = std::sync::OnceLock::new();
    MAP.get_or_init(|| include_str!("../assets/countries.txt").lines().filter_map(|l| l.split_once('\t')).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_locate_and_cidrs() {
        let mut csv = String::new();
        for i in 0..1200u32 {
            let a = std::net::Ipv4Addr::from(0x0100_0000 + i * 256);
            let b = std::net::Ipv4Addr::from(0x0100_0000 + i * 256 + 255);
            let cc = if i < 600 { "AU" } else { "CN" };
            let lon = if i < 600 { "151.2" } else { "116.4" };
            csv += &format!("{a},{b},OC,{cc},\"Some, Region\",City,-33.8,{lon}\n");
        }
        csv += "2001:4860::,2001:4860::ffff,EU,DE,x,y,52.5,13.4\n";
        let dir = std::env::temp_dir().join(format!("fgw-geo-{}", crate::auth::token()));
        assert_eq!(build(csv.as_bytes(), &dir).unwrap(), 3);
        let db = Db::open(&dir);
        assert_eq!(db.locate("1.0.1.5".parse().unwrap()).unwrap().country, "AU");
        assert_eq!(db.locate("1.2.100.1".parse().unwrap()).unwrap().country, "CN");
        assert!(db.locate("9.9.9.9".parse().unwrap()).is_none());
        assert_eq!(db.locate("2001:4860::5".parse().unwrap()).unwrap().country, "DE");
        // The 600 AU /24s are one range; AU and CN together join into one.
        let au = db.block_ranges(&["AU".into()]);
        assert_eq!((au.v4.as_str(), au.n4, au.n6), ("1.0.0.0-1.2.87.255", 1, 0));
        let both = db.block_ranges(&["AU".into(), "CN".into(), "DE".into()]);
        assert_eq!((both.v4.as_str(), both.v6.as_str()), ("1.0.0.0-1.4.175.255", "2001:4860::-2001:4860::ffff"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn backoff_grows_then_stays() {
        assert_eq!([1, 2, 3, 4, 9].map(backoff), [60, 300, 900, 3600, 3600]);
    }

    // The real thing from download.db-ip.com: cargo test --release -- --ignored real_download
    #[test]
    #[ignore]
    fn real_download() {
        let dir = std::env::temp_dir().join("fg-geo-real").join("geo");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
        let (m, prev) = crate::app::month_of(crate::caplog::now());
        let t = std::time::Instant::now();
        let watch = std::thread::spawn(|| for _ in 0..600 {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let (p, d, t) = (PHASE.load(Ordering::Relaxed), DONE.load(Ordering::Relaxed), TOTAL.load(Ordering::Relaxed));
            eprintln!("phase {p} {d} of {t}");
            if p == 0 || p == 3 { break; }
        });
        let r = refresh(&dir, &m, &prev, true).unwrap();
        eprintln!("{r:?} in {:?}", t.elapsed());
        let _ = watch.join();
        let db = Db::open(&dir);
        assert!(db.loaded());
        assert_eq!(db.locate("8.8.8.8".parse().unwrap()).unwrap().country, "US");
    }

    #[test]
    fn refresh_makes_its_folder() {
        let dir = std::env::temp_dir().join(format!("fg-geo-{}", std::process::id())).join("geo");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
        // Nothing listens on port 9, so the download fails, but after the folder exists.
        let r = refresh_from(&dir, "2026-11", "2026-10", true, "http://127.0.0.1:9");
        assert!(dir.is_dir());
        let e = r.unwrap().unwrap_err();
        assert!(e.contains("127.0.0.1:9"), "{e}");
        assert!(!meta(&dir).error.is_empty());
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }
}

#[cfg(test)]
mod non_public_regressions {
    use super::*;
    #[test]
    fn link_local_and_multicast_are_never_foreign_countries() {
        let db=Db{v4:vec![Span4{start:0,end:u32::MAX,cc:*b"ZA",lat:0,lon:0}],v6:vec![Span{start:0,end:u128::MAX,cc:*b"ZA",lat:0,lon:0}]};
        for ip in ["fe80::1","ff02::fb","ff02::1:3","::","::1","fc00::1","192.168.1.1","224.0.0.251","127.0.0.1","0.0.0.0"] {
            assert!(db.locate(ip.parse().unwrap()).is_none(),"{ip}");
        }
        assert_eq!(db.locate("8.8.8.8".parse().unwrap()).unwrap().country,"ZA");
    }
}

#[cfg(test)]
mod all_country_coverage {
    use super::*;
    #[test]
    fn every_supported_code_builds_both_family_ranges_and_looks_up() {
        let mut db=Db::default();
        for (i,code) in countries().keys().enumerate(){let c=code.as_bytes();let cc=[c[0],c[1]];let start=0x01000000+(i as u32)*256;
            db.v4.push(Span4{start,end:start+255,cc,lat:0,lon:0});
            let start=u128::from("2600::".parse::<std::net::Ipv6Addr>().unwrap())+((i as u128)<<64);db.v6.push(Span{start,end:start+65535,cc,lat:0,lon:0});
        }
        for (i,code) in countries().keys().enumerate(){
            let ip=std::net::Ipv4Addr::from(0x01000001+(i as u32)*256);let ip6=std::net::Ipv6Addr::from(u128::from("2600::".parse::<std::net::Ipv6Addr>().unwrap())+((i as u128)<<64)+1);
            assert_eq!(db.locate(ip.into()).unwrap().country,*code);assert_eq!(db.locate(ip6.into()).unwrap().country,*code);
            let e=db.block_ranges(&[code.to_string()]);assert_eq!((e.n4,e.n6),(1,1),"{code}");
            assert_eq!(e.v4,format!("{}-{}",std::net::Ipv4Addr::from(u32::from(ip)-1),std::net::Ipv4Addr::from(u32::from(ip)+254)));
            assert_eq!(e.v6,format!("{}-{}",std::net::Ipv6Addr::from(u128::from(ip6)-1),std::net::Ipv6Addr::from(u128::from(ip6)+65534)));
        }
        let all:Vec<_>=countries().keys().map(|s|s.to_string()).collect();let ranges=db.block_ranges(&all);assert_eq!(ranges.n4,1);assert_eq!(ranges.n6,all.len());
        let alternating:Vec<_>=all.iter().step_by(2).cloned().collect();let ranges=db.block_ranges(&alternating);assert_eq!((ranges.n4,ranges.n6),(alternating.len(),alternating.len()));
        let unknown=db.block_ranges(&["not-a-country".into()]);assert!(unknown.v4.is_empty()&&unknown.v6.is_empty());
    }
}
