//! Check GitHub Releases for a newer FoilGateway Network build, download
//! on demand, verify SHA256SUMS, install via `release::update`, and arm a
//! rollback timer so a failed restart puts the previous slot back.
//!
//! Never installs by itself — Check Now and Install Update are user clicks.
//! Follows HTTPS redirects so a future transfer of the repo still works.

use crate::lists;
use crate::release;
use ring::digest::SHA256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DAY_SECS: u64 = 24 * 60 * 60;
const DOWNLOAD_CAP: u64 = 200 * 1024 * 1024; // 200 MiB per asset

/// Repo URL from Cargo.toml `repository`. Empty when unset.
pub fn repo_url() -> &'static str {
    option_env!("CARGO_PKG_REPOSITORY").unwrap_or("")
}

/// `owner/name` for the GitHub API, or empty.
pub fn repo_slug() -> Option<&'static str> {
    let u = repo_url();
    let rest = u.strip_prefix("https://github.com/").or_else(|| u.strip_prefix("http://github.com/"))?;
    let rest = rest.trim_end_matches('/').trim_end_matches(".git");
    if rest.split('/').count() >= 2 {
        Some(rest)
    } else {
        None
    }
}

pub fn latest_api_url() -> Result<String, String> {
    let slug = repo_slug().ok_or("No GitHub repository is set in this build.")?;
    Ok(format!("https://api.github.com/repos/{slug}/releases/latest"))
}

/// Binary asset name for this build's CPU.
pub fn arch_asset() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("foilgw-x86_64"),
        "riscv64" => Ok("foilgw-riscv64"),
        other => Err(format!("This CPU ({other}) has no release asset.")),
    }
}

/// Compare dotted versions. Leading `v` ignored. Returns -1 / 0 / 1.
pub fn compare_versions(a: &str, b: &str) -> i32 {
    let parse = |s: &str| -> Vec<u64> {
        s.trim().trim_start_matches('v').split(|c| c == '.' || c == '-' || c == '+').filter_map(|p| {
            let digits: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() { None } else { digits.parse().ok() }
        }).collect()
    };
    let aa = parse(a);
    let bb = parse(b);
    let n = aa.len().max(bb.len());
    for i in 0..n {
        let x = aa.get(i).copied().unwrap_or(0);
        let y = bb.get(i).copied().unwrap_or(0);
        if x < y { return -1; }
        if x > y { return 1; }
    }
    0
}

/// Parse a SHA256SUMS file: `hash  name` or `hash *name` lines.
pub fn parse_sha256sums(text: &str) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut out = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let (hash, name) = if let Some((h, n)) = line.split_once("  ") {
            (h.trim(), n.trim())
        } else if let Some((h, n)) = line.split_once(" *") {
            (h.trim(), n.trim())
        } else if let Some((h, n)) = line.split_once('\t') {
            (h.trim(), n.trim())
        } else {
            continue;
        };
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("SHA256SUMS has a bad hash for {name}."));
        }
        let name = name.rsplit('/').next().unwrap_or(name);
        out.insert(name.to_string(), hash.to_ascii_lowercase());
    }
    if out.is_empty() {
        return Err("SHA256SUMS was empty or unreadable.".into());
    }
    Ok(out)
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut f = fs::File::open(path).map_err(|e| format!("Couldn't open {}: {e}", path.display()))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut ctx = ring::digest::Context::new(&SHA256);
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("Couldn't read {}: {e}", path.display()))?;
        if n == 0 { break; }
        ctx.update(&buf[..n]);
    }
    Ok(ctx.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

pub fn verify_file(path: &Path, expected_hex: &str) -> Result<(), String> {
    let got = sha256_file(path)?;
    if got != expected_hex.to_ascii_lowercase() {
        return Err(format!(
            "Checksum mismatch for {}: the file does not match SHA256SUMS.",
            path.file_name().and_then(|s| s.to_str()).unwrap_or("asset")
        ));
    }
    Ok(())
}

/// Pick the download URL for `name` from a GitHub release `assets` array.
pub fn asset_url(assets: &[Value], name: &str) -> Result<String, String> {
    for a in assets {
        if a["name"].as_str() == Some(name) {
            if let Some(u) = a["browser_download_url"].as_str() {
                return Ok(u.to_string());
            }
        }
    }
    Err(format!("Release has no asset named {name}."))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckState {
    pub last_checked: i64,
    pub latest: String,
    pub current: String,
    pub newer: bool,
    pub published_at: String,
    pub notes: String,
    pub html_url: String,
    pub bin_url: String,
    pub web_url: String,
    pub sums_url: String,
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Progress {
    pub phase: String, // Idle | Checking | Downloading | Verifying | Installing | Restarting | Done | Failed
    pub detail: String,
    pub error: String,
    pub busy: bool,
}

static STATE: OnceLock<Mutex<CheckState>> = OnceLock::new();
static PROGRESS: OnceLock<Mutex<Progress>> = OnceLock::new();

fn state() -> &'static Mutex<CheckState> {
    STATE.get_or_init(|| Mutex::new(CheckState { current: release::VERSION.into(), ..Default::default() }))
}
fn progress() -> &'static Mutex<Progress> {
    PROGRESS.get_or_init(|| Mutex::new(Progress { phase: "Idle".into(), ..Default::default() }))
}

fn state_path(dir: &str) -> PathBuf {
    PathBuf::from(dir).join("update-check.json")
}
fn pending_path(dir: &str) -> PathBuf {
    PathBuf::from(dir).join("update-pending.json")
}

pub fn load_state(dir: &str) {
    let path = state_path(dir);
    if let Ok(text) = fs::read_to_string(&path) {
        if let Ok(mut s) = serde_json::from_str::<CheckState>(&text) {
            s.current = release::VERSION.into();
            s.newer = compare_versions(release::VERSION, &s.latest) < 0;
            *state().lock().unwrap() = s;
        }
    }
}

fn save_state(dir: &str, s: &CheckState) {
    let _ = fs::write(state_path(dir), serde_json::to_string_pretty(s).unwrap_or_default());
}

fn set_progress(phase: impl Into<String>, detail: impl Into<String>, error: impl Into<String>, busy: bool) {
    let mut p = progress().lock().unwrap();
    p.phase = phase.into();
    p.detail = detail.into();
    p.error = error.into();
    p.busy = busy;
}

pub fn progress_json() -> Value {
    let p = progress().lock().unwrap().clone();
    serde_json::to_value(p).unwrap_or(Value::Null)
}

pub fn status_json(dir: &str) -> Value {
    let s = state().lock().unwrap().clone();
    let prev = release::previous();
    let pending = read_pending(dir);
    serde_json::json!({
        "current": release::VERSION,
        "latest": s.latest,
        "newer": s.newer,
        "published_at": s.published_at,
        "notes": s.notes,
        "html_url": s.html_url,
        "last_checked": s.last_checked,
        "error": s.error,
        "repo": repo_url(),
        "arch_asset": arch_asset().unwrap_or(""),
        "previous": prev.as_ref().map(|k| k.version.clone()),
        "pending": pending,
        "progress": progress_json(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUpdate {
    pub from: String,
    pub to: String,
    pub deadline: i64,
}

pub fn read_pending(dir: &str) -> Option<PendingUpdate> {
    let text = fs::read_to_string(pending_path(dir)).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn clear_pending(dir: &str) {
    let _ = fs::remove_file(pending_path(dir));
}

pub fn write_pending(dir: &str, from: &str, to: &str, rollback_secs: u64) -> Result<(), String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let p = PendingUpdate { from: from.into(), to: to.into(), deadline: now + rollback_secs as i64 };
    fs::write(pending_path(dir), serde_json::to_string_pretty(&p).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// Fetch latest release metadata and store it. Does not download installers.
pub fn check_now(dir: &str) -> Result<CheckState, String> {
    set_progress("Checking", "Asking GitHub for the latest release…", "", true);
    let url = latest_api_url()?;
    let resp = lists::agent()
        .get(&url)
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .call()
        .map_err(|e| format!("Could not reach GitHub Releases: {e}"))?;
    let mut body = String::new();
    resp.into_reader().take(2_000_000).read_to_string(&mut body).map_err(|e| format!("Could not read the release reply: {e}"))?;
    let v: Value = serde_json::from_str(&body).map_err(|_| "GitHub's reply was not valid JSON.".to_string())?;
    if let Some(msg) = v["message"].as_str() {
        set_progress("Failed", "", msg.to_string(), false);
        return Err(if msg.contains("Not Found") {
            "No release was found for this repository yet.".into()
        } else {
            format!("GitHub said: {msg}")
        });
    }
    let tag = v["tag_name"].as_str().unwrap_or("").trim_start_matches('v').to_string();
    if tag.is_empty() {
        set_progress("Failed", "", "Release has no version tag.", false);
        return Err("Release has no version tag.".into());
    }
    let assets = v["assets"].as_array().cloned().unwrap_or_default();
    let bin_name = arch_asset()?;
    let bin_url = asset_url(&assets, bin_name)?;
    let web_url = asset_url(&assets, "foilgw-web.tar.gz")?;
    let sums_url = asset_url(&assets, "SHA256SUMS")?;
    let notes = v["body"].as_str().unwrap_or("").to_string();
    let published = v["published_at"].as_str().unwrap_or("").to_string();
    let html_url = v["html_url"].as_str().unwrap_or("").to_string();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let s = CheckState {
        last_checked: now,
        latest: tag.clone(),
        current: release::VERSION.into(),
        newer: compare_versions(release::VERSION, &tag) < 0,
        published_at: published,
        notes,
        html_url,
        bin_url,
        web_url,
        sums_url,
        error: String::new(),
    };
    save_state(dir, &s);
    *state().lock().unwrap() = s.clone();
    set_progress("Idle", if s.newer { format!("Version {} is available.", s.latest) } else { String::from("You are on the latest version.") }, "", false);
    Ok(s)
}

/// Download, verify, install into slots, arm rollback pending, return Ok to restart.
pub fn install(dir: &str, rollback_secs: u64) -> Result<String, String> {
    let s = state().lock().unwrap().clone();
    if s.latest.is_empty() || s.bin_url.is_empty() {
        return Err("Check for updates first.".into());
    }
    if !s.newer && compare_versions(release::VERSION, &s.latest) >= 0 {
        return Err(format!("Already on {} (latest is {}).", release::VERSION, s.latest));
    }
    let tmp = PathBuf::from(format!("/tmp/foilgw-update-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).map_err(|e| format!("Could not create {tmp}: {e}", tmp = tmp.display()))?;
    let cleanup = |t: &Path| { let _ = fs::remove_dir_all(t); };

    let bin_name = arch_asset()?;
    let sums_path = tmp.join("SHA256SUMS");
    let bin_path = tmp.join(bin_name);
    let web_path = tmp.join("foilgw-web.tar.gz");

    set_progress("Downloading", "Downloading SHA256SUMS…", "", true);
    lists::download_to(&s.sums_url, &sums_path, 1_000_000, &|_, _| {}).map_err(|e| {
        cleanup(&tmp);
        set_progress("Failed", "", e.clone(), false);
        e
    })?;

    set_progress("Downloading", format!("Downloading {bin_name}…"), "", true);
    lists::download_to(&s.bin_url, &bin_path, DOWNLOAD_CAP, &|done, total| {
        let detail = if total > 0 {
            format!("Downloading {bin_name}… {} / {} bytes", done, total)
        } else {
            format!("Downloading {bin_name}… {} bytes", done)
        };
        set_progress("Downloading", &detail, "", true);
    }).map_err(|e| {
        cleanup(&tmp);
        set_progress("Failed", "", e.clone(), false);
        e
    })?;

    set_progress("Downloading", "Downloading foilgw-web.tar.gz…", "", true);
    lists::download_to(&s.web_url, &web_path, DOWNLOAD_CAP, &|done, total| {
        let detail = if total > 0 {
            format!("Downloading foilgw-web.tar.gz… {} / {} bytes", done, total)
        } else {
            format!("Downloading foilgw-web.tar.gz… {} bytes", done)
        };
        set_progress("Downloading", &detail, "", true);
    }).map_err(|e| {
        cleanup(&tmp);
        set_progress("Failed", "", e.clone(), false);
        e
    })?;

    set_progress("Verifying", "Checking SHA256SUMS…", "", true);
    let sums_text = fs::read_to_string(&sums_path).map_err(|e| {
        cleanup(&tmp);
        let m = format!("Could not read SHA256SUMS: {e}");
        set_progress("Failed", "", m.clone(), false);
        m
    })?;
    let sums = parse_sha256sums(&sums_text).map_err(|e| {
        cleanup(&tmp);
        set_progress("Failed", "", e.clone(), false);
        e
    })?;
    for (name, path) in [(bin_name, &bin_path), ("foilgw-web.tar.gz", &web_path)] {
        let Some(expect) = sums.get(name) else {
            cleanup(&tmp);
            let m = format!("SHA256SUMS is missing an entry for {name}.");
            set_progress("Failed", "", m.clone(), false);
            return Err(m);
        };
        verify_file(path, expect).map_err(|e| {
            cleanup(&tmp);
            set_progress("Failed", "", e.clone(), false);
            e
        })?;
    }

    set_progress("Installing", format!("Installing {}…", s.latest), "", true);
    let from = release::VERSION.to_string();
    let msg = release::update(&bin_path, Some(&web_path)).map_err(|e| {
        cleanup(&tmp);
        let m = format!("Install failed: {e}");
        set_progress("Failed", "", m.clone(), false);
        m
    })?;
    write_pending(dir, &from, &s.latest, rollback_secs).map_err(|e| {
        cleanup(&tmp);
        set_progress("Failed", "", e.clone(), false);
        e
    })?;
    cleanup(&tmp);
    set_progress("Restarting", "Restarting FoilGateway…", "", true);
    Ok(msg)
}

/// On serve start: load state, maybe auto-check, watch update-pending for rollback.
pub fn start_background(dir: String, rollback_secs: u64) {
    load_state(&dir);
    // Watchdog for a pending update confirm.
    let d = dir.clone();
    std::thread::Builder::new().name("fg-update-watch".into()).spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let Some(p) = read_pending(&d) else { continue };
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
            if now < p.deadline { continue; }
            eprintln!("foilgw: update to {} was not confirmed in time; rolling back to {}", p.to, p.from);
            clear_pending(&d);
            match release::rollback() {
                Ok(m) => {
                    eprintln!("foilgw: {m}");
                    // Exit so systemd restarts on the rolled-back binary.
                    std::process::exit(0);
                }
                Err(e) => eprintln!("foilgw: rollback after failed update confirm: {e}"),
            }
        }
    }).ok();

    // Daily check (and once shortly after start if never checked / stale).
    std::thread::Builder::new().name("fg-update-daily".into()).spawn(move || {
        loop {
            let due = {
                let s = state().lock().unwrap();
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
                s.last_checked == 0 || now.saturating_sub(s.last_checked) as u64 >= DAY_SECS
            };
            if due && !progress().lock().unwrap().busy {
                let _ = check_now(&dir);
            }
            std::thread::sleep(Duration::from_secs(3600));
        }
    }).ok();
    let _ = rollback_secs;
}

/// Ack that the UI reached the new build — clears the post-update rollback timer.
pub fn ack_pending(dir: &str) -> bool {
    if read_pending(dir).is_some() {
        clear_pending(dir);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn version_compare_orders() {
        assert_eq!(compare_versions("1.0.0", "1.0.0"), 0);
        assert_eq!(compare_versions("1.0.0", "1.0.1"), -1);
        assert_eq!(compare_versions("1.1.0", "1.0.9"), 1);
        assert_eq!(compare_versions("v1.0.0", "1.0.0"), 0);
        assert_eq!(compare_versions("0.7.8", "1.0.0"), -1);
    }

    #[test]
    fn sha256sums_parse_and_verify() {
        let dir = std::env::temp_dir().join(format!("fg-upd-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("foilgw-x86_64");
        fs::write(&f, b"hello-update").unwrap();
        let hash = sha256_file(&f).unwrap();
        let text = format!("{hash}  foilgw-x86_64\n{hash}  foilgw-web.tar.gz\n");
        let map = parse_sha256sums(&text).unwrap();
        assert_eq!(map.get("foilgw-x86_64").unwrap(), &hash);
        verify_file(&f, &hash).unwrap();
        assert!(verify_file(&f, "0".repeat(64).as_str()).is_err());
        assert!(parse_sha256sums("# only comment\n").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn asset_selection_and_missing() {
        let assets = vec![
            json!({"name": "foilgw-x86_64", "browser_download_url": "https://example/x"}),
            json!({"name": "foilgw-web.tar.gz", "browser_download_url": "https://example/w"}),
            json!({"name": "SHA256SUMS", "browser_download_url": "https://example/s"}),
        ];
        assert_eq!(asset_url(&assets, "foilgw-x86_64").unwrap(), "https://example/x");
        assert!(asset_url(&assets, "foilgw-riscv64").unwrap_err().contains("no asset"));
    }

    #[test]
    fn refuse_missing_sums_entry() {
        let text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  other\n";
        let map = parse_sha256sums(text).unwrap();
        assert!(map.get("foilgw-x86_64").is_none());
    }

    #[test]
    fn repo_slug_from_cargo() {
        // Built with repository set in Cargo.toml for 1.0.0.
        let slug = repo_slug();
        assert!(slug.is_some(), "CARGO_PKG_REPOSITORY should be set");
        assert_eq!(slug.unwrap(), "iBgeek/FoilGateway-Network");
        let url = latest_api_url().unwrap();
        assert!(url.ends_with("/releases/latest"));
        assert!(url.contains("api.github.com/repos/"));
    }
}
