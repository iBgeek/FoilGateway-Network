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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Automatic check interval after a successful check.
const CHECK_SECS: u64 = 60 * 60;
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
    /// When the last failed check happened (0 = last check succeeded).
    #[serde(default)]
    pub error_at: i64,
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
/// One updater operation (check or install) at a time.
static BUSY: AtomicBool = AtomicBool::new(false);

fn state() -> &'static Mutex<CheckState> {
    STATE.get_or_init(|| Mutex::new(CheckState { current: release::VERSION.into(), ..Default::default() }))
}
fn progress() -> &'static Mutex<Progress> {
    PROGRESS.get_or_init(|| Mutex::new(Progress { phase: "Idle".into(), ..Default::default() }))
}

/// Held for the length of a check or install. Dropping it frees the slot and,
/// unless `keep` was called, makes sure progress no longer says busy.
struct Op {
    keep: bool,
}
impl Op {
    fn begin() -> Result<Op, String> {
        BUSY.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Op { keep: false })
            .map_err(|_| "An update check or install is already running. Try again in a moment.".to_string())
    }
    /// Install succeeded and the process is about to restart: stay busy.
    fn keep(mut self) {
        self.keep = true;
    }
}
impl Drop for Op {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        {
            let mut p = progress().lock().unwrap();
            if p.busy {
                p.busy = false;
                if p.phase != "Failed" {
                    p.phase = "Idle".into();
                }
            }
        }
        BUSY.store(false, Ordering::Release);
    }
}

/// Holds the update slot for a manual Roll Back. Keep it until the process
/// restarts; dropping it (rollback failed) frees the slot.
pub struct RollbackSlot(#[allow(dead_code)] Op);
pub fn begin_rollback() -> Result<RollbackSlot, String> {
    Op::begin().map(RollbackSlot)
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

/// The newer version this gateway knows about, if any. Reads memory only:
/// no GitHub call and no change to the post-install confirm.
pub fn available() -> Option<String> {
    let s = state().lock().unwrap();
    s.newer.then(|| s.latest.clone())
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
    let now = unix_now();
    let p = PendingUpdate { from: from.into(), to: to.into(), deadline: now + rollback_secs as i64 };
    fs::write(pending_path(dir), serde_json::to_string_pretty(&p).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

/// A failed check: what to show, and how long GitHub asked us to wait (seconds).
#[derive(Debug)]
pub struct CheckError {
    pub message: String,
    pub retry_after: Option<u64>,
}
impl From<String> for CheckError {
    fn from(message: String) -> Self {
        CheckError { message, retry_after: None }
    }
}

/// Release-metadata request limits, separate from list/asset downloads, so a
/// hung server cannot hold the update slot for long.
const CHECK_CONNECT: Duration = Duration::from_secs(5);
const CHECK_TOTAL: Duration = Duration::from_secs(20);
#[cfg(test)]
static TEST_TIMEOUT: Mutex<Option<Duration>> = Mutex::new(None);
#[cfg(test)]
pub(crate) fn set_test_timeout(d: Duration) {
    *TEST_TIMEOUT.lock().unwrap() = Some(d);
}
fn check_total() -> Duration {
    #[cfg(test)]
    if let Some(d) = *TEST_TIMEOUT.lock().unwrap() {
        return d;
    }
    CHECK_TOTAL
}
fn check_agent() -> ureq::AgentBuilder {
    ureq::AgentBuilder::new()
        .timeout_connect(CHECK_CONNECT)
        .timeout(check_total())
        .user_agent(concat!("FoilGateway/", env!("CARGO_PKG_VERSION")))
}
#[cfg(test)]
static TEST_API: Mutex<Option<(String, Vec<u8>)>> = Mutex::new(None);
/// Test builds only: point checks at a local TLS fixture trusted through a test CA (DER).
#[cfg(test)]
pub(crate) fn set_test_api(url: String, ca_der: Vec<u8>) {
    *TEST_API.lock().unwrap() = Some((url, ca_der));
}

fn api_client() -> Result<(String, ureq::Agent), String> {
    #[cfg(test)]
    if let Some((url, ca)) = TEST_API.lock().unwrap().clone() {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(ca)).map_err(|e| e.to_string())?;
        let cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let agent = check_agent().tls_config(std::sync::Arc::new(cfg)).build();
        return Ok((url, agent));
    }
    Ok((latest_api_url()?, check_agent().build()))
}

/// Seconds GitHub asked us to wait, from Retry-After or an exhausted rate limit.
fn wait_hint(resp: &ureq::Response) -> Option<u64> {
    if let Some(s) = resp.header("retry-after").and_then(|v| retry_after_secs(v, unix_now())) {
        return Some(s);
    }
    if resp.header("x-ratelimit-remaining").map(str::trim) == Some("0") {
        let reset = resp.header("x-ratelimit-reset")?.trim().parse::<i64>().ok()?;
        return Some(reset.saturating_sub(unix_now()).max(0) as u64);
    }
    None
}

/// Retry-After as seconds: delay-seconds or an IMF-fixdate HTTP-date
/// ("Sun, 06 Nov 1994 08:49:37 GMT"). The obsolete RFC 850 and asctime
/// date forms are not recognised (then our own backoff applies).
pub(crate) fn retry_after_secs(v: &str, now: i64) -> Option<u64> {
    let v = v.trim();
    if let Ok(s) = v.parse::<u64>() {
        return Some(s);
    }
    let p: Vec<&str> = v.split(' ').collect();
    if p.len() != 6 || p[5] != "GMT" || !p[0].ends_with(',') {
        return None;
    }
    let d: i64 = p[1].parse().ok().filter(|_| p[1].len() == 2)?;
    let m = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].iter().position(|x| *x == p[2])? as i64 + 1;
    let y: i64 = p[3].parse().ok().filter(|_| p[3].len() == 4)?;
    let t: Vec<i64> = p[4].split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    if t.len() != 3 || !(1..=31).contains(&d) || t[0] > 23 || t[1] > 59 || t[2] > 60 {
        return None;
    }
    let at = days_from_civil(y, m, d) * 86400 + t[0] * 3600 + t[1] * 60 + t[2];
    Some(at.saturating_sub(now).max(0) as u64)
}
/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468
}
#[cfg(test)]
fn civil(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Ask GitHub for the latest release. No state change.
fn fetch_latest() -> Result<CheckState, CheckError> {
    let (url, agent) = api_client()?;
    let resp = match agent
        .get(&url)
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .call()
    {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            let retry_after = wait_hint(&r);
            let mut body = String::new();
            let _ = r.into_reader().take(64_000).read_to_string(&mut body);
            let msg = serde_json::from_str::<Value>(&body).ok().and_then(|v| v["message"].as_str().map(String::from));
            let message = match (code, msg) {
                (404, _) => "No release was found for this repository yet.".into(),
                (_, Some(m)) => format!("GitHub said: {m}"),
                (c, None) => format!("GitHub answered with status {c}."),
            };
            return Err(CheckError { message, retry_after });
        }
        Err(e) => return Err(format!("Could not reach GitHub Releases: {e}").into()),
    };
    let mut body = String::new();
    resp.into_reader().take(2_000_000).read_to_string(&mut body).map_err(|e| format!("Could not read the release reply: {e}"))?;
    let v: Value = serde_json::from_str(&body).map_err(|_| "GitHub's reply was not valid JSON.".to_string())?;
    if let Some(msg) = v["message"].as_str() {
        return Err(format!("GitHub said: {msg}").into());
    }
    let tag = v["tag_name"].as_str().unwrap_or("").trim().trim_start_matches('v').to_string();
    if tag.is_empty() || !tag.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())) {
        return Err(String::from("Release has no valid version tag.").into());
    }
    let assets = v["assets"].as_array().cloned().unwrap_or_default();
    let bin_name = arch_asset()?;
    let bin_url = asset_url(&assets, bin_name)?;
    let web_url = asset_url(&assets, "foilgw-web.tar.gz")?;
    let sums_url = asset_url(&assets, "SHA256SUMS")?;
    Ok(CheckState {
        last_checked: unix_now(),
        newer: compare_versions(release::VERSION, &tag) < 0,
        latest: tag,
        current: release::VERSION.into(),
        published_at: v["published_at"].as_str().unwrap_or("").to_string(),
        notes: v["body"].as_str().unwrap_or("").to_string(),
        html_url: v["html_url"].as_str().unwrap_or("").to_string(),
        bin_url,
        web_url,
        sums_url,
        error: String::new(),
        error_at: 0,
    })
}

/// Fetch latest release metadata and store it. Does not download installers.
/// On failure the last known release stays (so a known update stays visible)
/// and the error is recorded.
pub fn check_now(dir: &str) -> Result<CheckState, String> {
    check_once(dir).map_err(|e| e.message)
}

fn check_once(dir: &str) -> Result<CheckState, CheckError> {
    let _op = Op::begin()?;
    set_progress("Checking", "Asking GitHub for the latest release…", "", true);
    match fetch_latest() {
        Ok(s) => {
            save_state(dir, &s);
            *state().lock().unwrap() = s.clone();
            set_progress("Idle", if s.newer { format!("Version {} is available.", s.latest) } else { String::from("You are on the latest version.") }, "", false);
            Ok(s)
        }
        Err(e) => {
            let mut s = state().lock().unwrap();
            s.error = e.message.clone();
            s.error_at = unix_now();
            save_state(dir, &s);
            drop(s);
            set_progress("Failed", "", e.message.clone(), false);
            Err(e)
        }
    }
}

/// Download, verify, install into slots, arm rollback pending, return Ok to restart.
pub fn install(dir: &str, rollback_secs: u64) -> Result<String, String> {
    let op = Op::begin()?;
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
    op.keep();
    Ok(msg)
}

/// When the automatic checker runs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timing {
    /// First check after start: every start (restart, rollback, new version) checks fresh.
    pub first: Duration,
    /// After a successful check.
    pub every: Duration,
    /// First retry after a failure; doubles each failure up to `every`.
    pub retry: Duration,
}
pub(crate) const TIMING: Timing = Timing { first: Duration::from_secs(5), every: Duration::from_secs(CHECK_SECS), retry: Duration::from_secs(60) };

/// How long to wait before the next automatic check.
pub(crate) fn next_delay(t: Timing, failures: u32, retry_after: Option<u64>) -> Duration {
    if failures == 0 {
        return t.every;
    }
    // Our own backoff is capped; a wait GitHub asked for is never shortened.
    let backoff = t.retry.saturating_mul(1u32 << (failures - 1).min(16)).min(t.every);
    backoff.max(Duration::from_secs(retry_after.unwrap_or(0)))
}

/// The automatic checker. `sleep` returns false to stop (tests); the real one never stops.
pub(crate) fn run_checks(dir: &str, t: Timing, mut sleep: impl FnMut(Duration) -> bool) {
    let mut failures = 0u32;
    let mut wait = t.first;
    while sleep(wait) {
        wait = match check_once(dir) {
            Ok(_) => {
                failures = 0;
                next_delay(t, 0, None)
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                next_delay(t, failures, e.retry_after)
            }
        };
    }
}

/// On serve start: load state, check soon, then keep checking; watch update-pending for rollback.
pub fn start_background(dir: String, rollback_secs: u64) {
    load_state(&dir);
    // Watchdog for a pending update confirm.
    let d = dir.clone();
    std::thread::Builder::new().name("fg-update-watch".into()).spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let Some(p) = read_pending(&d) else { continue };
            let now = unix_now();
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
    start_checker(dir, TIMING);
    let _ = rollback_secs;
}

pub(crate) fn start_checker(dir: String, t: Timing) {
    std::thread::Builder::new().name("fg-update-check".into()).spawn(move || {
        run_checks(&dir, t, |d| {
            std::thread::sleep(d);
            true
        })
    }).ok();
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

#[cfg(test)]
mod check_schedule {
    //! Real HTTPS release API fixture (local TLS, test CA) plus a controlled clock for the scheduler.
    use super::*;
    use std::io::Write;
    use std::sync::Arc;
    static SERIAL: Mutex<()> = Mutex::new(());

    type Reply = Arc<Mutex<(u16, Vec<(String, String)>, String)>>;
    struct Fixture {
        reply: Reply,
        hits: Arc<std::sync::atomic::AtomicUsize>,
        dir: String,
    }
    fn release(tag: &str) -> String {
        let a = |n: &str| serde_json::json!({"name": n, "browser_download_url": format!("https://example.invalid/{n}")});
        serde_json::json!({"tag_name": tag, "body": "notes", "published_at": "2026-11-08T00:00:00Z", "html_url": "https://example.invalid/r",
            "assets": [a("foilgw-x86_64"), a("foilgw-riscv64"), a("foilgw-web.tar.gz"), a("SHA256SUMS")]}).to_string()
    }
    fn fixture(name: &str) -> Fixture {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(c.key_pair.serialize_der().into());
        let cfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions().unwrap().with_no_client_auth()
                .with_single_cert(vec![c.cert.der().clone()], key).unwrap(),
        );
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let reply: Reply = Arc::new(Mutex::new((200, vec![], release("v1.1.1"))));
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (r, h) = (reply.clone(), hits.clone());
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let (r, h, cfg) = (r.clone(), h.clone(), cfg.clone());
                std::thread::spawn(move || {
                    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut t = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), s);
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if t.read_exact(&mut b).is_err() { return; }
                        head.push(b[0]);
                    }
                    h.fetch_add(1, Ordering::SeqCst);
                    let (code, headers, body) = r.lock().unwrap().clone();
                    if code == 0 {
                        std::thread::sleep(Duration::from_secs(4));
                        return;
                    }
                    let mut out = format!("HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
                    for (k, v) in headers { out += &format!("{k}: {v}\r\n"); }
                    out += "\r\n";
                    let _ = t.write_all(out.as_bytes());
                    let _ = t.write_all(body.as_bytes());
                    let _ = t.flush();
                    t.conn.send_close_notify();
                    let _ = t.flush();
                });
            }
        });
        set_test_api(format!("https://localhost:{port}/repos/iBgeek/FoilGateway-Network/releases/latest"), c.cert.der().to_vec());
        let dir = std::env::temp_dir().join(format!("fg-upd-sched-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        *state().lock().unwrap() = CheckState { current: release::VERSION.into(), ..Default::default() };
        set_progress("Idle", "", "", false);
        Fixture { reply, hits, dir: dir.to_string_lossy().into() }
    }
    fn not_busy() -> bool {
        !progress().lock().unwrap().busy && !BUSY.load(Ordering::Acquire)
    }

    #[test]
    fn success_finds_newer_release_over_tls() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = fixture("ok");
        *f.reply.lock().unwrap() = (200, vec![], release("v99.0.0"));
        let s = check_now(&f.dir).unwrap();
        assert!(s.newer && s.latest == "99.0.0" && s.error.is_empty());
        assert_eq!(available().as_deref(), Some("99.0.0"));
        assert!(not_busy());
        let saved: CheckState = serde_json::from_str(&fs::read_to_string(state_path(&f.dir)).unwrap()).unwrap();
        assert_eq!(saved.latest, "99.0.0");
    }

    #[test]
    fn every_failure_clears_busy_keeps_known_update_and_records_error() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = fixture("fail");
        *f.reply.lock().unwrap() = (200, vec![], release("v99.0.0"));
        check_now(&f.dir).unwrap();
        let bad_tag = release("vNEXT");
        let no_tag = serde_json::json!({"assets": []}).to_string();
        let no_assets = serde_json::json!({"tag_name": "v99.1.0", "assets": []}).to_string();
        let cases: Vec<(u16, Vec<(String, String)>, String, &str)> = vec![
            (500, vec![], "oops".into(), "status 500"),
            (404, vec![], "{\"message\":\"Not Found\"}".into(), "No release"),
            (403, vec![("x-ratelimit-remaining".into(), "0".into())], "{\"message\":\"API rate limit exceeded\"}".into(), "rate limit"),
            (200, vec![], "not json".into(), "not valid JSON"),
            (200, vec![], no_tag, "version tag"),
            (200, vec![], bad_tag, "version tag"),
            (200, vec![], no_assets, "no asset"),
        ];
        for (code, headers, body, want) in cases {
            *f.reply.lock().unwrap() = (code, headers, body);
            let e = check_now(&f.dir).unwrap_err();
            assert!(e.contains(want), "{e}");
            assert!(not_busy(), "busy left set after: {e}");
            let s = state().lock().unwrap().clone();
            assert!(s.newer && s.latest == "99.0.0", "known update lost after: {e}");
            assert_eq!(s.error, e);
            assert!(s.error_at > 0);
            assert_eq!(progress().lock().unwrap().phase, "Failed");
        }
        // Unreachable server.
        set_test_api("https://localhost:9/x".into(), vec![1, 2, 3]);
        assert!(check_now(&f.dir).is_err());
        assert!(not_busy());
        // Recovery clears the error.
        let f = fixture("recover");
        *f.reply.lock().unwrap() = (200, vec![], release("v99.0.0"));
        let s = check_now(&f.dir).unwrap();
        assert!(s.error.is_empty() && s.error_at == 0);
    }

    #[test]
    fn retry_after_and_rate_limit_reset_are_honoured() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = fixture("retry");
        *f.reply.lock().unwrap() = (429, vec![("retry-after".into(), "120".into())], "{}".into());
        assert_eq!(check_once(&f.dir).unwrap_err().retry_after, Some(120));
        let reset = unix_now() + 900;
        *f.reply.lock().unwrap() = (403, vec![("x-ratelimit-remaining".into(), "0".into()), ("x-ratelimit-reset".into(), reset.to_string())], "{\"message\":\"API rate limit exceeded\"}".into());
        let w = check_once(&f.dir).unwrap_err().retry_after.unwrap();
        assert!((895..=900).contains(&w), "{w}");
        let t = TIMING;
        assert_eq!(next_delay(t, 1, Some(900)), Duration::from_secs(900));
        assert_eq!(next_delay(t, 1, Some(99_999)), Duration::from_secs(99_999), "never earlier than GitHub asked");
        assert_eq!(next_delay(t, 9, None), t.every, "our own backoff is capped");
        // HTTP-date Retry-After (IMF-fixdate).
        assert_eq!(retry_after_secs("Sun, 06 Nov 1994 08:49:37 GMT", 784111717), Some(60));
        assert_eq!(retry_after_secs("Sun, 06 Nov 1994 08:49:37 GMT", 784111800), Some(0), "past date means now");
        assert_eq!(retry_after_secs(" 45 ", 0), Some(45));
        assert_eq!(retry_after_secs("Sunday, 06-Nov-94 08:49:37 GMT", 0), None, "obsolete RFC 850 form unsupported");
        let date = |t: i64| {
            let (days, secs) = (t.div_euclid(86400), t.rem_euclid(86400));
            let (y, m, d) = civil(days);
            let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
            let mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][m as usize - 1];
            format!("{wd}, {d:02} {mon} {y} {:02}:{:02}:{:02} GMT", secs / 3600, secs / 60 % 60, secs % 60)
        };
        *f.reply.lock().unwrap() = (503, vec![("retry-after".into(), date(unix_now() + 300))], "{}".into());
        let w = check_once(&f.dir).unwrap_err().retry_after.unwrap();
        assert!((295..=300).contains(&w), "{w}");
    }

    #[test]
    fn stalled_reply_times_out_and_frees_the_slot() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = fixture("stall");
        assert_eq!((CHECK_CONNECT, CHECK_TOTAL), (Duration::from_secs(5), Duration::from_secs(20)));
        set_test_timeout(Duration::from_millis(800));
        *f.reply.lock().unwrap() = (0, vec![], String::new()); // 0 = accept, handshake, never answer
        let t0 = std::time::Instant::now();
        let e = check_now(&f.dir).unwrap_err();
        let took = t0.elapsed();
        set_test_timeout(CHECK_TOTAL);
        assert!(took < Duration::from_secs(3), "{took:?} {e}");
        assert!(not_busy());
        *f.reply.lock().unwrap() = (200, vec![], release("v1.1.1"));
        assert!(check_now(&f.dir).is_ok(), "slot free after the timeout");
    }

    #[test]
    fn manual_rollback_shares_the_operation_slot() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = fixture("rollback");
        let held = Op::begin().unwrap();
        assert!(begin_rollback().err().unwrap().contains("already running"));
        drop(held);
        let rb = begin_rollback().unwrap();
        let hits = f.hits.load(Ordering::SeqCst);
        assert!(check_now(&f.dir).unwrap_err().contains("already running"));
        assert!(install(&f.dir, 180).unwrap_err().contains("already running"));
        assert_eq!(f.hits.load(Ordering::SeqCst), hits);
        drop(rb); // a failed rollback releases it
        assert!(not_busy());
        assert!(check_now(&f.dir).is_ok());
    }

    #[test]
    fn only_one_operation_at_a_time() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = fixture("excl");
        let held = Op::begin().unwrap();
        let hits = f.hits.load(Ordering::SeqCst);
        assert!(check_now(&f.dir).unwrap_err().contains("already running"));
        assert!(install(&f.dir, 180).unwrap_err().contains("already running"));
        assert_eq!(f.hits.load(Ordering::SeqCst), hits, "no request while another operation runs");
        drop(held);
        assert!(check_now(&f.dir).is_ok());
        // Install refusing early (no newer release) frees the slot again.
        assert!(install(&f.dir, 180).is_err());
        assert!(not_busy());
    }

    #[test]
    fn scheduler_checks_at_start_hourly_and_backs_off_on_failure() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = fixture("sched");
        // Stale-looking cache from yesterday's build: still checked right after start.
        *state().lock().unwrap() = CheckState { last_checked: unix_now() - 60, latest: "1.0.1".into(), ..Default::default() };
        let plan: Vec<(u16, &str)> = vec![(200, "v1.0.1"), (500, ""), (500, ""), (500, ""), (200, "v99.0.0"), (200, "v99.0.0")];
        let mut waits = Vec::new();
        let mut step = 0usize;
        let reply = f.reply.clone();
        run_checks(&f.dir, TIMING, |d| {
            waits.push(d);
            if step == plan.len() { return false; }
            let (code, tag) = plan[step];
            *reply.lock().unwrap() = (code, vec![], if code == 200 { release(tag) } else { "x".into() });
            step += 1;
            true
        });
        let m = |s| Duration::from_secs(s);
        assert_eq!(waits, vec![m(5), m(3600), m(60), m(120), m(240), m(3600), m(3600)]);
        assert_eq!(f.hits.load(Ordering::SeqCst), 6);
        assert_eq!(available().as_deref(), Some("99.0.0"));
        assert!(not_busy());
    }
}
