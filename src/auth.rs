//! Admin accounts, sign-in sessions and the sign-in rate limit.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Every permission a Custom user can be given: (id, group, label).
/// Anything not listed here stays with admins.
pub const PERMS: &[(&str, &str, &str)] = &[
    ("status", "Monitoring", "Status and dashboard"),
    ("devices", "Monitoring", "Devices: list, new and waiting"),
    ("alerts", "Monitoring", "Alerts and audit"),
    ("log", "Monitoring", "Capture Log"),
    ("firewall_view", "Monitoring", "Firewall rules and ports (view only)"),
    ("speed_view", "Monitoring", "Speed test results"),
    ("updates_view", "Monitoring", "Updates: see if one is out"),
    ("device_actions", "Actions", "Block or allow a device, approve or deny a new one"),
    ("block_list", "Actions", "Block list: add or remove an address, network, website or port"),
    ("allow_list", "Actions", "Allow list: add or remove exceptions"),
    ("handle_alerts", "Actions", "Mark alerts handled"),
    ("speed_run", "Actions", "Run a speed test"),
    ("updates_check", "Actions", "Check for updates"),
];

/// Each permission needs the pages it is used from: (permission, view it implies).
/// Ticking an action ticks its view; saving or loading a user adds it.
pub const IMPLIES: &[(&str, &str)] = &[
    ("speed_run", "speed_view"),
    ("updates_check", "updates_view"),
    ("handle_alerts", "status"),
    ("device_actions", "devices"),
    ("block_list", "firewall_view"),
    ("allow_list", "firewall_view"),
    // The Troubleshooter is under Devices and the Audit page under Firewall.
    ("alerts", "devices"),
    ("alerts", "firewall_view"),
];

/// `perms` plus every view they imply, in PERMS order. Ids this build
/// doesn't know are kept at the end.
pub fn with_implied(perms: &[String]) -> Vec<String> {
    let has = |id: &str| perms.iter().any(|p| p == id) || IMPLIES.iter().any(|(a, v)| *v == id && perms.iter().any(|p| p == a));
    let mut out: Vec<String> = PERMS.iter().filter(|(id, ..)| has(id)).map(|(id, ..)| id.to_string()).collect();
    for p in perms {
        if !out.contains(p) {
            out.push(p.clone());
        }
    }
    out
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    /// Empty when this user has no password (API only).
    pub hash: String,
    #[serde(default = "admin")]
    pub role: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub perms: Vec<String>,
    #[serde(default = "yes")]
    pub web: bool,
    #[serde(default)]
    pub api: bool,
    /// SHA-256 of the API key, hex. The key itself is never kept.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_hint: String,
    #[serde(default)]
    pub key_made: i64,
    #[serde(default)]
    pub key_used: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_from: String,
    /// On disk only: the password hash of a user who isn't a web admin.
    /// Kept out of "hash" so an older version, after a rollback, can't
    /// let a Custom or API-only user sign in with full rights.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pw: String,
}

/// users.json as written to disk. See `User::pw`.
fn to_disk(users: &[User]) -> Vec<User> {
    users
        .iter()
        .map(|u| {
            let mut d = u.clone();
            if !(d.role == "admin" && d.web) {
                d.pw = std::mem::take(&mut d.hash);
            }
            d
        })
        .collect()
}

fn from_disk(mut users: Vec<User>) -> Vec<User> {
    for u in &mut users {
        // Users saved before views were implied get them now (written on the next save).
        if u.role != "admin" {
            u.perms = with_implied(&u.perms);
        }
        if u.hash.is_empty() {
            u.hash = std::mem::take(&mut u.pw);
        }
        u.pw.clear();
    }
    users
}

fn yes() -> bool {
    true
}

/// Who is asking, looked up fresh for every request so a change to a user
/// takes effect at once.
#[derive(Clone, Debug)]
pub struct Who {
    pub name: String,
    pub admin: bool,
    pub perms: Vec<String>,
    pub via_key: bool,
}

impl Who {
    pub fn can(&self, perm: &str) -> bool {
        self.admin || self.perms.iter().any(|p| p == perm)
    }
}

/// What the Users page sends to add or change one user.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Edit {
    /// Empty for a new user.
    #[serde(default)]
    pub old_name: String,
    pub name: String,
    pub role: String,
    #[serde(default)]
    pub perms: Vec<String>,
    #[serde(default)]
    pub web: bool,
    #[serde(default)]
    pub api: bool,
    /// Empty leaves the password as it is.
    #[serde(default)]
    pub password: String,
}

const KEY_PREFIX: &str = "fgk_";

fn sha256_hex(b: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, b).as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

/// Same time whatever the contents, so a wrong key can't be guessed bit by bit.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Someone who can still sign in and do everything.
fn usable_admin(u: &User) -> bool {
    u.role == "admin" && u.web && !u.hash.is_empty()
}

fn admin() -> String {
    "admin".into()
}

pub struct Session {
    pub user: String,
    pub ip: String,
    pub started: i64,
    last: Instant,
}

// Signed-in browsers stay signed in this long without using the page.
const IDLE: Duration = Duration::from_secs(8 * 3600);
const TRIES: usize = 5;
const WINDOW: Duration = Duration::from_secs(300);

pub struct Auth {
    path: String,
    users: Mutex<Vec<User>>,
    sessions: Mutex<HashMap<String, Session>>,
    fails: Mutex<HashMap<String, Vec<Instant>>>,
    /// When key use times were last written, so a busy API client
    /// doesn't write the users file on every request.
    use_saved: Mutex<Option<Instant>>,
}

pub fn hash(password: &str) -> Result<String, String> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).map_err(|e| e.to_string())?;
    let salt = SaltString::encode_b64(&raw).map_err(|e| e.to_string())?;
    Argon2::default().hash_password(password.as_bytes(), &salt).map(|h| h.to_string()).map_err(|e| e.to_string())
}

fn verify(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).map(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok()).unwrap_or(false)
}

pub fn check_password(p: &str) -> Result<(), String> {
    if p.chars().count() < 10 {
        return Err("Use at least 10 characters. Longer is safer.".into());
    }
    Ok(())
}

pub fn check_name(n: &str) -> Result<(), String> {
    if n.is_empty() || n.len() > 32 || !n.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_') {
        return Err("User names use letters, numbers, dot, dash or underscore.".into());
    }
    Ok(())
}

pub fn token() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("no random numbers from the system");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn new_admin(name: &str, hash: String) -> User {
    User { name: name.into(), hash, role: admin(), perms: vec![], web: true, api: false, key_hash: String::new(), key_hint: String::new(), key_made: 0, key_used: 0, key_from: String::new(), pw: String::new() }
}

impl Auth {
    pub fn load(path: &str) -> Auth {
        let users = std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str(&t).ok()).map(from_disk).unwrap_or_default();
        Auth { path: path.into(), users: Mutex::new(users), sessions: Mutex::new(HashMap::new()), fails: Mutex::new(HashMap::new()), use_saved: Mutex::new(None) }
    }

    fn save(&self, users: &[User]) -> Result<(), String> {
        use std::io::Write;
        let tmp = format!("{}.new", self.path);
        let text = serde_json::to_string_pretty(&to_disk(users)).map_err(|e| e.to_string())?;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            o.mode(0o600);
            // An older file made with wider rights keeps them on open, so set them too.
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        let mut f = o.open(&tmp).map_err(|e| e.to_string())?;
        f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }

    pub fn has_users(&self) -> bool {
        !self.users.lock().unwrap().is_empty()
    }

    pub fn names(&self) -> Vec<(String, String)> {
        self.users.lock().unwrap().iter().map(|u| (u.name.clone(), u.role.clone())).collect()
    }

    /// Everything the Users page shows. Never the key or password.
    pub fn list(&self) -> Vec<serde_json::Value> {
        self.users
            .lock()
            .unwrap()
            .iter()
            .map(|u| {
                serde_json::json!({
                    "name": u.name, "role": u.role, "perms": u.perms, "web": u.web, "api": u.api,
                    "has_password": !u.hash.is_empty(), "has_key": !u.key_hash.is_empty(),
                    "key_hint": u.key_hint, "key_made": u.key_made, "key_used": u.key_used, "key_from": u.key_from,
                })
            })
            .collect()
    }

    pub fn who(&self, name: &str) -> Option<Who> {
        let users = self.users.lock().unwrap();
        let u = users.iter().find(|u| u.name == name)?;
        Some(Who { name: u.name.clone(), admin: u.role == "admin", perms: if u.role == "admin" { vec![] } else { u.perms.clone() }, via_key: false })
    }

    #[cfg(test)]
    pub fn add(&self, name: &str, password: &str) -> Result<(), String> {
        check_name(name)?;
        check_password(password)?;
        let mut users = self.users.lock().unwrap();
        if users.iter().any(|u| u.name == name) {
            return Err(format!("{name} already exists."));
        }
        users.push(new_admin(name, hash(password)?));
        self.save(&users)
    }

    /// For setup, which hashed the password when it was typed.
    pub fn add_hashed(&self, name: &str, hash: &str) -> Result<(), String> {
        check_name(name)?;
        let mut users = self.users.lock().unwrap();
        if users.iter().any(|u| u.name == name) {
            return Err(format!("{name} already exists."));
        }
        users.push(new_admin(name, hash.into()));
        self.save(&users)
    }

    /// Adds a user (old_name empty) or changes one. Returns a line for the log.
    pub fn edit(&self, e: &Edit) -> Result<String, String> {
        check_name(&e.name)?;
        if e.role != "admin" && e.role != "custom" {
            return Err("Pick Admin or Custom.".into());
        }
        let mut perms: Vec<String> = Vec::new();
        if e.role == "custom" {
            for p in &e.perms {
                if !PERMS.iter().any(|(id, ..)| id == p) {
                    return Err("Unknown permission.".into());
                }
                if !perms.contains(p) {
                    perms.push(p.clone());
                }
            }
        }
        if !e.password.is_empty() {
            check_password(&e.password)?;
        }
        let new_hash = if e.password.is_empty() { None } else { Some(hash(&e.password)?) };
        let mut users = self.users.lock().unwrap();
        let mut next = users.clone();
        let adding = e.old_name.is_empty();
        if (adding || e.old_name != e.name) && next.iter().any(|u| u.name == e.name) {
            return Err(format!("{} already exists.", e.name));
        }
        let idx = if adding {
            next.push(new_admin(&e.name, String::new()));
            next.len() - 1
        } else {
            next.iter().position(|u| u.name == e.old_name).ok_or("No such user.")?
        };
        let u = &mut next[idx];
        let was_web = u.web;
        u.name = e.name.clone();
        u.role = e.role.clone();
        u.perms = with_implied(&perms);
        u.web = e.web;
        u.api = e.api;
        if let Some(h) = new_hash {
            u.hash = h;
        }
        if u.web && u.hash.is_empty() {
            return Err("Set a password so this user can sign in on this page.".into());
        }
        if !next.iter().any(usable_admin) {
            return Err("Keep at least one admin who can sign in, or nobody can manage the gateway.".into());
        }
        self.save(&next)?;
        let line = if adding { format!("added {} user {}", e.role, e.name) } else { format!("changed user {}", e.name) };
        let ended_web = was_web && !e.web;
        *users = next;
        drop(users);
        let mut sessions = self.sessions.lock().unwrap();
        if ended_web {
            sessions.retain(|_, s| s.user != e.old_name);
        } else if !adding && e.old_name != e.name {
            for s in sessions.values_mut() {
                if s.user == e.old_name {
                    s.user = e.name.clone();
                }
            }
        }
        Ok(line)
    }

    pub fn remove(&self, name: &str) -> Result<(), String> {
        let mut users = self.users.lock().unwrap();
        if !users.iter().any(|u| u.name == name) {
            return Err("No such user.".into());
        }
        if !users.iter().filter(|u| u.name != name).any(usable_admin) {
            return Err("Keep at least one admin who can sign in, or nobody can manage the gateway.".into());
        }
        let next: Vec<User> = users.iter().filter(|u| u.name != name).cloned().collect();
        self.save(&next)?;
        *users = next;
        drop(users);
        self.sessions.lock().unwrap().retain(|_, s| s.user != name);
        Ok(())
    }

    /// Takes back an account made by a setup that then failed.
    pub fn remove_last(&self, name: &str) -> Result<(), String> {
        let mut users = self.users.lock().unwrap();
        users.retain(|u| u.name != name);
        self.save(&users)
    }

    pub fn set_password(&self, name: &str, password: &str) -> Result<(), String> {
        check_password(password)?;
        let mut users = self.users.lock().unwrap();
        let u = users.iter_mut().find(|u| u.name == name).ok_or("No such user.")?;
        u.hash = hash(password)?;
        self.save(&users)
    }

    /// Makes a new key for a user, replacing any old one. The whole key is
    /// returned once and only its hash is kept.
    pub fn new_key(&self, name: &str) -> Result<String, String> {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).map_err(|e| e.to_string())?;
        let key = format!("{KEY_PREFIX}{}", raw.iter().map(|x| format!("{x:02x}")).collect::<String>());
        let mut users = self.users.lock().unwrap();
        let u = users.iter_mut().find(|u| u.name == name).ok_or("No such user.")?;
        u.key_hash = sha256_hex(key.as_bytes());
        u.key_hint = format!("{}…", &key[..KEY_PREFIX.len() + 4]);
        u.key_made = crate::caplog::now();
        u.key_used = 0;
        u.key_from = String::new();
        self.save(&users)?;
        Ok(key)
    }

    pub fn revoke_key(&self, name: &str) -> Result<(), String> {
        let mut users = self.users.lock().unwrap();
        let u = users.iter_mut().find(|u| u.name == name).ok_or("No such user.")?;
        if u.key_hash.is_empty() {
            return Err("This user has no key.".into());
        }
        (u.key_hash, u.key_hint, u.key_made, u.key_used, u.key_from) = (String::new(), String::new(), 0, 0, String::new());
        self.save(&users)
    }

    /// Checks an API key. Wrong keys count toward the same lockout as
    /// wrong passwords.
    pub fn key_login(&self, key: &str, ip: &str) -> Result<Who, String> {
        if self.locked(ip) {
            return Err("Too many wrong tries. Wait 5 minutes.".into());
        }
        let wanted = sha256_hex(key.as_bytes());
        let mut users = self.users.lock().unwrap();
        let mut hit = None;
        // Compare against every key, so the time taken doesn't depend on which matched.
        for (i, u) in users.iter().enumerate() {
            if !u.key_hash.is_empty() && same(&u.key_hash, &wanted) {
                hit = Some(i);
            }
        }
        let Some(i) = hit.filter(|&i| users[i].api && key.starts_with(KEY_PREFIX)) else {
            drop(users);
            self.fails.lock().unwrap().entry(ip.into()).or_default().push(Instant::now());
            return Err("That key isn't valid.".into());
        };
        let u = &mut users[i];
        u.key_used = crate::caplog::now();
        u.key_from = ip.into();
        let who = Who { name: u.name.clone(), admin: u.role == "admin", perms: if u.role == "admin" { vec![] } else { u.perms.clone() }, via_key: true };
        let mut saved = self.use_saved.lock().unwrap();
        if saved.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
            let _ = self.save(&users);
            *saved = Some(Instant::now());
        }
        Ok(who)
    }

    /// Too many wrong passwords from one address locks it out for a while.
    pub fn locked(&self, ip: &str) -> bool {
        let mut f = self.fails.lock().unwrap();
        // Old tries go for every address, so the map can't grow with each
        // address that ever got a password wrong.
        f.retain(|_, l| {
            l.retain(|t| t.elapsed() < WINDOW);
            !l.is_empty()
        });
        f.get(ip).is_some_and(|l| l.len() >= TRIES)
    }

    pub fn login(&self, name: &str, password: &str, ip: &str) -> Result<String, String> {
        if self.locked(ip) {
            return Err("Too many wrong tries. Wait 5 minutes.".into());
        }
        // Users who can't sign in on the page check like an unknown name.
        let hash = self.users.lock().unwrap().iter().find(|u| u.name == name && u.web && !u.hash.is_empty()).map(|u| u.hash.clone());
        // Check something even for unknown names so timing doesn't tell.
        let ok = verify(password, hash.as_deref().unwrap_or("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$Zm9v")) && hash.is_some();
        if !ok {
            self.fails.lock().unwrap().entry(ip.into()).or_default().push(Instant::now());
            return Err("Wrong name or password.".into());
        }
        self.fails.lock().unwrap().remove(ip);
        Ok(self.start(name, ip))
    }

    pub fn start(&self, name: &str, ip: &str) -> String {
        let t = token();
        let mut all = self.sessions.lock().unwrap();
        all.retain(|_, v| v.last.elapsed() < IDLE);
        all.insert(t.clone(), Session { user: name.into(), ip: ip.into(), started: crate::caplog::now(), last: Instant::now() });
        t
    }

    pub fn user_for(&self, token: &str) -> Option<String> {
        let mut s = self.sessions.lock().unwrap();
        s.retain(|_, v| v.last.elapsed() < IDLE);
        let v = s.get_mut(token)?;
        v.last = Instant::now();
        Some(v.user.clone())
    }

    pub fn end(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }

    /// (id prefix, user, ip, started) for the Sessions list.
    pub fn sessions(&self) -> Vec<(String, String, String, i64)> {
        self.sessions.lock().unwrap().iter().map(|(t, s)| (t[..8].to_string(), s.user.clone(), s.ip.clone(), s.started)).collect()
    }

    pub fn end_prefix(&self, prefix: &str) {
        if prefix.len() >= 8 {
            self.sessions.lock().unwrap().retain(|t, _| !t.starts_with(prefix));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_and_rate_limit() {
        let path = std::env::temp_dir().join(format!("fgw-users-{}.json", token()));
        let a = Auth::load(path.to_str().unwrap());
        assert!(!a.has_users());
        assert!(a.add("admin", "short").is_err());
        a.add("admin", "a long enough password").unwrap();
        assert!(Auth::load(path.to_str().unwrap()).has_users());
        let t = a.login("admin", "a long enough password", "1.1.1.1").unwrap();
        assert_eq!(a.user_for(&t).as_deref(), Some("admin"));
        for _ in 0..5 {
            assert!(a.login("admin", "wrong", "2.2.2.2").is_err());
        }
        assert!(a.login("admin", "a long enough password", "2.2.2.2").unwrap_err().contains("Too many"));
        assert!(a.remove("admin").is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn actions_bring_their_views() {
        let v = |p: &[&str]| with_implied(&p.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(v(&["speed_run"]), ["speed_view", "speed_run"]);
        assert_eq!(v(&["updates_check"]), ["updates_view", "updates_check"]);
        assert_eq!(v(&["handle_alerts"]), ["status", "handle_alerts"]);
        assert_eq!(v(&["device_actions"]), ["devices", "device_actions"]);
        assert_eq!(v(&["block_list", "allow_list"]), ["firewall_view", "block_list", "allow_list"]);
        assert_eq!(v(&["alerts"]), ["devices", "alerts", "firewall_view"]);
        assert_eq!(v(&["log"]), ["log"], "views imply nothing");
        assert_eq!(v(&["future_perm", "speed_run"]), ["speed_view", "speed_run", "future_perm"], "unknown ids are kept");
        // Saving a user adds the views; so does loading a file made before.
        let path = std::env::temp_dir().join(format!("fgw-users-{}.json", token()));
        let p = path.to_str().unwrap();
        let a = Auth::load(p);
        a.add("boss", "a long enough password").unwrap();
        let e = Edit { old_name: String::new(), name: "runner".into(), role: "custom".into(), perms: vec!["speed_run".into()], web: true, api: false, password: "a long enough password".into() };
        a.edit(&e).unwrap();
        assert_eq!(a.who("runner").unwrap().perms, ["speed_view", "speed_run"]);
        let mut j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        for u in j.as_array_mut().unwrap() {
            if u["name"] == "runner" { u["perms"] = serde_json::json!(["block_list"]); }
        }
        std::fs::write(p, j.to_string()).unwrap();
        assert_eq!(Auth::load(p).who("runner").unwrap().perms, ["firewall_view", "block_list"]);
        assert!(Auth::load(p).who("boss").unwrap().admin);
        let _ = std::fs::remove_file(path);
    }
}
