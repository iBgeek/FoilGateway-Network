//! Admin accounts, sign-in sessions and the sign-in rate limit.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub hash: String,
    #[serde(default = "admin")]
    pub role: String,
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

impl Auth {
    pub fn load(path: &str) -> Auth {
        let users = std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        Auth { path: path.into(), users: Mutex::new(users), sessions: Mutex::new(HashMap::new()), fails: Mutex::new(HashMap::new()) }
    }

    fn save(&self, users: &[User]) -> Result<(), String> {
        let tmp = format!("{}.new", self.path);
        std::fs::write(&tmp, serde_json::to_string_pretty(users).unwrap()).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }

    pub fn has_users(&self) -> bool {
        !self.users.lock().unwrap().is_empty()
    }

    pub fn names(&self) -> Vec<(String, String)> {
        self.users.lock().unwrap().iter().map(|u| (u.name.clone(), u.role.clone())).collect()
    }

    pub fn add(&self, name: &str, password: &str) -> Result<(), String> {
        check_name(name)?;
        check_password(password)?;
        let mut users = self.users.lock().unwrap();
        if users.iter().any(|u| u.name == name) {
            return Err(format!("{name} already exists."));
        }
        users.push(User { name: name.into(), hash: hash(password)?, role: admin() });
        self.save(&users)
    }

    /// For setup, which hashed the password when it was typed.
    pub fn add_hashed(&self, name: &str, hash: &str) -> Result<(), String> {
        check_name(name)?;
        let mut users = self.users.lock().unwrap();
        if users.iter().any(|u| u.name == name) {
            return Err(format!("{name} already exists."));
        }
        users.push(User { name: name.into(), hash: hash.into(), role: admin() });
        self.save(&users)
    }

    pub fn remove(&self, name: &str) -> Result<(), String> {
        let mut users = self.users.lock().unwrap();
        if users.len() <= 1 {
            return Err("Keep at least one admin, or nobody can sign in.".into());
        }
        users.retain(|u| u.name != name);
        self.save(&users)?;
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
        let hash = self.users.lock().unwrap().iter().find(|u| u.name == name).map(|u| u.hash.clone());
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
}
