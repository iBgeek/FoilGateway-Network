//! Where the setup wizard is, kept on disk so moving a cable, a reload or
//! a restart of the service doesn't lose anyone's place.

use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct Wizard {
    pub active: bool,
    pub step: String,
    pub user: String,
    /// argon2 hash; the password itself is never stored or sent back.
    #[serde(default)]
    pub pw_hash: String,
    pub lan: Vec<String>,
    pub wan: String,
    pub admin_port: u16,
    pub safety: String,
    pub safety_hosts: String,
    pub new_devices: String,
    /// Cable-path placement: internet_switch or router_switch.
    #[serde(default)]
    pub placement: String,
    /// Set while the new layout waits for the browser to confirm it.
    pub applied: Option<Applied>,
    /// What happened last, shown on the Review step ("undone, nobody confirmed").
    pub note: String,
    /// The account this run made, taken away again if it's undone.
    pub created_user: String,
    /// Settings file from before, put back if it's undone.
    pub old_cfg: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Applied {
    pub at: i64,
    pub secs: u64,
}

pub fn path(dir: &str) -> String {
    format!("{dir}/setup.json")
}

pub fn load(dir: &str) -> Wizard {
    std::fs::read_to_string(path(dir)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

pub fn save(dir: &str, w: &Wizard) {
    use std::os::unix::fs::OpenOptionsExt;
    let text = serde_json::to_string_pretty(w).unwrap_or_default();
    let f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path(dir));
    if let Ok(mut f) = f {
        use std::io::Write;
        let _ = f.write_all(text.as_bytes());
    }
}
