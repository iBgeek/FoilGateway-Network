//! Keeping the version before an update, and going back to it.
//!
//! `foilgw update <binary> [web]` puts the running binary, its web files,
//! its version and a copy of the settings in the "previous" slot, then
//! installs the new ones. `foilgw rollback-version` (or Settings > Setup)
//! swaps the two back. Each file goes in with a rename, so a power cut
//! leaves either the old or the new one, never half of one.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The settings files' layout. Bump when a release changes what's in
/// policy.json, users.json or gateway.conf in a way older versions can't read.
pub const SETTINGS_SCHEMA: u32 = 3;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const SETTINGS: [&str; 2] = ["policy.json", "users.json"];

pub fn lib_dir() -> PathBuf {
    std::env::var("FOILGW_LIB").unwrap_or_else(|_| "/usr/local/lib/foilgateway".into()).into()
}
pub fn bin_path() -> PathBuf {
    std::env::var("FOILGW_BIN").unwrap_or_else(|_| "/usr/local/bin/foilgw".into()).into()
}
fn web_dir() -> PathBuf {
    std::env::var("FOILGW_WEB").unwrap_or_else(|_| "/usr/share/foilgateway/web".into()).into()
}
fn conf_path() -> PathBuf {
    std::env::var("FOILGW_CONF").unwrap_or_else(|_| crate::config::PATH.into()).into()
}
fn prev_dir() -> PathBuf {
    lib_dir().join("previous")
}

/// What a slot holds: its version and settings layout (None: unknown,
/// as for anything older than 0.5.9).
#[derive(Debug, Clone, PartialEq)]
pub struct Kept {
    pub version: String,
    pub schema: Option<u32>,
}

fn read_kept(dir: &Path) -> Option<Kept> {
    if !dir.join("foilgw").is_file() {
        return None;
    }
    let text = fs::read_to_string(dir.join("VERSION")).unwrap_or_default();
    let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string()));
    Some(Kept { version: get("version=").unwrap_or_else(|| "unknown".into()), schema: get("schema=").and_then(|s| s.parse().ok()) })
}

/// The version kept for going back, if there is one.
pub fn previous() -> Option<Kept> {
    read_kept(&prev_dir())
}

/// For the settings page.
pub fn info() -> serde_json::Value {
    let p = previous();
    let differs = p.as_ref().map(|k| k.schema != Some(SETTINGS_SCHEMA)).unwrap_or(false);
    // When schemas differ, a rollback restores the older layout. List what that
    // typically drops so the confirm dialog can say it plainly (H9).
    let lost: Vec<&str> = if differs {
        vec![
            "Device policies and names added since the update",
            "Whitelist and Blacklist entries added since the update",
            "Port overrides and Geo-Blocking picks made since the update",
        ]
    } else {
        vec![]
    };
    serde_json::json!({
        "current": VERSION,
        "previous": p.as_ref().map(|k| k.version.clone()),
        "schema_differs": differs,
        "lost": lost,
    })
}

/// Ask a binary what it is. Anything before 0.5.9 has no settings-schema
/// command, so its layout is unknown.
fn probe(bin: &Path) -> Kept {
    let run = |a: &str| Command::new(bin).arg(a).output().ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let version = run("version").map(|v| v.trim_start_matches("foilgw ").to_string()).unwrap_or_else(|| "unknown".into());
    Kept { version, schema: run("settings-schema").and_then(|s| s.parse().ok()) }
}

fn copy_dir(from: &Path, to: &Path) -> Result<(), String> {
    fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    for e in fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))? {
        let e = e.map_err(|e| e.to_string())?;
        let (src, dst) = (e.path(), to.join(e.file_name()));
        if e.file_type().map_err(|e| e.to_string())?.is_dir() {
            copy_dir(&src, &dst)?;
        } else {
            fs::copy(&src, &dst).map_err(|e| format!("{}: {e}", src.display()))?;
        }
    }
    Ok(())
}

fn rm(p: &Path) {
    if p.is_dir() {
        let _ = fs::remove_dir_all(p);
    } else {
        let _ = fs::remove_file(p);
    }
}

fn sibling(p: &Path, tag: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(format!(".{tag}-{}", std::process::id()));
    s.into()
}

/// Put a file in place: copy next to it, then rename over it.
fn install_file(from: &Path, to: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = sibling(to, "new");
    fs::copy(from, &tmp).map_err(|e| format!("{} -> {}: {e}", from.display(), tmp.display()))?;
    // Keep the mode and owner of what it replaces.
    match fs::metadata(to) {
        Ok(m) => {
            use std::os::unix::fs::MetadataExt;
            let _ = fs::set_permissions(&tmp, m.permissions());
            let _ = std::os::unix::fs::chown(&tmp, Some(m.uid()), Some(m.gid()));
        }
        Err(_) => {
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode));
        }
    }
    let f = fs::File::open(&tmp).map_err(|e| e.to_string())?;
    let _ = f.sync_all();
    fs::rename(&tmp, to).map_err(|e| {
        rm(&tmp);
        format!("{}: {e}", to.display())
    })
}

/// Swap two paths in one step (renameat2 RENAME_EXCHANGE); if `to` isn't
/// there yet, a plain rename.
fn exchange(a: &Path, b: &Path) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    if !b.exists() {
        return fs::rename(a, b).map_err(|e| format!("{}: {e}", b.display()));
    }
    let ca = CString::new(a.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let cb = CString::new(b.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    const RENAME_EXCHANGE: libc::c_uint = 2;
    let r = unsafe { libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, ca.as_ptr(), libc::AT_FDCWD, cb.as_ptr(), RENAME_EXCHANGE) };
    if r == 0 {
        Ok(())
    } else {
        Err(format!("swap {} and {}: {}", a.display(), b.display(), std::io::Error::last_os_error()))
    }
}

/// Put a web folder (or nothing: the built-in pages) in place.
fn install_web(from: Option<&Path>) -> Result<(), String> {
    let web = web_dir();
    match from {
        Some(src) => {
            let tmp = sibling(&web, "new");
            rm(&tmp);
            if src.is_dir() {
                copy_dir(src, &tmp)?;
            } else {
                fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
                let ok = Command::new("tar").arg("xzf").arg(src).arg("-C").arg(&tmp).status().map(|s| s.success()).unwrap_or(false);
                if !ok {
                    rm(&tmp);
                    return Err(format!("couldn't unpack {}", src.display()));
                }
            }
            if let Some(p) = web.parent() {
                let _ = fs::create_dir_all(p);
            }
            exchange(&tmp, &web)?;
            rm(&tmp); // the old folder, now under the temporary name
        }
        None => {
            let old = sibling(&web, "old");
            if web.exists() {
                fs::rename(&web, &old).map_err(|e| e.to_string())?;
                rm(&old);
            }
        }
    }
    Ok(())
}

/// Fill a slot folder with what's installed now.
fn snapshot(dir: &Path, kept: &Kept) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    rm(dir);
    fs::create_dir_all(dir.join("settings")).map_err(|e| format!("{}: {e}", dir.display()))?;
    fs::copy(bin_path(), dir.join("foilgw")).map_err(|e| format!("{}: {e}", bin_path().display()))?;
    let _ = fs::set_permissions(dir.join("foilgw"), fs::Permissions::from_mode(0o755));
    if web_dir().is_dir() {
        copy_dir(&web_dir(), &dir.join("web"))?;
    }
    let state = PathBuf::from(crate::state_dir());
    for f in SETTINGS {
        if state.join(f).is_file() {
            fs::copy(state.join(f), dir.join("settings").join(f)).map_err(|e| e.to_string())?;
        }
    }
    if conf_path().is_file() {
        fs::copy(conf_path(), dir.join("settings/gateway.conf")).map_err(|e| e.to_string())?;
    }
    let schema = kept.schema.map(|s| s.to_string()).unwrap_or_default();
    fs::write(dir.join("VERSION"), format!("version={}\nschema={schema}\n", kept.version)).map_err(|e| e.to_string())
}

/// Make `slot` the previous one, replacing whatever was there.
fn promote(slot: &Path) -> Result<(), String> {
    let prev = prev_dir();
    exchange(slot, &prev)?;
    rm(slot);
    Ok(())
}

/// `foilgw update <binary> [web]`: keep what's installed, then install the new one.
pub fn update(new_bin: &Path, web: Option<&Path>) -> Result<String, String> {
    if !new_bin.is_file() {
        return Err(format!("{} isn't there", new_bin.display()));
    }
    let new = probe(new_bin);
    if new.version == "unknown" {
        return Err(format!("{} doesn't run as foilgw here", new_bin.display()));
    }
    fs::create_dir_all(lib_dir()).map_err(|e| format!("{}: {e}", lib_dir().display()))?;
    let mut kept_old = None;
    if bin_path().is_file() {
        let cur = probe(&bin_path());
        let slot = lib_dir().join(format!(".slot-{}", std::process::id()));
        snapshot(&slot, &cur)?;
        promote(&slot)?;
        kept_old = Some(cur.version);
    }
    install_file(new_bin, &bin_path(), 0o755)?;
    if web.is_some() {
        install_web(web)?;
    }
    Ok(match kept_old {
        Some(v) => format!("Installed {}. Kept {v} for going back.", new.version),
        None => format!("Installed {}.", new.version),
    })
}

/// `foilgw rollback-version`: swap the installed and previous versions.
/// Settings stay unless the previous version used a different layout
/// (or an unknown one); then the copy taken at the update goes back.
pub fn rollback() -> Result<String, String> {
    let prev = previous().ok_or("No previous version is kept, so there's nothing to go back to.")?;
    let pdir = prev_dir();
    let cur = probe(&bin_path());
    let cur = Kept { version: if cur.version == "unknown" { VERSION.into() } else { cur.version }, schema: cur.schema };
    // What's installed now becomes the new previous (taken first, so a
    // failure from here on leaves everything as it was).
    let slot = lib_dir().join(format!(".slot-{}", std::process::id()));
    snapshot(&slot, &cur)?;
    install_file(&pdir.join("foilgw"), &bin_path(), 0o755)?;
    let pweb = pdir.join("web");
    install_web(pweb.is_dir().then_some(pweb.as_path()))?;
    let restore = prev.schema != cur.schema || prev.schema.is_none();
    if restore {
        let state = PathBuf::from(crate::state_dir());
        for f in SETTINGS {
            let src = pdir.join("settings").join(f);
            if src.is_file() {
                install_file(&src, &state.join(f), 0o600)?;
            }
        }
        let c = pdir.join("settings/gateway.conf");
        if c.is_file() {
            install_file(&c, &conf_path(), 0o644)?;
        }
    }
    promote(&slot)?;
    Ok(format!(
        "Now on {} again ({} is kept; run rollback-version again to switch back).{}",
        prev.version,
        cur.version,
        if restore { " Settings were put back to how they were at the update." } else { "" }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_swaps_folders() {
        let d = std::env::temp_dir().join(format!("fgrel-{}", std::process::id()));
        rm(&d);
        fs::create_dir_all(d.join("a")).unwrap();
        fs::create_dir_all(d.join("b")).unwrap();
        fs::write(d.join("a/x"), "A").unwrap();
        fs::write(d.join("b/x"), "B").unwrap();
        exchange(&d.join("a"), &d.join("b")).unwrap();
        assert_eq!(fs::read_to_string(d.join("a/x")).unwrap(), "B");
        assert_eq!(fs::read_to_string(d.join("b/x")).unwrap(), "A");
        exchange(&d.join("a"), &d.join("c")).unwrap();
        assert!(d.join("c/x").exists() && !d.join("a").exists());
        rm(&d);
    }
}
