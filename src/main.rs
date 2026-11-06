#![recursion_limit = "256"]
mod about;
mod anyport;
mod app;
mod names;
mod auth;
mod bridge;
mod caplog;
mod certs;
mod config;
mod dhcpwatch;
mod dhcp;
mod geo;
mod lists;
mod mdns;
mod net;
mod oui;
mod pdns;
mod ports;
mod presets;
mod policy;
mod profiles;
mod recent;
mod release;
mod updater;
mod rules;
mod web;
mod wizard;

use config::Config;
use std::fs;
use std::io::Write;
use std::process::{exit, Command, Stdio};

pub const STATE: &str = "/var/lib/foilgateway";
const ROLLBACK_UNIT: &str = "foilgw-rollback";

pub fn state_dir() -> String {
    std::env::var("FOILGW_STATE").unwrap_or(STATE.into())
}

pub fn nft(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
    let mut child = Command::new("nft")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("can't run nft: {e}"))?;
    if let Some(text) = stdin {
        child.stdin.take().unwrap().write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn backup_path() -> String {
    format!("{}/last-good.nft", state_dir())
}

/// Loads the table in one transaction, checks the safety rules are first,
/// and arms a timer that puts the previous table back unless confirmed.
/// The daemon also undoes it itself when the time runs out, which is the
/// only undo on a box without systemd (FOILGW_ALLOW_NO_SYSTEMD=1, tests).
///
/// `prev` is the text this daemon last loaded, if it knows it: it becomes
/// the undo file as is, so a big country set isn't listed back out of the
/// kernel. The load is one nft transaction, so a rejected file changes
/// nothing and needs no separate check run (that parsed everything twice).
pub fn apply_text(cfg: &Config, text: &str, prev: &str) -> Result<(), String> {
    rules::safety_first(cfg, text)?;

    fs::create_dir_all(state_dir()).map_err(|e| e.to_string())?;
    let restore = if prev.starts_with("table netdev") {
        prev.to_string()
    } else {
        let mut restore = String::new();
        for fam in ["netdev", "inet"] {
            let previous = nft(&["list", "table", fam, rules::TABLE], None).unwrap_or_default();
            restore += &format!("table {fam} {t}\ndelete table {fam} {t}\n{previous}", t = rules::TABLE);
        }
        restore
    };
    fs::write(backup_path(), restore).map_err(|e| e.to_string())?;

    // Clear any earlier undo unit so the name is free again.
    let (timer, service) = (format!("{ROLLBACK_UNIT}.timer"), format!("{ROLLBACK_UNIT}.service"));
    for verb in ["stop", "reset-failed"] {
        let _ = Command::new("systemctl").args([verb, &timer, &service]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
    // `foilgw rollback` puts the rules back, and takes the bridge apart
    // too if this change built it.
    let me = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or("/usr/local/bin/foilgw".into());
    let armed = Command::new("systemd-run")
        .args(["--unit", ROLLBACK_UNIT, &format!("--on-active={}", cfg.rollback_secs), &format!("--setenv=FOILGW_STATE={}", state_dir()), &me, "rollback"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !armed && std::env::var("FOILGW_ALLOW_NO_SYSTEMD").as_deref() != Ok("1") {
        return Err("couldn't arm the undo timer, nothing changed".into());
    }

    if let Err(e) = nft(&["-f", "-"], Some(text)) {
        let _ = Command::new("systemctl").args(["stop", &timer]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        return Err(format!("rules rejected, nothing changed: {e}"));
    }
    // -t leaves set contents out: only the rules' order is checked.
    let listed = nft(&["-t", "list", "table", "inet", rules::TABLE], None)?;
    if let Err(e) = rules::safety_first(cfg, &listed) {
        nft(&["-f", &backup_path()], None)?;
        return Err(format!("safety check failed after loading, put the old rules back: {e}"));
    }
    Ok(())
}

pub fn confirm() -> Result<(), String> {
    bridge::persist(&state_dir());
    bridge::clear_pending(&state_dir());
    bridge::keep_shape(&state_dir());
    let s = Command::new("systemctl")
        .args(["stop", &format!("{ROLLBACK_UNIT}.timer")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match s {
        Ok(s) if s.success() => Ok(()),
        _ if std::env::var("FOILGW_ALLOW_NO_SYSTEMD").as_deref() == Ok("1") => Ok(()),
        _ => Err("no change was waiting".into()),
    }
}

pub fn undo() -> Result<(), String> {
    let res = nft(&["-f", &backup_path()], None).map(|_| ());
    bridge::unshape(&state_dir());
    if bridge::pending(&state_dir()) {
        bridge::down(&state_dir())?;
        bridge::clear_pending(&state_dir());
    }
    res
}

/// Reads extra block rules for testing: lines of "chain: rule".
fn read_blocks(path: &str) -> Result<Vec<(&'static str, Vec<String>)>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("can't read {path}: {e}"))?;
    let mut out: Vec<(&'static str, Vec<String>)> = vec![("input", vec![]), ("forward", vec![]), ("output", vec![])];
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (chain, rule) = line.split_once(':').ok_or(format!("expected chain: rule, got {line}"))?;
        let slot = out.iter_mut().find(|(c, _)| *c == chain.trim()).ok_or(format!("unknown chain {chain}"))?;
        slot.1.push(rule.trim().to_string());
    }
    Ok(out)
}

const UNIT_PATH: &str = "/etc/systemd/system/foilgw.service";
const UNIT: &str = include_str!("../dist/foilgw.service");

/// The unit this version wants, keeping the installed ExecStart (the
/// binary may live somewhere else on that box).
fn unit_text(installed: &str) -> String {
    let exec = installed.lines().find(|l| l.starts_with("ExecStart="));
    UNIT.lines().map(|l| if l.starts_with("ExecStart=") { exec.unwrap_or(l) } else { l }).collect::<Vec<_>>().join("\n") + "\n"
}

/// An upgrade only swaps the binary, so bring an installed unit up to
/// date here. Takes effect from the next start.
fn refresh_unit(path: &std::path::Path) {
    let Ok(old) = std::fs::read_to_string(path) else { return };
    let new = unit_text(&old);
    if old != new && std::fs::write(path, &new).is_ok() {
        let _ = std::process::Command::new("systemctl").arg("daemon-reload").status();
        eprintln!("foilgw: updated {}", path.display());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let conf = std::env::var("FOILGW_CONF").unwrap_or(config::PATH.into());
    let result = match args.first().map(String::as_str) {
        // With a file: the old test path, safety rules plus those lines.
        // Without: the rules from the saved settings, same as the web page.
        Some("apply") => Config::load(&conf).and_then(|cfg| {
            let text = match args.get(1) {
                Some(p) => rules::ruleset(&cfg, &read_blocks(p)?),
                None => {
                    let a = app::App::open(&conf);
                    a.warm_lists();
                    a.ruleset(&cfg)
                }
            };
            apply_text(&cfg, &text, "")?;
            println!("Applied. Run `foilgw confirm` within {} s or it is undone.", cfg.rollback_secs);
            Ok(())
        }),
        Some("confirm") => confirm().map(|_| println!("Kept.")),
        Some("rollback") => undo().map(|_| println!("Put back.")),
        // Builds the bridge from the configured ports, after `apply`. The
        // same undo timer takes it apart unless `confirm` comes first.
        Some("bridge") => Config::load(&conf).and_then(|cfg| {
            if bridge::exists() {
                return Err(format!("{} is already up", bridge::NAME));
            }
            bridge::mark_pending(&state_dir());
            bridge::up(&state_dir(), &cfg.wan, &cfg.lan, &[]).inspect_err(|_| {
                let _ = undo();
            })?;
            println!("Bridge {} is up. Run `foilgw confirm` to keep it.", bridge::NAME);
            Ok(())
        }),
        Some("show") => Config::load(&conf).map(|cfg| print!("{}", app::App::open(&conf).ruleset(&cfg))),
        Some("serve") => {
            refresh_unit(std::path::Path::new(UNIT_PATH));
            web::serve(app::App::open(&conf))
        }
        // Prints the DNS answers seen on a port, for checking from SSH:
        // foilgw dns-watch eth1 [seconds]
        Some("dns-watch") => match args.get(1) {
            Some(port) => {
                let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(30);
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(secs));
                    exit(0)
                });
                pdns::watch(port, &mut |mac, a| {
                    let ips: Vec<String> = a.ips.iter().map(|(ip, ttl)| format!("{ip} ttl {ttl}")).collect();
                    println!("{} looked up {}: {}", pdns::mac_text(&mac), a.name, ips.join(", "));
                })
            }
            None => Err("usage: foilgw dns-watch <port> [seconds]".into()),
        },
        Some("update") => match args.get(1) {
            Some(b) => release::update(std::path::Path::new(b), args.get(2).map(std::path::Path::new)).map(|m| {
                println!("{m}");
                println!("Restart to run it: systemctl restart foilgw (devices lose the internet for a few seconds, everyone signs in again).");
            }),
            None => Err("usage: foilgw update <new-binary> [web.tar.gz | web-folder]".into()),
        },
        Some("rollback-version") => release::rollback().map(|m| {
            println!("{m}");
            let ok = Command::new("systemctl").args(["restart", "foilgw"]).status().map(|s| s.success()).unwrap_or(false);
            if ok {
                println!("Restarted.");
            } else {
                println!("Restart FoilGateway to run it (systemctl restart foilgw).");
            }
        }),
        Some("settings-schema") => {
            println!("{}", release::SETTINGS_SCHEMA);
            Ok(())
        }
        Some("version") => {
            println!("foilgw {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err("usage: foilgw serve | apply [rules-file] | bridge | confirm | rollback | show | dns-watch <port> [seconds] | update <binary> [web] | rollback-version | version".into()),
    };
    if let Err(e) = result {
        eprintln!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod unit_tests {
    #[test]
    fn unit_upgrade_keeps_the_binary_path() {
        let old = "[Unit]\nAfter=network-online.target\n\n[Service]\nExecStart=/opt/fg/foilgw serve\n";
        let new = super::unit_text(old);
        assert!(new.contains("After=network-online.target systemd-networkd.service NetworkManager.service"));
        assert!(new.contains("ExecStart=/opt/fg/foilgw serve\n"));
        assert_eq!(super::unit_text(&new), new);
    }
}

// musl's allocator kept growing under load; this one gives memory back.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;
