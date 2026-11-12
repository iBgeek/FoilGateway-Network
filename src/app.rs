//! The daemon's state and the jobs that keep it current: device discovery,
//! traffic counting, block logging, list downloads, and every change to the
//! rules going through the apply-with-undo path.

use crate::caplog::{now, Log};
use crate::config::Config;
use crate::policy::{parse_entry, Device, DevicePolicy, Entry, Policy};
use crate::rules::{self, DeviceRules, Match, Mode, Nets, Plan};
use crate::{auth::Auth, geo, lists, net};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Seek};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

thread_local! {
    /// Who the request on this thread is for. Set by the web layer before a
    /// route runs, so a change can record its owner. Empty: the gateway itself.
    static ACTOR: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

pub fn set_actor(name: &str) {
    ACTOR.with(|a| *a.borrow_mut() = name.to_string());
}

impl Pending {
    /// Only the user who made the change, or an admin, can keep it.
    pub fn may_keep(&self, user: &str, admin: bool) -> bool {
        admin || (!self.by.is_empty() && self.by == user)
    }
}

pub struct Pending {
    /// The user who made the change. Only they or an admin can keep it.
    pub by: String,
    pub deadline: Instant,
    pub secs: u64,
    old_cfg: Option<String>,
    old_policy: Policy,
    pub what: String,
    pub new_port: Option<u16>,
    /// The gateway's own address changed too, so undo puts the old one back.
    addr_changed: bool,
}

#[derive(Default, Clone, serde::Serialize)]
pub struct FeedStatus {
    pub id: String,
    pub name: String,
    pub url: String,
    pub entries: usize,
    pub fetched_at: i64,
    pub error: String,
}

#[derive(Default)]
pub struct Feeds {
    pub telemetry_hosts: Vec<String>,
    pub telemetry: Nets,
    pub threats: Nets,
    /// Which list each telemetry host came from, and each address list's
    /// entries, so a block can name its list.
    pub host_feed: HashMap<String, &'static str>,
    pub addr_feeds: Vec<(&'static str, Vec<String>)>,
    pub status: BTreeMap<String, FeedStatus>,
}

#[derive(Default)]
pub struct Live {
    pub rates: HashMap<String, (f64, f64)>,
    pub totals: HashMap<String, (u64, u64)>,
    last: HashMap<String, (u64, u64)>,
    last_at: Option<Instant>,
    cpu_prev: (u64, u64),
    pub cpu: f64,
    /// Bits per second (down, up) on the WAN port and on all LAN ports
    /// together, from the ports' own counters.
    pub wan_bps: (f64, f64),
    pub lan_bps: (f64, f64),
    port_last: HashMap<String, (u64, u64)>,
    pub tz_offset: i64,
    tz_checked: Option<Instant>,
    tz_for: String,
}

pub struct App {
    pub conf_path: String,
    pub dir: String,
    pub cfg: RwLock<Option<Config>>,
    pub policy: RwLock<Policy>,
    pub auth: Auth,
    pub log: Log,
    pub seen: Mutex<lists::SeenAddrs>,
    pub feeds: RwLock<Feeds>,
    pub geo: RwLock<geo::Db>,
    pub pending: Mutex<Option<Pending>>,
    pub live: Mutex<Live>,
    pub map_traffic: Mutex<crate::maptraffic::Tracker>,
    pub speed_test: Arc<crate::speedtest::SpeedTest>,
    pub detection: Mutex<crate::detection::Detector>,
    /// Host names devices gave in DHCP before we knew them, by MAC.
    pub heard: Mutex<HashMap<String, String>>,
    /// When we last asked the network for a device's name, by MAC.
    pub asked: Mutex<HashMap<String, (i64, u32)>>,
    /// Where the gateway's public address is, and when we looked.
    pub home: Mutex<(Option<geo::Place>, i64)>,
    pub started: Instant,
    pub wizard: Mutex<crate::wizard::Wizard>,
    pub anyport: Arc<crate::anyport::AnyPort>,
    applying: Mutex<String>,
    pub restart: AtomicBool,
    /// Country ranges for (countries, database load), built once.
    geo_cache: Mutex<(Vec<String>, u64, Arc<rules::Elems>)>,
    /// Bumped each time the location database is loaded again.
    geo_gen: std::sync::atomic::AtomicU64,
    /// A country change waiting for the background apply, and that apply's state.
    geo_dirty: AtomicBool,
    geo_running: AtomicBool,
    pub geo_job: Mutex<GeoJob>,
    /// Blocks from the last hour, for the troubleshooter.
    pub recent: Mutex<crate::recent::Recent>,
    /// Names devices looked up (passive DNS) and owners of addresses.
    pub pdns: Mutex<crate::pdns::Pdns>,
    pub owners: crate::pdns::Owners,
}

/// The last country apply, for the Geo-Blocking page.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct GeoJob {
    /// "", "applying", "done" or "failed".
    pub state: String,
    pub countries: usize,
    pub ranges: usize,
    pub ms: u64,
    pub error: String,
    pub at: i64,
}

pub fn month_of(t: i64) -> (String, String) {
    let days = t.div_euclid(86400);
    // civil-from-days, Howard Hinnant's method
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mp = (5 * (doe - (365 * yoe + yoe / 4 - yoe / 100)) + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    (format!("{y:04}-{m:02}"), format!("{py:04}-{pm:02}"))
}

impl App {
    pub fn open(conf_path: &str) -> App {
        let dir = crate::state_dir();
        let _ = std::fs::create_dir_all(&dir);
        // Signs of an earlier install, checked before the log file is made:
        // every earlier version made its log on the first start, and setup
        // makes an account. A config written by hand is still a fresh install.
        let installed = [format!("{dir}/users.json"), format!("{dir}/capture.db")].iter().any(|p| std::path::Path::new(p).exists());
        let log = Log::open(&format!("{dir}/capture.db")).unwrap_or_else(|e| {
            eprintln!("{e}; logging to memory only");
            Log::open(":memory:").unwrap()
        });
        *crate::bridge::FIXED.lock().unwrap() = Config::load(conf_path).ok().and_then(|c| c.fixed);
        let app = App {
            conf_path: conf_path.into(),
            cfg: RwLock::new(Config::load(conf_path).ok()),
            policy: RwLock::new({
                let mut p = Policy::open(&format!("{dir}/policy.json"), installed);
                // Makers saved by older versions keep the list's stray punctuation.
                for d in p.devices.values_mut() {
                    d.vendor = crate::oui::tidy(&d.vendor);
                }
                p
            }),
            auth: Auth::load(&format!("{dir}/users.json")),
            log,
            seen: Mutex::new(lists::SeenAddrs::load(&format!("{dir}/addresses.json"))),
            feeds: RwLock::new(Feeds::default()),
            geo: RwLock::new(geo::Db::open(std::path::Path::new(&format!("{dir}/geo")))),
            pending: Mutex::new(None),
            live: Mutex::new(Live::default()),
            map_traffic: Mutex::new(Default::default()),
            speed_test: Arc::new(Default::default()),
            detection: Mutex::new(Default::default()),
            heard: Mutex::new(HashMap::new()),
            asked: Mutex::new(HashMap::new()),
            home: Mutex::new((None, 0)),
            started: Instant::now(),
            wizard: Mutex::new(crate::wizard::load(&dir)),
            anyport: Arc::new(crate::anyport::AnyPort::open(&dir)),
            applying: Mutex::new(String::new()),
            geo_cache: Mutex::new((Vec::new(), u64::MAX, Arc::default())),
            geo_gen: Default::default(),
            geo_dirty: AtomicBool::new(false),
            geo_running: AtomicBool::new(false),
            geo_job: Mutex::new(GeoJob::default()),
            restart: AtomicBool::new(false),
            recent: Mutex::new(Default::default()),
            pdns: Mutex::new(Default::default()),
            owners: Default::default(),
            dir,
        };
        app.load_feeds();
        app
    }

    pub fn policy_path(&self) -> String {
        format!("{}/policy.json", self.dir)
    }

    pub fn needs_setup(&self) -> bool {
        !self.auth.has_users() || self.cfg.read().unwrap().is_none() || self.wizard.lock().unwrap().active
    }

    // ---- building the rules ----

    fn resolve_entries(&self, list: &[String]) -> Nets {
        let seen = self.seen.lock().unwrap();
        let mut n = Nets::default();
        for e in list {
            match parse_entry(e) {
                Ok(Entry::Net(x)) => n.add(&x),
                Ok(Entry::Site(s)) => seen.of(&s).iter().for_each(|a| n.add(a)),
                _ => {}
            }
        }
        n
    }

    fn device_matches(&self, list: &[String]) -> Vec<Match> {
        let mut nets = Nets::default();
        let mut out = Vec::new();
        let seen = self.seen.lock().unwrap();
        for e in list {
            match parse_entry(e) {
                Ok(Entry::Net(x)) => nets.add(&x),
                Ok(Entry::Site(s)) => seen.of(&s).iter().for_each(|a| nets.add(a)),
                Ok(Entry::Port(p, n)) => out.push(Match::Port(p, n)),
                Err(_) => {}
            }
        }
        if !nets.is_empty() {
            out.insert(0, Match::Nets(nets));
        }
        out
    }

    pub fn plan(&self, p: &Policy) -> Plan {
        self.plan_with(p, true)
    }

    fn plan_with(&self, p: &Policy, build_geo: bool) -> Plan {
        let feeds = self.feeds.read().unwrap();
        let at = now();
        let white_live: Vec<String> = p.white.iter().filter(|e| p.white_live(e, at)).cloned().collect();
        let white = self.resolve_entries(&white_live);
        let mut telemetry = Nets::default();
        let tele_on = p.telemetry_all || p.devices.values().any(|d| d.telemetry);
        if tele_on {
            for a in feeds.telemetry.v4.iter().chain(&feeds.telemetry.v6) {
                telemetry.add(a);
            }
            let seen = self.seen.lock().unwrap();
            for h in &feeds.telemetry_hosts {
                for a in seen.of(h) {
                    // An address the owner allowed stays allowed.
                    if !white.v4.contains(&a) && !white.v6.contains(&a) {
                        telemetry.add(&a);
                    }
                }
            }
        }
        let countries = self.geo_elems(p, build_geo).unwrap_or_default();
        let (local, router, dns) = self.local_nets();
        let t = now();
        Plan {
            audit: p.devices.iter().filter(|(_, d)| d.auditing(t)).map(|(m, _)| m.clone()).collect(),
            mode: p.mode,
            telemetry_all: p.telemetry_all,
            black: self.resolve_entries(&p.black),
            white,
            telemetry,
            threats: if p.threats { feeds.threats.clone() } else { Nets::default() },
            countries,
            local,
            router,
            dns,
            strict_outbound: p.strict_outbound,
            ipv6_enabled: !p.block_ipv6,
            block_vpn: p.block_vpn,
            block_dot: p.block_dot,
            dns_proxy: p.dns_proxy,
            deep_detect: p.deep_detect,
            inbound: p
                .inbound
                .iter()
                .filter(|i| !i.follow)
                .filter_map(|i| {
                    let proto = match i.proto.as_str() {
                        "tcp" => "tcp",
                        "udp" => "udp",
                        _ => return None,
                    };
                    Some(rules::Inbound { proto, port: i.port, mac: (!i.mac.is_empty()).then(|| i.mac.clone()), on: i.on, lan_off: i.lan_off })
                })
                .collect(),
            devices: p
                .devices
                .iter()
                .map(|(mac, d)| {
                    let allow: Vec<String> = d.allow.iter().filter(|e| d.allow_live(e, at)).cloned().collect();
                    DeviceRules {
                        mac: mac.clone(),
                        policy: d.policy,
                        telemetry: d.telemetry,
                        allow: self.device_matches(&allow),
                        deny: self.device_matches(&d.deny),
                    }
                })
                .collect(),
        }
    }

    /// The bridge's network, the router and the DNS servers it named, from
    /// our lease on the bridge (or what the system has, if it got the address).
    pub fn local_nets(&self) -> (Nets, Nets, Nets) {
        let (mut local, mut router, mut dns) = (Nets::default(), Nets::default(), Nets::default());
        let o = self.anyport.owned();
        let name = crate::bridge::NAME;
        let cidrs: Vec<String> = match o.leases.get(name) {
            Some(c) => vec![c.clone()],
            None => net::bridge_port().map(|p| p.ips).unwrap_or_default(),
        };
        for c in cidrs {
            if let Some(n) = crate::policy::parse_net(&c) {
                local.add(&n);
            }
        }
        match o.routes.get(name) {
            Some(r) => router.add(r),
            None => net::default_gateways().iter().for_each(|g| router.add(g)),
        }
        let named = o.dns.get(name).cloned().unwrap_or_default();
        for d in if named.is_empty() { net::resolvers() } else { named } {
            dns.add(&d);
        }
        (local, router, dns)
    }

    pub fn ruleset(&self, cfg: &Config) -> String {
        let p = self.policy.read().unwrap().clone();
        rules::policy_ruleset(cfg, &self.plan(&p))
    }

    /// The country ranges for a policy. With `build` false only a ready
    /// copy is handed out, so a page request never waits for a build.
    pub fn geo_elems(&self, p: &Policy, build: bool) -> Option<Arc<rules::Elems>> {
        if !p.geo || p.countries.is_empty() {
            return Some(Arc::default());
        }
        let gen = self.geo_gen.load(Ordering::Relaxed);
        let ready = |c: &(Vec<String>, u64, Arc<rules::Elems>)| (c.0 == p.countries && c.1 == gen).then(|| c.2.clone());
        if !build {
            return self.geo_cache.try_lock().ok().and_then(|c| ready(&c));
        }
        let mut c = self.geo_cache.lock().unwrap();
        if let Some(e) = ready(&c) {
            return Some(e);
        }
        let geo = self.geo.read().unwrap();
        if !geo.loaded() {
            return Some(Arc::default());
        }
        let e = Arc::new(geo.block_ranges(&p.countries));
        *c = (p.countries.clone(), gen, e.clone());
        Some(e)
    }

    /// The rules as the Rules page shows them: country sets as a count.
    pub fn ruleset_view(&self, cfg: &Config) -> String {
        let p = self.policy.read().unwrap().clone();
        let mut plan = self.plan_with(&p, false);
        let c = &plan.countries;
        plan.countries = Arc::new(rules::Elems { v4: String::new(), v6: String::new(), n4: c.n4, n6: c.n6, hidden: true });
        rules::policy_ruleset(cfg, &plan)
    }

    /// The location database was loaded again.
    pub fn geo_reloaded(&self) {
        self.geo_gen.fetch_add(1, Ordering::Relaxed);
    }

    /// Countries changed: save now, load the rules in the background. A
    /// country set only touches traffic crossing the bridge, never the way
    /// to this page or SSH (input chain, safety rules first), so it needs no
    /// browser confirm. Changes made while one loads are folded into one
    /// more load afterwards.
    pub fn geo_apply(self: &Arc<Self>) {
        self.geo_dirty.store(true, Ordering::Release);
        if self.geo_running.swap(true, Ordering::AcqRel) {
            return;
        }
        let a = self.clone();
        std::thread::spawn(move || loop {
            while a.geo_dirty.swap(false, Ordering::AcqRel) {
                let n = a.policy.read().unwrap().countries.len();
                *a.geo_job.lock().unwrap() = GeoJob { state: "applying".into(), countries: n, at: now(), ..Default::default() };
                // An owner change waiting for its confirm goes first.
                while a.pending.lock().unwrap().is_some() {
                    std::thread::sleep(Duration::from_millis(500));
                }
                let t = Instant::now();
                let res = a.load_rules();
                let p = a.policy.read().unwrap().clone();
                let ranges = a.geo_elems(&p, false).map(|e| e.n4 + e.n6).unwrap_or(0);
                let ms = t.elapsed().as_millis() as u64;
                let job = match res {
                    Ok(_) => GeoJob { state: "done".into(), countries: n, ranges, ms, at: now(), ..Default::default() },
                    Err(e) => GeoJob { state: "failed".into(), countries: n, ranges, ms, error: e, at: now() },
                };
                a.log.note("setting", &match job.state.as_str() {
                    "done" => format!("Geo-Blocking: {n} countries blocked ({ranges} ranges), loaded in {:.1} s.", ms as f64 / 1000.0),
                    _ => format!("Geo-Blocking: couldn't load the country rules: {}", job.error),
                });
                *a.geo_job.lock().unwrap() = job;
            }
            a.geo_running.store(false, Ordering::Release);
            // A change that came in just as this one ended.
            if !a.geo_dirty.load(Ordering::Acquire) || a.geo_running.swap(true, Ordering::AcqRel) {
                return;
            }
        });
    }

    // ---- changes ----

    /// Every owner change comes through here: rules go in with the undo
    /// timer armed, and the files are only written once nft took them.
    /// Returns how many seconds the browser has to confirm.
    pub fn change(&self, cfg: Option<Config>, policy: Policy, what: &str) -> Result<u64, String> {
        self.confirm_pending("");
        let mut last = self.applying.lock().unwrap();
        let old_cfg_text = std::fs::read_to_string(&self.conf_path).ok();
        let old_policy = self.policy.read().unwrap().clone();
        let cur = self.cfg.read().unwrap().clone();
        let addr_changed = matches!((&cur, &cfg), (Some(a), Some(b)) if a.fixed != b.fixed);
        let new_port = match (&cur, &cfg) {
            (Some(a), Some(b)) if a.admin_port != b.admin_port => Some(b.admin_port),
            _ => None,
        };
        let Some(c) = cfg.clone().or(cur) else {
            policy.save(&self.policy_path())?;
            *self.policy.write().unwrap() = policy;
            return Ok(0);
        };
        let text = rules::policy_ruleset(&c, &self.plan(&policy));
        self.detection.lock().unwrap().invalidate();
        crate::apply_text(&c, &text, &last)?;
        *last = text;
        if addr_changed {
            if let Err(e) = self.set_address(c.fixed.as_ref()) {
                let _ = crate::undo();
                let _ = self.set_address(self.cfg.read().unwrap().as_ref().and_then(|c| c.fixed.as_ref()));
                return Err(e);
            }
        }
        if let Some(c) = &cfg {
            c.save(&self.conf_path)?;
            *self.cfg.write().unwrap() = Some(c.clone());
        }
        policy.save(&self.policy_path())?;
        *self.policy.write().unwrap() = policy;
        *self.pending.lock().unwrap() = Some(Pending {
            by: ACTOR.with(|a| a.borrow().clone()),
            deadline: Instant::now() + Duration::from_secs(c.rollback_secs),
            secs: c.rollback_secs,
            old_cfg: old_cfg_text,
            old_policy,
            what: what.into(),
            new_port,
            addr_changed,
        });
        self.log.note("setting", &format!("Changed: {what}. Waiting for the browser to confirm."));
        Ok(c.rollback_secs)
    }

    /// Puts a fixed address (or DHCP) on the bridge. networkd gets a new
    /// file when it owns the bridge; otherwise we set it ourselves.
    pub fn set_address(&self, fixed: Option<&crate::config::Fixed>) -> Result<(), String> {
        *crate::bridge::FIXED.lock().unwrap() = fixed.cloned();
        let br = crate::bridge::NAME;
        if !crate::bridge::exists() || crate::bridge::networkd_address(fixed)? {
            return Ok(());
        }
        let run = |args: &[&str]| -> Result<(), String> {
            let out = std::process::Command::new("ip").args(args).output().map_err(|e| format!("can't run ip: {e}"))?;
            if out.status.success() { Ok(()) } else { Err(format!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim())) }
        };
        let resolv = "/etc/resolv.conf";
        let saved = format!("{}/resolv.conf.dhcp", self.dir);
        let plain_file = std::fs::symlink_metadata(resolv).map(|m| m.file_type().is_file()).unwrap_or(false);
        match fixed {
            Some(f) => {
                self.anyport.stop_dhcp(br);
                let _ = run(&["addr", "flush", "dev", br, "scope", "global"]);
                run(&["addr", "add", &f.cidr(), "dev", br])?;
                if let Some(g) = f.gateway {
                    run(&["route", "replace", "default", "via", &g.to_string(), "dev", br])?;
                }
                if plain_file && !f.dns.is_empty() {
                    if !std::path::Path::new(&saved).exists() {
                        let _ = std::fs::copy(resolv, &saved);
                    }
                    let text: String = f.dns.iter().map(|d| format!("nameserver {d}\n")).collect();
                    let _ = std::fs::write(resolv, format!("# Set by FoilGateway (fixed address).\n{text}"));
                }
            }
            None => {
                let _ = run(&["addr", "flush", "dev", br, "scope", "global"]);
                if std::fs::copy(&saved, resolv).is_ok() {
                    let _ = std::fs::remove_file(&saved);
                }
                if let Some(p) = net::port(br) {
                    self.anyport.start_dhcp(br, &p.mac);
                }
            }
        }
        Ok(())
    }

    /// The browser reached us after a change, so keep it.
    /// Keep the waiting change for a user: only the user who made it, or an admin.
    pub fn confirm_pending_as(&self, from: &str, user: &str, admin: bool) -> bool {
        let mine = self.pending.lock().unwrap().as_ref().is_some_and(|p| p.may_keep(user, admin));
        mine && self.confirm_pending(from)
    }

    /// For tests: a change waiting to be kept, made by `by`.
    #[cfg(test)]
    pub fn test_pending(&self, by: &str) {
        let old_policy = self.policy.read().unwrap().clone();
        *self.pending.lock().unwrap() = Some(Pending { by: by.into(), deadline: Instant::now() + Duration::from_secs(60), secs: 60, old_cfg: None, old_policy, what: "test".into(), new_port: None, addr_changed: false });
    }

    pub fn confirm_pending(&self, from: &str) -> bool {
        let Some(p) = self.pending.lock().unwrap().take() else { return false };
        let _ = crate::confirm();
        crate::bridge::clear_pending(&self.dir);
        let by = if from.is_empty() { String::new() } else { format!(" from {from}") };
        self.log.note("setting", &format!("Kept: {}. Confirmed{by}.", p.what));
        if p.new_port.is_some() {
            // systemd starts us again on the new port.
            self.restart.store(true, Ordering::Relaxed);
        }
        true
    }

    /// Undo the waiting change at once, as if its time ran out.
    pub fn undo_now(&self) {
        if let Some(p) = self.pending.lock().unwrap().as_mut() {
            p.deadline = Instant::now();
        }
        self.undo_if_late();
    }

    fn undo_if_late(&self) {
        let mut slot = self.pending.lock().unwrap();
        let late = slot.as_ref().is_some_and(|p| Instant::now() >= p.deadline);
        if !late {
            return;
        }
        let p = slot.take().unwrap();
        drop(slot);
        let res = crate::undo();
        // What is loaded now is the undo file, not the last text.
        self.applying.lock().unwrap().clear();
        match &p.old_cfg {
            Some(t) => {
                let _ = std::fs::write(&self.conf_path, t);
                *self.cfg.write().unwrap() = Config::parse(t).ok();
            }
            None => {
                let _ = std::fs::remove_file(&self.conf_path);
                *self.cfg.write().unwrap() = None;
            }
        }
        if p.addr_changed {
            let fixed = self.cfg.read().unwrap().as_ref().and_then(|c| c.fixed.clone());
            if let Err(e) = self.set_address(fixed.as_ref()) {
                self.log.note("setting", &format!("Couldn't put the old address back: {e}"));
            }
        }
        let mut old = p.old_policy;
        // Devices found meanwhile are kept, with their first settings.
        for (mac, d) in self.policy.read().unwrap().devices.iter() {
            old.devices.entry(mac.clone()).or_insert(d.clone());
        }
        let _ = old.save(&self.policy_path());
        *self.policy.write().unwrap() = old;
        let how = if res.is_ok() { "" } else { " (the system timer does the rules)" };
        self.log.note("setting", &format!("Undone: {}. Nobody confirmed within {} s{how}.", p.what, p.secs));
        self.setup_undone(&format!("Nobody confirmed within {} seconds, so the gateway took the bridge apart and went back to how it was. Check the cables and try again.", p.secs));
    }

    /// Setup's part of an undo: the account it made goes too, and the
    /// wizard is back on Review with everything else still filled in.
    pub fn setup_undone(&self, why: &str) {
        let mut w = self.wizard.lock().unwrap();
        if w.applied.take().is_none() {
            return;
        }
        if !w.created_user.is_empty() {
            let _ = self.auth.remove_last(&w.created_user);
            w.created_user.clear();
        }
        w.step = "Review".into();
        w.note = why.into();
        crate::wizard::save(&self.dir, &w);
    }

    /// New addresses for the same choices: no owner change, so once the
    /// safety rules check out it is kept straight away.
    pub fn refresh_rules(&self) {
        self.detection.lock().unwrap().invalidate();
        if self.pending.lock().unwrap().is_some() {
            return;
        }
        if let Err(e) = self.load_rules() {
            self.log.note("alert", &format!("Couldn't update the rules: {e}"));
        }
    }

    /// Loads the rules for the saved settings and keeps them, unless they
    /// are already what is loaded.
    fn load_rules(&self) -> Result<(), String> {
        if self.needs_setup() {
            return Ok(());
        }
        let Some(cfg) = self.cfg.read().unwrap().clone() else { return Ok(()) };
        let text = self.ruleset(&cfg);
        let mut last = self.applying.lock().unwrap();
        if *last == text {
            return Ok(());
        }
        self.detection.lock().unwrap().invalidate();
        crate::apply_text(&cfg, &text, &last).and_then(|_| crate::confirm())?;
        *last = text;
        Ok(())
    }

    // ---- what the owner sees ----

    pub fn tz_offset(&self) -> i64 {
        let tz = self.policy.read().unwrap().timezone.clone();
        let mut l = self.live.lock().unwrap();
        if l.tz_for != tz || l.tz_checked.is_none_or(|t| t.elapsed() > Duration::from_secs(600)) {
            let out = std::process::Command::new("date").env("TZ", &tz).arg("+%z").output();
            let z = out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let digits: String = z.chars().filter(|c| c.is_ascii_digit()).collect();
            let (h, m) = (digits.get(..2).and_then(|x| x.parse::<i64>().ok()).unwrap_or(0), digits.get(2..4).and_then(|x| x.parse::<i64>().ok()).unwrap_or(0));
            l.tz_offset = sign * (h * 3600 + m * 60);
            l.tz_checked = Some(Instant::now());
            l.tz_for = tz;
        }
        l.tz_offset
    }

    pub fn midnight(&self) -> i64 {
        let off = self.tz_offset();
        let t = now();
        t - (t + off).rem_euclid(86400)
    }

    /// Is traffic actually going through us?
    pub fn path_state(&self) -> (bool, String) {
        let Some(cfg) = self.cfg.read().unwrap().clone() else { return (false, "Setup isn't finished.".into()) };
        let wan = net::port_cached(&cfg.wan);
        let lan: Vec<net::Port> = cfg.lan.iter().filter_map(|l| net::port_cached(l)).collect();
        let members = crate::bridge::members();
        let mut why = Vec::new();
        if !crate::bridge::exists() {
            why.push("the bridge isn't built".to_string());
        } else if !members.contains(&cfg.wan) || !cfg.lan.iter().any(|l| members.contains(l)) {
            why.push(format!("the bridge is missing a port ({} has {})", crate::bridge::NAME, members.join(", ")));
        }
        if !wan.as_ref().is_some_and(|p| p.link) {
            why.push(format!("the WAN port {} has no cable", cfg.wan));
        }
        if !lan.iter().any(|p| p.link) {
            why.push(format!("the LAN port {} has no cable", cfg.lan.join(", ")));
        }
        if !net::bridge_filtering() {
            why.push("bridge filtering (br_netfilter) is off".into());
        }
        if why.is_empty() {
            (true, "Traffic between the router and your devices goes through the gateway.".into())
        } else {
            (false, format!("Not in the traffic path yet: {}. Below is what it would do once it is.", why.join(", ")))
        }
    }

    /// Plain lines for "What it would do".
    pub fn summary(&self) -> Vec<String> {
        let p = self.policy.read().unwrap().clone();
        let cfg = self.cfg.read().unwrap().clone();
        let plan = self.plan_with(&p, false);
        let mut out = Vec::new();
        if let Some(c) = &cfg {
            if c.safety {
                out.push(format!("Always let {} reach the gateway (ports {}) and the internet, whatever else is set.", c.safety_hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>().join(", "), c.safety_ports.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ")));
            } else {
                out.push("Management safety is off. A bad rule could lock you out.".into());
            }
        }
        match p.mode {
            Mode::BlockAll => out.push("Block everything: nothing passes through, trusted or not.".into()),
            Mode::LanOnly => out.push("Local Network Only: devices reach each other and the local network. The router only answers DHCP and DNS, and nothing goes to the internet.".into()),
            Mode::Normal => out.push("Normal: devices reach the internet unless something below stops them. From the router side, only the ports turned on under Ports get in.".into()),
            Mode::Audit => out.push("Audit: nothing is blocked except by Block Everything or Local Network Only. Everything the rules below would block is let through and listed under Firewall > Audit.".into()),
        }
        if !plan.audit.is_empty() {
            let names: Vec<String> = plan.audit.iter().map(|m| p.devices.get(m).map(|d| Self::device_label(d, m)).unwrap_or_else(|| m.clone())).collect();
            out.push(format!("In audit: {}. What would be blocked for them is let through and listed under Firewall > Audit.", names.join(", ")));
        }
        let open: Vec<String> = p.inbound.iter().filter(|i| i.on && !i.follow && i.mac.is_empty()).map(|i| format!("{} {}", i.proto, i.port)).collect();
        if !open.is_empty() {
            out.push(format!("Open from the router side to every device: {}.", open.join(", ")));
        }
        let lan: Vec<String> = p.inbound.iter().filter(|i| i.lan_off && i.mac.is_empty()).map(|i| format!("{} {}", i.proto, i.port)).collect();
        if !lan.is_empty() {
            out.push(format!("Blocked from the LAN side for every device: {}.", lan.join(", ")));
        }
        let count = |pol: DevicePolicy| p.devices.values().filter(|d| d.policy == pol).count();
        for (pol, what) in [(DevicePolicy::Block, "fully blocked"), (DevicePolicy::LanOnly, "kept on the LAN"), (DevicePolicy::Trusted, "trusted (skip Black list, threat lists and countries)")] {
            let n = count(pol);
            if n > 0 {
                out.push(format!("{n} device{} {what}.", if n == 1 { "" } else { "s" }));
            }
        }
        if p.telemetry_all {
            out.push(format!("Block telemetry for every device, both ways ({} addresses known).", plan.telemetry.len()));
        } else {
            let n = p.devices.values().filter(|d| d.telemetry).count();
            if n > 0 {
                out.push(format!("Block telemetry for {n} device{} ({} addresses known).", if n == 1 { "" } else { "s" }, plan.telemetry.len()));
            }
        }
        if !p.white.is_empty() {
            out.push(format!("White list: {} always allowed ({}).", plural(p.white.len(), "entry", "entries"), plural(plan.white.len(), "address", "addresses")));
        }
        if !p.black.is_empty() {
            out.push(format!("Black list: {} blocked ({}).", plural(p.black.len(), "entry", "entries"), plural(plan.black.len(), "address", "addresses")));
        }
        if p.threats {
            out.push(format!("Threat lists: {} networks blocked.", plan.threats.len()));
        }
        if !p.countries.is_empty() {
            if !p.geo || !self.geo.try_read().is_ok_and(|g| g.loaded()) {
                out.push(format!("{} countries chosen, waiting for the location database.", p.countries.len()));
            } else if self.geo_elems(&p, false).is_none() {
                out.push(format!("Block {} countries (rules being prepared).", p.countries.len()));
            } else {
                out.push(format!("Block {} countries ({} address ranges).", p.countries.len(), plan.countries.n4 + plan.countries.n6));
            }
        }
        out
    }

    pub fn device_by_ip(&self, ip: &str) -> Option<(String, Device)> {
        self.policy.read().unwrap().devices.iter().find(|(_, d)| d.ip == ip).map(|(m, d)| (m.clone(), d.clone()))
    }

    pub fn device_label(d: &Device, mac: &str) -> String {
        if !d.name.is_empty() {
            d.name.clone()
        } else if !d.hostname.is_empty() {
            d.hostname.clone()
        } else if !d.vendor.is_empty() && !d.vendor.starts_with("Private") {
            format!("{} {}", d.vendor, &mac[9..])
        } else {
            format!("Device {}", &mac[9..])
        }
    }

    /// Devices with no host name yet: ask the router's DNS, then the
    /// device itself (mDNS, NetBIOS). Every known device with an address is
    /// asked, not only ones seen in the last minutes: devices on the router
    /// side are seen once and then only now and then, and 0.5.2 skipped them
    /// for good. A device that doesn't answer is asked again after 2, 4, 8 ..
    /// up to 60 minutes; 16 per round, most recently seen first.
    pub fn find_names(&self) {
        let t = now();
        let todo: Vec<(String, std::net::Ipv4Addr)> = {
            let p = self.policy.read().unwrap();
            let mut asked = self.asked.lock().unwrap();
            asked.retain(|m, _| p.devices.get(m).is_some_and(|d| d.hostname.is_empty()));
            let mut due: Vec<_> = p
                .devices
                .iter()
                .filter(|(m, d)| d.hostname.is_empty() && asked.get(*m).is_none_or(|&(at, tries)| t - at >= retry_after(tries)))
                .filter_map(|(m, d)| Some((d.last_seen, m.clone(), d.ip.parse().ok()?)))
                .collect();
            due.sort_by_key(|d| std::cmp::Reverse(d.0));
            due.into_iter().take(16).map(|(_, m, ip)| (m, ip)).collect()
        };
        if todo.is_empty() {
            return;
        }
        let mut dns = net::gateways();
        for r in net::resolvers() {
            if let Ok(ip) = r.parse() {
                if !dns.contains(&ip) {
                    dns.push(ip);
                }
            }
        }
        for (mac, ip) in todo {
            let name = crate::names::lookup(ip, &dns);
            {
                let mut asked = self.asked.lock().unwrap();
                let tries = asked.get(&mac).map(|a| a.1 + 1).unwrap_or(0);
                asked.insert(mac.clone(), (t, tries));
            }
            if !name.is_empty() {
                if let Some(d) = self.policy.write().unwrap().devices.get_mut(&mac) {
                    d.hostname = name;
                }
            }
        }
    }

    /// Where the gateway's public address is, for the map. Looked up once
    /// every 10 minutes, or every minute while it keeps failing.
    pub fn home_place(&self) -> Option<geo::Place> {
        let t = now();
        {
            let h = self.home.lock().unwrap();
            let wait = if h.0.is_some() { 600 } else { 60 };
            if t - h.1 < wait {
                return h.0.clone();
            }
        }
        self.home.lock().unwrap().1 = t;
        let ip = crate::lists::fetch_text("https://api.ipify.org").ok().and_then(|s| s.trim().parse::<std::net::IpAddr>().ok());
        let place = ip.and_then(|ip| self.geo.read().unwrap().locate(ip));
        *self.home.lock().unwrap() = (place.clone(), t);
        place
    }

    // ---- background jobs ----

    /// The service stopped while a setup waited for its confirm, so the
    /// timer that would undo it is gone. Undo it now instead.
    pub fn recover_setup(&self) {
        let w = self.wizard.lock().unwrap().clone();
        if w.applied.is_none() {
            return;
        }
        let _ = crate::undo();
        match &w.old_cfg {
            Some(t) => {
                let _ = std::fs::write(&self.conf_path, t);
                *self.cfg.write().unwrap() = Config::parse(t).ok();
            }
            None => {
                let _ = std::fs::remove_file(&self.conf_path);
                *self.cfg.write().unwrap() = None;
            }
        }
        self.log.note("setting", "Setup was undone: the service restarted before anyone confirmed it.");
        self.setup_undone("The gateway restarted before you confirmed, so it went back to how it was. Press Apply again.");
    }

    /// Whether the ports answer setup traffic: until the roles are set,
    /// and while a new layout waits for its confirm.
    pub fn setup_mode(&self) -> bool {
        let applied = self.wizard.lock().unwrap().applied.is_some();
        applied || self.needs_setup()
    }

    pub fn start_setup_jobs(self: &Arc<Self>) {
        let a = self.clone();
        std::thread::spawn(move || loop {
                if a.setup_mode() {
                    a.anyport.tick();
                }
                for n in std::mem::take(&mut *a.anyport.notes.lock().unwrap()) {
                    a.log.note("setting", &n);
                }
                std::thread::sleep(Duration::from_secs(1));
        });
        if !self.setup_mode() {
            self.anyport.resume();
        }
        let a = self.clone();
        let b = self.clone();
        let c = self.clone();
        std::thread::spawn(move || {
            crate::mdns::run(
                move || {
                    let mut v: Vec<String> = if a.setup_mode() { net::ports().into_iter().map(|p| p.name).filter(|n| !net::enslaved(n)).collect() } else { vec![] };
                    if crate::bridge::exists() {
                        v.push(crate::bridge::NAME.to_string());
                    }
                    v
                },
                move |port, asker| {
                    let p = net::port(port)?;
                    let own = p.ips.iter().filter_map(|i| i.split_once('/')).filter_map(|(ip, len)| Some((ip.parse::<std::net::Ipv4Addr>().ok()?, len.parse::<u32>().ok()?)));
                    let mut first = None;
                    for (ip, len) in own {
                        let m = if len == 0 { 0 } else { u32::MAX << (32 - len.min(32)) };
                        if u32::from(ip) & m == u32::from(asker) & m {
                            return Some(ip);
                        }
                        first.get_or_insert(ip);
                    }
                    if b.anyport.owned().setup.iter().any(|s| s == port) && (asker.is_link_local() || asker.is_unspecified() || first.is_none()) {
                        return Some(crate::anyport::SETUP_ADDR);
                    }
                    first.or(b.anyport.owned().setup.iter().any(|s| s == port).then_some(crate::anyport::SETUP_ADDR))
                },
                move |n| c.log.note("setting", n),
            )
        });
    }

    /// After a restart with setup done, the bridge comes back as it was.
    /// DHCP crossing the bridge goes in the Capture Log and the journal.
    fn watch_dhcp(&self) {
        let mut on: Option<(String, crate::dhcpwatch::Watch)> = None;
        loop {
            let wan = self.cfg.read().unwrap().as_ref().map(|c| c.wan.clone()).filter(|_| crate::bridge::exists());
            if on.as_ref().map(|o| &o.0) != wan.as_ref() {
                on = wan.and_then(|w| crate::dhcpwatch::Watch::open(&w).map(|s| (w, s)));
            }
            let Some((_, w)) = &on else {
                std::thread::sleep(Duration::from_secs(2));
                continue;
            };
            if let Some(d) = w.next() {
                let text = crate::dhcpwatch::text(&d);
                eprintln!("foilgw: {text}");
                let host = crate::names::tidy(&d.host);
                if !host.is_empty() {
                    let known = self.policy.write().unwrap().devices.get_mut(&d.mac).map(|v| v.hostname = host.clone()).is_some();
                    if !known {
                        let mut heard = self.heard.lock().unwrap();
                        if heard.len() >= 4096 {
                            heard.clear();
                        }
                        heard.insert(d.mac.clone(), host);
                    }
                }
                self.log.add("dhcp", &d.mac, &text, now(), self.tz_offset());
            }
        }
    }

    pub fn restore_bridge(&self) {
        if self.needs_setup() {
            return;
        }
        // networkd builds it at boot from our files; we only filter it.
        if crate::bridge::exists() || crate::bridge::networkd_owned() {
            if let Err(e) = crate::bridge::filtering() {
                self.log.note("alert", &format!("Bridged traffic isn't filtered: {e}"));
            }
            return;
        }
        let Some(cfg) = self.cfg.read().unwrap().clone() else { return };
        match crate::bridge::up(&self.dir, &cfg.wan, &cfg.lan, &self.anyport.ours()) {
            Ok(_) => self.log.note("setting", &format!("Bridge {} rebuilt with {} and {}.", crate::bridge::NAME, cfg.wan, cfg.lan.join(", "))),
            Err(e) => self.log.note("alert", &format!("Couldn't rebuild the bridge: {e}")),
        }
    }

    pub fn start_jobs(self: &Arc<Self>) {
        self.restore_bridge();
        let a = self.clone();
        std::thread::spawn(move || a.watch_dhcp());
        self.start_setup_jobs();
        let a = self.clone();
        std::thread::spawn(move || loop {
            a.undo_if_late();
            std::thread::sleep(Duration::from_millis(500));
        });
        let a = self.clone();
        std::thread::spawn(move || loop {
            a.poll_devices();
            a.poll_traffic();
            a.poll_inbound();
            a.poll_detection();
            a.expire_audit();
            a.expire_allows();
            std::thread::sleep(Duration::from_secs(2));
        });
        let a = self.clone();
        std::thread::spawn(move || a.read_kernel_log());
        self.start_name_jobs();
        let a = self.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(60));
            a.check_surges();
            a.tidy_maps();
        });
        // The page's certificate follows the gateway's addresses.
        let a = self.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(60));
            match crate::certs::check(&a.dir) {
                Some(Ok(_)) => a.log.note("setting", "New certificate for the settings page (address changed or due to renew)."),
                Some(Err(e)) => a.log.note("alert", &format!("Couldn't renew the settings page certificate: {e}")),
                None => {}
            }
        });
        let a = self.clone();
        std::thread::spawn(move || loop {
            a.find_names();
            std::thread::sleep(Duration::from_secs(30));
        });
        // Its own loop, so it starts with the service instead of waiting
        // behind the feed downloads.
        let a = self.clone();
        std::thread::spawn(move || {
            let dir = format!("{}/geo", a.dir);
            if a.policy.read().unwrap().geo {
                eprintln!("foilgw: location database on, files in {dir}");
            } else {
                eprintln!("foilgw: location database is off in Settings, nothing to download");
            }
            loop {
                if a.update_geo() && a.geo.read().unwrap().loaded() {
                    a.refresh_rules();
                }
                if a.geo.read().unwrap().loaded() {
                    a.home_place();
                }
                std::thread::sleep(Duration::from_secs(60));
            }
        });
        let a = self.clone();
        std::thread::spawn(move || loop {
            a.resolve_sites();
            a.update_feeds();
            a.refresh_rules();
            let days = a.policy.read().unwrap().log_days.max(1);
            a.log.prune(days);
            std::thread::sleep(Duration::from_secs(300));
        });
    }

    /// Devices are whatever the bridge learned on the LAN ports, with the
    /// address from the neighbour table or from their own packets.
    pub fn poll_devices(&self) {
        let Some(lan) = self.cfg.read().unwrap().as_ref().map(|c| c.lan.clone()) else { return };
        let leases = net::leases();
        let learned = net::learned();
        let neigh: HashMap<String, String> = net::neighbours().into_iter().filter(|n| n.dev == crate::bridge::NAME || lan.contains(&n.dev)).map(|n| (n.mac, n.ip)).collect();
        let found: Vec<(String, String, String)> = crate::bridge::macs_on(&lan)
            .into_iter()
            .map(|mac| {
                let ip = neigh.get(&mac).or(learned.get(&mac)).or(leases.get(&mac).map(|l| &l.0)).cloned().unwrap_or_default();
                let host = leases.get(&mac).map(|l| l.1.clone()).filter(|h| !h.is_empty() && h != "*").or_else(|| self.heard.lock().unwrap().remove(&mac)).unwrap_or_default();
                (mac, ip, host)
            })
            .collect();
        let t = now();
        let mut changed_rules = false;
        let mut new_ones = Vec::new();
        {
            let mut p = self.policy.write().unwrap();
            let default = p.new_devices;
            for (mac, ip, host) in found {
                match p.devices.get_mut(&mac) {
                    Some(d) => {
                        // Rules go by MAC, so a new address changes nothing there.
                        if !ip.is_empty() {
                            d.ip = ip;
                        }
                        if !host.is_empty() {
                            d.hostname = host;
                        }
                        d.last_seen = t;
                    }
                    None => {
                        let sticky = sticky_name_hint(&p.devices, &mac, &ip, &host, t, p.sticky_identity);
                        let mut d = Device {
                            ip,
                            vendor: crate::oui::vendor(&mac),
                            policy: default,
                            first_seen: t,
                            last_seen: t,
                            new: true,
                            hostname: host,
                            ..Default::default()
                        };
                        if let Some((name, _)) = sticky {
                            if d.name.is_empty() {
                                d.name = name; // soft: keep the earlier name; do not migrate policy
                            }
                        }
                        changed_rules |= default != DevicePolicy::Normal;
                        new_ones.push((mac.clone(), d.clone()));
                        p.devices.insert(mac, d);
                    }
                }
            }
        }
        let off = self.tz_offset();
        for (mac, d) in &new_ones {
            let label = Self::device_label(d, mac);
            let maker = if d.vendor.is_empty() { "unknown maker".into() } else { d.vendor.clone() };
            let sticky = if crate::oui::is_private(mac) && !d.name.is_empty() {
                " Looks like a renamed private address; kept the earlier name."
            } else {
                ""
            };
            self.log.add("device", mac, &format!("New device {label} at {} ({maker}). Set to {}.{}", d.ip, d.policy.label(), sticky), t, off);
        }
        if !new_ones.is_empty() || changed_rules || t % 60 < 2 {
            let _ = self.policy.read().unwrap().save(&self.policy_path());
        }
        if changed_rules {
            self.refresh_rules();
        }
    }

    pub fn poll_traffic(&self) {
        let map_counts = crate::maptraffic::counters();
        let mut tracker=self.map_traffic.lock().unwrap();
        match map_counts {Some(counters)=>tracker.sample(counters,Instant::now()),None=>tracker.invalidate()}
        drop(tracker);
        let up = net::device_bytes("dev_up");
        let down = net::device_bytes("dev_down");
        let ports = self.cfg.read().unwrap().as_ref().map(|c| (c.wan.clone(), c.lan.clone()));
        // Dashboard cards that are off (Settings > View) don't get sampled.
        let (cpu_on, wan_on, lan_on) = {
            let p = self.policy.read().unwrap();
            (p.card_on("cpu"), p.card_on("wan"), p.card_on("lan"))
        };
        let ticks = if cpu_on { Some(net::cpu_ticks()) } else { None };
        let mut l = self.live.lock().unwrap();
        match ticks {
            Some((busy, total)) => {
                let (pb, pt) = l.cpu_prev;
                if total > pt && pt > 0 {
                    l.cpu = (busy - pb.min(busy)) as f64 * 100.0 / (total - pt) as f64;
                }
                l.cpu_prev = (busy, total);
            }
            // Start fresh when it comes back, not with an average since it went off.
            None => {
                l.cpu_prev = (0, 0);
                l.cpu = 0.0;
            }
        }
        let secs = l.last_at.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0);
        // A device usually shows in both sets; each once.
        let macs: std::collections::BTreeSet<&String> = up.keys().chain(down.keys()).collect();
        let mut rates = HashMap::new();
        for mac in macs {
            let now_v = (up.get(mac).copied().unwrap_or(0), down.get(mac).copied().unwrap_or(0));
            let prev = l.last.get(mac).copied();
            // Counters start again from zero whenever the rules reload.
            let delta = match prev {
                Some(p) => (if now_v.0 >= p.0 { now_v.0 - p.0 } else { now_v.0 }, if now_v.1 >= p.1 { now_v.1 - p.1 } else { now_v.1 }),
                None => now_v,
            };
            l.last.insert(mac.clone(), now_v);
            let t = l.totals.entry(mac.clone()).or_default();
            t.0 += delta.0;
            t.1 += delta.1;
            if secs > 0.0 && prev.is_some() {
                rates.insert(mac.clone(), (delta.0 as f64 / secs, delta.1 as f64 / secs));
            }
        }
        // Gone from the kernel's sets (an hour quiet): nothing to compare with.
        l.last.retain(|m, _| up.contains_key(m) || down.contains_key(m));
        // Port throughput for the dashboard, from /sys counters.
        if let Some((wan, lans)) = ports {
            let port_rate = |name: &str, l: &mut Live| -> (f64, f64) {
                let now_v = net::port_bytes(name);
                let prev = l.port_last.insert(name.to_string(), now_v);
                match prev {
                    Some(p) if secs > 0.0 && now_v.0 >= p.0 && now_v.1 >= p.1 => (((now_v.0 - p.0) * 8) as f64 / secs, ((now_v.1 - p.1) * 8) as f64 / secs),
                    _ => (0.0, 0.0),
                }
            };
            l.wan_bps = if wan_on { port_rate(&wan, &mut l) } else { (0.0, 0.0) };
            let mut sum = (0.0, 0.0);
            if lan_on {
                for n in &lans {
                    let r = port_rate(n, &mut l);
                    // A LAN port sends what goes down to devices.
                    sum = (sum.0 + r.1, sum.1 + r.0);
                }
            }
            l.lan_bps = sum;
            // A port whose card is off drops its last reading, so turning it
            // back on starts from a fresh one.
            l.port_last.retain(|n, _| (wan_on && *n == wan) || (lan_on && lans.contains(n)));
        }
        l.rates = rates;
        l.last_at = Some(Instant::now());
    }

    /// Block lines come from the kernel log: each drop chain logs with a
    /// "fgw:<reason> " prefix, rate limited in the rule itself.
    fn read_kernel_log(&self) {
        let Ok(mut f) = std::fs::File::open("/dev/kmsg") else {
            self.log.note("alert", "Can't read the kernel log, so blocks won't show in the Capture Log.");
            return;
        };
        let _ = f.seek(std::io::SeekFrom::End(0));
        let r = std::io::BufReader::new(f);
        for line in r.lines() {
            let Ok(line) = line else { continue };
            if let Some(b) = parse_block(&line) {
                self.record_block(&b);
            }
        }
    }

    pub fn record_block(&self, b: &Block) {
        let reason = rules::REASONS.iter().find(|r| r.0 == b.reason).map(|r| r.1).unwrap_or("not allowed in");
        let lan = self.cfg.read().unwrap().as_ref().map(|c| c.lan.clone()).unwrap_or_default();
        let came_in = if b.physin.is_empty() { &b.inif } else { &b.physin };
        let outbound = lan.contains(came_in);
        let (dev_ip, other) = if outbound { (&b.src, &b.dst) } else { (&b.dst, &b.src) };
        let dev_mac = if outbound { &b.smac } else { &b.dmac };
        let known = self.policy.read().unwrap().devices.get(dev_mac).cloned().map(|d| (dev_mac.clone(), d));
        let (mac, label) = match known.or_else(|| self.device_by_ip(dev_ip)) {
            Some((m, d)) => (m.clone(), Self::device_label(&d, &m)),
            None => (String::new(), dev_ip.clone()),
        };
        if b.reason == "wan" && !mac.is_empty() && b.dport > 0 && (b.proto == "tcp" || b.proto == "udp") {
            self.saw_inbound(&b.proto, b.dport, &mac, other);
        }
        // The port isn't in the text: one line covers every port on the
        // address, listed apart.
        let dir = if outbound { "to" } else { "from" };
        let place = other.parse().ok().and_then(|ip| self.geo.read().unwrap().locate(ip)).map(|p| format!(" ({})", p.country)).unwrap_or_default();
        let at = now();
        let text = if b.audit { format!("{label} {dir} {other}{place}: would be blocked ({reason}), let through by audit") } else { format!("{label} {dir} {other}{place}: {reason}") };
        let off = self.tz_offset();
        let domain = if mac.is_empty() { String::new() } else { self.domain_of(&mac, other) };
        let meta = crate::caplog::Meta { reason: b.reason.clone(), remote: other.clone(), proto: b.proto.clone(), port: b.dport, dir: if outbound { "out" } else { "in" }.into(), domain, outcome:if b.audit{"audit_allowed"}else{"dropped"}.into() };
        self.log.add_block(if b.audit { "audit" } else { "block" }, &mac, &text, at, off, &meta);
        if !b.audit { self.log.handle_stopped_alerts(&mac,&meta); }
        self.recent.lock().unwrap().add(
            crate::recent::Key { mac: mac.clone(), reason: b.reason.clone(), remote: other.clone(), proto: b.proto.clone(), port: b.dport, outbound, audit: b.audit },
            at,
        );
        if b.reason=="wan" && b.audit && !mac.is_empty() {
            self.log.add_block("alert",&mac,&format!("{label} received a new router-side {0} {1} attempt from {other}. Audit is on, so it was let through.",b.proto,b.dport),at,off,&meta);
        }
        if b.reason == "threat" && b.audit {
            self.log.add_block("alert", &mac, &format!("{label} reached {dir} {other}, which is on a threat list. Audit is on, so it was let through."), at, off, &meta);
        }
    }

    pub fn poll_detection(&self){
        // Keep sampling and publication within one application rules epoch.
        let _rules_epoch=self.applying.lock().unwrap();
        let on=self.policy.read().unwrap().deep_detect;
        let snapshot=if on{crate::detection::snapshot()}else{Ok(crate::detection::Snapshot{signals:vec![],generation:0})};
        let (alerts,resolved)={let mut detector=self.detection.lock().unwrap();let alerts=detector.ingest(on,snapshot);(alerts,detector.take_resolved())};
        if let Err(e)=self.log.resolve_tcp(&resolved){self.detection.lock().unwrap().storage_failed(e);return;}
        for a in alerts{let label=self.policy.read().unwrap().devices.get(&a.mac).map(|d|Self::device_label(d,&a.mac)).unwrap_or(a.mac.clone());
            let text=if a.reason=="port_sweep"{format!("{label}: {} distinct TCP destination ports {} {} in 60 seconds.",a.count,if a.outbound{"to"}else{"from"},a.remote)}else{format!("{label}: {} TCP attempts {} {} were refused or had no SYN-ACK within 10 seconds.",a.count,if a.outbound{"to"}else{"from"},a.remote)};
            if let Err(e)=self.log.pattern(&a,now(),&text){self.detection.lock().unwrap().storage_failed(e);return;}
        }
    }

    /// Keep raw blocked evidence, without alerting about traffic already stopped.
    pub fn check_surges(&self) { self.recent.lock().unwrap().prune(now()); }

    /// Once a minute: forgets per-device numbers for devices that are
    /// gone from the list and from the kernel's counters.
    fn tidy_maps(&self) {
        let known: std::collections::HashSet<String> = self.policy.read().unwrap().devices.keys().cloned().collect();
        let mut l = self.live.lock().unwrap();
        let Live { totals, last, rates, .. } = &mut *l;
        totals.retain(|m, _| known.contains(m) || last.contains_key(m));
        rates.retain(|m, _| last.contains_key(m));
        drop(l);
        self.heard.lock().unwrap().retain(|m, _| !known.contains(m));
    }

    /// Turns off a device's audit when its time is up.
    pub fn expire_audit(&self) {
        let t = now();
        if self.pending.lock().unwrap().is_some() {
            return;
        }
        let done: Vec<String> = {
            let mut p = self.policy.write().unwrap();
            let mut done = Vec::new();
            for (m, d) in p.devices.iter_mut() {
                if d.audit_until != 0 && d.audit_until <= t {
                    d.audit_until = 0;
                    done.push(Self::device_label(d, m));
                }
            }
            if !done.is_empty() {
                let _ = p.save(&self.policy_path());
            }
            done
        };
        if !done.is_empty() {
            self.log.note("setting", &format!("Audit time is up for {}. Blocking as normal again.", done.join(", ")));
            self.refresh_rules();
        }
    }

    /// Drops time-boxed white / device-allow entries whose until has passed.
    pub fn expire_allows(&self) {
        if self.pending.lock().unwrap().is_some() {
            return;
        }
        let t = now();
        let gone = {
            let mut p = self.policy.write().unwrap();
            if !p.white_expiry && p.white_until.is_empty() && p.devices.values().all(|d| d.allow_until.is_empty()) {
                return;
            }
            let gone = p.expire_allows(t);
            if !gone.is_empty() {
                let _ = p.save(&self.policy_path());
            }
            gone
        };
        if !gone.is_empty() {
            self.log.note("setting", &format!("Allow time is up: {}. Blocking as normal again.", gone.join("; ")));
            self.refresh_rules();
        }
    }

    /// Something on the router side reached for a port on a LAN device,
    /// blocked or let through. It goes on the Ports list for that device;
    /// a port nobody listed yet shows as new, and stays shut until it's
    /// turned on. A device's entry follows the one for everybody until
    /// the owner sets it.
    pub fn saw_inbound(&self, proto: &str, port: u16, mac: &str, from: &str) {
        let mut p = self.policy.write().unwrap();
        let everyone = p.inbound.iter().find(|i| i.same(proto, port, "")).map(|i| (i.on, i.lan_off));
        let t = now();
        let fresh = match p.inbound.iter_mut().find(|i| i.same(proto, port, mac)) {
            Some(i) => {
                i.hits += 1;
                i.last_seen = t;
                i.from = from.to_string();
                false
            }
            None => {
                p.inbound.push(crate::policy::InPort {
                    proto: proto.into(),
                    port,
                    mac: mac.into(),
                    on: everyone.is_some_and(|e| e.0),
                    lan_off: everyone.is_some_and(|e| e.1),
                    follow: everyone.is_some(),
                    new: everyone.is_none(),
                    hits: 1,
                    last_seen: t,
                    from: from.to_string(),
                    ..Default::default()
                });
                true
            }
        };
        if fresh {
            let _ = p.save(&self.policy_path());
            let label = p.devices.get(mac).map(|d| Self::device_label(d, mac)).unwrap_or(mac.to_string());
            drop(p);
            self.log.add_block("device", mac, &format!("{from} on the router side tried {proto} {port} on {label}. It's on the Ports list."), t, self.tz_offset(), &crate::caplog::Meta{reason:"port_observed".into(),..Default::default()});
        }
    }

    /// Connections that came in from the router side and were let
    /// through also count as seen ports.
    pub fn poll_inbound(&self) {
        let devs: HashMap<String, String> = self.policy.read().unwrap().devices.iter().filter(|(_, d)| !d.ip.is_empty()).map(|(m, d)| (d.ip.clone(), m.clone())).collect();
        let mut seen = std::collections::HashSet::new();
        let mut out: Vec<String> = Vec::new();
        // The gateway's own lookups (device names over mDNS and NetBIOS)
        // aren't the router side knocking.
        let own: std::collections::HashSet<String> = net::all_ports_cached().iter().flat_map(|p| p.ips.iter()).map(|c| c.split('/').next().unwrap_or("").to_string()).collect();
        let mut local = None;
        for c in net::connections_cached().iter() {
            if own.contains(&c.src) {
                continue;
            }
            // A LAN device started it: an outbound use of that port.
            if devs.contains_key(&c.src) && c.dport > 0 && c.proto != "icmp" && !devs.contains_key(&c.dst) {
                out.push(format!("{} {}", c.proto, c.dport));
            }
            if c.proto == "icmp" || c.dport == 0 || devs.contains_key(&c.src) || !seen.insert((c.src.clone(), c.dst.clone(), c.dport)) {
                continue;
            }
            if let Some(mac) = devs.get(&c.dst) {
                // Only the local network is the router side; the internet
                // can't open a connection into a bridge without the router's help.
                let near = c.src.parse::<std::net::Ipv4Addr>().ok().is_some_and(|ip| local.get_or_insert_with(|| self.local_nets().0).v4.iter().any(|n| in_net(ip, n)));
                if near {
                    let known = self.policy.read().unwrap().inbound.iter().any(|i| i.same(&c.proto, c.dport, mac));
                    if !known {
                        self.saw_inbound(&c.proto, c.dport, mac, &c.src);
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        let t = now();
        // Once a minute per port is plenty for "last used".
        let stale: Vec<String> = { let p = self.policy.read().unwrap(); out.into_iter().filter(|k| p.out_seen.get(k).is_none_or(|&w| t - w > 60)).collect() };
        if !stale.is_empty() {
            let mut p = self.policy.write().unwrap();
            for k in stale {
                p.out_seen.insert(k, t);
            }
            p.trim_out_seen(t);
        }
    }

    pub fn resolve_sites(&self) {
        let p = self.policy.read().unwrap().clone();
        let mut sites: Vec<String> = Vec::new();
        for e in p.white.iter().chain(&p.black).chain(p.devices.values().flat_map(|d| d.allow.iter().chain(&d.deny))) {
            if let Ok(Entry::Site(s)) = parse_entry(e) {
                sites.push(s);
            }
        }
        if p.telemetry_all || p.devices.values().any(|d| d.telemetry) {
            sites.extend(self.feeds.read().unwrap().telemetry_hosts.iter().cloned());
        }
        sites.sort();
        sites.dedup();
        for s in sites {
            // Lookups happen without the lock so the pages never wait on DNS.
            let mut tmp = lists::SeenAddrs::default();
            tmp.refresh(&s);
            let mut seen = self.seen.lock().unwrap();
            let e = seen.sites.entry(s.clone()).or_default();
            e.extend(tmp.of(&s));
        }
        self.seen.lock().unwrap().save(&format!("{}/addresses.json", self.dir));
    }

    /// Looks up the sites on the owner's own lists, for the command line,
    /// which has no background lookups.
    pub fn warm_lists(&self) {
        let p = self.policy.read().unwrap().clone();
        p.white.iter().chain(&p.black).chain(p.devices.values().flat_map(|d| d.allow.iter().chain(&d.deny))).for_each(|e| self.warm(e));
    }

    /// Looks up one site straight away so a new list entry works at once.
    pub fn warm(&self, entry: &str) {
        if let Ok(Entry::Site(s)) = parse_entry(entry) {
            let mut tmp = lists::SeenAddrs::default();
            tmp.refresh(&s);
            self.seen.lock().unwrap().sites.entry(s.clone()).or_default().extend(tmp.of(&s));
        }
    }

    fn feed_dir(&self) -> String {
        format!("{}/feeds", self.dir)
    }

    fn load_feeds(&self) {
        let dir = self.feed_dir();
        let mut f = Feeds::default();
        for (feed, threat) in lists::TELEMETRY.iter().map(|x| (x, false)).chain(lists::THREATS.iter().map(|x| (x, true))) {
            let path = format!("{dir}/{}.txt", feed.id);
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let fetched = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
            let entries = if feed.hosts {
                let h = lists::parse_hosts(&text);
                let n = h.len();
                for x in &h {
                    f.host_feed.entry(x.clone()).or_insert(feed.id);
                }
                f.telemetry_hosts.extend(h);
                n
            } else {
                let a = lists::parse_addresses(&text);
                let target = if threat { &mut f.threats } else { &mut f.telemetry };
                a.iter().for_each(|x| target.add(x));
                let n = a.len();
                f.addr_feeds.push((feed.id, a));
                n
            };
            let old_err = self.feeds.read().unwrap().status.get(feed.id).map(|s| s.error.clone()).unwrap_or_default();
            f.status.insert(feed.id.into(), FeedStatus { id: feed.id.into(), name: feed.name.into(), url: feed.url.into(), entries, fetched_at: fetched, error: old_err });
        }
        f.telemetry_hosts.sort();
        f.telemetry_hosts.dedup();
        *self.feeds.write().unwrap() = f;
    }

    pub fn update_feeds(&self) {
        let p = self.policy.read().unwrap().clone();
        let tele = p.telemetry_all || p.devices.values().any(|d| d.telemetry);
        let dir = self.feed_dir();
        let _ = std::fs::create_dir_all(&dir);
        let mut got = false;
        for (feed, on) in lists::TELEMETRY.iter().map(|x| (x, tele)).chain(lists::THREATS.iter().map(|x| (x, p.threats))) {
            if !on {
                continue;
            }
            let path = format!("{dir}/{}.txt", feed.id);
            let age = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok());
            if age.is_some_and(|a| a < Duration::from_secs(24 * 3600)) {
                continue;
            }
            match lists::fetch_text(feed.url) {
                Ok(text) => {
                    let _ = std::fs::write(&path, &text);
                    self.log.note("download", &format!("Downloaded {} from {}, {:.0} KB.", feed.name, feed.url, text.len() as f64 / 1000.0));
                    got = true;
                }
                Err(e) => {
                    self.log.note("download", &format!("{} from {} didn't download: {e}", feed.name, feed.url));
                    if let Some(s) = self.feeds.write().unwrap().status.get_mut(feed.id) {
                        s.error = e;
                    }
                }
            }
        }
        if got {
            self.load_feeds();
            self.resolve_sites();
        }
    }

    /// Downloads the location database when it's on and due. After a
    /// failure it waits 1, 5, 15, then 60 minutes before trying again.
    pub fn update_geo(&self) -> bool {
        if !self.policy.read().unwrap().geo {
            return true;
        }
        if now() < geo::NEXT_TRY.load(Ordering::Relaxed) || geo::BUSY.swap(true, Ordering::AcqRel) {
            return false;
        }
        let dir = std::path::PathBuf::from(format!("{}/geo", self.dir));
        let first = !self.geo.read().unwrap().loaded();
        let (m, prev) = month_of(now());
        let res = geo::refresh(&dir, &m, &prev, first);
        let ok = !matches!(res, Some(Err(_)));
        match res {
            Some(Ok(line)) => {
                self.log.note("download", &line);
                let db = geo::Db::open(&dir);
                *self.geo.write().unwrap() = db;
                self.geo_reloaded();
            }
            Some(Err(e)) => {
                let n = geo::FAILS.fetch_add(1, Ordering::Relaxed) + 1;
                geo::NEXT_TRY.store(now() + geo::backoff(n), Ordering::Relaxed);
                let line = format!("{e} Trying again in {} minutes.", geo::backoff(n) / 60);
                eprintln!("foilgw: {line}");
                self.log.note("download", &line);
            }
            None => {}
        }
        if ok {
            geo::FAILS.store(0, Ordering::Relaxed);
            geo::NEXT_TRY.store(0, Ordering::Relaxed);
        }
        geo::BUSY.store(false, Ordering::Release);
        ok
    }

    /// Starts the download now instead of waiting for the next round, and
    /// keeps retrying on the backoff until it works or is turned off.
    pub fn geo_now(self: &Arc<Self>) {
        geo::NEXT_TRY.store(0, Ordering::Relaxed);
        geo::FAILS.store(0, Ordering::Relaxed);
        let a = self.clone();
        std::thread::spawn(move || {
            while !a.update_geo() && a.policy.read().unwrap().geo && geo::FAILS.load(Ordering::Relaxed) < 4 {
                let wait = (geo::NEXT_TRY.load(Ordering::Relaxed) - now()).clamp(1, 3600);
                std::thread::sleep(Duration::from_secs(wait as u64));
            }
            a.refresh_rules();
        });
    }
}

#[derive(Debug, PartialEq)]
pub struct Block {
    pub reason: String,
    /// Logged by audit: would have been blocked, was let through.
    pub audit: bool,
    pub inif: String,
    /// The bridge port it came in on.
    pub physin: String,
    /// Ethernet source and destination.
    pub smac: String,
    pub dmac: String,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub dport: u16,
}

/// "6,1234,5678,-;fgw:black IN=eth3 OUT=eth2 ... SRC=a DST=b ... PROTO=TCP SPT=1 DPT=443"
pub fn parse_block(line: &str) -> Option<Block> {
    let msg = line.split_once(';').map(|x| x.1).unwrap_or(line);
    // Our prefix starts the message; "br-fgw: port ..." lines don't count.
    let rest = msg.trim_start().strip_prefix(rules::LOG_PREFIX)?;
    let word = rest.split_whitespace().next()?;
    let (audit, reason) = match word.strip_prefix("audit:") {
        Some(r) => (true, r.to_string()),
        None => (false, word.to_string()),
    };
    if !rules::REASONS.iter().any(|r| r.0 == reason) {
        return None;
    }
    let field = |k: &str| rest.split_whitespace().find_map(|w| w.strip_prefix(k)).unwrap_or("").to_string();
    // MAC=dst:src:type, 14 bytes as hex pairs.
    let mac = field("MAC=");
    let pairs: Vec<&str> = mac.split(':').collect();
    let (dmac, smac) = if pairs.len() >= 12 { (pairs[..6].join(":"), pairs[6..12].join(":")) } else { (String::new(), String::new()) };
    Some(Block {
        reason,
        audit,
        inif: field("IN="),
        physin: field("PHYSIN="),
        smac,
        dmac,
        src: field("SRC="),
        dst: field("DST="),
        proto: field("PROTO=").to_ascii_lowercase(),
        dport: field("DPT=").parse().unwrap_or(0),
    })
}

/// Seconds before asking a silent device for its name again.
pub fn retry_after(tries: u32) -> i64 {
    (120i64 << tries.min(5)).min(3600)
}

fn in_net(ip: std::net::Ipv4Addr, net: &str) -> bool {
    let (a, len) = net.split_once('/').unwrap_or((net, "32"));
    let (Ok(a), Ok(len)) = (a.parse::<std::net::Ipv4Addr>(), len.parse::<u32>()) else { return false };
    let m = if len == 0 { 0 } else { u32::MAX << (32 - len.min(32)) };
    u32::from(ip) & m == u32::from(a) & m
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Soft sticky-name heuristic: a new privacy MAC with the same IP or hostname
/// as a device that went quiet gets that device's name. Policy is not copied.
/// When `strong` (Wave I Stronger Identity), also match by hostname alone on a
/// longer quiet window, still without copying policy.
fn sticky_name_hint(
    devices: &std::collections::BTreeMap<String, Device>,
    new_mac: &str,
    ip: &str,
    host: &str,
    now: i64,
    strong: bool,
) -> Option<(String, String)> {
    if !crate::oui::is_private(new_mac) {
        return None;
    }
    let quiet_need = if strong { 30 } else { 60 };
    let mut best: Option<(i64, String, String)> = None; // (last_seen, name, old_mac)
    for (mac, d) in devices {
        if mac == new_mac {
            continue;
        }
        // Must have been quiet so we are not twin-homed.
        if now.saturating_sub(d.last_seen) < quiet_need {
            continue;
        }
        let ip_hit = !ip.is_empty() && d.ip == ip;
        let host_hit = !host.is_empty()
            && ((!d.hostname.is_empty() && d.hostname.eq_ignore_ascii_case(host))
                || (!d.name.is_empty() && d.name.eq_ignore_ascii_case(host)));
        // Soft: IP or hostname. Strong: also accept hostname-only matches that
        // soft would have caught via IP — already covered; keep same hits but
        // with the shorter quiet window above.
        if !(ip_hit || host_hit) {
            continue;
        }
        let name = if !d.name.is_empty() {
            d.name.clone()
        } else if !d.hostname.is_empty() {
            d.hostname.clone()
        } else {
            continue;
        };
        let score = d.last_seen;
        if best.as_ref().map(|(s, _, _)| score >= *s).unwrap_or(true) {
            best = Some((score, name, mac.clone()));
        }
    }
    best.map(|(_, name, mac)| (name, mac))
}

#[cfg(test)]
mod tests {
    #[test]
    fn name_retries_back_off() {
        assert_eq!([0, 1, 2, 3, 4, 5, 9].map(super::retry_after), [120, 240, 480, 960, 1920, 3600, 3600]);
    }

    use super::*;

    #[test]
    fn bridge_messages_arent_blocks() {
        assert!(parse_block("6,1,2,-;br-fgw: port 2(eth1) entered disabled state").is_none());
    }

    #[test]
    fn kernel_log_line() {
        let l = "4,812,99812345,-;fgw:black IN=eth3 OUT=eth2 MAC=aa SRC=10.10.10.50 DST=93.184.216.34 LEN=60 TOS=0x00 TTL=63 ID=1 DF PROTO=TCP SPT=40000 DPT=443 WINDOW=64240 SYN";
        let b = parse_block(l).unwrap();
        assert_eq!(b, Block { reason: "black".into(), inif: "eth3".into(), physin: "".into(), smac: "".into(), dmac: "".into(), src: "10.10.10.50".into(), dst: "93.184.216.34".into(), proto: "tcp".into(), dport: 443, audit: false });
        assert!(parse_block("6,1,1,-;eth0: link up").is_none());
        let a = parse_block("6,813,99812346,-;fgw:audit:country IN=eth3 OUT=eth2 MAC=aa SRC=10.10.10.50 DST=1.2.3.4 LEN=60 PROTO=UDP SPT=1 DPT=53").unwrap();
        assert!(a.audit && a.reason == "country" && a.proto == "udp" && a.dport == 53);
        let br = "4,9,9,-;fgw:wan IN=br-fgw OUT=br-fgw PHYSIN=eth2 PHYSOUT=eth3 MAC=02:00:00:00:00:0a:02:00:00:00:00:0b:08:00 SRC=10.9.0.42 DST=10.9.0.50 LEN=60 PROTO=TCP SPT=5000 DPT=3389 SYN";
        let b = parse_block(br).unwrap();
        assert_eq!((b.physin.as_str(), b.dmac.as_str(), b.smac.as_str(), b.dport), ("eth2", "02:00:00:00:00:0a", "02:00:00:00:00:0b", 3389));
    }

    #[test]
    fn months() {
        assert_eq!(month_of(1_793_577_600), ("2026-11".to_string(), "2026-10".to_string()));
        assert_eq!(month_of(1_767_225_600), ("2026-01".to_string(), "2025-12".to_string()));
    }
}

#[cfg(test)]
mod sticky_tests {
    use super::*;
    use crate::policy::Device;

    #[test]
    fn sticky_name_hint_copies_quiet_same_ip() {
        let mut devices = std::collections::BTreeMap::new();
        devices.insert(
            "aa:bb:cc:00:00:01".into(),
            Device {
                name: "Phone".into(),
                ip: "10.0.0.5".into(),
                last_seen: 1000,
                ..Default::default()
            },
        );
        let hit = sticky_name_hint(&devices, "da:00:00:00:00:02", "10.0.0.5", "", 2000, false);
        assert_eq!(hit.as_ref().map(|(n, _)| n.as_str()), Some("Phone"));
        // Non-private MAC: no hint.
        assert!(sticky_name_hint(&devices, "b8:27:eb:00:00:03", "10.0.0.5", "", 2000, false).is_none());
        assert!(sticky_name_hint(&devices, "da:00:00:00:00:02", "10.0.0.5", "", 2000, true).is_some());
    }
}
