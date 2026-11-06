//! The HTTPS settings page. A small HTTP/1.1 server on rustls: one thread
//! per connection, one request per connection. That keeps it tiny, and it
//! means every confirm after a change is a fresh connection, which is the
//! point: it proves the browser can still get in.

use crate::app::App;
use crate::auth;
use crate::caplog::now;
use crate::config::Config;
use crate::policy::{normal_mac, parse_entry, DevicePolicy, Entry, Policy};
use crate::rules::Mode;
use crate::{geo, net};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

static OPEN: AtomicUsize = AtomicUsize::new(0);
const MAX_OPEN: usize = 64;

const CSS: &str = include_str!("../assets/style.css");
const JS: &str = include_str!("../assets/app.js");
const ICON: &str = include_str!("../assets/icon.svg");
const LAND: &str = include_str!("../assets/land.js");
const PAGE: &str = include_str!("../assets/page.html");
const HELP_BUNDLE: &str = include_str!("../assets/help/bundle.json");
const MANUAL_HTML: &str = include_str!("../assets/manual.html");
const LICENSE_TXT: &str = include_str!("../assets/LICENSE");

/// Where the page files live on disk. A file there wins over the copy
/// built into the program, so the pages can be updated without a new
/// binary. FOILGW_WEB moves the folder.
fn web_dir() -> String {
    std::env::var("FOILGW_WEB").unwrap_or_else(|_| "/usr/share/foilgateway/web".into())
}

fn asset(name: &str, built_in: &'static str) -> Vec<u8> {
    std::fs::read(format!("{}/{name}", web_dir())).unwrap_or_else(|_| built_in.as_bytes().to_vec())
}

/// Board / SoC model when the kernel exposes one (Armbian / device-tree).
fn board_model() -> String {
    for path in ["/sys/firmware/devicetree/base/model", "/proc/device-tree/model"] {
        if let Ok(raw) = std::fs::read(path) {
            let s = String::from_utf8_lossy(&raw);
            let t = s.trim_end_matches('\0').trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    String::new()
}

/// Static file under the web folder, with a built-in fallback. Name must stay under web/.
fn web_file(rel: &str, built_in: &'static str) -> Option<Vec<u8>> {
    if rel.is_empty() || rel.contains("..") || rel.starts_with('/') || rel.contains('\\') {
        return None;
    }
    match std::fs::read(format!("{}/{rel}", web_dir())) {
        Ok(b) => Some(b),
        Err(_) if !built_in.is_empty() => Some(built_in.as_bytes().to_vec()),
        Err(_) => None,
    }
}

pub struct Req {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub ip: String,
    /// The address and port the browser connected to.
    pub local: String,
    pub local_port: u16,
}

pub struct Resp {
    status: u16,
    kind: &'static str,
    body: Vec<u8>,
    extra: Vec<String>,
}

fn resp(status: u16, kind: &'static str, body: impl Into<Vec<u8>>) -> Resp {
    Resp { status, kind, body: body.into(), extra: vec![] }
}

fn ok(v: Value) -> Resp {
    resp(200, "application/json", v.to_string())
}

fn bad(msg: impl std::fmt::Display) -> Resp {
    resp(400, "application/json", json!({ "error": msg.to_string() }).to_string())
}

fn download(body: Result<Vec<u8>, String>, kind: &'static str, name: &str) -> Resp {
    match body {
        Ok(b) => {
            let mut r = resp(200, kind, b);
            r.extra.push(format!("Content-Disposition: attachment; filename=\"{name}\""));
            r
        }
        Err(e) => bad(e),
    }
}

fn certs(app: &App) -> Value {
    let st = crate::certs::state(&app.dir);
    let thumb = crate::certs::ca_der(&app.dir).map(|d| crate::certs::thumbprint(&d)).unwrap_or_default();
    json!({ "ca": st.ca, "ca_thumbprint": thumb, "server": st.server, "names": crate::certs::wanted_names(), "now": now() })
}

fn redirect(to: &str) -> Resp {
    let mut r = resp(303, "text/plain", "");
    r.extra.push(format!("Location: {to}"));
    r
}

fn cert(dir: &str) -> Result<Arc<rustls::ServerConfig>, String> {
    crate::certs::startup(dir)?;
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(crate::certs::Resolver));
    Ok(Arc::new(cfg))
}

pub fn serve(app: App) -> Result<(), String> {
    // Byte counts per connection. Off by default in the kernel, costs little.
    let acct = "/proc/sys/net/netfilter/nf_conntrack_acct";
    if std::fs::read_to_string(acct).map(|v| v.trim() != "1").unwrap_or(true) {
        let _ = std::fs::write(acct, "1");
    }
    let app = Arc::new(app);
    let tls = cert(&app.dir)?;
    let port = app.cfg.read().unwrap().as_ref().map(|c| c.admin_port).unwrap_or(8443);
    let port = std::env::var("FOILGW_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(port);
    app.log.note("setting", &format!("FoilGateway {} started, settings page on port {port}.", env!("CARGO_PKG_VERSION")));
    if app.cfg.read().unwrap().is_some() && !app.needs_setup() {
        // Put the saved rules back after a restart.
        app.refresh_rules();
    }
    app.recover_setup();
    app.start_jobs();
    let rollback = app.cfg.read().unwrap().as_ref().map(|c| c.rollback_secs).unwrap_or(180);
    crate::updater::start_background(app.dir.clone(), rollback);
    let a = app.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(500));
        if a.restart.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(1500));
            std::process::exit(0);
        }
    });
    listen(app, tls, port)
}

fn listen(app: Arc<App>, tls: Arc<rustls::ServerConfig>, port: u16) -> Result<(), String> {
    let l = TcpListener::bind(("::", port)).or_else(|_| TcpListener::bind(("0.0.0.0", port))).map_err(|e| format!("can't listen on port {port}: {e}"))?;
    eprintln!("foilgw: settings page on https://0.0.0.0:{port}/");
    // Workers stay around and take connections off a queue. A thread per
    // connection grew the heap without bound on musl.
    let (tx, rx) = std::sync::mpsc::channel::<TcpStream>();
    let rx = Arc::new(Mutex::new(rx));
    let mut workers = 0;
    for s in l.incoming().flatten() {
        let busy = OPEN.load(Ordering::Relaxed);
        if busy >= MAX_OPEN {
            continue;
        }
        OPEN.fetch_add(1, Ordering::Relaxed);
        if busy >= workers && workers < MAX_OPEN {
            workers += 1;
            let (app, tls, rx) = (app.clone(), tls.clone(), rx.clone());
            std::thread::spawn(move || loop {
                let next = rx.lock().unwrap().recv();
                let Ok(s) = next else { return };
                let _ = handle(&app, tls.clone(), s);
                OPEN.fetch_sub(1, Ordering::Relaxed);
            });
        }
        let _ = tx.send(s);
    }
    Ok(())
}

fn spawn_listener(app: &Arc<App>, port: u16) {
    if let Ok(tls) = cert(&app.dir) {
        let a = app.clone();
        std::thread::spawn(move || {
            let _ = listen(a, tls, port);
        });
    }
}

fn peer_ip(s: &TcpStream) -> String {
    match s.peer_addr().map(|a| a.ip()) {
        Ok(IpAddr::V6(v)) => v.to_ipv4_mapped().map(|x| x.to_string()).unwrap_or(v.to_string()),
        Ok(ip) => ip.to_string(),
        Err(_) => String::new(),
    }
}

fn handle(app: &Arc<App>, tls: Arc<rustls::ServerConfig>, tcp: TcpStream) -> Result<(), String> {
    tcp.set_read_timeout(Some(Duration::from_secs(15))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(30))).ok();
    let ip = peer_ip(&tcp);
    let (local, local_port) = match tcp.local_addr() {
        Ok(a) => (match a.ip() {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(|x| x.to_string()).unwrap_or(v.to_string()),
            ip => ip.to_string(),
        }, a.port()),
        Err(_) => (String::new(), 0),
    };
    let conn = rustls::ServerConnection::new(tls).map_err(|e| e.to_string())?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        let n = s.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 32 * 1024 {
            return Ok(());
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("").to_string();
    let target = first.next().unwrap_or("/").to_string();
    let headers: HashMap<String, String> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if len > 8 * 1024 * 1024 {
        return Ok(());
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    let (path, qs) = target.split_once('?').unwrap_or((&target, ""));
    let query = qs.split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), unescape(v))).collect();
    let req = Req { method, path: path.to_string(), query, headers, body, ip, local, local_port };
    let r = route(app, &req);
    let reason = match r.status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let mut out = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nStrict-Transport-Security: max-age=31536000\r\nContent-Security-Policy: default-src 'self'; connect-src 'self' https://foilgateway.local:* https://192.168.30.1:* https://169.254.42.1:*; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'\r\n",
        r.status,
        r.kind,
        r.body.len()
    );
    for e in &r.extra {
        out += e;
        out += "\r\n";
    }
    out += "\r\n";
    s.write_all(out.as_bytes()).map_err(|e| e.to_string())?;
    s.write_all(&r.body).map_err(|e| e.to_string())?;
    s.conn.send_close_notify();
    let _ = s.flush();
    Ok(())
}

fn unescape(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                if let Ok(x) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                    out.push(x);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn cookie(req: &Req) -> String {
    req.headers.get("cookie").and_then(|c| c.split(';').find_map(|kv| kv.trim().strip_prefix("fg_session=").map(String::from))).unwrap_or_default()
}

fn session_cookie(token: &str) -> String {
    format!("Set-Cookie: fg_session={token}; Path=/; HttpOnly; Secure; SameSite=Strict")
}

/// HTML shells the SPA owns. Direct load and refresh must hit these, not the
/// plain 404. Keep in sync with SUBS / nav in assets/app.js.
fn spa_page(path: &str) -> Option<Resp> {
    Some(match path {
        "/" => page("dashboard", "Dashboard"),
        "/devices" => page("devices", "Devices"),
        "/devices/troubleshoot" => page("devices", "Troubleshooter"),
        "/firewall" | "/firewall/audit" | "/firewall/geo" | "/firewall/white" | "/firewall/black"
        | "/firewall/rules" | "/firewall/mode" | "/firewall/presets" | "/firewall/hardening"
        | "/firewall/coach" => {
            let title = match path {
                "/firewall/audit" => "Audit",
                "/firewall/geo" => "Geo-Blocking",
                "/firewall/white" => "Whitelist",
                "/firewall/black" => "Blacklist",
                "/firewall/rules" => "Rules as loaded",
                "/firewall/mode" => "Protection Mode",
                "/firewall/presets" => "Protection Levels",
                "/firewall/hardening" => "Hardening",
                "/firewall/coach" => "Best Practices",
                _ => "Firewall",
            };
            page("firewall", title)
        }
        "/ports" => page("ports", "Ports"),
        "/ports/devices" => page("ports", "Ports per device"),
        "/log" => page("log", "Capture Log"),
        "/settings" => page("settings", "Settings"),
        "/settings/general" => page("settings", "Time and location"),
        "/settings/log" => page("settings", "Capture Log settings"),
        "/settings/account" => page("settings", "Account"),
        "/settings/setup" => page("settings", "Setup"),
        "/settings/certs" => page("settings", "Certificates"),
        "/settings/view" => page("settings", "View"),
        "/settings/updates" => page("settings", "Updates"),
        "/settings/help" => page("settings", "Help"),
        "/settings/about" => page("settings", "About"),
        _ => return None,
    })
}

fn page(name: &str, title: &str) -> Resp {
    let t = String::from_utf8_lossy(&asset("page.html", PAGE)).into_owned();
    let extra = if name == "dashboard" { "<script src=\"/s/land.js\"></script>\n" } else { "" };
    resp(200, "text/html; charset=utf-8", t.replace("{title}", title).replace("{name}", name).replace("{extra}", extra))
}

fn body(req: &Req) -> Value {
    serde_json::from_slice(&req.body).unwrap_or(Value::Null)
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").trim().to_string()
}

fn route(app: &Arc<App>, req: &Req) -> Resp {
    let p = req.path.as_str();
    match p {
        "/s/style.css" => return resp(200, "text/css", asset("style.css", CSS)),
        "/s/app.js" => return resp(200, "application/javascript", asset("app.js", JS)),
        "/s/icon.svg" => return resp(200, "image/svg+xml", asset("icon.svg", ICON)),
        "/s/land.js" => return resp(200, "application/javascript", asset("land.js", LAND)),
        "/s/manual.html" => return resp(200, "text/html; charset=utf-8", asset("manual.html", MANUAL_HTML)),
        "/s/LICENSE" => return resp(200, "text/plain; charset=utf-8", asset("LICENSE", LICENSE_TXT)),
        "/s/help/bundle.json" => {
            let b = web_file("help/bundle.json", HELP_BUNDLE).unwrap_or_else(|| HELP_BUNDLE.as_bytes().to_vec());
            return resp(200, "application/json; charset=utf-8", b);
        }
        p if p.starts_with("/s/help/") => {
            let name = &p["/s/help/".len()..];
            // Markdown chapters for Download Manual tooling; only known suffixes.
            if !(name.ends_with(".md") || name.ends_with(".json") || name.ends_with(".html")) {
                return resp(404, "text/plain", "not found");
            }
            let rel = format!("help/{name}");
            let built_in = if name == "bundle.json" { HELP_BUNDLE } else if name == "manual.html" { MANUAL_HTML } else { "" };
            match web_file(&rel, built_in) {
                Some(b) if !b.is_empty() || !built_in.is_empty() => {
                    let ctype = if name.ends_with(".json") {
                        "application/json; charset=utf-8"
                    } else if name.ends_with(".html") {
                        "text/html; charset=utf-8"
                    } else {
                        "text/markdown; charset=utf-8"
                    };
                    return resp(200, ctype, b);
                }
                _ => return resp(404, "text/plain", "not found"),
            }
        }
        _ => {}
    }
    // Every change needs this header. Other sites can't add it without asking first.
    if req.method == "POST" && req.headers.get("x-fg").map(String::as_str) != Some("1") {
        return resp(403, "text/plain", "missing X-FG header");
    }
    let token = cookie(req);
    let user = app.auth.user_for(&token);

    // The reconnect check in the setup page: anything that answers will do.
    if p == "/api/ping" {
        return ok(json!({"ok": true}));
    }
    // First connect: nothing but the wizard until there's an admin and the
    // new layout has been confirmed.
    if setup_open(app) && user.is_none() {
        if let Some(r) = setup_route(app, req) {
            return r;
        }
        return if p.starts_with("/api/") { resp(401, "application/json", json!({"error": "setup", "redirect": "/setup"}).to_string()) } else { redirect("/setup") };
    }
    match p {
        "/login" => return page("login", "Sign in"),
        "/api/login" if req.method == "POST" => {
            let b = body(req);
            return match app.auth.login(&s(&b, "user"), b["password"].as_str().unwrap_or(""), &req.ip) {
                Ok(t) => {
                    app.log.note("setting", &format!("{} signed in from {}.", s(&b, "user"), req.ip));
                    let mut r = ok(json!({"ok": true}));
                    r.extra.push(session_cookie(&t));
                    r
                }
                Err(e) => {
                    app.log.note("alert", &format!("Failed sign-in for {} from {}.", s(&b, "user"), req.ip));
                    let mut r = bad(&e);
                    if e.starts_with("Too many") {
                        r.status = 429;
                    }
                    r
                }
            };
        }
        _ => {}
    }
    let Some(user) = user else {
        return if p.starts_with("/api/") { resp(401, "application/json", json!({"error": "Please sign in again.", "redirect": "/login"}).to_string()) } else { redirect("/login") };
    };
    // Any signed-in request after a change shows the browser still gets in.
    if p == "/api/confirm" {
        if app.wizard.lock().unwrap().applied.is_some() {
            return setup_confirm(app, req);
        }
        return ok(json!({ "kept": app.confirm_pending(&req.ip) }));
    }
    if app.setup_mode() {
        if let Some(r) = setup_route(app, req) {
            return r;
        }
        match p {
            "/api/logout" => {}
            p if p.starts_with("/api/") => return resp(401, "application/json", json!({"error": "setup", "redirect": "/setup"}).to_string()),
            _ => return redirect("/setup"),
        }
    }
    if let Some(r) = spa_page(p) {
        return r;
    }
    match (req.method.as_str(), p) {
        ("GET", "/api/certs") => ok(certs(app)),
        ("POST", "/api/certs") => {
            if s(&body(req), "action") != "new" {
                return bad("Unknown action.");
            }
            match crate::certs::issue(&app.dir, crate::certs::wanted_names()) {
                Ok(_) => {
                    app.log.note("setting", &format!("New certificate for the settings page, made by {user}."));
                    ok(certs(app))
                }
                Err(e) => bad(format!("Couldn't make a new certificate: {e}")),
            }
        }
        ("GET", "/api/certs/foilgateway-ca.crt") => download(crate::certs::ca_pem(&app.dir).map(String::into_bytes), "application/x-pem-file", "foilgateway-ca.crt"),
        ("GET", "/api/certs/foilgateway-ca.cer") => download(crate::certs::ca_der(&app.dir), "application/pkix-cert", "foilgateway-ca.cer"),
        (_, "/setup") => redirect("/"),
        ("POST", "/api/restart") => restart(app, &user),
        ("POST", "/api/rollback-version") => rollback_version(app, &user),
        ("GET", "/api/updates") => updates_status(app),
        ("POST", "/api/updates/check") => updates_check(app, &user),
        ("POST", "/api/updates/install") => updates_install(app, &user),
        ("GET", "/api/updates/progress") => ok(crate::updater::progress_json()),
        ("POST", "/api/updates/ack") => updates_ack(app),
        ("POST", "/api/updates/rollback") => rollback_version(app, &user),
        ("POST", "/api/logout") => {
            app.auth.end(&token);
            let mut r = ok(json!({"ok": true}));
            r.extra.push("Set-Cookie: fg_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict".into());
            r
        }
        ("GET", "/api/status") => ok(status(app, &user)),
        ("GET", "/api/dashboard") => ok(dashboard(app, &user)),
        ("GET", "/api/devices") => ok(devices(app, &user, req)),
        ("POST", "/api/device") => device_change(app, req),
        ("GET", "/api/troubleshoot") => ok(troubleshoot(app, &user, req)),
        ("POST", "/api/allow") => allow_change(app, req, &user),
        ("GET", "/api/audit") => ok(audit_page(app, &user)),
        ("POST", "/api/audit") => audit_change(app, req, &user),
        ("POST", "/api/profile") => profile_change(app, req, &user),
        ("POST", "/api/alert") => {
            let b = body(req);
            match b["id"].as_i64() {
                Some(id) => {
                    app.log.handle_id(id);
                    ok(json!({ "ok": true }))
                }
                None => bad("Which alert?"),
            }
        }
        ("GET", "/api/firewall") => ok(firewall(app, &user, req.query.contains_key("rules"))),
        ("POST", "/api/firewall") => firewall_change(app, req),
        ("GET", "/api/coach") => ok(coach_get(app, &user)),
        ("POST", "/api/coach") => coach_post(app, req),
        ("POST", "/api/list") => list_change(app, req),
        ("GET", "/api/ports") => ok(ports(app, &user, req)),
        ("POST", "/api/ports") => ports_change(app, req, &user),
        ("GET", "/api/log") => {
            let off = app.tz_offset();
            let kind = qs(req, "kind");
            let (mut since, until) = date_range(req, off);
            if req.query.contains_key("today") {
                since = since.max(app.midnight());
            }
            let q = qs(req, "q");
            let (rows, total) = app.log.page(&kind, &q, since, until, &qs(req, "sort"), qn(req, "offset", 0, i64::MAX), qn(req, "limit", 200, 1000));
            let download_bytes = app.log.download_bytes(&kind, &q, since, until);
            ok(json!({ "status": status(app, &user), "rows": log_rows(app, rows), "total": total, "offset": off, "download_bytes": download_bytes }))
        }
        ("GET", "/api/log.txt") => {
            let off = app.tz_offset();
            let (since, until) = date_range(req, off);
            let mut t = String::from("time\tkind\tcount\thandled\tline\n");
            for r in app.log.page(&qs(req, "kind"), "", since, until, "old", 0, i64::MAX).0 {
                let ports = if r.remote.is_empty() || r.ports.is_empty() { String::new() } else { format!(" [{}]", r.ports.replace(',', ", ")) };
                let domain = if r.domain.is_empty() { String::new() } else { format!(" ({})", r.domain) };
                t += &format!("{}\t{}\t{}\t{}\t{}{domain}{ports}\n", stamp(r.last + off), r.kind, r.count, if r.handled { "handled" } else { "" }, r.text);
            }
            let span = match (qs(req, "from"), qs(req, "to")) {
                (f, t) if f.is_empty() && t.is_empty() => String::new(),
                (f, t) => format!(" from {} to {}", if f.is_empty() { "the start".into() } else { f }, if t.is_empty() { "now".into() } else { t }),
            };
            app.log.note("setting", &format!("{user} downloaded the Capture Log{span}."));
            let mut r = resp(200, "text/plain; charset=utf-8", t);
            r.extra.push("Content-Disposition: attachment; filename=\"foilgateway-log.txt\"".into());
            r
        }
        ("GET", "/api/settings") => ok(settings(app, &user)),
        ("POST", "/api/settings") => settings_change(app, req, &user),
        ("GET", "/api/backup") => {
            let b = json!({ "foilgateway_backup": 1, "gateway_conf": app.cfg.read().unwrap().as_ref().map(|c| c.to_text()), "policy": *app.policy.read().unwrap() });
            let mut r = resp(200, "application/json", serde_json::to_string_pretty(&b).unwrap());
            r.extra.push("Content-Disposition: attachment; filename=\"foilgateway-settings.json\"".into());
            r
        }
        ("POST", "/api/restore") => {
            let b = body(req);
            let Ok(pol) = serde_json::from_value::<Policy>(b["policy"].clone()) else { return bad("That file isn't a FoilGateway settings backup.") };
            let cfg = match b["gateway_conf"].as_str().map(Config::parse) {
                Some(Ok(c)) => Some(c),
                Some(Err(e)) => return bad(format!("The ports part of the backup is broken: {e}")),
                None => None,
            };
            done(app.change(cfg, pol, &format!("settings restored from a backup by {user}")))
        }
        _ => resp(404, "text/plain", "Not found"),
    }
}

fn setup_route(app: &Arc<App>, req: &Req) -> Option<Resp> {
    Some(match (req.method.as_str(), req.path.as_str()) {
        (_, "/setup") => page("setup", "Setup"),
        ("GET", "/api/setup/info") => setup_info(app, req),
        ("POST", "/api/setup/state") => setup_state(app, req),
        ("POST", "/api/setup/blink") => setup_blink(app, req),
        ("POST", "/api/setup") => setup_apply(app, req),
        (_, "/api/setup/confirm") => setup_confirm(app, req),
        _ => return None,
    })
}

fn qs(req: &Req, k: &str) -> String {
    req.query.get(k).cloned().unwrap_or_default()
}

fn qn(req: &Req, k: &str, def: i64, max: i64) -> i64 {
    req.query.get(k).and_then(|v| v.parse::<i64>().ok()).unwrap_or(def).clamp(0, max)
}

/// Seconds since 1970 at local midnight of a YYYY-MM-DD date.
fn day_start(d: &str, offset: i64) -> Option<i64> {
    let mut it = d.splitn(3, '-').map(|x| x.parse::<i64>().ok());
    let (y, m, day) = (it.next()??, it.next()??, it.next()??);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400 - offset)
}

/// from= and to= (both days included) as a span of seconds.
fn date_range(req: &Req, offset: i64) -> (i64, i64) {
    let from = day_start(&qs(req, "from"), offset).unwrap_or(0);
    let to = day_start(&qs(req, "to"), offset).map(|t| t + 86399).unwrap_or(i64::MAX);
    (from, to)
}

fn done(r: Result<u64, String>) -> Resp {
    match r {
        Ok(secs) => ok(json!({ "pending": secs > 0, "secs": secs })),
        Err(e) => bad(e),
    }
}

pub fn stamp(t: i64) -> String {
    let days = t.div_euclid(86400);
    let sec = t.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", sec / 3600, sec / 60 % 60, sec % 60)
}

fn parse_hosts(v: &Value) -> Result<Vec<String>, String> {
    let list: Vec<String> = match v {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str()).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
        Value::String(t) => t.split([',', ' ', '\n']).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
        _ => vec![],
    };
    for h in &list {
        h.parse::<std::net::Ipv4Addr>().map_err(|_| format!("{h} isn't an IPv4 address like 10.10.10.42"))?;
    }
    Ok(list)
}

fn lan_list(v: &Value) -> Option<Vec<String>> {
    match v {
        Value::Array(a) => Some(a.iter().filter_map(|x| x.as_str()).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()),
        Value::String(t) => Some(t.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()),
        _ => None,
    }
}

fn build_cfg(b: &Value, old: Option<&Config>) -> Result<Config, String> {
    let lan = lan_list(&b["lan"]).or(old.map(|c| c.lan.clone())).unwrap_or_default();
    let wan = if b["wan"].is_string() { s(b, "wan") } else { old.map(|c| c.wan.clone()).unwrap_or_default() };
    if lan.is_empty() {
        return Err("Pick at least one LAN port.".into());
    }
    if lan.contains(&wan) {
        return Err("A port can't be WAN and LAN at once.".into());
    }
    let safety = b["safety"].as_bool().or(old.map(|c| c.safety)).unwrap_or(true);
    let hosts = if b.get("safety_hosts").is_some() { parse_hosts(&b["safety_hosts"])? } else { old.map(|c| c.safety_hosts.iter().map(|h| h.to_string()).collect()).unwrap_or_default() };
    let port = b["admin_port"].as_u64().or_else(|| s(b, "admin_port").parse().ok()).unwrap_or(old.map(|c| c.admin_port as u64).unwrap_or(8443));
    let extra: Vec<String> = old.map(|c| c.safety_ports.iter().filter(|p| **p != 22 && **p != c.admin_port).map(|p| p.to_string()).collect()).unwrap_or_default();
    let from = match b["admin_from"].as_str() {
        Some("lan") => "lan",
        Some(_) => "both",
        None => old.map(|c| if c.admin_from_wan { "both" } else { "lan" }).unwrap_or("both"),
    };
    let rollback = old.map(|c| c.rollback_secs).or_else(|| std::env::var("FOILGW_ROLLBACK_SECS").ok().and_then(|v| v.parse().ok())).unwrap_or(180);
    let placement = match b["placement"].as_str() {
        Some(v) => crate::presets::Placement::parse(v).ok_or_else(|| format!("placement: expected internet_switch or router_switch, got {v}"))?,
        None => old.map(|c| c.placement).unwrap_or_default(),
    };
    let text = format!(
        "lan={}\nwan={wan}\nsafety={}\nsafety_hosts={}\nsafety_ports={}\nadmin_port={port}\nadmin_from={from}\nrollback_secs={rollback}\nplacement={}\n",
        lan.join(","),
        if safety { "on" } else { "off" },
        hosts.join(","),
        extra.join(","),
        placement.conf_value(),
    );
    let mut c = Config::parse(&text).map_err(|e| match e.as_str() {
        "safety is on but safety_hosts is empty" => String::from("Add at least one computer that always keeps access, or turn safety off."),
        _ => e,
    })?;
    c.fixed = old.and_then(|o| o.fixed.clone());
    Ok(c)
}

/// 255.255.255.0 or 24.
fn prefix_of(mask: &str) -> Option<u8> {
    let m = mask.trim().trim_start_matches('/');
    if let Ok(n) = m.parse::<u8>() {
        return (1..=32).contains(&n).then_some(n);
    }
    let bits = u32::from(m.parse::<std::net::Ipv4Addr>().ok()?);
    let n = bits.leading_ones();
    (n >= 1 && bits.checked_shl(n).unwrap_or(0) == 0).then_some(n as u8)
}

/// The fixed address form: ip, mask, gateway, dns.
fn fixed_from(b: &Value) -> Result<crate::config::Fixed, String> {
    let ip: std::net::Ipv4Addr = s(b, "ip").trim().parse().map_err(|_| "The address should look like 10.10.10.5.".to_string())?;
    let prefix = prefix_of(&s(b, "mask")).ok_or("The mask should look like 255.255.255.0.")?;
    let net = |a: std::net::Ipv4Addr| u32::from(a) & (u32::MAX << (32 - prefix as u32));
    let gateway = match s(b, "gateway").trim() {
        "" => None,
        g => {
            let g: std::net::Ipv4Addr = g.parse().map_err(|_| "The gateway should look like 10.10.10.1.".to_string())?;
            if net(g) != net(ip) {
                return Err(format!("The gateway {g} isn't on the same network as {ip}/{prefix}."));
            }
            Some(g)
        }
    };
    if gateway == Some(ip) {
        return Err("The gateway can't be the gateway's own address.".into());
    }
    let mut dns = Vec::new();
    for d in s(b, "dns").split([',', ' ']).map(str::trim).filter(|d| !d.is_empty()) {
        dns.push(d.parse().map_err(|_| format!("{d} isn't a DNS server address."))?);
    }
    Ok(crate::config::Fixed { ip, prefix, gateway, dns })
}

const STEPS: [&str; 8] = ["Welcome", "Admin", "Mode", "Ports", "Settings port", "Safety", "Review", "Apply"];

/// Setup pages answer without a sign-in while nobody has one yet: on the
/// first run, and while that run's new layout waits for its confirm.
fn setup_open(app: &App) -> bool {
    !app.auth.has_users() || {
        let w = app.wizard.lock().unwrap();
        w.active && !w.created_user.is_empty()
    }
}

/// The wizard as the page sees it. The password hash stays here.
fn wizard_json(app: &App) -> Value {
    let mut w = app.wizard.lock().unwrap();
    if !w.active || w.step.is_empty() {
        let cfg = app.cfg.read().unwrap().clone();
        w.active = true;
        w.step = if app.auth.has_users() { "Mode".into() } else { "Welcome".into() };
        w.safety = cfg.as_ref().map(|c| if c.safety { "on" } else { "off" }).unwrap_or("on").into();
        w.admin_port = cfg.as_ref().map(|c| c.admin_port).unwrap_or(8443);
        w.lan = cfg.as_ref().map(|c| c.lan.clone()).unwrap_or_default();
        w.wan = cfg.as_ref().map(|c| c.wan.clone()).unwrap_or_default();
        w.safety_hosts = cfg.as_ref().map(|c| c.safety_hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
        w.new_devices = serde_json::to_value(app.policy.read().unwrap().new_devices).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        if w.placement.is_empty() {
            w.placement = cfg.as_ref().map(|c| c.placement.conf_value().to_string()).unwrap_or_else(|| "router_switch".into());
        }
        crate::wizard::save(&app.dir, &w);
    }
    let left = app.pending.lock().unwrap().as_ref().map(|p| p.deadline.saturating_duration_since(std::time::Instant::now()).as_secs());
    let placement = if w.placement.is_empty() { "router_switch".into() } else { w.placement.clone() };
    json!({
        "step": w.step, "user": w.user, "has_password": !w.pw_hash.is_empty(), "lan": w.lan, "wan": w.wan,
        "admin_port": w.admin_port, "safety": w.safety != "off", "safety_hosts": w.safety_hosts, "new_devices": w.new_devices,
        "placement": placement,
        "applied": w.applied.as_ref().map(|a| json!({"secs": a.secs, "left": left.unwrap_or(0)})), "note": w.note,
        "first": !app.auth.has_users() || !w.created_user.is_empty(),
    })
}

fn setup_info(app: &App, req: &Req) -> Resp {
    let here = net::port_of(&req.ip);
    let ports: Vec<Value> = net::ports()
        .into_iter()
        .map(|p| {
            let (blinking, no_blink) = app.anyport.blink_state(&p.name);
            let mut v = json!(p);
            v["here"] = json!(here.as_deref() == Some(p.name.as_str()));
            v["blinking"] = json!(blinking);
            v["no_blink"] = json!(no_blink);
            v
        })
        .collect();
    // Whoever hands out addresses upstream is on the WAN side.
    let wan_guess = ports.iter().find(|p| p["default_route"] == true).or_else(|| ports.iter().find(|p| p["leased"].as_array().is_some_and(|l| !l.is_empty()))).and_then(|p| p["name"].as_str());
    let wizard = wizard_json(app);
    ok(json!({
        "ports": ports,
        "here": here,
        "client_ip": req.ip,
        "local": req.local,
        "wan_guess": wan_guess,
        "fallback_addr": crate::anyport::FALLBACK.to_string(),
        "last_try": crate::anyport::SETUP_ADDR.to_string(),
        "name": crate::mdns::NAME,
        "wizard": wizard,
        "hostname": std::fs::read_to_string("/etc/hostname").unwrap_or_default().trim(),
        "port": req.local_port,
    }))
}

/// Saves what the page has so far. Checked here, so a bad value shows on
/// the step it belongs to.
fn setup_state(app: &App, req: &Req) -> Resp {
    let b = body(req);
    let mut w = app.wizard.lock().unwrap();
    if w.applied.is_some() {
        return bad("The new layout is waiting for its confirm. Wait for it, or for it to be undone.");
    }
    if b["user"].is_string() {
        let u = s(&b, "user");
        if let Err(e) = auth::check_name(&u) {
            return bad(e);
        }
        w.user = u;
    }
    if let Some(pw) = b["password"].as_str().filter(|p| !p.is_empty()) {
        if let Err(e) = auth::check_password(pw) {
            return bad(e);
        }
        match auth::hash(pw) {
            Ok(h) => w.pw_hash = h,
            Err(e) => return bad(e),
        }
    }
    if let Some(l) = lan_list(&b["lan"]) {
        w.lan = l;
    }
    if b["wan"].is_string() {
        w.wan = s(&b, "wan");
    }
    if let Some(p) = b["admin_port"].as_u64().or_else(|| s(&b, "admin_port").parse().ok()) {
        if !(1..=65535).contains(&p) || p == 22 {
            return bad("Pick a port from 1 to 65535, but not 22 (that's SSH).");
        }
        w.admin_port = p as u16;
    }
    if let Some(on) = b["safety"].as_bool() {
        w.safety = if on { "on" } else { "off" }.into();
    }
    if b["safety_hosts"].is_string() {
        w.safety_hosts = s(&b, "safety_hosts");
    }
    if b["new_devices"].is_string() {
        w.new_devices = s(&b, "new_devices");
    }
    if b["placement"].is_string() {
        let p = s(&b, "placement");
        if crate::presets::Placement::parse(&p).is_none() {
            return bad("Pick Between Internet And Switch, or Between Router And Switch.");
        }
        w.placement = p;
    }
    let step = s(&b, "step");
    if STEPS.contains(&step.as_str()) {
        w.step = step;
        w.note.clear();
    }
    crate::wizard::save(&app.dir, &w);
    drop(w);
    ok(wizard_json(app))
}

fn setup_blink(app: &App, req: &Req) -> Resp {
    let name = s(&body(req), "port");
    if net::port(&name).is_none() {
        return bad("No such port.");
    }
    match app.anyport.blink(&name) {
        Ok(_) => ok(json!({"ok": true})),
        Err(e) => bad(e),
    }
}

fn setup_apply(app: &Arc<App>, req: &Req) -> Resp {
    let w = app.wizard.lock().unwrap().clone();
    if w.applied.is_some() {
        return bad("Already applied, waiting for the confirm.");
    }
    let first = !app.auth.has_users();
    if first && (w.user.is_empty() || w.pw_hash.is_empty()) {
        return bad("Go back to Admin and set a user name and password.");
    }
    let form = json!({ "lan": w.lan, "wan": w.wan, "safety": w.safety != "off", "safety_hosts": w.safety_hosts, "admin_port": w.admin_port, "placement": if w.placement.is_empty() { "router_switch".into() } else { w.placement.clone() } });
    let old = app.cfg.read().unwrap().clone();
    let cfg = match build_cfg(&form, old.as_ref()) {
        Ok(c) => c,
        Err(e) => return bad(e),
    };
    if cfg.lan.iter().chain([&cfg.wan]).any(|p| net::port(p).is_none()) {
        return bad("Pick ports this gateway has.");
    }
    let mut pol = app.policy.read().unwrap().clone();
    pol.new_devices = serde_json::from_value(json!(w.new_devices)).unwrap_or(pol.new_devices);
    let old_text = std::fs::read_to_string(&app.conf_path).ok();
    if first {
        // Mark the account as ours before it exists, so the page's heartbeat
        // isn't sent to the sign-in page in between.
        app.wizard.lock().unwrap().created_user = w.user.clone();
        if let Err(e) = app.auth.add_hashed(&w.user, &w.pw_hash) {
            app.wizard.lock().unwrap().created_user.clear();
            return bad(e);
        }
        app.log.note("setting", &format!("Admin {} created from {}.", w.user, req.ip));
    }
    match app.change(Some(cfg.clone()), pol, &format!("setup: LAN {}, WAN {}, settings port {}", cfg.lan.join(", "), cfg.wan, cfg.admin_port)) {
        Ok(secs) => {
            let mut w = app.wizard.lock().unwrap();
            w.applied = Some(crate::wizard::Applied { at: now(), secs });
            w.old_cfg = old_text;
            w.step = "Apply".into();
            w.note.clear();
            if first {
                w.created_user = w.user.clone();
            }
            crate::wizard::save(&app.dir, &w);
            drop(w);
            // The rules are in; now the ports go into the bridge. An undo
            // takes it apart again.
            if !crate::bridge::exists() {
                crate::bridge::mark_pending(&app.dir);
            }
            let members: Vec<String> = std::iter::once(cfg.wan.clone()).chain(cfg.lan.iter().cloned()).collect();
            let had_fallback = app.anyport.serving_fallback(&members);
            if let Err(e) = crate::bridge::up(&app.dir, &cfg.wan, &cfg.lan, &app.anyport.ours()) {
                app.undo_now();
                return bad(format!("Couldn't build the bridge, so setup is being undone: {e}"));
            }
            app.anyport.bridged(&members, had_fallback);
            app.log.note("setting", &format!("Bridge {} built: {} toward the router, {} toward your devices.", crate::bridge::NAME, cfg.wan, cfg.lan.join(", ")));
            if let Some(p) = app.pending.lock().unwrap().as_ref().and_then(|p| p.new_port) {
                spawn_listener(app, p);
            }
            ok(json!({ "pending": true, "secs": secs, "port": cfg.admin_port }))
        }
        Err(e) => {
            if first {
                // Nothing went in, so don't keep the account either.
                let _ = app.auth.remove_last(&w.user);
                app.wizard.lock().unwrap().created_user.clear();
            }
            bad(e)
        }
    }
}

/// The new layout is kept only when this comes from a browser through the
/// bridge: that is what proves the owner can still get in. Either side
/// counts, since the settings page answers on both.
fn setup_confirm(app: &Arc<App>, req: &Req) -> Resp {
    let w = app.wizard.lock().unwrap().clone();
    if w.applied.is_none() {
        let done = !w.active && !app.needs_setup();
        return ok(json!({ "kept": done, "applied": false, "wizard": if done { Value::Null } else { wizard_json(app) } }));
    }
    let Some(cfg) = app.cfg.read().unwrap().clone() else { return bad("No settings to confirm.") };
    let here = net::port_of(&req.ip);
    let left = app.pending.lock().unwrap().as_ref().map(|p| p.deadline.saturating_duration_since(std::time::Instant::now()).as_secs()).unwrap_or(0);
    // Any browser that reaches the page through the bridge proves it works,
    // from the router side as much as from a device.
    // A port left out of the bridge doesn't count; that browser would be cut off.
    let through = here.as_deref().is_none_or(|p| p == crate::bridge::NAME || p == cfg.wan || cfg.lan.iter().any(|l| l == p));
    if !crate::bridge::exists() || !through {
        return ok(json!({ "kept": false, "applied": true, "here": here, "lan": cfg.lan, "left": left }));
    }
    let here = here.unwrap_or_else(|| crate::bridge::NAME.to_string());
    if !app.confirm_pending(&req.ip) {
        return ok(json!({ "kept": false, "applied": true, "here": here, "lan": cfg.lan, "left": 0 }));
    }
    let mut w = app.wizard.lock().unwrap();
    *w = crate::wizard::Wizard { step: "Done".into(), ..Default::default() };
    crate::wizard::save(&app.dir, &w);
    drop(w);
    let local = req.local.parse().ok();
    // Everything now lives on the bridge. Setup's extra addresses go,
    // except 192.168.30.1 when the router hasn't given the bridge one yet.
    let br = crate::bridge::NAME.to_string();
    // Ours, or one networkd got.
    let leased = app.anyport.owned().leases.contains_key(&br) || net::bridge_port().is_some_and(|p| p.ips.iter().any(|c| !c.starts_with("169.254.") && !c.starts_with("192.168.30.1/") && c.contains('.')));
    if !leased {
        app.log.note("setting", "The bridge has no address from the router yet, so 192.168.30.1 stays on it for now.");
    }
    // The address this browser came in on stays too, so the page keeps working.
    let setup_addr = local.is_some_and(|l| l == crate::anyport::SETUP_ADDR || l == crate::anyport::FALLBACK);
    let keep: Vec<String> = if leased && !setup_addr { vec![] } else { vec![br.clone()] };
    app.anyport.finish(&keep, &br, local.map(|l| (br.clone(), l)));
    app.anyport.resume();
    app.log.note("setting", &format!("Setup confirmed from {} on {here}.", req.ip));
    ok(json!({ "kept": true, "here": here, "port": cfg.admin_port, "kept_setup_addr": app.anyport.owned().setup.contains(&br) || local == Some(crate::anyport::FALLBACK) }))
}

fn status(app: &App, user: &str) -> Value {
    let cfg = app.cfg.read().unwrap().clone();
    let (in_path, why) = app.path_state();
    let port = |n: Option<String>| n.and_then(|n| net::port_cached(&n)).map(|p| json!(p)).unwrap_or(Value::Null);
    // Work only a dashboard card needs is skipped while that card is off.
    let cards = app.policy.read().unwrap().dash_cards.clone();
    let on = |id: &str| cards.get(id).copied().unwrap_or(true);
    let (used, total) = if on("memory") { net::memory() } else { (0, 0) };
    let disk = if on("disk") { net::disk(&app.dir) } else { (0, 0) };
    let pend = app.pending.lock().unwrap().as_ref().map(|p| json!({"what": p.what, "left": p.deadline.saturating_duration_since(std::time::Instant::now()).as_secs()}));
    // Copy out and let go: tz_offset below reads the policy again, and a
    // second read waits behind any writer, which then waits on us.
    let t = now();
    let (mode, telemetry_all, new_devices, timezone, hour12, date_fmt, auditing, admin_keep_both, white_expiry) = {
        let pol = app.policy.read().unwrap();
        let auditing: Vec<Value> = pol.devices.iter().filter(|(_, d)| d.auditing(t)).map(|(m, d)| json!({ "mac": m, "label": App::device_label(d, m), "until": d.audit_until })).collect();
        (pol.mode, pol.telemetry_all, pol.devices.values().filter(|d| d.new).count(), pol.timezone.clone(), pol.hour12, pol.date_fmt.clone(), auditing, pol.admin_keep_both, pol.white_expiry)
    };
    let admin_from_wan = cfg.as_ref().map(|c| c.admin_from_wan).unwrap_or(true);
    // Nudge while settings still answer from the router side, until LAN-only or Keep Both.
    let admin_nudge = admin_from_wan && !admin_keep_both && cfg.is_some();
    let (wan_bps, lan_bps) = {
        let l = app.live.lock().unwrap();
        (l.wan_bps, l.lan_bps)
    };
    json!({
        "user": user,
        "version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "board": board_model(),
        "host": std::fs::read_to_string("/etc/hostname").unwrap_or_default().trim(),
        "in_path": in_path,
        "path_note": why,
        "mode": mode,
        "auditing": auditing,
        "wan_bps": [wan_bps.0, wan_bps.1],
        "lan_bps": [lan_bps.0, lan_bps.1],
        "telemetry_all": telemetry_all,
        "wan": port(cfg.as_ref().map(|c| c.wan.clone())),
        // The first LAN port with a cable stands for all of them on the dashboard.
        "lan": port(cfg.as_ref().and_then(|c| c.lan.iter().find(|l| net::port_cached(l).is_some_and(|p| p.link)).or(c.lan.first()).cloned())),
        "wan_name": cfg.as_ref().map(|c| c.wan.clone()),
        "lan_name": cfg.as_ref().map(|c| c.lan.join(", ")),
        "lans": cfg.as_ref().map(|c| c.lan.clone()).unwrap_or_default(),
        "filtering": net::bridge_filtering(),
        "bridge": crate::bridge::exists(),
        "uptime": net::uptime_secs(),
        "daemon_uptime": app.started.elapsed().as_secs(),
        "cpu": app.live.lock().unwrap().cpu,
        "temp": net::temperature(),
        "mem_used": used,
        "mem_total": total,
        "disk_used": disk.0,
        "disk_total": disk.1,
        "blocked_today": if on("blocked") { app.log.blocked_since(app.midnight()) } else { 0 },
        "blocked_usual": if on("blocked") { app.log.blocked_between(app.midnight().saturating_sub(86400), app.midnight()) } else { 0 },
        // Attack card uses these (excludes telemetry / Local Network Only / Block All noise).
        "blocked_alarm_today": if on("blocked") { app.log.blocked_alarm_since(app.midnight()) } else { 0 },
        "blocked_alarm_usual": if on("blocked") { app.log.blocked_alarm_between(app.midnight().saturating_sub(86400), app.midnight()) } else { 0 },
        "alarm_quiet": app.policy.read().unwrap().alarm_quiet(now()),
        "cards": cards,
        "new_devices": new_devices,
        "pending": pend,
        "safety": cfg.as_ref().map(|c| c.safety),
        "now": now(),
        "offset": app.tz_offset(),
        "timezone": timezone,
        "hour12": hour12,
        "date_fmt": date_fmt,
        "rollback_secs": cfg.as_ref().map(|c| c.rollback_secs).unwrap_or(180),
        "admin_from": if admin_from_wan { "both" } else { "lan" },
        "admin_nudge": admin_nudge,
        "white_expiry": white_expiry,
    })
}

fn geo_state(app: &App) -> Value {
    let on = app.policy.read().unwrap().geo;
    let (phase, done, total) = (geo::PHASE.load(Ordering::Relaxed), geo::DONE.load(Ordering::Relaxed), geo::TOTAL.load(Ordering::Relaxed));
    let m = geo::meta(std::path::Path::new(&format!("{}/geo", app.dir)));
    json!({
        "on": on,
        "loaded": app.geo.read().unwrap().loaded(),
        "phase": phase,
        "done": done,
        "total": total,
        "size_note": geo::SIZE_NOTE,
        "source": geo::SOURCE,
        "month": m.month,
        "fetched_at": m.fetched_at,
        "error": m.error,
        "next_try": geo::NEXT_TRY.load(Ordering::Relaxed),
    })
}

/// The line under a device's name. The maker shows only when the name
/// isn't already the maker's.
fn device_sub(d: &crate::policy::Device, mac: &str) -> String {
    let named = !d.name.is_empty() || !d.hostname.is_empty();
    let mut parts = Vec::new();
    if named && !d.vendor.is_empty() {
        parts.push(d.vendor.as_str());
    }
    if !d.ip.is_empty() {
        parts.push(d.ip.as_str());
    }
    parts.push(mac);
    parts.join(" · ")
}

fn device_json(app: &App, mac: &str, d: &crate::policy::Device) -> Value {
    let live = app.live.lock().unwrap();
    let rate = live.rates.get(mac).copied().unwrap_or((0.0, 0.0));
    let tot = live.totals.get(mac).copied().unwrap_or((0, 0));
    json!({
        "mac": mac, "label": App::device_label(d, mac), "sub": device_sub(d, mac), "name": d.name, "hostname": d.hostname, "ip": d.ip, "vendor": d.vendor,
        "policy": d.policy, "telemetry": d.telemetry, "allow": d.allow, "deny": d.deny,
        "first_seen": d.first_seen, "last_seen": d.last_seen, "new": d.new,
        "up_rate": rate.0, "down_rate": rate.1, "up": tot.0, "down": tot.1,
        "online": now() - d.last_seen < 120,
        "audit_until": d.audit_until, "auditing": d.auditing(now()),
    })
}

/// Colour by where the data is going, as the desktop app's map_dir does:
/// who started it would paint nearly everything as outbound. Ties and
/// missing counts fall back to who started it.
fn map_dir(bytes_in: u64, bytes_out: u64, remote_started: bool) -> &'static str {
    if bytes_in > bytes_out {
        "in"
    } else if bytes_out > bytes_in {
        "out"
    } else if remote_started {
        "in"
    } else {
        "out"
    }
}

/// One connection seen from the local device: (device, remote, dir).
/// (device label, device MAC or "", remote address, direction).
fn side<'a>(by_ip: &'a HashMap<String, (String, String)>, c: &'a net::Conn) -> (&'a str, &'a str, &'a str, &'static str) {
    let (dev, mac, remote, remote_started, bytes_in, bytes_out) = if let Some(d) = by_ip.get(&c.src) {
        (d.0.as_str(), d.1.as_str(), c.dst.as_str(), false, c.reply_bytes, c.orig_bytes)
    } else if let Some(d) = by_ip.get(&c.dst) {
        (d.0.as_str(), d.1.as_str(), c.src.as_str(), true, c.orig_bytes, c.reply_bytes)
    } else {
        (c.src.as_str(), "", c.dst.as_str(), false, c.reply_bytes, c.orig_bytes)
    };
    (dev, mac, remote, map_dir(bytes_in, bytes_out, remote_started))
}

/// Live connections through the gateway: the biggest 200 for the list,
/// and every one of them summed by place and direction for the map, so
/// the map leaves nothing out. `only` keeps one device's, by its address.
fn conns(app: &App, only: Option<&str>) -> (Vec<Value>, Value) {
    let t = now();
    let (by_ip, blocked_countries, allowed_macs, white_addrs) = {
        let pol = app.policy.read().unwrap();
        let by_ip: HashMap<String, (String, String)> = pol.devices.iter().filter(|(_, d)| !d.ip.is_empty()).map(|(m, d)| (d.ip.clone(), (App::device_label(d, m), m.clone()))).collect();
        // Trusted / auditing devices (and white-listed remotes) may still reach a blocked country.
        let allowed_macs: std::collections::HashSet<String> = pol
            .devices
            .iter()
            .filter(|(_, d)| d.policy == DevicePolicy::Trusted || d.auditing(t))
            .map(|(m, _)| m.clone())
            .collect();
        let blocked_countries: std::collections::HashSet<String> = pol.countries.iter().cloned().collect();
        // Exact addresses and /32-style singles from the white list text.
        let white_addrs: std::collections::HashSet<String> = pol
            .white
            .iter()
            .filter_map(|e| parse_entry(e).ok())
            .filter_map(|e| match e {
                Entry::Net(n) => Some(n),
                _ => None,
            })
            .collect();
        (by_ip, blocked_countries, allowed_macs, white_addrs)
    };
    // Connections to the gateway itself (these pages, SSH) aren't traffic through it.
    let own: std::collections::HashSet<String> = net::all_ports_cached().iter().flat_map(|p| p.ips.iter()).map(|c| c.split('/').next().unwrap_or("").to_string()).collect();
    let all = net::connections_cached();
    let mut list: Vec<&net::Conn> = all.iter().filter(|c| !own.contains(&c.src) && !own.contains(&c.dst)).filter(|c| only.is_none_or(|ip| c.src == ip || c.dst == ip)).collect();
    list.sort_unstable_by_key(|c| std::cmp::Reverse(c.bytes));
    let geo = app.geo.read().unwrap();
    // Map: place (0.1 degree) + direction -> (lat, lon, bytes, connections).
    // (lat, lon, bytes, connections, a few names for the tooltip)
    // names = destinations; devices = local device labels for the hover tip.
    type Flow = (f64, f64, u64, u64, Vec<String>, Vec<String>);
    let mut flows: HashMap<(i32, i32, &str), Flow> = HashMap::new();
    let (mut unplaced, mut unplaced_bytes) = (0u64, 0u64);
    let mut rows = Vec::with_capacity(list.len().min(200));
    // Live connections per country, for the Countries tile.
    let mut per_country: HashMap<String, u64> = HashMap::new();
    let names = geo::countries();
    for (i, c) in list.iter().enumerate() {
        let (dev, mac, remote, dir) = side(&by_ip, c);
        let place = remote.parse().ok().and_then(|ip| geo.locate(ip));
        let domain = app.domain_of(mac, remote);
        let owner = app.owner_of(remote);
        // Blocked countries stay off Countries Now / the map unless traffic is
        // genuinely allowed (Trusted, auditing, or white-listed remote). Stale
        // conntrack after a geo block must not keep the country on the list.
        let country_active = match place.as_ref().map(|p| p.country.as_str()) {
            Some(code) if blocked_countries.contains(code) => {
                allowed_macs.contains(mac) || white_addrs.iter().any(|n| n == remote || n.starts_with(&(remote.to_string() + "/")))
            }
            _ => true,
        };
        if let Some(p) = &place {
            if country_active {
                *per_country.entry(p.country.clone()).or_default() += 1;
            }
        }
        match place.as_ref().map(|p| (p.lat, p.lon)) {
            Some((lat, lon)) if country_active => {
                let f = flows.entry(((lat * 10.0).round() as i32, (lon * 10.0).round() as i32, dir)).or_insert((lat, lon, 0, 0, Vec::new(), Vec::new()));
                f.2 += c.bytes;
                f.3 += 1;
                // Biggest connections come first, so these are the busiest names.
                let n = if !domain.is_empty() { domain.clone() } else if !owner.is_empty() { owner.clone() } else { remote.to_string() };
                if f.4.len() < 4 && !f.4.contains(&n) {
                    f.4.push(n);
                }
                let dlab = if !dev.is_empty() { dev.to_string() } else { "Unknown device".into() };
                if f.5.len() < 4 && !f.5.contains(&dlab) {
                    f.5.push(dlab);
                }
            }
            Some(_) => {
                // Blocked country, not allowed: leave off the map.
            }
            None => {
                unplaced += 1;
                unplaced_bytes += c.bytes;
            }
        }
        if i < 200 {
            let country = place.as_ref().map(|p| names.get(p.country.as_str()).copied().unwrap_or(p.country.as_str()).to_string()).unwrap_or_default();
            let ports = [(c.proto.clone(), c.dport)];
            let desc = crate::about::describe(&crate::about::Line { device: dev, dir, remote, domain: &domain, owner: &owner, country: &country, ports: if c.dport > 0 { &ports } else { &[] } });
            rows.push(json!({ "key": format!("{} {}:{} {}:{}", c.proto, c.src, c.sport, c.dst, c.dport), "device": dev, "mac": mac, "remote": remote, "dir": dir, "proto": c.proto, "port": c.dport, "state": c.state, "bytes": c.bytes, "place": place,
                "domain": domain, "owner": owner, "what": crate::ports::purpose(&c.proto, c.dport), "desc": desc }));
        }
    }
    let mut flows: Vec<_> = flows.into_iter().map(|((_, _, dir), (lat, lon, bytes, n, top, devices))| json!({ "lat": lat, "lon": lon, "dir": dir, "bytes": bytes, "n": n, "names": top, "devices": devices })).collect();
    flows.sort_unstable_by_key(|f| std::cmp::Reverse(f["bytes"].as_u64().unwrap_or(0)));
    let mut countries: Vec<(u64, String, String)> = per_country.into_iter().map(|(code, n)| (n, names.get(code.as_str()).map(|s| s.to_string()).unwrap_or_else(|| code.clone()), code)).collect();
    countries.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let countries: Vec<Value> = countries.into_iter().map(|(n, name, code)| json!({ "code": code, "name": name, "n": n })).collect();
    let map = json!({ "flows": flows, "total": list.len(), "unplaced": unplaced, "unplaced_bytes": unplaced_bytes, "countries": countries });
    (rows, map)
}

/// Only what still needs the owner: not handled, and not about a device
/// already trusted or blocked. Newest first.
fn true_alerts(rows: Vec<crate::caplog::Row>, settled: &std::collections::HashSet<String>) -> Vec<Value> {
    let mut out: Vec<_> = rows.into_iter().filter(|r| !r.handled && !settled.contains(&r.device)).collect();
    out.sort_by_key(|r| std::cmp::Reverse(r.last));
    out.truncate(100);
    out.into_iter()
        .map(|r| {
            let link = alert_link(&r);
            let mut v = json!(r);
            v["link"] = json!(link);
            v
        })
        .collect()
}

/// Where clicking an alert takes the owner: the thing it's about.
fn alert_link(r: &crate::caplog::Row) -> String {
    let dev = !r.device.is_empty();
    if r.kind == "device" && dev {
        // "... tried tcp 8080 on <device>. It's on the Ports list."
        let w: Vec<&str> = r.text.split_whitespace().collect();
        if let Some(i) = w.iter().position(|x| *x == "tried") {
            if let (Some(proto), Some(port)) = (w.get(i + 1), w.get(i + 2).and_then(|p| p.parse::<u16>().ok())) {
                return format!("/ports/devices?q={}&port={proto}-{port}", r.device);
            }
        }
        return format!("/devices#{}", r.device);
    }
    if r.kind == "alert" && dev && (r.reason == "surge" || r.text.contains("threat list")) {
        return format!("/devices/troubleshoot?mac={}", r.device);
    }
    format!("/log?kind={}&focus={}", r.kind, r.id)
}

/// Whether something brings the daemon back after it exits: systemd sets
/// INVOCATION_ID for its services (the unit has Restart=always); another
/// supervisor can say so with FOILGW_SUPERVISED=1.
fn supervised() -> bool {
    std::env::var_os("INVOCATION_ID").is_some() || std::env::var("FOILGW_SUPERVISED").as_deref() == Ok("1")
}

/// Settings > Setup > Restart. Answers first, then saves and exits so the
/// supervisor starts a fresh one; the rules stay loaded in the kernel
/// meanwhile, only the bridge setup at start interrupts traffic.

fn updates_status(app: &Arc<App>) -> Resp {
    // Reaching Updates (or any status poll) after an install confirms the new build.
    let _ = crate::updater::ack_pending(&app.dir);
    ok(crate::updater::status_json(&app.dir))
}

fn updates_check(app: &Arc<App>, user: &str) -> Resp {
    if !app.auth.names().iter().any(|(n, r)| n == user && r == "admin") {
        return resp(403, "application/json", json!({"error": "Only an admin can check for updates."}).to_string());
    }
    match crate::updater::check_now(&app.dir) {
        Ok(s) => {
            app.log.note("setting", &format!("{user} checked for updates (latest {}).", s.latest));
            ok(crate::updater::status_json(&app.dir))
        }
        Err(e) => {
            let mut st = crate::updater::status_json(&app.dir);
            if let Some(obj) = st.as_object_mut() {
                obj.insert("error".into(), json!(e));
            }
            bad(&e)
        }
    }
}

fn updates_install(app: &Arc<App>, user: &str) -> Resp {
    if !app.auth.names().iter().any(|(n, r)| n == user && r == "admin") {
        return resp(403, "application/json", json!({"error": "Only an admin can install updates."}).to_string());
    }
    if app.pending.lock().unwrap().is_some() {
        return bad("A change is waiting to be kept. Keep it or let it go back first.");
    }
    if !supervised() {
        return bad("Nothing would start FoilGateway again here (it isn't running as its service), so nothing was changed.");
    }
    if crate::updater::progress_json()["busy"].as_bool() == Some(true) {
        return bad("An update is already in progress.");
    }
    let rollback = app.cfg.read().unwrap().as_ref().map(|c| c.rollback_secs).unwrap_or(180);
    let _ = app.policy.read().unwrap().save(&app.policy_path());
    let app = app.clone();
    let user = user.to_string();
    std::thread::spawn(move || {
        match crate::updater::install(&app.dir, rollback) {
            Ok(m) => {
                app.log.note("setting", &format!("{user} installed an update: {m}"));
                eprintln!("foilgw: {m}");
                std::thread::sleep(std::time::Duration::from_millis(500));
                std::process::exit(0);
            }
            Err(e) => {
                app.log.note("alert", &format!("Update install failed: {e}"));
            }
        }
    });
    ok(json!({"started": true}))
}

fn updates_ack(app: &Arc<App>) -> Resp {
    let cleared = crate::updater::ack_pending(&app.dir);
    ok(json!({"cleared": cleared}))
}

fn restart(app: &Arc<App>, user: &str) -> Resp {
    if !app.auth.names().iter().any(|(n, r)| n == user && r == "admin") {
        return resp(403, "application/json", json!({"error": "Only an admin can restart the gateway."}).to_string());
    }
    if app.pending.lock().unwrap().is_some() {
        return bad("A change is waiting to be kept. Keep it or let it go back first.");
    }
    if !supervised() {
        return bad("Nothing would start FoilGateway again here (it isn't running as its service), so it wasn't stopped.");
    }
    app.log.note("setting", &format!("{user} restarted FoilGateway."));
    let app = app.clone();
    std::thread::spawn(move || {
        // Long enough for this answer to reach the browser.
        std::thread::sleep(std::time::Duration::from_millis(800));
        let _ = app.policy.read().unwrap().save(&app.policy_path());
        eprintln!("foilgw: restart asked for from the settings page");
        std::process::exit(0);
    });
    ok(json!({"restarting": true}))
}

/// Settings > Setup: go back to the version kept at the last update.
fn rollback_version(app: &Arc<App>, user: &str) -> Resp {
    if !app.auth.names().iter().any(|(n, r)| n == user && r == "admin") {
        return resp(403, "application/json", json!({"error": "Only an admin can go back to the previous version."}).to_string());
    }
    let Some(prev) = crate::release::previous() else {
        return bad("No previous version is kept, so there's nothing to go back to.");
    };
    if app.pending.lock().unwrap().is_some() {
        return bad("A change is waiting to be kept. Keep it or let it go back first.");
    }
    if !supervised() {
        return bad("Nothing would start FoilGateway again here (it isn't running as its service), so nothing was changed.");
    }
    let _ = app.policy.read().unwrap().save(&app.policy_path());
    app.log.note("setting", &format!("{user} went back to FoilGateway {}.", prev.version));
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(800));
        // Held to the end, so nothing saves over settings put back below.
        let _hold = app.policy.write().unwrap();
        match crate::release::rollback() {
            Ok(m) => {
                eprintln!("foilgw: {m}");
                std::process::exit(0);
            }
            Err(e) => {
                drop(_hold);
                app.log.note("alert", &format!("Going back to the previous version failed: {e}. Nothing was restarted."));
            }
        }
    });
    ok(json!({"restarting": true, "to": prev.version}))
}

fn choice_name(c: &str) -> &'static str {
    match c {
        "allow" => "Allow",
        "block_wan" => "Block from WAN",
        "block_lan" => "Block from LAN",
        "block_both" => "Block Both",
        _ => "Same as Global",
    }
}

fn dashboard(app: &App, user: &str) -> Value {
    let _ = crate::updater::ack_pending(&app.dir);
    let (settled, online, total) = {
        let pol = app.policy.read().unwrap();
        let t = now();
        // A device the owner trusted or blocked needs no more looking at.
        let settled: std::collections::HashSet<String> = pol.devices.iter().filter(|(_, d)| matches!(d.policy, DevicePolicy::Trusted | DevicePolicy::Block)).map(|(m, _)| m.clone()).collect();
        (settled, pol.devices.values().filter(|d| t - d.last_seen < 600).count(), pol.devices.len())
    };
    let mut all = true_alerts(app.log.rows("device", "", now() - 7 * 86400, 200).into_iter().chain(app.log.rows("alert", "", now() - 7 * 86400, 200)).collect(), &settled);
    // M16: best-effort identification from the maker name we already know.
    {
        let pol = app.policy.read().unwrap();
        if pol.alarm_quiet(now()) {
            all.retain(|a| a["reason"].as_str() != Some("surge"));
        }
        for a in &mut all {
            let mac = a["device"].as_str().unwrap_or("").to_string();
            if mac.is_empty() { continue; }
            if let Some(d) = pol.devices.get(&mac) {
                if !d.vendor.is_empty() && !d.vendor.starts_with("Private") {
                    a["guess"] = json!(format!("Likely a {} device", d.vendor));
                    a["label"] = json!(App::device_label(d, &mac));
                }
            }
        }
    }
    let (conn_list, conn_map) = conns(app, None);
    json!({
        "status": status(app, user),
        "online": online,
        "device_count": total,
        "conns": conn_list,
        "map": conn_map,
        "home": app.home.lock().unwrap().0.clone(),
        "alerts": all,
        "summary": app.summary(),
        "geo": geo_state(app),
    })
}

/// Lower case text a search can match a device by.
fn device_words(mac: &str, d: &crate::policy::Device) -> String {
    format!("{} {} {} {} {} {}", App::device_label(d, mac), d.name, d.hostname, d.ip, d.vendor, mac).to_lowercase()
}

fn ip_key(ip: &str) -> u32 {
    ip.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(u32::MAX)
}

/// One page of devices. q searches, filter is online, new, blocked or
/// trusted, sort is name, ip, seen or traffic. mac= adds that device's
/// connections and today's blocks.
fn devices(app: &App, user: &str, req: &Req) -> Value {
    let q = qs(req, "q").to_lowercase();
    let filter = qs(req, "filter");
    let sort = qs(req, "sort");
    let (offset, limit) = (qn(req, "offset", 0, i64::MAX) as usize, qn(req, "limit", 100, 500) as usize);
    let totals = app.live.lock().unwrap().totals.clone();
    let t = now();
    let (page, total, all, new_devices, picked) = {
        let pol = app.policy.read().unwrap();
        let mut list: Vec<(&String, &crate::policy::Device)> = pol
            .devices
            .iter()
            .filter(|(m, d)| q.is_empty() || device_words(m, d).contains(&q))
            .filter(|(_, d)| match filter.as_str() {
                "online" => t - d.last_seen < 120,
                "new" => d.new,
                "blocked" => matches!(d.policy, DevicePolicy::Block | DevicePolicy::LanOnly),
                "trusted" => d.policy == DevicePolicy::Trusted,
                _ => true,
            })
            .collect();
        match sort.as_str() {
            "ip" => list.sort_by_cached_key(|(_, d)| ip_key(&d.ip)),
            "seen" => list.sort_by_key(|(_, d)| std::cmp::Reverse(d.last_seen)),
            "traffic" => list.sort_by_cached_key(|(m, _)| std::cmp::Reverse(totals.get(*m).map(|x| x.0 + x.1).unwrap_or(0))),
            _ => list.sort_by_cached_key(|(m, d)| App::device_label(d, m).to_lowercase()),
        }
        let total = list.len();
        let page: Vec<(String, crate::policy::Device)> = list.into_iter().skip(offset).take(limit).map(|(m, d)| (m.clone(), d.clone())).collect();
        let picked = req.query.get("mac").and_then(|m| pol.devices.get(m).map(|d| (m.clone(), d.clone(), profiles_json(&pol, m, d))));
        (page, total, pol.devices.len(), pol.new_devices, picked)
    };
    let rows: Vec<Value> = page.iter().map(|(m, d)| device_json(app, m, d)).collect();
    let detail = picked.map(|(m, d, profiles)| {
        // Item 20: while Audit is on, name the busiest destination so far.
        let culprit = if d.auditing(t) {
            let (rows, _) = app.log.audit_list(now() - 7 * 86400, 500);
            rows.into_iter().filter(|r| r.device == m).max_by_key(|r| r.count).map(|r| {
                let what = if r.meta.port > 0 {
                    format!("{} {}/{}", r.meta.remote, r.meta.proto, r.meta.port)
                } else if !r.meta.remote.is_empty() {
                    r.meta.remote.clone()
                } else {
                    "unknown destination".into()
                };
                json!({ "what": what, "count": r.count, "remote": r.meta.remote, "proto": r.meta.proto, "port": r.meta.port, "reason": r.meta.reason, "dir": r.meta.dir })
            })
        } else {
            None
        };
        json!({
            "profiles": profiles,
            "device": device_json(app, &m, &d),
            "conns": if d.ip.is_empty() { vec![] } else { conns(app, Some(&d.ip)).0 },
            "blocked": log_rows(app, app.log.page("block", &m, app.midnight(), i64::MAX, "new", 0, 200).0.into_iter().filter(|r| r.device == m).collect()),
            "culprit": culprit,
        })
    });
    json!({ "status": status(app, user), "devices": rows, "total": total, "all": all, "offset": offset, "new_devices": new_devices, "detail": detail })
}

/// Ports that aren't a good idea to open, and why, in a few words.
pub fn port_risk(proto: &str, port: u16) -> Option<&'static str> {
    Some(match (proto, port) {
        ("tcp", 3389) => "Not recommended from outside: Remote Desktop is heavily scanned. Home-network use is fine under Normal.",
        ("tcp", 445) | ("tcp", 139) => "Not recommended: Windows file sharing, a favourite of ransomware.",
        ("udp", 137) | ("udp", 138) => "Not recommended: old Windows name service, leaks device names.",
        ("tcp", 23) => "Not recommended: Telnet sends passwords in plain text.",
        ("tcp", 21) => "Not recommended: FTP sends passwords in plain text.",
        ("tcp", 5900..=5903) => "Not recommended: VNC is often attacked and weakly protected.",
        ("tcp", 22) => "Use with care: SSH gets constant password guessing. Use keys.",
        ("udp", 1900) | ("tcp", 1900) => "Not recommended: UPnP lets devices open ports on their own.",
        ("tcp", 3306) | ("tcp", 1433) | ("tcp", 5432) | ("tcp", 27017) | ("tcp", 6379) => "Not recommended: databases shouldn't be reachable from outside their machine.",
        ("tcp", 9100) | ("tcp", 631) | ("tcp", 515) => "Not recommended: printers are easy to take over.",
        ("tcp", 80) | ("tcp", 8080) => "Use with care: plain HTTP isn't encrypted.",
        ("udp", 161) => "Not recommended: SNMP often has default passwords.",
        ("tcp", 135) => "Not recommended: Windows RPC, often attacked.",
        ("tcp", 5985) | ("tcp", 5986) => "Not recommended: remote PowerShell, a common way in.",
        _ => return None,
    })
}

fn port_name(proto: &str, port: u16) -> &'static str {
    match (proto, port) {
        ("tcp", 3389) => "Remote Desktop",
        ("tcp", 22) => "SSH",
        ("tcp", 80) => "Web (HTTP)",
        ("tcp", 443) => "Web (HTTPS)",
        ("tcp", 445) => "File sharing (SMB)",
        ("tcp", 139) | ("udp", 137) | ("udp", 138) => "NetBIOS",
        ("tcp", 21) => "FTP",
        ("tcp", 23) => "Telnet",
        ("tcp", 5900..=5903) => "VNC",
        ("udp", 1900) => "UPnP",
        ("tcp", 3306) => "MySQL",
        ("tcp", 1433) => "SQL Server",
        ("tcp", 5432) => "PostgreSQL",
        ("tcp", 27017) => "MongoDB",
        ("tcp", 6379) => "Redis",
        ("tcp", 9100) | ("tcp", 631) | ("tcp", 515) => "Printer",
        ("tcp", 8080) => "Web (alternate)",
        ("udp", 161) => "SNMP",
        ("tcp", 5985) | ("tcp", 5986) => "Remote PowerShell",
        ("udp", 53) | ("tcp", 53) => "DNS",
        _ => "",
    }
}

fn port_label(proto: &str, port: u16) -> String {
    format!("{} {port}", proto.to_uppercase())
}

fn direction(inbound: bool, outbound: bool) -> &'static str {
    match (inbound, outbound) {
        (true, true) => "Both",
        (true, false) => "Inbound",
        (false, true) => "Outbound",
        _ => "Not seen yet",
    }
}

#[derive(Default)]
struct PortRow {
    set: Option<&'static str>,
    hits: u64,
    last_seen: i64,
    from: String,
    new: bool,
    custom: bool,
    outbound: bool,
    overrides: usize,
}

/// tab=global: one row per port, with the setting for every device.
/// tab=devices: every device matching q and show (all, own, none), sorted
/// (own first, name, ip, seen), a page at a time; open=MAC adds that
/// device's ports.
fn ports(app: &App, user: &str, req: &Req) -> Value {
    let q = qs(req, "q").to_lowercase();
    let (offset, limit) = (qn(req, "offset", 0, i64::MAX) as usize, qn(req, "limit", 100, 500) as usize);
    let devices_tab = qs(req, "tab") == "devices";
    let out = {
        let pol = app.policy.read().unwrap();
        let mut rows: std::collections::BTreeMap<(String, u16), PortRow> = Default::default();
        for i in &pol.inbound {
            let r = rows.entry((i.proto.clone(), i.port)).or_default();
            if i.mac.is_empty() {
                r.set = Some(i.choice());
                r.custom |= i.custom;
            } else if i.is_own() {
                r.overrides += 1;
            }
            r.hits += i.hits;
            r.new |= i.new;
            if i.last_seen > r.last_seen {
                r.last_seen = i.last_seen;
                r.from = i.from.clone();
            }
        }
        for (k, t) in &pol.out_seen {
            let Some((proto, port)) = k.split_once(' ').and_then(|(a, b)| Some((a.to_string(), b.parse::<u16>().ok()?))) else { continue };
            let r = rows.entry((proto, port)).or_default();
            r.outbound = true;
            r.last_seen = r.last_seen.max(*t);
        }
        let known: Vec<Value> = rows.iter().map(|((proto, port), r)| json!({ "proto": proto, "port": port, "label": port_label(proto, *port), "name": port_name(proto, *port), "set": r.set })).collect();
        if !devices_tab {
            let list: Vec<Value> = rows
                .iter()
                .filter(|((proto, port), _)| q.is_empty() || format!("{} {}", port_label(proto, *port), port_name(proto, *port)).to_lowercase().contains(&q))
                .map(|((proto, port), r)| {
                    json!({
                        "proto": proto, "port": port, "label": port_label(proto, *port), "name": port_name(proto, *port), "risk": port_risk(proto, *port),
                        "choice": r.set.unwrap_or("default"), "set": r.set.is_some(), "custom": r.custom, "new": r.new,
                        "direction": direction(r.hits > 0, r.outbound), "hits": r.hits, "last_seen": r.last_seen, "from": r.from, "overrides": r.overrides,
                    })
                })
                .collect();
            json!({ "tab": "global", "total": list.len(), "ports": list, "known": known, "mode": pol.mode })
        } else {
            // Every device, a page at a time; the opened one carries every
            // port with its own choice or "global".
            let global: HashMap<(&str, u16), &'static str> = pol.inbound.iter().filter(|i| i.mac.is_empty()).map(|i| ((i.proto.as_str(), i.port), i.choice())).collect();
            let mut own: HashMap<&str, Vec<&crate::policy::InPort>> = HashMap::new();
            for i in pol.inbound.iter().filter(|i| i.is_own()) {
                own.entry(i.mac.as_str()).or_default().push(i);
            }
            let show = qs(req, "show");
            let open = qs(req, "open");
            let count = |m: &str| own.get(m).map_or(0, |v| v.len());
            let mut macs: Vec<(&String, &crate::policy::Device)> = pol
                .devices
                .iter()
                .filter(|(m, _)| match show.as_str() {
                    "own" => count(m) > 0,
                    "none" => count(m) == 0,
                    _ => true,
                })
                .filter(|(m, d)| q.is_empty() || device_words(m, d).contains(&q))
                .collect();
            match qs(req, "sort").as_str() {
                "name" => macs.sort_by_cached_key(|(m, d)| App::device_label(d, m).to_lowercase()),
                "ip" => macs.sort_by_cached_key(|(_, d)| (d.ip.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(u32::MAX), d.ip.clone())),
                "seen" => macs.sort_by_key(|(_, d)| std::cmp::Reverse(d.last_seen)),
                _ => macs.sort_by_cached_key(|(m, d)| (count(m) == 0, App::device_label(d, m).to_lowercase())),
            }
            let total = macs.len();
            let list: Vec<Value> = macs
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|(m, d)| {
                    let shut = matches!(d.policy, DevicePolicy::Block | DevicePolicy::LanOnly).then_some(d.policy);
                    let mut v = json!({ "mac": m, "label": App::device_label(d, m), "ip": d.ip, "shut": shut, "own": count(m) });
                    if *m == open {
                        let mine: HashMap<(&str, u16), &crate::policy::InPort> = own.get(m.as_str()).map(|v| v.iter().map(|i| ((i.proto.as_str(), i.port), *i)).collect()).unwrap_or_default();
                        let ports: Vec<Value> = rows
                            .iter()
                            .map(|((proto, port), r)| {
                                let g = global.get(&(proto.as_str(), *port)).copied();
                                let mine = mine.get(&(proto.as_str(), *port));
                                json!({
                                    "proto": proto, "port": port, "label": port_label(proto, *port), "name": port_name(proto, *port), "risk": port_risk(proto, *port),
                                    "direction": direction(r.hits > 0, r.outbound), "new": r.new,
                                    "choice": mine.map_or("global", |i| i.choice()), "global": g.unwrap_or("block_wan"),
                                    "alert": mine.and(g).map(|g| format!("Global rule applies: the setting for all devices ({}) is used instead of this one.", choice_name(g))),
                                })
                            })
                            .collect();
                        v["ports"] = json!(ports);
                    }
                    v
                })
                .collect();
            json!({ "tab": "devices", "total": total, "offset": offset, "devices": list, "known": known, "with_own": own.len(), "mode": pol.mode })
        }
    };
    let mut out = out;
    out["status"] = status(app, user);
    out
}

/// Set a port for everybody or for one device, add one by hand, or take
/// one off the list.
fn ports_change(app: &Arc<App>, req: &Req, user: &str) -> Resp {
    let b = body(req);
    let proto = s(&b, "proto").to_ascii_lowercase();
    if proto != "tcp" && proto != "udp" {
        return bad("Pick TCP or UDP.");
    }
    let Some(port) = b["port"].as_u64().or_else(|| s(&b, "port").trim().parse().ok()).filter(|p| (1..=65535).contains(p)).map(|p| p as u16) else { return bad("A port is a number from 1 to 65535.") };
    let mac = s(&b, "mac");
    let mut pol = app.policy.read().unwrap().clone();
    if !mac.is_empty() && !pol.devices.contains_key(&mac) {
        return bad("No such device.");
    }
    let who = if mac.is_empty() { "every device".to_string() } else { pol.devices.get(&mac).map(|d| App::device_label(d, &mac)).unwrap_or_default() };
    let label = port_label(&proto, port);
    let global = pol.inbound.iter().find(|i| i.same(&proto, port, "")).cloned();
    let what = match s(&b, "action").as_str() {
        "add" => {
            if pol.inbound.iter().any(|i| i.same(&proto, port, &mac) && (mac.is_empty() || i.is_own())) {
                return bad("That port is on the list already.");
            }
            pol.inbound.retain(|i| !i.same(&proto, port, &mac));
            let mut e = crate::policy::InPort { proto: proto.clone(), port, mac: mac.clone(), custom: true, own: !mac.is_empty(), ..Default::default() };
            let choice = s(&b, "choice");
            if !e.set_choice(if choice.is_empty() { "allow" } else { &choice }) {
                return bad("Unknown choice.");
            }
            let shown = choice_name(e.choice());
            pol.inbound.push(e);
            format!("{label} added for {who} as {shown} by {user}")
        }
        "remove" => {
            let before = pol.inbound.len();
            pol.inbound.retain(|i| !i.same(&proto, port, &mac));
            if pol.inbound.len() == before {
                return bad("That port isn't on the list.");
            }
            format!("{label} for {who} taken off the list by {user}")
        }
        "seen" => {
            pol.inbound.iter_mut().filter(|i| i.same(&proto, port, &mac)).for_each(|i| i.new = false);
            pol.save(&app.policy_path()).ok();
            *app.policy.write().unwrap() = pol;
            return ok(json!({"ok": true}));
        }
        "choice" => {
            let choice = s(&b, "choice");
            if mac.is_empty() && choice == "global" {
                return bad("Same as global is for one device.");
            }
            if choice != "global" && !crate::policy::CHOICES.contains(&choice.as_str()) {
                return bad("Unknown choice.");
            }
            if !pol.inbound.iter().any(|i| i.same(&proto, port, &mac)) {
                pol.inbound.push(crate::policy::InPort { proto: proto.clone(), port, mac: mac.clone(), custom: true, ..Default::default() });
            }
            let i = pol.inbound.iter_mut().find(|i| i.same(&proto, port, &mac)).unwrap();
            i.new = false;
            if choice == "global" {
                // Back to whatever everybody gets.
                i.own = false;
                i.custom = false;
                i.follow = global.is_some();
                let (on, lan_off) = global.as_ref().map(|g| (g.on, g.lan_off)).unwrap_or((false, false));
                (i.on, i.lan_off) = (on, lan_off);
            } else {
                i.set_choice(&choice);
                if !mac.is_empty() {
                    i.own = true;
                    i.follow = false;
                }
            }
            if mac.is_empty() {
                // Devices that follow everybody show the new setting.
                let (on, lan_off) = (pol.inbound.iter().find(|i| i.same(&proto, port, "")).map(|g| (g.on, g.lan_off))).unwrap_or_default();
                for d in pol.inbound.iter_mut().filter(|i| !i.mac.is_empty() && i.proto == proto && i.port == port && !i.is_own()) {
                    (d.on, d.lan_off, d.follow) = (on, lan_off, true);
                }
            }
            let note = if !mac.is_empty() && choice != "global" && global.is_some() { " (global rule applies: the setting for all devices is used)" } else { "" };
            format!("{label} set to {} for {who} by {user}{note}", choice_name(&choice))
        }
        _ => {
            // Older pages: on/off from the router side.
            let Some(on) = b["on"].as_bool() else { return bad("Say on or off.") };
            let Some(i) = pol.inbound.iter_mut().find(|i| i.same(&proto, port, &mac)) else { return bad("That port isn't on the list.") };
            i.on = on;
            i.follow = false;
            i.own = !mac.is_empty();
            i.new = false;
            format!("{label} from the router side {} for {who} by {user}", if on { "opened" } else { "shut" })
        }
    };
    done(app.change(None, pol, &what))
}

fn check_list(v: &Value) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for e in v.as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>()).unwrap_or_default() {
        let e = e.trim();
        if e.is_empty() {
            continue;
        }
        let shown = match parse_entry(e)? {
            Entry::Net(n) => n,
            Entry::Site(s) => s,
            Entry::Port(p, n) => format!("{p}/{n}"),
        };
        if !out.contains(&shown) {
            out.push(shown);
        }
    }
    Ok(out)
}

fn device_change(app: &App, req: &Req) -> Resp {
    let b = body(req);
    let Some(mac) = normal_mac(&s(&b, "mac")) else { return bad("Unknown device.") };
    let mut pol = app.policy.read().unwrap().clone();
    if b["forget"].as_bool() == Some(true) {
        let gone = pol.devices.remove(&mac);
        let Some(d) = gone else { return bad("Unknown device.") };
        return done(app.change(None, pol, &format!("forgot {}", App::device_label(&d, &mac))));
    }
    let Some(d) = pol.devices.get_mut(&mac) else { return bad("Unknown device.") };
    let before = d.clone();
    let mut what = Vec::new();
    if b["name"].is_string() {
        let n: String = s(&b, "name").chars().filter(|c| !c.is_control()).take(48).collect();
        what.push(format!("named {} \"{n}\"", App::device_label(d, &mac)));
        d.name = n;
    }
    if let Ok(p) = serde_json::from_value::<DevicePolicy>(b["policy"].clone()) {
        what.push(format!("{} set to {}", App::device_label(d, &mac), p.label()));
        d.policy = p;
        d.new = false;
    }
    if let Some(t) = b["telemetry"].as_bool() {
        what.push(format!("telemetry {} for {}", if t { "blocked" } else { "allowed" }, App::device_label(d, &mac)));
        d.telemetry = t;
    }
    for (k, label) in [("allow", "allow list"), ("deny", "deny list")] {
        if b[k].is_array() {
            match check_list(&b[k]) {
                Ok(l) => {
                    what.push(format!("{} {label} now {} entries", App::device_label(d, &mac), l.len()));
                    if k == "allow" { d.allow = l } else { d.deny = l }
                }
                Err(e) => return bad(e),
            }
        }
    }
    if b["seen"].as_bool() == Some(true) {
        d.new = false;
        what.push(format!("{} marked as looked at", App::device_label(d, &mac)));
    }
    let only_cosmetic = d.policy == before.policy && d.telemetry == before.telemetry && d.allow == before.allow && d.deny == before.deny;
    let entries: Vec<String> = d.allow.iter().chain(&d.deny).cloned().collect();
    let handled = !d.new;
    if only_cosmetic {
        // Names and the "new" flag don't change any rule.
        let r = pol.save(&app.policy_path());
        *app.policy.write().unwrap() = pol;
        if handled {
            app.log.handle_device(&mac);
        }
        return match r {
            Ok(_) => ok(json!({"pending": false})),
            Err(e) => bad(e),
        };
    }
    for e in &entries {
        app.warm(e);
    }
    let r = app.change(None, pol, &what.join(", "));
    if r.is_ok() && handled {
        app.log.handle_device(&mac);
    }
    done(r)
}

fn firewall(app: &App, user: &str, with_rules: bool) -> Value {
    let pol = app.policy.read().unwrap().clone();
    let feeds = app.feeds.read().unwrap();
    let seen = app.seen.lock().unwrap();
    let addr_count = |l: &Vec<String>| -> Vec<Value> {
        l.iter()
            .map(|e| {
                let n = match parse_entry(e) {
                    Ok(Entry::Site(s)) => seen.of(&s).len(),
                    _ => 1,
                };
                json!({ "entry": e, "addresses": n, "site": matches!(parse_entry(e), Ok(Entry::Site(_))) })
            })
            .collect()
    };
    let white = addr_count(&pol.white);
    let black = addr_count(&pol.black);
    drop(seen);
    let summary = app.summary();
    let cfg = app.cfg.read().unwrap().clone();
    let preset_chip = crate::presets::chip(&pol);
    let presets = crate::presets::Preset::ALL.iter().map(|p| json!({
        "id": p,
        "label": p.label(),
        "one_line": p.one_line(),
        "diff": p.diff(&pol),
        "current": matches!(pol.preset, Some(cur) if cur == *p) && preset_chip != "Custom",
    })).collect::<Vec<_>>();
    json!({
        "status": status(app, user),
        "mode": pol.mode, "telemetry_all": pol.telemetry_all, "threats": pol.threats,
        "strict_outbound": pol.strict_outbound,
        "block_ipv6": pol.block_ipv6,
        "block_vpn": pol.block_vpn,
        "block_dot": pol.block_dot,
        "white_expiry": pol.white_expiry,
        "dns_proxy": pol.dns_proxy,
        "sticky_identity": pol.sticky_identity,
        "deep_detect": pol.deep_detect,
        "peer_filter": pol.peer_filter,
        "peer_filter_available": false,
        "preset": pol.preset,
        "preset_chip": preset_chip,
        "presets": presets,
        "doh_warning": (pol.threats || pol.block_dot) && !pol.dns_proxy,
        "rdp_external": pol.inbound.iter().any(|i| i.mac.is_empty() && i.proto == "tcp" && i.port == 3389 && i.on),
        "rdp_lan_blocked": pol.inbound.iter().any(|i| i.mac.is_empty() && i.proto == "tcp" && i.port == 3389 && i.lan_off),
        "white": white, "black": black,
        "countries": pol.countries, "all_countries": geo::countries(),
        "new_devices": pol.new_devices,
        "feeds": feeds.status.values().collect::<Vec<_>>(),
        "telemetry_hosts": feeds.telemetry_hosts.len(),
        "geo": geo_state(app),
        "summary": summary,
        "geo_job": app.geo_job.lock().unwrap().clone(),
        "placement": cfg.as_ref().map(|c| c.placement.conf_value()).unwrap_or("router_switch"),
        "admin_from": cfg.as_ref().map(|c| if c.admin_from_wan { "both" } else { "lan" }).unwrap_or("both"),
        // Only the Rules page asks; country sets show as a count there.
        "rules": if with_rules { cfg.as_ref().map(|c| app.ruleset_view(c)).unwrap_or_default() } else { String::new() },
    })
}

fn firewall_change(app: &Arc<App>, req: &Req) -> Resp {
    let b = body(req);
    let mut pol = app.policy.read().unwrap().clone();
    // Preview: return old→new lines without applying. Reuses preset / mode_diff.
    if b["preview"].as_bool() == Some(true) {
        let diff = if b["leave_audit"].as_bool() == Some(true) {
            crate::presets::Preset::Normal.diff(&pol)
        } else if let Some(raw) = b["preset"].as_str() {
            match crate::presets::Preset::parse(raw) {
                Some(p) => p.diff(&pol),
                None => return bad("Unknown protection preset."),
            }
        } else if let Ok(m) = serde_json::from_value::<Mode>(b["mode"].clone()) {
            crate::presets::mode_diff(&pol, m)
        } else {
            Vec::new()
        };
        return ok(json!({ "diff": diff }));
    }
    let mut what = Vec::new();
    let mut cfg_patch: Option<Config> = None;
    // Named preset apply (Leave Audit → Normal uses preset=normal; home_user still parses).
    if let Some(raw) = b["preset"].as_str() {
        let Some(p) = crate::presets::Preset::parse(raw) else {
            return bad("Unknown protection preset.");
        };
        let diff = p.diff(&pol);
        p.apply(&mut pol);
        what.push(format!("protection preset {}", p.label()));
        if !diff.is_empty() {
            what.push(format!("{} changes", diff.len()));
        }
        if p.bundle().prefer_admin_lan {
            if let Some(mut c) = app.cfg.read().unwrap().clone() {
                if c.admin_from_wan {
                    c.admin_from_wan = false;
                    cfg_patch = Some(c);
                    what.push("settings page answers from LAN devices only".into());
                }
            }
        }
    }
    if b["leave_audit"].as_bool() == Some(true) {
        crate::presets::leave_audit(&mut pol);
        what.push("left Audit; applied Normal".into());
        if let Some(mut c) = app.cfg.read().unwrap().clone() {
            if c.admin_from_wan {
                c.admin_from_wan = false;
                cfg_patch = Some(c);
                what.push("settings page answers from LAN devices only".into());
            }
        }
    }
    if let Ok(m) = serde_json::from_value::<Mode>(b["mode"].clone()) {
        match m {
            Mode::Normal => {
                // Protection Mode Normal is the lever for the Normal protection level.
                let diff = crate::presets::Preset::Normal.diff(&pol);
                crate::presets::Preset::Normal.apply(&mut pol);
                what.push("protection mode Normal".into());
                if !diff.is_empty() {
                    what.push(format!("{} changes", diff.len()));
                }
                if crate::presets::Preset::Normal.bundle().prefer_admin_lan {
                    if let Some(mut c) = app.cfg.read().unwrap().clone() {
                        if c.admin_from_wan {
                            c.admin_from_wan = false;
                            cfg_patch = Some(c);
                            what.push("settings page answers from LAN devices only".into());
                        }
                    }
                }
            }
            other => {
                what.push(format!("protection mode {}", match other {
                    Mode::LanOnly => "Local Network Only",
                    Mode::BlockAll => "Block Everything",
                    Mode::Audit => "Audit",
                    Mode::Normal => "Normal",
                }));
                pol.mode = other;
            }
        }
    }
    if let Some(t) = b["telemetry_all"].as_bool() {
        what.push(format!("Block All Telemetry {}", if t { "On" } else { "Off" }));
        pol.telemetry_all = t;
    }
    if let Some(t) = b["threats"].as_bool() {
        what.push(format!("Threat Lists {}", if t { "On" } else { "Off" }));
        pol.threats = t;
    }
    if let Some(t) = b["strict_outbound"].as_bool() {
        what.push(format!("Strict Outbound {}", if t { "On" } else { "Off" }));
        pol.strict_outbound = t;
    }
    if let Some(t) = b["block_ipv6"].as_bool() {
        what.push(format!("Block IPv6 {}", if t { "On" } else { "Off" }));
        pol.block_ipv6 = t;
    } else if let Some(through) = b["ipv6_enabled"].as_bool() {
        // Legacy coach/UI patches: through=true means Block IPv6 Off.
        let block = !through;
        what.push(format!("Block IPv6 {}", if block { "On" } else { "Off" }));
        pol.block_ipv6 = block;
    }
    if let Some(t) = b["block_vpn"].as_bool() {
        what.push(format!("Block VPN Ports {}", if t { "On" } else { "Off" }));
        pol.block_vpn = t;
    }
    if let Some(t) = b["block_dot"].as_bool() {
        what.push(format!("Block Encrypted DNS (Port 853) {}", if t { "On" } else { "Off" }));
        pol.block_dot = t;
    }
    if let Some(t) = b["white_expiry"].as_bool() {
        what.push(format!("Whitelist Expiry {}", if t { "On" } else { "Off" }));
        pol.white_expiry = t;
    }
    if let Some(t) = b["dns_proxy"].as_bool() {
        what.push(format!("DNS Proxy {}", if t { "On" } else { "Off" }));
        pol.dns_proxy = t;
    }
    if let Some(t) = b["sticky_identity"].as_bool() {
        what.push(format!("Stronger Device Identity {}", if t { "On" } else { "Off" }));
        pol.sticky_identity = t;
    }
    if let Some(t) = b["deep_detect"].as_bool() {
        what.push(format!("Deeper Detection {}", if t { "On" } else { "Off" }));
        pol.deep_detect = t;
    }
    if let Some(t) = b["peer_filter"].as_bool() {
        // Bridge placements cannot enable device-to-device filtering.
        if t {
            return bad("Device-To-Device Filter is not available for your placement.");
        }
        what.push("Device-To-Device Filter Off".into());
        pol.peer_filter = false;
    }
    if let Some(t) = b["admin_keep_both"].as_bool() {
        pol.admin_keep_both = t;
        what.push(if t { "keep settings reachable from both sides".into() } else { "clear keep-both choice".into() });
    }
    if b["rdp_off"].as_bool() == Some(true) {
        if let Some(p) = pol.inbound.iter_mut().find(|i| i.mac.is_empty() && i.proto == "tcp" && i.port == 3389) {
            p.on = false;
            what.push("Remote Desktop Off".into());
        }
    }
    if let Some(from) = b["admin_from"].as_str() {
        if let Some(mut c) = app.cfg.read().unwrap().clone().or(cfg_patch.clone()) {
            c.admin_from_wan = from != "lan";
            cfg_patch = Some(c);
            what.push(format!("settings page answers {}", if from == "lan" { "from LAN devices only" } else { "from both sides" }));
        }
    }
    if let Ok(p) = serde_json::from_value::<DevicePolicy>(b["new_devices"].clone()) {
        what.push(format!("new devices get {}", p.label()));
        pol.new_devices = p;
    }
    if let Some(list) = b["countries"].as_array() {
        let known = geo::countries();
        let mut cs: Vec<String> = list.iter().filter_map(|x| x.as_str()).filter(|c| known.contains_key(c)).map(String::from).collect();
        cs.sort();
        cs.dedup();
        // Countries alone: saved now and loaded in the background, no confirm.
        if what.is_empty() {
            {
                let mut live = app.policy.write().unwrap();
                live.countries = cs;
                if let Err(e) = live.save(&app.policy_path()) {
                    return bad(e);
                }
            }
            app.geo_apply();
            return ok(json!({ "pending": false, "secs": 0, "geo": true }));
        }
        what.push(format!("{} countries blocked", cs.len()));
        pol.countries = cs;
    }
    if what.is_empty() {
        return bad("Nothing to change.");
    }
    let lists_needed = pol.telemetry_all || pol.threats;
    let r = app.change(cfg_patch, pol, &what.join(", "));
    if r.is_ok() && lists_needed {
        // Fetch the lists now rather than in five minutes.
        let a = app.clone();
        std::thread::spawn(move || {
            a.update_feeds();
            a.refresh_rules();
        });
    }
    done(r)
}

fn coach_get(app: &App, user: &str) -> Value {
    let pol = app.policy.read().unwrap().clone();
    let cfg = app.cfg.read().unwrap().clone();
    let admin_from_wan = cfg.as_ref().map(|c| c.admin_from_wan).unwrap_or(true);
    json!({
        "status": status(app, user),
        "questions": crate::presets::coach_questions(&pol, admin_from_wan),
        "suggestions": crate::presets::coach_suggestions(&pol, admin_from_wan, &json!({})).into_iter().filter(|s| !pol.coach_dismissed.iter().any(|d| d == &s.id)).collect::<Vec<_>>(),
        "preset_chip": crate::presets::chip(&pol),
        "mode": pol.mode,
        "dismissed": pol.coach_dismissed.clone(),
        "placement": cfg.as_ref().map(|c| json!({
            "id": c.placement.conf_value(),
            "label": c.placement.label(),
            "plain": c.placement.plain(),
            "can_see": c.placement.can_see(),
            "cannot_see": c.placement.cannot_see(),
        })),
    })
}

fn coach_post(app: &Arc<App>, req: &Req) -> Resp {
    let b = body(req);
    let pol = app.policy.read().unwrap().clone();
    let cfg = app.cfg.read().unwrap().clone();
    let admin_from_wan = cfg.as_ref().map(|c| c.admin_from_wan).unwrap_or(true);
    let answers = b.get("answers").cloned().unwrap_or(json!({}));
    if let Some(id) = b["dismiss"].as_str() {
        let mut pol = pol;
        if !pol.coach_dismissed.iter().any(|d| d == id) {
            pol.coach_dismissed.push(id.into());
        }
        return done(app.change(None, pol, &format!("dismissed Best Practices tip {id}")));
    }
    if let Some(id) = b["accept"].as_str() {
        let suggestions = crate::presets::coach_suggestions(&pol, admin_from_wan, &answers);
        let Some(s) = suggestions.into_iter().find(|s| s.id == id) else {
            return bad("That suggestion is no longer available.");
        };
        let patch = s.patch;
        let mut pol = pol;
        let what = vec![format!("Best Practices: {}", s.title)];
        let mut cfg_patch = None;
        if let Some(raw) = patch.get("preset").and_then(|v| v.as_str()) {
            if let Some(p) = crate::presets::Preset::parse(raw) {
                p.apply(&mut pol);
                if p.bundle().prefer_admin_lan {
                    if let Some(mut c) = cfg.clone() {
                        if c.admin_from_wan {
                            c.admin_from_wan = false;
                            cfg_patch = Some(c);
                        }
                    }
                }
            }
        }
        if let Some(t) = patch.get("threats").and_then(|v| v.as_bool()) { pol.threats = t; }
        if let Some(t) = patch.get("telemetry_all").and_then(|v| v.as_bool()) { pol.telemetry_all = t; }
        if let Some(t) = patch.get("block_dot").and_then(|v| v.as_bool()) { pol.block_dot = t; }
        if let Some(t) = patch.get("block_ipv6").and_then(|v| v.as_bool()) { pol.block_ipv6 = t; }
        else if let Some(through) = patch.get("ipv6_enabled").and_then(|v| v.as_bool()) { pol.block_ipv6 = !through; }
        if let Some(t) = patch.get("white_expiry").and_then(|v| v.as_bool()) { pol.white_expiry = t; }
        if let Some(t) = patch.get("block_vpn").and_then(|v| v.as_bool()) { pol.block_vpn = t; }
        if let Some(t) = patch.get("strict_outbound").and_then(|v| v.as_bool()) { pol.strict_outbound = t; }
        if let Some(t) = patch.get("dns_proxy").and_then(|v| v.as_bool()) { pol.dns_proxy = t; }
        if let Some(t) = patch.get("sticky_identity").and_then(|v| v.as_bool()) { pol.sticky_identity = t; }
        if let Some(t) = patch.get("deep_detect").and_then(|v| v.as_bool()) { pol.deep_detect = t; }
        if patch.get("peer_filter").and_then(|v| v.as_bool()) == Some(true) {
            return bad("Device-To-Device Filter is not available for your placement.");
        }
        pol.coach_dismissed.retain(|d| d != id);
        if patch.get("rdp_off").and_then(|v| v.as_bool()) == Some(true) {
            if let Some(p) = pol.inbound.iter_mut().find(|i| i.mac.is_empty() && i.proto == "tcp" && i.port == 3389) {
                p.on = false;
            }
        }
        if patch.get("admin_from").and_then(|v| v.as_str()) == Some("lan") {
            if let Some(mut c) = cfg.or(cfg_patch.clone()) {
                c.admin_from_wan = false;
                cfg_patch = Some(c);
            }
        }
        let lists_needed = pol.telemetry_all || pol.threats;
        let r = app.change(cfg_patch, pol, &what.join(", "));
        if r.is_ok() && lists_needed {
            let a = app.clone();
            std::thread::spawn(move || { a.update_feeds(); a.refresh_rules(); });
        }
        return done(r);
    }
    ok(json!({
        "suggestions": crate::presets::coach_suggestions(&pol, admin_from_wan, &answers).into_iter().filter(|s| !pol.coach_dismissed.iter().any(|d| d == &s.id)).collect::<Vec<_>>(),
    }))
}

fn list_change(app: &App, req: &Req) -> Resp {
    let b = body(req);
    let which = s(&b, "list");
    if which != "white" && which != "black" {
        return bad("Unknown list.");
    }
    let mut pol = app.policy.read().unwrap().clone();
    let other_name = if which == "white" { "Black list" } else { "White list" };
    
    let what = if b["add"].is_string() {
        let mut added = Vec::new();
        let mut moved: Vec<String> = Vec::new();
        for raw in s(&b, "add").split(['\n', ',', ' ']).filter(|x| !x.trim().is_empty()) {
            let e = match parse_entry(raw) {
                Ok(Entry::Net(n)) => n,
                Ok(Entry::Site(s)) => s,
                Ok(Entry::Port(..)) => return bad("Ports go on a device's own lists, not here."),
                Err(e) => return bad(e),
            };
            // One place per entry: adding to one list takes it off the other.
            let (list, other) = if which == "white" { (&mut pol.white, &mut pol.black) } else { (&mut pol.black, &mut pol.white) };
            if other.contains(&e) {
                other.retain(|x| x != &e);
                moved.push(e.clone());
            }
            if !list.contains(&e) {
                list.push(e.clone());
                added.push(e);
            }
        }
        if which == "white" {
            for e in &added {
                pol.white_until.remove(e); // hand-added = permanent
            }
        }
        for e in &added {
            app.warm(e);
        }
        if added.is_empty() {
            return bad("Already on the list.");
        }
        let off = if moved.is_empty() { String::new() } else { format!(", took {} off the {other_name}", moved.join(", ")) };
        format!("added {} to the {}{off}", added.join(", "), if which == "white" { "White list" } else { "Black list" })
    } else if b["remove"].is_string() {
        let e = s(&b, "remove");
        let list = if which == "white" { &mut pol.white } else { &mut pol.black };
        list.retain(|x| x != &e);
        if which == "white" {
            pol.white_until.remove(&e);
        }
        format!("removed {e} from the {}", if which == "white" { "White list" } else { "Black list" })
    } else {
        return bad("Nothing to change.");
    };
    done(app.change(None, pol, &what))
}

fn timezones() -> Vec<String> {
    let mut out = Vec::new();
    fn walk(dir: &std::path::Path, base: &str, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let full = if base.is_empty() { name.clone() } else { format!("{base}/{name}") };
            if e.path().is_dir() {
                if !["posix", "right", "Etc", "SystemV"].contains(&name.as_str()) {
                    walk(&e.path(), &full, out);
                }
            } else if name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) && full.contains('/') {
                out.push(full);
            }
        }
    }
    walk(std::path::Path::new("/usr/share/zoneinfo"), "", &mut out);
    out.sort();
    out.insert(0, "UTC".into());
    out
}

fn settings(app: &App, user: &str) -> Value {
    let cfg = app.cfg.read().unwrap().clone();
    json!({
        "status": status(app, user),
        "release": crate::release::info(),
        "cfg": cfg.as_ref().map(|c| json!({ "lan": c.lan, "wan": c.wan, "placement": c.placement.conf_value(), "safety": c.safety, "safety_hosts": c.safety_hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>(), "safety_ports": c.safety_ports, "admin_port": c.admin_port, "admin_from": if c.admin_from_wan { "both" } else { "lan" }, "rollback_secs": c.rollback_secs,
            "ip_mode": if c.fixed.is_some() { "fixed" } else { "dhcp" },
            "fixed": c.fixed.as_ref().map(|f| json!({ "ip": f.ip.to_string(), "mask": std::net::Ipv4Addr::from(u32::MAX << (32 - f.prefix as u32)).to_string(), "gateway": f.gateway.map(|g| g.to_string()).unwrap_or_default(), "dns": f.dns.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ") })) })),
        "bridge_ips": net::bridge_port().map(|p| p.ips).unwrap_or_default(),
        "log_days": app.policy.read().unwrap().log_days,
        "log_count": app.log.page("", "", 0, i64::MAX, "old", 0, 1).1,
        "log_oldest": app.log.page("", "", 0, i64::MAX, "old", 0, 1).0.first().map(|r| r.last),
        "ports": net::ports(),
        "users": app.auth.names().into_iter().map(|(n, r)| json!({"name": n, "role": r})).collect::<Vec<_>>(),
        "sessions": app.auth.sessions().into_iter().map(|(i, u, ip, t)| json!({"id": i, "user": u, "ip": ip, "started": t})).collect::<Vec<_>>(),
        "geo": geo_state(app),
        "timezone": app.policy.read().unwrap().timezone,
        "hour12": app.policy.read().unwrap().hour12,
        "date_fmt": app.policy.read().unwrap().date_fmt.clone(),
        "timezones": timezones(),
    })
}

fn settings_change(app: &Arc<App>, req: &Req, user: &str) -> Resp {
    let b = body(req);
    let action = s(&b, "action");
    let cfg = app.cfg.read().unwrap().clone();
    match action.as_str() {
        "ports" | "safety" | "admin_port" | "admin_from" | "placement" => {
            // Moving the WAN role can cut the gateway off from the router, so
            // the page has to unlock it first, and so does the request.
            if action == "ports" && b["wan"].is_string() && cfg.as_ref().is_some_and(|c| c.wan != s(&b, "wan")) && b["wan_unlocked"].as_bool() != Some(true) {
                return bad("The WAN port is locked. Unlock it and confirm first.");
            }
            if action == "safety" && b["safety"].as_bool() == Some(false) && b["confirm_off"].as_bool() != Some(true) {
                return bad("Turning safety off means a bad rule can lock everyone out. Tick the box to confirm.");
            }
            let c = match build_cfg(&b, cfg.as_ref()) {
                Ok(c) => c,
                Err(e) => return bad(e),
            };
            let what = match action.as_str() {
                "ports" => format!("ports: LAN {}, WAN {}", c.lan.join(", "), c.wan),
                "safety" => format!("management safety {}, always reachable from {}", if c.safety { "on" } else { "off" }, c.safety_hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>().join(", ")),
                "admin_from" => format!("settings page answers {}", if c.admin_from_wan { "from both sides" } else { "from LAN devices only" }),
                "placement" => format!("placement {}", c.placement.label()),
                _ => format!("settings page moved to port {}", c.admin_port),
            };
            let pol = app.policy.read().unwrap().clone();
            let r = app.change(Some(c.clone()), pol, &what);
            if r.is_ok() && action == "admin_port" {
                spawn_listener(app, c.admin_port);
            }
            if r.is_ok() && action == "ports" && crate::bridge::exists() {
                if let Err(e) = crate::bridge::reshape(&app.dir, &c.wan, &c.lan) {
                    app.undo_now();
                    return bad(format!("Couldn't change the bridge ports, so the change is undone: {e}"));
                }
            }
            match r {
                Ok(secs) => ok(json!({ "pending": secs > 0, "secs": secs, "port": c.admin_port })),
                Err(e) => bad(e),
            }
        }
        "address" => {
            let Some(mut c) = cfg else { return bad("Finish setup first.") };
            c.fixed = match s(&b, "ip_mode").as_str() {
                "dhcp" => None,
                "fixed" => match fixed_from(&b) {
                    Ok(f) => Some(f),
                    Err(e) => return bad(e),
                },
                _ => return bad("Pick DHCP or a fixed address."),
            };
            let what = match &c.fixed {
                Some(f) => format!("gateway address fixed at {}{}", f.cidr(), f.gateway.map(|g| format!(" via {g}")).unwrap_or_default()),
                None => "gateway address from the router by DHCP".into(),
            };
            let pol = app.policy.read().unwrap().clone();
            done(app.change(Some(c), pol, &what))
        }
        "card" => {
            let id = s(&b, "id");
            let Some(on) = b["on"].as_bool() else { return bad("Say on or off.") };
            if id.is_empty() || id.len() > 32 || !id.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_') {
                return bad("Unknown card.");
            }
            let r = {
                let mut pol = app.policy.write().unwrap();
                if !pol.dash_cards.contains_key(&id) && pol.dash_cards.len() >= 64 {
                    return bad("Too many cards.");
                }
                pol.dash_cards.insert(id, on);
                pol.save(&app.policy_path())
            };
            match r {
                Ok(_) => ok(json!({"pending": false})),
                Err(e) => bad(e),
            }
        }
        "log_days" => {
            let Some(days) = b["days"].as_i64().or_else(|| s(&b, "days").parse().ok()).filter(|d| (1..=3650).contains(d)) else { return bad("Keep between 1 and 3650 days.") };
            let mut pol = app.policy.read().unwrap().clone();
            pol.log_days = days;
            let r = pol.save(&app.policy_path());
            *app.policy.write().unwrap() = pol;
            app.log.prune(days);
            app.log.note("setting", &format!("{user} set the Capture Log to keep {days} days."));
            match r {
                Ok(_) => ok(json!({"pending": false})),
                Err(e) => bad(e),
            }
        }
        "geo" => {
            let on = b["on"].as_bool().unwrap_or(false);
            let mut pol = app.policy.read().unwrap().clone();
            pol.geo = on;
            let r = pol.save(&app.policy_path());
            *app.policy.write().unwrap() = pol;
            app.log.note("setting", &format!("{user} turned the location database {}.", if on { "on" } else { "off" }));
            if on {
                app.geo_now();
            } else {
                app.refresh_rules();
            }
            match r {
                Ok(_) => ok(json!({"pending": false})),
                Err(e) => bad(e),
            }
        }
        "timezone" => {
            let tz = s(&b, "timezone");
            if !timezones().contains(&tz) {
                return bad("Unknown time zone.");
            }
            let mut pol = app.policy.read().unwrap().clone();
            pol.timezone = tz.clone();
            let r = pol.save(&app.policy_path());
            *app.policy.write().unwrap() = pol;
            app.log.note("setting", &format!("{user} set the time zone to {tz}."));
            match r {
                Ok(_) => ok(json!({"pending": false})),
                Err(e) => bad(e),
            }
        }
        "time_prefs" => {
            let mut pol = app.policy.read().unwrap().clone();
            if let Some(h) = b["hour12"].as_bool() {
                pol.hour12 = h;
            }
            if let Some(f) = b["date_fmt"].as_str() {
                if !matches!(f, "ymd" | "mdy" | "dmy") {
                    return bad("Date format must be ymd, mdy or dmy.");
                }
                pol.date_fmt = f.to_string();
            }
            let r = pol.save(&app.policy_path());
            *app.policy.write().unwrap() = pol;
            app.log.note("setting", &format!("{user} changed time display prefs."));
            match r {
                Ok(_) => ok(json!({"pending": false})),
                Err(e) => bad(e),
            }
        }
        "add_user" => match app.auth.add(&s(&b, "name"), b["password"].as_str().unwrap_or("")) {
            Ok(_) => {
                app.log.note("setting", &format!("{user} added admin {}.", s(&b, "name")));
                ok(json!({"pending": false}))
            }
            Err(e) => bad(e),
        },
        "remove_user" => match app.auth.remove(&s(&b, "name")) {
            Ok(_) => {
                app.log.note("setting", &format!("{user} removed admin {}.", s(&b, "name")));
                ok(json!({"pending": false}))
            }
            Err(e) => bad(e),
        },
        "password" => {
            let name = if s(&b, "name").is_empty() { user.to_string() } else { s(&b, "name") };
            match app.auth.set_password(&name, b["password"].as_str().unwrap_or("")) {
                Ok(_) => {
                    app.log.note("setting", &format!("{user} changed the password for {name}."));
                    ok(json!({"pending": false}))
                }
                Err(e) => bad(e),
            }
        }
        "end_session" => {
            app.auth.end_prefix(&s(&b, "id"));
            ok(json!({"pending": false}))
        }
        "rerun_setup" => {
            if s(&b, "confirm").trim() != "YES" {
                return bad("Type YES to run setup again.");
            }
            let mut w = app.wizard.lock().unwrap();
            *w = crate::wizard::Wizard::default();
            crate::wizard::save(&app.dir, &w);
            drop(w);
            wizard_json(app);
            app.log.note("setting", &format!("{user} started setup again."));
            ok(json!({"redirect": "/setup"}))
        }
        _ => bad("Unknown setting."),
    }
}

// ---- 0.5.8: troubleshooter, audit, allow, profiles ----

fn reason_label(r: &str) -> &'static str {
    crate::rules::REASONS.iter().find(|x| x.0 == r).map(|x| x.1).unwrap_or("blocked")
}

/// Everything known about one block line, for every page that shows one:
/// the plain line, the name looked up, who runs the address, each port's
/// use, and which list stopped it.
pub struct BlockFacts<'a> {
    pub mac: &'a str,
    pub label: &'a str,
    pub reason: &'a str,
    pub remote: &'a str,
    /// "out" when the device started it. Blocked tries carry no byte
    /// counts, so map_dir falls back to who started it.
    pub dir: &'a str,
    pub ports: &'a [(String, u16)],
    /// The name stored with the line, if any.
    pub domain: &'a str,
}

fn block_info(app: &App, ix: &crate::about::Index, f: &BlockFacts) -> Value {
    let which = app.which_list(ix, f.reason, f.mac, f.remote);
    let mut domain = if f.domain.is_empty() { app.domain_of(f.mac, f.remote) } else { f.domain.to_string() };
    if domain.is_empty() {
        domain = which.host.clone();
    }
    let owner = app.owner_of(f.remote);
    let country = f.remote.parse().ok().and_then(|ip| app.geo.read().unwrap().locate(ip)).map(|p| geo::countries().get(p.country.as_str()).copied().unwrap_or(p.country.as_str()).to_string()).unwrap_or_default();
    let dir = map_dir(0, 0, f.dir == "in");
    let desc = crate::about::describe(&crate::about::Line { device: f.label, dir, remote: f.remote, domain: &domain, owner: &owner, country: &country, ports: f.ports });
    json!({
        "desc": desc, "domain": domain, "owner": owner, "list": which,
        "ports": f.ports.iter().map(|(p, n)| {
            let u = crate::ports::lookup(p, *n);
            json!({ "proto": p, "port": n, "what": crate::ports::purpose(p, *n), "source": u.map(|u| u.source), "iana": u.map(|u| u.iana) })
        }).collect::<Vec<_>>(),
    })
}

/// Log rows with the plain line added to blocks and audit lines.
fn log_rows(app: &App, rows: Vec<crate::caplog::Row>) -> Vec<Value> {
    let pol = app.policy.read().unwrap();
    let labels: HashMap<&str, String> = pol.devices.iter().map(|(m, d)| (m.as_str(), App::device_label(d, m))).collect();
    let need = rows.iter().any(|r| !r.remote.is_empty());
    let ix = if need { Some(app.list_index()) } else { None };
    let out = rows
        .into_iter()
        .map(|r| {
            let mut v = json!(r);
            if let (Some(ix), false) = (&ix, r.remote.is_empty()) {
                let label = labels.get(r.device.as_str()).cloned().unwrap_or_else(|| if r.device.is_empty() { "A device".into() } else { r.device.clone() });
                let ports = crate::caplog::port_list(&r.ports);
                let info = block_info(app, ix, &BlockFacts { mac: &r.device, label: &label, reason: &r.reason, remote: &r.remote, dir: &r.dir, ports: &ports, domain: &r.domain });
                v["info"] = info;
            }
            v
        })
        .collect();
    drop(pol);
    out
}

/// What the owner can do about one block: a button (`allow`, with the
/// words for it) or only a pointer to the page that controls it.
fn allow_action(pol: &crate::policy::Policy, reason: &str, proto: &str, port: u16) -> Value {
    let global = |p: &str, n: u16| pol.inbound.iter().any(|i| i.same(p, n, ""));
    match reason {
        "devblock" | "devlan" | "telemetry" | "black" | "threat" | "country" => json!({ "allow": "Allow This Address" }),
        "devdeny" => json!({ "allow": "Take It Off the Deny List" }),
        "wan" | "lanport" if port > 0 && (proto == "tcp" || proto == "udp") => {
            if global(proto, port) {
                json!({ "href": format!("/ports?q={port}"), "why": "This port has a setting for every device. Change it on the Ports page." })
            } else {
                json!({ "allow": if reason == "wan" { "Open This Port for This Device" } else { "Let the LAN Side Use This Port" } })
            }
        }
        "mode" | "lanonly" => json!({ "href": "/firewall", "why": "The whole network is set to block this. Change the mode on the Firewall page." }),
        _ => json!({ "why": "Nothing to allow here." }),
    }
}

/// For blocks about a port (router side, LAN side), what to do about each
/// port on the line; empty for blocks about an address.
fn port_actions(pol: &crate::policy::Policy, reason: &str, ports: &[(String, u16)]) -> Vec<Value> {
    if reason != "wan" && reason != "lanport" {
        return vec![];
    }
    ports.iter().map(|(p, n)| json!({ "proto": p, "port": n, "action": allow_action(pol, reason, p, *n) })).collect()
}

fn troubleshoot(app: &App, user: &str, req: &Req) -> Value {
    let t = now();
    let mac = qs(req, "mac");
    let pol = app.policy.read().unwrap().clone();
    let mut devs: Vec<(String, String)> = pol.devices.iter().map(|(m, d)| (App::device_label(d, m), m.clone())).collect();
    devs.sort_by_cached_key(|(l, m)| (l.to_lowercase(), m.clone()));
    let lines = if mac.is_empty() { vec![] } else { app.recent.lock().unwrap().for_device(&mac, t - 3600) };
    let ix = app.list_index();
    let dev_label = pol.devices.get(&mac).map(|d| App::device_label(d, &mac)).unwrap_or_default();
    let mut groups: Vec<Value> = Vec::new();
    for (reason, label) in crate::rules::REASONS {
        // One row per address, its ports merged; the badge is the sum.
        let entries: Vec<Value> = crate::recent::Recent::by_address(&lines, reason)
            .into_iter()
            .map(|m| {
                let dir = if m.outbound { "out" } else { "in" };
                let info = block_info(app, &ix, &BlockFacts { mac: &mac, label: &dev_label, reason, remote: &m.remote, dir, ports: &m.ports, domain: "" });
                json!({
                    "remote": m.remote, "dir": dir, "count": m.count, "last": m.last, "audit": m.audit, "info": info,
                    "action": allow_action(&pol, reason, m.ports.first().map(|p| p.0.as_str()).unwrap_or(""), m.ports.first().map(|p| p.1).unwrap_or(0)),
                    "actions": port_actions(&pol, reason, &m.ports),
                })
            })
            .collect();
        if !entries.is_empty() {
            let n: u64 = entries.iter().map(|e| e["count"].as_u64().unwrap_or(0)).sum();
            groups.push(json!({ "reason": reason, "label": label, "count": n, "entries": entries }));
        }
    }
    let d = pol.devices.get(&mac);
    let alerts: Vec<Value> = if mac.is_empty() { vec![] } else { app.log.rows("alert", "", t - 7 * 86400, 200).into_iter().filter(|r| !r.handled && r.device == mac && r.reason == "surge").map(|mut r| {
        // Lines from 0.5.8 still say to open the troubleshooter: this is it.
        r.text = r.text.replace(" Open the troubleshooter to see what and allow it if it should work.", "");
        json!(r)
    }).collect() };
    // Same likely-culprit as the device detail, so Allow sits next to it here too.
    let culprit = if !mac.is_empty() && d.is_some_and(|x| x.auditing(t)) {
        let (rows, _) = app.log.audit_list(t - 7 * 86400, 500);
        rows.into_iter().filter(|r| r.device == mac).max_by_key(|r| r.count).map(|r| {
            let what = if r.meta.port > 0 {
                format!("{} {}/{}", r.meta.remote, r.meta.proto, r.meta.port)
            } else if !r.meta.remote.is_empty() {
                r.meta.remote.clone()
            } else {
                "unknown destination".into()
            };
            json!({ "what": what, "count": r.count, "remote": r.meta.remote, "proto": r.meta.proto, "port": r.meta.port, "reason": r.meta.reason, "dir": r.meta.dir })
        })
    } else {
        None
    };
    json!({
        "status": status(app, user),
        "devices": devs.into_iter().map(|(l, m)| json!({ "mac": m, "label": l })).collect::<Vec<_>>(),
        "mac": mac,
        "device": d.map(|d| device_json(app, &mac, d)),
        "groups": groups,
        "alerts": alerts,
        "culprit": culprit,
        "names_seen": app.pdns.lock().unwrap().len().1,
        "mode": pol.mode,
        "now": t,
    })
}

/// Allows what one block (or audit line) was about, the narrowest way
/// that works for its reason.
fn allow_change(app: &Arc<App>, req: &Req, user: &str) -> Resp {
    let b = body(req);
    let Some(mac) = normal_mac(&s(&b, "mac")) else { return bad("Unknown device.") };
    let reason = s(&b, "reason");
    let remote = s(&b, "remote");
    let proto = s(&b, "proto").to_ascii_lowercase();
    let port = b["port"].as_u64().unwrap_or(0).min(65535) as u16;
    let mut pol = app.policy.read().unwrap().clone();
    let Some(d) = pol.devices.get(&mac) else { return bad("Unknown device.") };
    let label = App::device_label(d, &mac);
    let ip_reasons = ["devblock", "devlan", "telemetry", "black", "threat", "country"];
    let action = allow_action(&pol, &reason, &proto, port);
    if action["allow"].is_null() {
        return bad(action["why"].as_str().unwrap_or("Nothing to allow here."));
    }
    let permanent = b["permanent"].as_bool().unwrap_or(!pol.white_expiry);
    let what = if ip_reasons.contains(&reason.as_str()) {
        let Some(net) = remote.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string()) else { return bad("That isn't an address.") };
        let until = if permanent || !pol.white_expiry { 0 } else { now() + crate::policy::WHITE_AUTO_SECS };
        let d = pol.devices.get_mut(&mac).unwrap();
        if !d.allow.contains(&net) {
            d.allow.push(net.clone());
        }
        if until > 0 {
            d.allow_until.insert(net.clone(), until);
        } else {
            d.allow_until.remove(&net);
        }
        if until > 0 {
            format!("{net} allowed for {label} for 30 days by {user}")
        } else {
            format!("{net} added to the allow list of {label} by {user}")
        }
    } else if reason == "devdeny" {
        let ip: Option<std::net::IpAddr> = remote.parse().ok();
        let seen = app.seen.lock().unwrap();
        let d = pol.devices.get_mut(&mac).unwrap();
        let before = d.deny.len();
        d.deny.retain(|e| match crate::policy::parse_entry(e) {
            Ok(crate::policy::Entry::Port(p, n)) => !(p == proto && n == port),
            Ok(crate::policy::Entry::Net(n)) => !ip.is_some_and(|ip| crate::policy::parse_net(&n).is_some_and(|_| net_has(&n, ip))),
            Ok(crate::policy::Entry::Site(s)) => !seen.of(&s).contains(&remote),
            Err(_) => true,
        });
        if d.deny.len() == before {
            return bad("Nothing on the deny list matches this any more.");
        }
        format!("deny list entry for {remote} taken off {label} by {user}")
    } else {
        // wan or lanport, no setting for every device (checked above).
        let e = match pol.inbound.iter_mut().find(|i| i.same(&proto, port, &mac)) {
            Some(e) => e,
            None => {
                pol.inbound.push(crate::policy::InPort { proto: proto.clone(), port, mac: mac.clone(), ..Default::default() });
                pol.inbound.last_mut().unwrap()
            }
        };
        if reason == "wan" {
            e.on = true;
        } else {
            e.lan_off = false;
        }
        (e.own, e.follow, e.custom, e.new) = (true, false, true, false);
        format!("{} {} for {label} by {user}", port_label(&proto, port), if reason == "wan" { "opened from the router side" } else { "allowed from the LAN side" })
    };
    let r = app.change(None, pol, &what);
    if r.is_ok() {
        let reasons: Vec<&str> = if ip_reasons.contains(&reason.as_str()) { ip_reasons.to_vec() } else { vec![reason.as_str()] };
        let (p, n) = if ip_reasons.contains(&reason.as_str()) { ("", 0) } else { (proto.as_str(), port) };
        app.log.handle_audit(&mac, &remote, p, n, &reasons);
        app.log.handle_surge(&mac);
    }
    done(r)
}

pub fn net_has(net: &str, ip: std::net::IpAddr) -> bool {
    let (a, len) = net.split_once('/').unwrap_or((net, ""));
    match (a.parse::<std::net::IpAddr>(), ip) {
        (Ok(std::net::IpAddr::V4(n)), std::net::IpAddr::V4(i)) => {
            let len: u32 = len.parse().unwrap_or(32).min(32);
            let m = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(n) & m == u32::from(i) & m
        }
        (Ok(std::net::IpAddr::V6(n)), std::net::IpAddr::V6(i)) => {
            let len: u32 = len.parse().unwrap_or(128).min(128);
            let m = if len == 0 { 0 } else { u128::MAX << (128 - len) };
            u128::from(n) & m == u128::from(i) & m
        }
        _ => false,
    }
}

fn audit_page(app: &App, user: &str) -> Value {
    let (rows, total) = app.log.audit_list(now() - 7 * 86400, 500);
    let pol = app.policy.read().unwrap().clone();
    let ix = app.list_index();
    let list: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let label = pol.devices.get(&r.device).map(|d| App::device_label(d, &r.device)).unwrap_or_else(|| if r.device.is_empty() { "Unknown device".into() } else { r.device.clone() });
            let known = !r.device.is_empty() && pol.devices.contains_key(&r.device);
            let action = if !known { json!({ "why": "Not a known device." }) } else { allow_action(&pol, &r.meta.reason, &r.meta.proto, r.meta.port) };
            let ports = crate::caplog::port_list(&r.ports);
            let info = block_info(app, &ix, &BlockFacts { mac: &r.device, label: &label, reason: &r.meta.reason, remote: &r.meta.remote, dir: &r.meta.dir, ports: &ports, domain: &r.meta.domain });
            json!({
                "key": format!("{}|{}|{}", r.device, r.meta.reason, r.meta.remote),
                "mac": r.device, "device": label, "reason": r.meta.reason, "why": reason_label(&r.meta.reason),
                "remote": r.meta.remote, "proto": r.meta.proto, "port": r.meta.port, "dir": r.meta.dir,
                "count": r.count, "first": r.first, "last": r.last, "action": action, "info": info,
                "actions": if known { port_actions(&pol, &r.meta.reason, &ports) } else { vec![] },
            })
        })
        .collect();
    let t = now();
    // Item 20: for each device in Audit, point at the busiest remote/port.
    let mut by_mac: std::collections::HashMap<String, (u64, String, String, u16, String, String)> = std::collections::HashMap::new();
    for r in &list {
        let mac = r["mac"].as_str().unwrap_or("").to_string();
        if mac.is_empty() { continue; }
        let count = r["count"].as_u64().unwrap_or(0);
        let remote = r["remote"].as_str().unwrap_or("").to_string();
        let proto = r["proto"].as_str().unwrap_or("").to_string();
        let port = r["port"].as_u64().unwrap_or(0) as u16;
        let reason = r["reason"].as_str().unwrap_or("").to_string();
        let dir = r["dir"].as_str().unwrap_or("").to_string();
        let e = by_mac.entry(mac).or_insert((0, String::new(), String::new(), 0, String::new(), String::new()));
        if count > e.0 {
            *e = (count, remote, proto, port, reason, dir);
        }
    }
    let auditing: Vec<Value> = pol.devices.iter().filter(|(_, d)| d.auditing(t)).map(|(m, d)| {
        let culprit = by_mac.get(m).map(|(n, remote, proto, port, reason, dir)| {
            let what = if *port > 0 {
                format!("{remote} {proto}/{port}")
            } else if !remote.is_empty() {
                remote.clone()
            } else {
                "unknown destination".into()
            };
            json!({ "what": what, "count": n, "remote": remote, "proto": proto, "port": port, "reason": reason, "dir": dir })
        });
        json!({ "mac": m, "label": App::device_label(d, m), "until": d.audit_until, "culprit": culprit })
    }).collect();
    json!({ "status": status(app, user), "rows": list, "total": total, "mode": pol.mode, "auditing": auditing, "offset": app.tz_offset() })
}

/// Audit on or off for one device, and "keep blocking" for audit lines.
fn audit_change(app: &Arc<App>, req: &Req, user: &str) -> Resp {
    let b = body(req);
    if s(&b, "action") == "keep" {
        let Some(mac) = normal_mac(&s(&b, "mac")) else { return bad("Unknown device.") };
        let reason = s(&b, "reason");
        let port = b["port"].as_u64().unwrap_or(0).min(65535) as u16;
        let n = app.log.handle_audit(&mac, &s(&b, "remote"), &s(&b, "proto"), port, &[reason.as_str()]);
        return ok(json!({ "ok": true, "handled": n }));
    }
    let Some(mac) = normal_mac(&s(&b, "mac")) else { return bad("Unknown device.") };
    let mut pol = app.policy.read().unwrap().clone();
    let Some(d) = pol.devices.get_mut(&mac) else { return bad("Unknown device.") };
    let label = App::device_label(d, &mac);
    let what = match b["minutes"].as_i64() {
        Some(0) => {
            d.audit_until = 0;
            format!("audit off for {label} by {user}")
        }
        Some(-1) => {
            d.audit_until = i64::MAX;
            format!("audit on for {label} until turned off, by {user}")
        }
        Some(m) if (1..=7 * 24 * 60).contains(&m) => {
            d.audit_until = now() + m * 60;
            format!("audit on for {label} for {} by {user}", if m % 60 == 0 { plural_h(m / 60) } else { format!("{m} minutes") })
        }
        _ => return bad("Pick how long."),
    };
    done(app.change(None, pol, &what))
}

fn plural_h(h: i64) -> String {
    if h == 1 { "1 hour".into() } else { format!("{h} hours") }
}

/// Profiles that fit a device, and whether each is already in place.
fn profiles_json(pol: &crate::policy::Policy, mac: &str, d: &crate::policy::Device) -> Vec<Value> {
    crate::profiles::for_device(&d.vendor, &d.hostname)
        .into_iter()
        .map(|p| {
            let open = |proto: &str, port: u16, who: &str| pol.inbound.iter().any(|i| i.same(proto, port, who) && i.on);
            let global_set = |proto: &str, port: u16| pol.inbound.iter().find(|i| i.same(proto, port, ""));
            let done = p.ports.iter().all(|(pr, n)| match global_set(pr, *n) {
                Some(g) => g.on,
                None => open(pr, *n, mac),
            }) && p.discovery.iter().all(|(pr, n)| open(pr, *n, ""));
            let risky: Vec<String> = p.ports.iter().chain(p.discovery).filter(|(pr, n)| port_risk(pr, *n).is_some()).map(|(pr, n)| port_label(pr, *n)).collect();
            json!({
                "id": p.id, "name": p.name, "what": p.what, "source": p.source, "note": p.note,
                "ports": p.ports.iter().map(|(pr, n)| port_label(pr, *n)).collect::<Vec<_>>(),
                "discovery": p.discovery.iter().map(|(pr, n)| port_label(pr, *n)).collect::<Vec<_>>(),
                "risky": risky, "applied": done,
            })
        })
        .collect()
}

fn profile_change(app: &Arc<App>, req: &Req, user: &str) -> Resp {
    let b = body(req);
    let Some(mac) = normal_mac(&s(&b, "mac")) else { return bad("Unknown device.") };
    let Some(p) = crate::profiles::get(&s(&b, "id")) else { return bad("Unknown profile.") };
    let mut pol = app.policy.read().unwrap().clone();
    let Some(d) = pol.devices.get(&mac) else { return bad("Unknown device.") };
    let label = App::device_label(d, &mac);
    let mut skipped = Vec::new();
    for (proto, port) in p.ports {
        if pol.inbound.iter().any(|i| i.same(proto, *port, "")) {
            // The setting for every device wins; leave the owner's choice there.
            skipped.push(port_label(proto, *port));
            continue;
        }
        match pol.inbound.iter_mut().find(|i| i.same(proto, *port, &mac)) {
            Some(e) => {
                (e.on, e.own, e.follow, e.custom, e.new) = (true, true, false, true, false);
            }
            None => pol.inbound.push(crate::policy::InPort { proto: proto.to_string(), port: *port, mac: mac.clone(), on: true, own: true, custom: true, ..Default::default() }),
        }
    }
    for (proto, port) in p.discovery {
        match pol.inbound.iter_mut().find(|i| i.same(proto, *port, "")) {
            Some(e) => {
                (e.on, e.new) = (true, false);
            }
            None => pol.inbound.push(crate::policy::InPort { proto: proto.to_string(), port: *port, on: true, custom: true, ..Default::default() }),
        }
        // Devices that follow everybody's setting see the new one.
        for i in pol.inbound.iter_mut().filter(|i| !i.mac.is_empty() && i.proto == *proto && i.port == *port && !i.is_own()) {
            (i.on, i.follow) = (true, true);
        }
    }
    let mut what = format!("{} settings applied to {label} by {user}", p.name);
    if !skipped.is_empty() {
        what += &format!(" ({} left as set for every device)", skipped.join(", "));
    }
    done(app.change(None, pol, &what))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spa_routes_cover_every_submenu_path() {
        // Must match SUBS + top nav in assets/app.js. A missing entry is the
        // Direct load of /settings/updates must serve the SPA shell.
        const PATHS: &[&str] = &[
            "/",
            "/devices", "/devices/troubleshoot",
            "/firewall", "/firewall/mode", "/firewall/presets", "/firewall/hardening",
            "/firewall/coach", "/firewall/geo", "/firewall/white", "/firewall/black",
            "/firewall/audit", "/firewall/rules",
            "/ports", "/ports/devices",
            "/log",
            "/settings", "/settings/certs", "/settings/general", "/settings/log",
            "/settings/account", "/settings/view", "/settings/setup",
            "/settings/updates", "/settings/help", "/settings/about",
        ];
        for p in PATHS {
            let r = spa_page(p).unwrap_or_else(|| panic!("SPA path {p} has no server shell"));
            assert_eq!(r.status, 200, "{p}");
            assert!(r.kind.starts_with("text/html"), "{p} kind {}", r.kind);
        }
        assert!(spa_page("/settings/nope").is_none());
        assert!(spa_page("/api/updates").is_none());
    }


    #[test]
    fn map_direction_follows_the_data() {
        // The desktop app's own cases.
        assert_eq!(map_dir(1_200_000, 40_000, false), "in");
        assert_eq!(map_dir(10, 900, false), "out");
        assert_eq!(map_dir(0, 0, false), "out");
        assert_eq!(map_dir(0, 0, true), "in");
        // Real conntrack lines with accounting on, seen from the LAN device.
        let by_ip: HashMap<String, (String, String)> = [("192.168.1.42".to_string(), ("laptop".to_string(), "aa:bb:cc:00:00:01".to_string()))].into();
        let download = net::parse_conntrack("ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.42 dst=142.250.72.14 sport=51544 dport=443 packets=410 bytes=24816 src=142.250.72.14 dst=192.168.1.42 sport=443 dport=51544 packets=2210 bytes=3145728 [ASSURED] mark=0 use=1").unwrap();
        assert_eq!(side(&by_ip, &download), ("laptop", "aa:bb:cc:00:00:01", "142.250.72.14", "in"));
        let upload = net::parse_conntrack("ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.42 dst=52.96.165.2 sport=50110 dport=443 packets=3100 bytes=4194304 src=52.96.165.2 dst=192.168.1.42 sport=443 dport=50110 packets=900 bytes=51200 [ASSURED] mark=0 use=1").unwrap();
        assert_eq!(side(&by_ip, &upload), ("laptop", "aa:bb:cc:00:00:01", "52.96.165.2", "out"));
        let served = net::parse_conntrack("ipv4     2 tcp      6 300 ESTABLISHED src=203.0.113.9 dst=192.168.1.42 sport=40022 dport=22 packets=60 bytes=4800 src=192.168.1.42 dst=203.0.113.9 sport=22 dport=40022 packets=80 bytes=96000 [ASSURED] mark=0 use=1").unwrap();
        assert_eq!(side(&by_ip, &served), ("laptop", "aa:bb:cc:00:00:01", "203.0.113.9", "out"));
    }

    // Load test: cargo test --release -- --ignored scale --nocapture
    #[test]
    fn alerts_only_what_needs_the_owner() {
        let row = |device: &str, handled: bool, last: i64| crate::caplog::Row { id: last, first: last, last, reason: String::new(), kind: "device".into(), device: device.into(), text: format!("{device} {handled}"), count: 1, handled, remote: String::new(), dir: String::new(), ports: String::new(), domain: String::new() };
        let settled: std::collections::HashSet<String> = ["trusted-or-blocked".to_string()].into();
        let a = true_alerts(vec![row("open", false, 1), row("open", true, 2), row("trusted-or-blocked", false, 3), row("", false, 4)], &settled);
        let texts: Vec<&str> = a.iter().map(|v| v["text"].as_str().unwrap()).collect();
        assert_eq!(texts, [" false", "open false"]);
    }

    // Worst case for Geo-Blocking: every country but one, on the real
    // database from the real_download test. Writes the ruleset to
    // $GEO_OUT for timing nft. cargo test --release -- --ignored geo_worst_case
    #[test]
    #[ignore]
    fn geo_worst_case() {
        use std::time::Instant;
        let rss = || std::fs::read_to_string("/proc/self/status").unwrap_or_default().lines().find(|l| l.starts_with("VmRSS")).unwrap_or("").split_whitespace().nth(1).unwrap_or("0").parse::<u64>().unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("fg-geoworst-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("geo")).unwrap();
        for f in ["geo4.bin", "geo6.bin", "geo.json"] {
            std::fs::copy(std::env::temp_dir().join("fg-geo-real/geo").join(f), dir.join("geo").join(f)).unwrap();
        }
        std::fs::write(dir.join("gateway.conf"), "mode=bridge\nlan=eth1\nwan=eth0\nsafety_hosts=10.10.10.42\nadmin_port=8443\n").unwrap();
        std::env::set_var("FOILGW_STATE", &dir);
        let conf = dir.join("gateway.conf").display().to_string();
        let r0 = rss();
        let t = Instant::now();
        let app = Arc::new(App::open(&conf));
        eprintln!("open with location db: {:?}, rss {} -> {} kB", t.elapsed(), r0, rss());
        {
            let mut p = app.policy.write().unwrap();
            p.geo = true;
            p.countries = geo::countries().keys().filter(|c| **c != "US").map(|c| c.to_string()).collect();
        }
        let cfg = Config::load(&conf).unwrap();
        let (a, c2) = (app.clone(), cfg.clone());
        let t = Instant::now();
        let build = std::thread::spawn(move || a.ruleset(&c2));
        // Page calls while the build runs: none may wait for it.
        let (mut worst, mut n) = (std::time::Duration::ZERO, 0);
        while !build.is_finished() {
            let t = Instant::now();
            let _ = firewall(&app, "t", false);
            let _ = dashboard(&app, "t");
            worst = worst.max(t.elapsed());
            n += 1;
        }
        let text = build.join().unwrap();
        eprintln!("ruleset build (cold): {:?}; {n} firewall+dashboard calls meanwhile, slowest {:?}", t.elapsed(), worst);
        let t = Instant::now();
        let again = app.ruleset(&cfg);
        eprintln!("ruleset build (cached): {:?}, {} bytes, rss {} kB", t.elapsed(), again.len(), rss());
        let t = Instant::now();
        let fw = firewall(&app, "t", false).to_string().len();
        let fw_t = t.elapsed();
        let t = Instant::now();
        let view = app.ruleset_view(&cfg).len();
        eprintln!("firewall page after: {fw_t:?} ({fw} bytes); rules view {:?} ({view} bytes)", t.elapsed());
        let p = app.policy.read().unwrap().clone();
        let e = app.geo_elems(&p, false).unwrap();
        eprintln!("{} countries -> {} v4 + {} v6 ranges", p.countries.len(), e.n4, e.n6);
        if let Ok(out) = std::env::var("GEO_OUT") {
            std::fs::write(out, &text).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore]
    fn scale() {
        use std::time::Instant;
        let dir = std::env::temp_dir().join(format!("fg-scale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mac = |n: usize| format!("02:00:00:00:{:02x}:{:02x}", n / 256, n % 256);
        let ip = |n: usize| format!("10.10.{}.{}", 10 + n / 250, 1 + n % 250);
        let mut pol = Policy::default();
        for n in 0..500 {
            let d = crate::policy::Device { name: if n % 3 == 0 { format!("Laptop {n}") } else { String::new() }, ip: ip(n), vendor: "Raspberry Pi".into(), first_seen: 1, last_seen: now() - (n as i64 % 600), new: n % 50 == 0, ..Default::default() };
            pol.devices.insert(mac(n), d);
            if n % 5 == 0 {
                pol.inbound.push(crate::policy::InPort { proto: "tcp".into(), port: 8000 + (n % 40) as u16, mac: mac(n), on: true, own: true, ..Default::default() });
            }
        }
        for p in 0..60u16 {
            pol.inbound.push(crate::policy::InPort { proto: "tcp".into(), port: 8000 + p, on: p % 2 == 0, lan_off: p % 3 == 0, hits: 3, ..Default::default() });
        }
        std::fs::write(dir.join("policy.json"), serde_json::to_string(&pol).unwrap()).unwrap();
        let mut ct = String::new();
        for n in 0..5000 {
            let d = n % 500;
            ct += &format!("ipv4     2 tcp      6 431999 ESTABLISHED src={} dst=93.184.{}.{} sport={} dport=443 packets=10 bytes={} src=93.184.{}.{} dst={} sport=443 dport={} packets=12 bytes={} [ASSURED] mark=0 use=1\n", ip(d), n % 200, n % 250, 30000 + n, 1000 + n, n % 200, n % 250, ip(d), 30000 + n, 5000 + n);
        }
        std::fs::write(dir.join("conntrack"), ct).unwrap();
        std::fs::write(dir.join("gateway.conf"), "mode=bridge\nlan=eth1\nwan=eth0\nsafety_hosts=10.10.10.42\nadmin_port=8443\n").unwrap();
        std::env::set_var("FOILGW_STATE", &dir);
        std::env::set_var("FOILGW_CONNTRACK", dir.join("conntrack"));
        let conf = dir.join("gateway.conf").display().to_string();
        let app = Arc::new(App::open(&conf));
        let t = Instant::now();
        for n in 0..20000 {
            app.log.note("block", &format!("{} tried tcp {} from 1.2.{}.{}", ip(n % 500), 8000 + n % 90, n % 200, n % 250));
        }
        eprintln!("20000 log lines written in {:?}", t.elapsed());
        let req = |q: &[(&str, &str)]| Req { method: "GET".into(), path: "/".into(), query: q.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(), headers: HashMap::new(), body: vec![], ip: "10.10.10.42".into(), local: String::new(), local_port: 8443 };
        let time = |what: &str, f: &dyn Fn() -> usize| {
            f();
            let t = Instant::now();
            let mut size = 0;
            for _ in 0..10 {
                size = f();
            }
            eprintln!("{what:<34} {:>8.2} ms  (size {size})", t.elapsed().as_secs_f64() * 100.0);
            let rss = || std::fs::read_to_string("/proc/self/status").unwrap_or_default().lines().find(|l| l.starts_with("VmRSS")).unwrap_or("").split_whitespace().nth(1).unwrap_or("0").parse::<u64>().unwrap_or(0);
            let before = rss();
            for _ in 0..std::env::var("SOAK_RUNS").ok().and_then(|v| v.parse().ok()).unwrap_or(0) {
                f();
            }
            eprintln!("{:<34} rss {} -> {} kB", "", before, rss());
        };
        let len = |v: Value| v.to_string().len();
        time("poll_traffic (5000 conntrack)", &|| { app.poll_traffic(); 0 });
        time("net::connections parse", &|| net::connections().len());
        time("/api/dashboard", &|| len(dashboard(&app, "t")));
        time("/api/devices first 100", &|| len(devices(&app, "t", &req(&[]))));
        time("/api/devices q=laptop sort=traffic", &|| len(devices(&app, "t", &req(&[("q", "laptop"), ("sort", "traffic")]))));
        time("/api/ports global", &|| len(ports(&app, "t", &req(&[("tab", "global")]))));
        time("/api/ports per device", &|| len(ports(&app, "t", &req(&[("tab", "devices")]))));
        time("/api/log first 200", &|| app.log.page("", "", 0, i64::MAX, "new", 0, 200).1 as usize);
        time("/api/log search", &|| app.log.page("block", "10.10.10.7 ", 0, i64::MAX, "count", 0, 200).1 as usize);
        let cfg = Config::load(&conf).unwrap();
        time("nft ruleset build", &|| app.ruleset(&cfg).len());
        let _ = std::fs::remove_dir_all(&dir);
    }



    #[test]
    fn risky_ports_say_why() {
        assert!(port_risk("tcp", 3389).unwrap().starts_with("Not recommended"));
        assert!(port_risk("tcp", 445).is_some());
        assert!(port_risk("udp", 1900).is_some());
        assert!(port_risk("tcp", 443).is_none());
        assert_eq!(port_name("tcp", 3389), "Remote Desktop");
    }

    #[test]
    fn stamps_and_query() {
        assert_eq!(stamp(0), "1970-01-01 00:00:00");
        assert_eq!(stamp(1_793_586_896), "2026-11-02 02:34:56");
        assert_eq!(unescape("a%20b+c%2F"), "a b c/");
        assert_eq!(unescape("100%"), "100%");
    }

    #[test]
    fn dates_masks_and_fixed_addresses() {
        assert_eq!(day_start("2026-11-02", 0), Some(1_793_577_600));
        assert_eq!(day_start("2026-11-02", -8 * 3600), Some(1_793_577_600 + 8 * 3600));
        assert_eq!(day_start("nope", 0), None);
        assert_eq!((prefix_of("255.255.255.0"), prefix_of("24"), prefix_of("255.0.255.0")), (Some(24), Some(24), None));
        let f = fixed_from(&json!({"ip": "10.10.10.5", "mask": "255.255.255.0", "gateway": "10.10.10.1", "dns": "10.10.10.1, 9.9.9.9"})).unwrap();
        assert_eq!((f.cidr(), f.dns.len()), ("10.10.10.5/24".into(), 2));
        assert!(fixed_from(&json!({"ip": "10.10.10.5", "mask": "255.255.255.0", "gateway": "10.10.11.1"})).is_err());
        let old = build_cfg(&json!({"lan": "eth3", "wan": "eth0", "safety": false}), None).unwrap();
        let mut with = old.clone();
        with.fixed = Some(f);
        assert!(build_cfg(&json!({"admin_port": 9000}), Some(&with)).unwrap().fixed.is_some());
    }

    #[test]
    fn config_from_form() {
        let b = json!({"lan": "eth3", "wan": "eth0", "safety_hosts": "10.10.10.42", "admin_port": 9443});
        let c = build_cfg(&b, None).unwrap();
        assert_eq!(c.safety_ports, vec![22, 9443]);
        assert!(build_cfg(&json!({"lan": "eth3", "wan": "eth3", "safety_hosts": "10.0.0.1"}), None).is_err());
        assert!(build_cfg(&json!({"lan": "eth3", "wan": "eth0", "safety_hosts": "nope"}), None).is_err());
        let c2 = build_cfg(&json!({"admin_port": 8444}), Some(&c)).unwrap();
        assert_eq!((c2.lan.clone(), c2.admin_port), (vec!["eth3".to_string()], 8444));
        let c3 = build_cfg(&json!({"lan": ["eth0", "eth1"], "wan": "eth3", "safety": false}), None).unwrap();
        assert_eq!(c3.lan, vec!["eth0", "eth1"]);
        assert!(build_cfg(&json!({"lan": ["eth0", "eth3"], "wan": "eth3", "safety": false}), None).is_err());
    }
}
