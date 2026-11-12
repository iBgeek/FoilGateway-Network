//! Sends gateway events to webhook addresses as short signed JSON messages.
//! One worker thread, a bounded queue, and retries for 10 minutes.

use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Event ids, their titles, and what the Notifications page says about them.
pub const EVENTS: &[(&str, &str)] = &[
    ("new_device", "New device"),
    ("look", "Needs a look"),
    ("blocked", "Blocked connection"),
    ("audit", "Audit"),
    ("settings", "Settings changed"),
    ("update", "Update available"),
    ("started", "Gateway started"),
];

const QUEUE_MAX: usize = 200;
const RECENT_MAX: usize = 50;
const RETRY_FOR: u64 = 600;
const SAME_WINDOW: i64 = 60;
/// Needs-a-look, new-device and blocked messages: the first one for a device
/// goes out at once, the rest in the next 5 minutes go as one message with a count.
const GROUP_WINDOW: i64 = 300;
const GROUPED: [&str; 3] = ["look", "new_device", "blocked"];
const MAX_DESTS: usize = 10;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Dest {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub secret_made: i64,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub last_sent: i64,
    #[serde(default)]
    pub last_result: String,
}

#[derive(Serialize, Deserialize, Default)]
struct Saved {
    #[serde(default)]
    dests: Vec<Dest>,
    /// The last version an "update available" message went out for.
    #[serde(default)]
    update_sent: String,
}

#[derive(Serialize, Clone)]
struct Sent {
    seq: u64,
    at: i64,
    to: String,
    what: String,
    /// delivered, retrying, failed or dropped
    result: String,
    tries: u32,
    done_at: i64,
    error: String,
}

struct Job {
    seq: u64,
    dest: String,
    body: String,
    event: String,
    started: Instant,
    due: Instant,
    tries: u32,
}

struct Hub {
    path: String,
    saved: Mutex<Saved>,
    queue: Mutex<VecDeque<Job>>,
    wake: Condvar,
    recent: Mutex<VecDeque<Sent>>,
    seen: Mutex<HashMap<String, i64>>,
    groups: Mutex<HashMap<String, Group>>,
    seq: Mutex<u64>,
}

/// One device's grouped messages in the current window.
#[derive(Default)]
struct Group {
    start: i64,
    more: u32,
    last: String,
}

static HUB: OnceLock<Hub> = OnceLock::new();

fn hub() -> Option<&'static Hub> {
    HUB.get()
}

/// Loads notify.json and starts the sender. Safe to call once at startup.
pub fn start(dir: &str) {
    let path = format!("{dir}/notify.json");
    let saved = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let h = Hub {
        path,
        saved: Mutex::new(saved),
        queue: Mutex::new(VecDeque::new()),
        wake: Condvar::new(),
        recent: Mutex::new(VecDeque::new()),
        seen: Mutex::new(HashMap::new()),
        groups: Mutex::new(HashMap::new()),
        seq: Mutex::new(0),
    };
    if HUB.set(h).is_ok() {
        std::thread::Builder::new().name("notify".into()).spawn(worker).ok();
        // Sends each group's count once its window is over.
        std::thread::Builder::new().name("notify-groups".into()).spawn(|| loop {
            std::thread::sleep(Duration::from_secs(15));
            let Some(h) = hub() else { return };
            let due = group_flush(&mut lock(&h.groups), now());
            for (ev, device, text) in due {
                send_event(h, &ev, &device, &text, now());
            }
        }).ok();
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now() -> i64 {
    crate::caplog::now()
}

/// Which event a Capture Log line is, if any.
pub fn classify(kind: &str, text: &str) -> Option<&'static str> {
    match kind {
        "device" if text.starts_with("New device") => Some("new_device"),
        "device" | "alert" => Some("look"),
        "block" => Some("blocked"),
        "audit" => Some("audit"),
        "setting" if text.starts_with("FoilGateway ") && text.contains(" started,") => Some("started"),
        // Sign-ins stay in the Capture Log but aren't sent.
        "setting" if text.contains(" signed in from ") => None,
        "setting" => Some("settings"),
        _ => None,
    }
}

/// Called for every new Capture Log line. Never blocks on the network.
pub fn event(kind: &str, device: &str, text: &str) {
    let Some(h) = hub() else { return };
    let Some(ev) = classify(kind, text) else { return };
    let at = now();
    if GROUPED.contains(&ev) {
        let out = group_step(&mut lock(&h.groups), ev, device, text, at);
        for (ev, device, text) in out {
            send_event(h, &ev, &device, &text, at);
        }
        return;
    }
    {
        let mut seen = lock(&h.seen);
        let key = format!("{ev}|{device}|{text}");
        if seen.get(&key).is_some_and(|t| at - t < SAME_WINDOW) {
            return;
        }
        if seen.len() > 2000 {
            seen.retain(|_, t| at - *t < SAME_WINDOW);
        }
        seen.insert(key, at);
    }
    send_event(h, ev, device, text, at);
}

/// Called after an update check finds a newer version. One message per version.
pub fn update_available(version: &str) {
    let Some(h) = hub() else { return };
    {
        let mut s = lock(&h.saved);
        if s.update_sent == version {
            return;
        }
        s.update_sent = version.to_string();
        let _ = save(&h.path, &s);
    }
    send_event(h, "update", "", &format!("FoilGateway {version} is available."), now());
}

fn title(ev: &str) -> &'static str {
    EVENTS.iter().find(|(id, _)| *id == ev).map(|(_, t)| *t).unwrap_or("Test message")
}

type Msg = (String, String, String);

fn group_key(ev: &str, device: &str) -> String {
    format!("{ev}|{device}")
}

fn group_summary(ev: &str, device: &str, g: &Group) -> Msg {
    let n = g.more;
    let text = format!("{n} more like this in 5 minutes. Latest: {}", g.last);
    (ev.to_string(), device.to_string(), text)
}

/// What to send now for one grouped event: the event itself when it opens a
/// window (after the last window's count, if any), else nothing.
fn group_step(groups: &mut HashMap<String, Group>, ev: &str, device: &str, text: &str, at: i64) -> Vec<Msg> {
    let mut out = Vec::new();
    let g = groups.entry(group_key(ev, device)).or_default();
    if g.start > 0 && at - g.start < GROUP_WINDOW {
        g.more += 1;
        g.last = text.to_string();
        return out;
    }
    if g.more > 0 {
        out.push(group_summary(ev, device, g));
    }
    *g = Group { start: at, more: 0, last: String::new() };
    out.push((ev.to_string(), device.to_string(), text.to_string()));
    out
}

/// Counts for windows that are over; quiet groups are forgotten.
fn group_flush(groups: &mut HashMap<String, Group>, at: i64) -> Vec<Msg> {
    let mut out = Vec::new();
    groups.retain(|k, g| {
        if at - g.start < GROUP_WINDOW {
            return true;
        }
        if g.more > 0 {
            let (ev, device) = k.split_once('|').unwrap_or((k.as_str(), ""));
            out.push(group_summary(ev, device, g));
        }
        false
    });
    out
}

fn send_event(h: &Hub, ev: &str, device: &str, text: &str, at: i64) {
    let targets: Vec<(String, String)> = lock(&h.saved).dests.iter().filter(|d| d.events.iter().any(|e| e == ev)).map(|d| (d.id.clone(), d.name.clone())).collect();
    for (id, name) in targets {
        queue(h, &id, &name, ev, device, text, at);
    }
}

fn queue(h: &Hub, dest: &str, name: &str, ev: &str, device: &str, text: &str, at: i64) -> u64 {
    let body = json!({
        "gateway": "FoilGateway Network",
        "version": env!("CARGO_PKG_VERSION"),
        "event": ev,
        "title": title(ev),
        "text": text,
        "device": device,
        "at": at,
    })
    .to_string();
    let seq = {
        let mut s = lock(&h.seq);
        *s += 1;
        *s
    };
    let what = if text.is_empty() { title(ev).to_string() } else { format!("{}: {}", title(ev), text) };
    record(h, Sent { seq, at, to: name.into(), what, result: "retrying".into(), tries: 0, done_at: 0, error: String::new() });
    let mut q = lock(&h.queue);
    if q.len() >= QUEUE_MAX {
        if let Some(old) = q.pop_front() {
            finish(h, old.seq, "dropped", old.tries, "Too many messages waiting.");
        }
    }
    let t = Instant::now();
    q.push_back(Job { seq, dest: dest.into(), body, event: ev.into(), started: t, due: t, tries: 0 });
    drop(q);
    h.wake.notify_one();
    seq
}

fn record(h: &Hub, s: Sent) {
    let mut r = lock(&h.recent);
    r.push_front(s);
    r.truncate(RECENT_MAX);
}

fn finish(h: &Hub, seq: u64, result: &str, tries: u32, error: &str) {
    let mut r = lock(&h.recent);
    if let Some(s) = r.iter_mut().find(|s| s.seq == seq) {
        s.result = result.into();
        s.tries = tries;
        s.error = error.chars().take(200).collect();
        if result != "retrying" {
            s.done_at = now();
        }
    }
}

/// The value of the signature header: HMAC-SHA256 of "timestamp.body".
pub fn sign(secret: &str, ts: i64, body: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, format!("{ts}.{body}").as_bytes());
    format!("sha256={}", tag.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirects(0)
        .user_agent(concat!("FoilGateway/", env!("CARGO_PKG_VERSION")))
        .build()
}

fn post(agent: &ureq::Agent, d: &Dest, ev: &str, body: &str) -> Result<(), String> {
    let ts = now();
    let r = agent
        .post(&d.url)
        .set("Content-Type", "application/json")
        .set("X-FoilGateway-Event", ev)
        .set("X-FoilGateway-Timestamp", &ts.to_string())
        .set("X-FoilGateway-Signature", &sign(&d.secret, ts, body))
        .send_string(body);
    match r {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(code, _)) => Err(format!("The address answered {code}.")),
        Err(e) => Err(match e.kind() {
            ureq::ErrorKind::Dns => "The address name couldn't be found.".into(),
            ureq::ErrorKind::ConnectionFailed => "Couldn't connect to the address.".into(),
            ureq::ErrorKind::Io => "The connection failed or timed out.".into(),
            _ => "The message couldn't be sent.".into(),
        }),
    }
}

fn worker() {
    let Some(h) = hub() else { return };
    let agent = agent();
    // Addresses that just failed, and when to try them next. Their other
    // messages wait until then, so one unreachable address costs one
    // connect timeout per retry instead of one per waiting message, and
    // doesn't hold up the others.
    let mut held: HashMap<String, Instant> = HashMap::new();
    loop {
        let job = {
            let mut q = lock(&h.queue);
            loop {
                let t = Instant::now();
                for j in q.iter_mut() {
                    if let Some(&until) = held.get(&j.dest) {
                        j.due = j.due.max(until);
                    }
                }
                if let Some(i) = q.iter().position(|j| j.due <= t) {
                    break q.remove(i);
                }
                let wait = q.iter().map(|j| j.due.saturating_duration_since(t)).min().unwrap_or(Duration::from_secs(3600));
                q = h.wake.wait_timeout(q, wait).map(|(g, _)| g).unwrap_or_else(|e| e.into_inner().0);
            }
        };
        let Some(mut job) = job else { continue };
        let dest = lock(&h.saved).dests.iter().find(|d| d.id == job.dest).cloned();
        let Some(dest) = dest else {
            held.remove(&job.dest);
            finish(h, job.seq, "dropped", job.tries, "The destination was removed.");
            continue;
        };
        job.tries += 1;
        let result = post(&agent, &dest, &job.event, &job.body);
        let ok = result.is_ok();
        let err = result.err().unwrap_or_default();
        let gave_up = !ok && job.started.elapsed().as_secs() >= RETRY_FOR;
        let state = if ok { "delivered" } else if gave_up { "failed" } else { "retrying" };
        finish(h, job.seq, state, job.tries, &err);
        {
            let mut s = lock(&h.saved);
            if let Some(d) = s.dests.iter_mut().find(|d| d.id == job.dest) {
                d.last_sent = now();
                d.last_result = if ok { "delivered".into() } else { state.into() };
            }
        }
        if ok {
            held.remove(&job.dest);
            continue;
        }
        // 5 s, 10 s, 20 s ... up to 2 minutes between tries.
        let wait = (5u64 << job.tries.min(6).saturating_sub(1)).min(120);
        let next = Instant::now() + Duration::from_secs(if gave_up { 5 } else { wait });
        held.insert(job.dest.clone(), next);
        let mut q = lock(&h.queue);
        // The address is down now, so its messages past 10 minutes stop here.
        q.retain(|j| {
            let old = j.dest == job.dest && j.started.elapsed().as_secs() >= RETRY_FOR;
            if old {
                finish(h, j.seq, "failed", j.tries, &err);
            }
            !old
        });
        if !gave_up {
            job.due = next;
            q.push_back(job);
        }
    }
}

fn save(path: &str, s: &Saved) -> Result<(), String> {
    use std::io::Write;
    let tmp = format!("{path}.new");
    let text = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp).map_err(|e| e.to_string())?;
    f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn random_hex(n: usize) -> Result<String, String> {
    let mut raw = vec![0u8; n];
    getrandom::getrandom(&mut raw).map_err(|e| e.to_string())?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn check_url(url: &str) -> Result<(), String> {
    let rest = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://")).ok_or("The address must start with http:// or https://.")?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || host.contains('@') || url.len() > 300 || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("That address isn't valid.".into());
    }
    Ok(())
}

fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.chars().count() > 40 || name.chars().any(|c| c.is_control()) {
        return Err("Give the destination a name of 1 to 40 characters.".into());
    }
    Ok(())
}

/// What the Notifications page shows. Secrets never leave the gateway
/// except once, when they're made.
pub fn view() -> Value {
    let Some(h) = hub() else { return json!({"dests": [], "recent": [], "events": events_json()}) };
    let dests: Vec<Value> = lock(&h.saved)
        .dests
        .iter()
        .map(|d| json!({"id": d.id, "name": d.name, "url": d.url, "events": d.events, "secret_made": d.secret_made, "last_sent": d.last_sent, "last_result": d.last_result}))
        .collect();
    let recent: Vec<Sent> = lock(&h.recent).iter().cloned().collect();
    json!({"dests": dests, "recent": recent, "events": events_json()})
}

fn events_json() -> Vec<Value> {
    EVENTS.iter().map(|(id, t)| json!({"id": id, "title": t})).collect()
}

/// Changes from the Notifications page. Returns the new view, plus the
/// secret once when one is made, and a log line.
pub fn change(b: &Value) -> Result<(Value, String), String> {
    let h = hub().ok_or("Notifications aren't running.")?;
    let s = |k: &str| b[k].as_str().unwrap_or("").trim().to_string();
    let id = s("id");
    let mut secret = None;
    let line;
    match s("action").as_str() {
        "save" => {
            let name = s("name");
            let url = s("url");
            check_name(&name)?;
            check_url(&url)?;
            let mut events: Vec<String> = Vec::new();
            for e in b["events"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
                let e = e.as_str().unwrap_or("");
                if !EVENTS.iter().any(|(id, _)| *id == e) {
                    return Err("Unknown event.".into());
                }
                if !events.iter().any(|x| x == e) {
                    events.push(e.into());
                }
            }
            let mut st = lock(&h.saved);
            if st.dests.iter().any(|d| d.name.eq_ignore_ascii_case(&name) && d.id != id) {
                return Err(format!("{name} already exists."));
            }
            if id.is_empty() {
                if st.dests.len() >= MAX_DESTS {
                    return Err(format!("You can have up to {MAX_DESTS} destinations."));
                }
                let new_secret = random_hex(32)?;
                st.dests.push(Dest { id: random_hex(8)?, name: name.clone(), url, secret: new_secret.clone(), secret_made: now(), events, ..Default::default() });
                secret = Some(new_secret);
                line = format!("added notification destination {name}");
            } else {
                let d = st.dests.iter_mut().find(|d| d.id == id).ok_or("No such destination.")?;
                (d.name, d.url, d.events) = (name.clone(), url, events);
                line = format!("changed notification destination {name}");
            }
            save(&h.path, &st)?;
        }
        "remove" => {
            let mut st = lock(&h.saved);
            let name = st.dests.iter().find(|d| d.id == id).map(|d| d.name.clone()).ok_or("No such destination.")?;
            st.dests.retain(|d| d.id != id);
            save(&h.path, &st)?;
            line = format!("removed notification destination {name}");
        }
        "new_secret" => {
            let mut st = lock(&h.saved);
            let d = st.dests.iter_mut().find(|d| d.id == id).ok_or("No such destination.")?;
            let new_secret = random_hex(32)?;
            d.secret = new_secret.clone();
            d.secret_made = now();
            line = format!("made a new signing secret for {}", d.name);
            save(&h.path, &st)?;
            secret = Some(new_secret);
        }
        "test" => {
            let name = lock(&h.saved).dests.iter().find(|d| d.id == id).map(|d| d.name.clone()).ok_or("No such destination.")?;
            queue(h, &id, &name, "test", "", "This is a test message from FoilGateway.", now());
            line = format!("sent a test notification to {name}");
        }
        _ => return Err("Unknown action.".into()),
    }
    let mut v = view();
    if let Some(sec) = secret {
        v["secret"] = json!(sec);
    }
    Ok((v, line))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_matches_known_hmac() {
        // HMAC-SHA256 of "1.{}" with key "key", worked out with openssl.
        let sig = sign("key", 1, "{}");
        assert_eq!(sig, "sha256=1ba6b8171186efc613e8bcc0cbdab2748f24984d7c5a84faa2637afa0e40d224");
        assert_ne!(sig, sign("key", 2, "{}"));
        assert_ne!(sig, sign("other", 1, "{}"));
    }

    #[test]
    fn repeats_for_a_device_go_as_one_message_with_a_count() {
        let mut g = HashMap::new();
        let t = 1_000_000;
        // The first goes at once; the next ones in 5 minutes are only counted.
        assert_eq!(group_step(&mut g, "look", "aa", "port 1", t).len(), 1);
        for i in 2..=5 {
            assert!(group_step(&mut g, "look", "aa", &format!("port {i}"), t + i).is_empty());
        }
        // Another device has its own window.
        assert_eq!(group_step(&mut g, "look", "bb", "port 9", t + 10).len(), 1);
        assert!(group_flush(&mut g, t + 100).is_empty(), "window still open");
        let due = group_flush(&mut g, t + GROUP_WINDOW);
        assert_eq!(due, vec![("look".to_string(), "aa".to_string(), "4 more like this in 5 minutes. Latest: port 5".to_string())]);
        // A new event after the window sends at once again.
        assert_eq!(group_step(&mut g, "look", "aa", "port 6", t + GROUP_WINDOW + 1).len(), 1);
        // If it comes before the flush ran, the count goes first.
        assert!(group_step(&mut g, "look", "aa", "port 7", t + GROUP_WINDOW + 2).is_empty());
        let out = group_step(&mut g, "look", "aa", "port 8", t + 2 * GROUP_WINDOW + 5);
        assert_eq!(out.len(), 2);
        assert!(out[0].2.starts_with("1 more like this") && out[1].2 == "port 8");
    }

    #[test]
    fn sign_ins_are_not_sent() {
        assert_eq!(classify("setting", "admin signed in from 10.0.0.2."), None);
        assert_eq!(classify("setting", "Changed: added 1.2.3.4 to the Black list."), Some("settings"));
    }

    #[test]
    fn events_are_sorted_into_the_right_kind() {
        assert_eq!(classify("device", "New device Pixel at 1.2.3.4"), Some("new_device"));
        assert_eq!(classify("device", "tried tcp 80"), Some("look"));
        assert_eq!(classify("alert", "x"), Some("look"));
        assert_eq!(classify("block", "x"), Some("blocked"));
        assert_eq!(classify("audit", "x"), Some("audit"));
        assert_eq!(classify("setting", "FoilGateway 1.2.0 started, settings page on port 8443."), Some("started"));
        assert_eq!(classify("setting", "tony changed X."), Some("settings"));
        assert_eq!(classify("dhcp", "x"), None);
        assert_eq!(classify("download", "x"), None);
    }

    #[test]
    fn only_web_addresses_are_accepted() {
        assert!(check_url("http://192.168.1.40:8797/foilgateway").is_ok());
        assert!(check_url("https://example.com/hook").is_ok());
        assert!(check_url("file:///etc/passwd").is_err());
        assert!(check_url("http://").is_err());
        assert!(check_url("http://user@host/").is_err());
        assert!(check_url("http://a b/").is_err());
    }

    /// Reads one HTTP request from a listener and answers 200.
    fn take(l: &std::net::TcpListener) -> (HashMap<String, String>, String) {
        use std::io::{BufRead, BufReader, Read, Write};
        let (mut c, _) = l.accept().unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut r = BufReader::new(c.try_clone().unwrap());
        let mut heads = HashMap::new();
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        loop {
            line.clear();
            r.read_line(&mut line).unwrap();
            if line.trim().is_empty() {
                break;
            }
            let (k, v) = line.split_once(':').unwrap();
            heads.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
        let n: usize = heads["content-length"].parse().unwrap();
        let mut body = vec![0; n];
        r.read_exact(&mut body).unwrap();
        c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        (heads, String::from_utf8(body).unwrap())
    }

    /// Other tests in this run also write log lines, so skip their messages.
    fn take_for(l: &std::net::TcpListener, text: &str) -> (HashMap<String, String>, String) {
        loop {
            let (h, b) = take(l);
            if b.contains(text) {
                return (h, b);
            }
        }
    }

    #[test]
    fn signed_messages_arrive_and_failed_sends_are_retried() {
        let dir = std::env::temp_dir().join(format!("foilgw-notify-{}", crate::auth::token()));
        std::fs::create_dir_all(&dir).unwrap();
        start(dir.to_str().unwrap());
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (v, _) = change(&json!({"action": "save", "name": "Jarvis", "url": format!("http://127.0.0.1:{port}/hook"), "events": ["new_device", "settings"]})).unwrap();
        let secret = v["secret"].as_str().unwrap().to_string();
        assert_eq!(secret.len(), 64);
        let id = v["dests"][0]["id"].as_str().unwrap().to_string();
        assert!(v["dests"][0].get("secret").is_none(), "the secret is only returned once");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join("notify.json")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // Not subscribed: nothing goes out. Subscribed: one signed message.
        event("block", "aa", "stopped");
        event("device", "aa", "New device Pixel at 192.168.1.9.");
        let (h, body) = take_for(&l, "Pixel at 192.168.1.9");
        assert_eq!(h["x-foilgateway-event"], "new_device");
        let ts: i64 = h["x-foilgateway-timestamp"].parse().unwrap();
        assert_eq!(h["x-foilgateway-signature"], sign(&secret, ts, &body));
        let b: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(b["text"], "New device Pixel at 192.168.1.9.");
        // The same event again within a minute is not sent twice.
        event("device", "aa", "New device Pixel at 192.168.1.9.");
        // A failed send is retried: stop listening, send, then listen again.
        let addr = l.local_addr().unwrap();
        drop(l);
        event("setting", "", "tony changed the block list.");
        let end = Instant::now() + Duration::from_secs(5);
        while !view()["recent"].as_array().unwrap().iter().any(|r| r["result"] == "retrying" && r["tries"].as_u64() >= Some(1)) {
            assert!(Instant::now() < end, "first try never failed");
            std::thread::sleep(Duration::from_millis(50));
        }
        let l = std::net::TcpListener::bind(addr).unwrap();
        let (h, _) = take_for(&l, "tony changed the block list.");
        assert_eq!(h["x-foilgateway-event"], "settings");
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let r = view()["recent"].as_array().unwrap().iter().find(|r| r["what"].as_str().unwrap().contains("tony changed the block list.")).cloned().unwrap();
            if r["result"] == "delivered" {
                assert!(r["tries"].as_u64().unwrap() >= 2);
                break;
            }
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(50));
        }
        // Send Test, a new secret, then remove.
        change(&json!({"action": "test", "id": id})).unwrap();
        let (h, _) = take_for(&l, "This is a test message");
        assert_eq!(h["x-foilgateway-event"], "test");
        let (v, _) = change(&json!({"action": "new_secret", "id": id})).unwrap();
        assert_ne!(v["secret"].as_str().unwrap(), secret);
        assert!(change(&json!({"action": "save", "name": "x", "url": "ftp://a/", "events": []})).is_err());
        change(&json!({"action": "remove", "id": id})).unwrap();
        assert!(view()["dests"].as_array().unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
