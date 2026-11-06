//! The Capture Log: one SQLite file at /var/lib/foilgateway/capture.db.
//! Identical blocks on the same day share one row with a count, so the
//! dashboard and the log show the same numbers.

use rusqlite::{params, Connection};
use serde::Serialize;
use std::sync::Mutex;

pub struct Log {
    db: Mutex<Connection>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Row {
    pub id: i64,
    pub first: i64,
    pub last: i64,
    pub kind: String,
    pub device: String,
    pub text: String,
    pub count: i64,
    pub handled: bool,
    /// For blocks, audit lines and some alerts: the reason code.
    pub reason: String,
    /// For blocks and audit lines (0.5.9 on): what they were about.
    pub remote: String,
    pub dir: String,
    /// "tcp 443,udp 443": every port seen for the address that day.
    pub ports: String,
    /// The name the device looked up for the address, when seen.
    pub domain: String,
}

/// What a block line was about.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct Meta {
    pub reason: String,
    pub remote: String,
    pub proto: String,
    pub port: u16,
    /// "out" when the device started it, "in" when it came from the router side.
    pub dir: String,
    pub domain: String,
}

/// A port as kept in the ports column: "tcp 443", or "icmp".
pub fn port_item(proto: &str, port: u16) -> String {
    if port == 0 { proto.to_string() } else { format!("{proto} {port}") }
}

/// The ports column back as (proto, port), in the order first seen.
pub fn port_list(s: &str) -> Vec<(String, u16)> {
    s.split(',').filter(|x| !x.is_empty()).map(|x| match x.split_once(' ') {
        Some((p, n)) => (p.to_string(), n.parse().unwrap_or(0)),
        None => (x.to_string(), 0),
    }).collect()
}

/// At most this many ports listed on one line; more still count.
pub const MAX_PORTS: usize = 16;

fn add_port(list: &str, item: &str) -> Option<String> {
    let have: Vec<&str> = list.split(',').filter(|x| !x.is_empty()).collect();
    if have.contains(&item) || have.len() >= MAX_PORTS {
        return None;
    }
    Some(if list.is_empty() { item.to_string() } else { format!("{list},{item}") })
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct AuditRow {
    pub device: String,
    #[serde(flatten)]
    pub meta: Meta,
    pub count: i64,
    pub first: i64,
    pub last: i64,
    pub text: String,
    pub ports: String,
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

impl Log {
    pub fn open(path: &str) -> Result<Log, String> {
        let db = Connection::open(path).map_err(|e| format!("can't open the log: {e}"))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA wal_autocheckpoint=200;
             PRAGMA journal_size_limit=1048576;
             CREATE TABLE IF NOT EXISTS events (
               id INTEGER PRIMARY KEY, first INTEGER, last INTEGER, day TEXT,
               kind TEXT, device TEXT, text TEXT, key TEXT, count INTEGER, handled INTEGER DEFAULT 0);
             CREATE INDEX IF NOT EXISTS ev_key ON events(day, key);
             CREATE INDEX IF NOT EXISTS ev_last ON events(last);",
        )
        .map_err(|e| e.to_string())?;
        // 0.5.8: blocks and audit lines also keep what they were about, so
        // they can be grouped and allowed. Older rows have these empty.
        let have: Vec<String> = db
            .prepare("PRAGMA table_info(events)")
            .and_then(|mut st| st.query_map([], |r| r.get::<_, String>(1)).map(|m| m.flatten().collect()))
            .unwrap_or_default();
        // 0.5.9: one line per device and address, with every port listed,
        // and the name the device looked up.
        for (col, ty) in [("reason", "TEXT DEFAULT ''"), ("remote", "TEXT DEFAULT ''"), ("proto", "TEXT DEFAULT ''"), ("port", "INTEGER DEFAULT 0"), ("dir", "TEXT DEFAULT ''"), ("ports", "TEXT DEFAULT ''"), ("domain", "TEXT DEFAULT ''")] {
            if !have.iter().any(|c| c == col) {
                db.execute_batch(&format!("ALTER TABLE events ADD COLUMN {col} {ty}")).map_err(|e| e.to_string())?;
            }
        }
        db.execute_batch("CREATE INDEX IF NOT EXISTS ev_kind ON events(kind, handled, last);").map_err(|e| e.to_string())?;
        Ok(Log { db: Mutex::new(db) })
    }

    /// A block or audit line, with what it was about kept apart. Blocks
    /// and audit lines are one line per device, reason and address a day,
    /// whatever the port: the ports are listed on it and the count is the
    /// total. Alerts stay one line per text.
    pub fn add_block(&self, kind: &str, device: &str, text: &str, at: i64, tz_offset: i64, m: &Meta) {
        let day = ((at + tz_offset) / 86400).to_string();
        let by_address = kind == "block" || kind == "audit";
        let key = if by_address { format!("{kind}|{device}|{}|{}|{}", m.reason, m.remote, m.dir) } else { format!("{kind}|{device}|{text}") };
        let item = if by_address { port_item(&m.proto, m.port) } else { String::new() };
        let db = self.db();
        let found: Option<(i64, String, String)> = db.query_row("SELECT id, COALESCE(ports,''), COALESCE(domain,'') FROM events WHERE day = ?1 AND key = ?2", params![day, key], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).ok();
        if let Some((id, ports, domain)) = &found {
            let _ = db.execute("UPDATE events SET count = count + 1, last = ?1 WHERE id = ?2", params![at, id]);
            if let Some(p) = add_port(ports, &item) {
                let _ = db.execute("UPDATE events SET ports = ?1 WHERE id = ?2", params![p, id]);
            }
            if domain.is_empty() && !m.domain.is_empty() {
                let _ = db.execute("UPDATE events SET domain = ?1 WHERE id = ?2", params![m.domain, id]);
            }
        }
        if found.is_none() {
            let _ = db.execute(
                "INSERT INTO events (first, last, day, kind, device, text, key, count, reason, remote, proto, port, dir, ports, domain) VALUES (?1, ?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![at, day, kind, device, text, key, m.reason, m.remote, m.proto, m.port, m.dir, item, m.domain],
            );
        } else {
            // Audit lines the owner already dealt with come back when it happens again.
            let _ = db.execute("UPDATE events SET handled = 0 WHERE day = ?1 AND key = ?2 AND kind = 'audit'", params![day, key]);
        }
    }

    /// Would-be blocks nobody has dealt with yet, one line per device,
    /// reason and address (every port on it merged and listed, the count
    /// the total), busiest last-seen first.
    pub fn audit_list(&self, since: i64, limit: i64) -> (Vec<AuditRow>, i64) {
        let db = self.db();
        let base = "FROM events WHERE kind = 'audit' AND handled = 0 AND last >= ?1 GROUP BY device, reason, remote";
        let total: i64 = db.query_row(&format!("SELECT COUNT(*) FROM (SELECT 1 {base})"), params![since], |r| r.get(0)).unwrap_or(0);
        // Lines from before 0.5.9 have one port each and no ports column.
        let Ok(mut st) = db.prepare(&format!("SELECT device, reason, remote, MAX(dir), SUM(count), MIN(first), MAX(last), MAX(text), GROUP_CONCAT(CASE WHEN COALESCE(ports,'') != '' THEN ports ELSE CASE WHEN port > 0 THEN proto || ' ' || port ELSE proto END END, ','), MAX(COALESCE(domain,'')) {base} ORDER BY MAX(last) DESC LIMIT ?2")) else { return (vec![], 0) };
        let rows = st.query_map(params![since, limit], |r| {
            let mut ports = String::new();
            for p in r.get::<_, Option<String>>(8)?.unwrap_or_default().split(',') {
                if let Some(x) = add_port(&ports, p) {
                    ports = x;
                }
            }
            let first = port_list(&ports).into_iter().next().unwrap_or_default();
            Ok(AuditRow {
                device: r.get(0)?,
                meta: Meta { reason: r.get(1)?, remote: r.get(2)?, proto: first.0, port: first.1, dir: r.get(3)?, domain: r.get(9)? },
                count: r.get(4)?,
                first: r.get(5)?,
                last: r.get(6)?,
                text: r.get(7)?,
                ports,
            })
        });
        (rows.map(|r| r.flatten().collect()).unwrap_or_default(), total)
    }

    /// Marks matching audit lines dealt with. An empty `proto` matches any
    /// port (allowing an address covers every port on it); `reasons`
    /// limits which kinds of block count.
    pub fn handle_audit(&self, device: &str, remote: &str, proto: &str, port: u16, reasons: &[&str]) -> usize {
        let list = reasons.join(",");
        self.db()
            .execute(
                "UPDATE events SET handled = 1 WHERE kind = 'audit' AND handled = 0 AND device = ?1 AND remote = ?2 AND (?3 = '' OR (proto = ?3 AND port = ?4) OR instr(',' || COALESCE(ports,'') || ',', ',' || ?3 || ' ' || ?4 || ',') > 0) AND instr(',' || ?5 || ',', ',' || reason || ',') > 0",
                params![device, remote, proto, port, list],
            )
            .unwrap_or(0)
    }

    /// Marks one alert (or any line) dealt with.
    pub fn handle_id(&self, id: i64) {
        let _ = self.db().execute("UPDATE events SET handled = 1 WHERE id = ?1", params![id]);
    }

    /// Marks a device's sudden-blocks alerts dealt with.
    pub fn handle_surge(&self, device: &str) {
        let _ = self.db().execute("UPDATE events SET handled = 1 WHERE device = ?1 AND kind = 'alert' AND reason = 'surge'", params![device]);
    }

    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Adds a line, or bumps the count of the same line from today.
    pub fn add(&self, kind: &str, device: &str, text: &str, at: i64, tz_offset: i64) {
        let day = ((at + tz_offset) / 86400).to_string();
        let key = format!("{kind}|{device}|{text}");
        let db = self.db();
        let bumped = db
            .execute("UPDATE events SET count = count + 1, last = ?1 WHERE day = ?2 AND key = ?3", params![at, day, key])
            .unwrap_or(0);
        if bumped == 0 {
            let _ = db.execute(
                "INSERT INTO events (first, last, day, kind, device, text, key, count) VALUES (?1, ?1, ?2, ?3, ?4, ?5, ?6, 1)",
                params![at, day, kind, device, text, key],
            );
        }
    }

    pub fn note(&self, kind: &str, text: &str) {
        self.add(kind, "", text, now(), 0);
    }

    /// Newest first. `kind` empty means all; `search` matches anywhere in the line.
    pub fn rows(&self, kind: &str, search: &str, since: i64, limit: i64) -> Vec<Row> {
        self.page(kind, search, since, i64::MAX, "new", 0, limit).0
    }

    /// One page of lines between `since` and `until`, and how many match in all.
    /// `sort` is new, old or count.
    #[allow(clippy::too_many_arguments)]
    pub fn page(&self, kind: &str, search: &str, since: i64, until: i64, sort: &str, offset: i64, limit: i64) -> (Vec<Row>, i64) {
        let db = self.db();
        let like = format!("%{search}%");
        let order = match sort {
            "old" => "last ASC",
            "count" => "count DESC, last DESC",
            _ => "last DESC",
        };
        // "look" = unhandled alerts and new-device lines that still need an owner.
        let filter = "WHERE ((?1 = 'look' AND kind IN ('alert','device') AND handled = 0) OR (?1 != 'look' AND (?1 = '' OR kind = ?1))) AND (?2 = '%%' OR text LIKE ?2 OR device LIKE ?2) AND last >= ?3 AND last <= ?4";
        let total: i64 = db.query_row(&format!("SELECT COUNT(*) FROM events {filter}"), params![kind, like, since, until], |r| r.get(0)).unwrap_or(0);
        let mut st = match db.prepare(&format!("SELECT id, first, last, kind, device, text, count, handled, COALESCE(reason, ''), COALESCE(remote, ''), COALESCE(dir, ''), CASE WHEN COALESCE(ports,'') != '' THEN ports WHEN port > 0 THEN proto || ' ' || port ELSE COALESCE(proto, '') END, COALESCE(domain, '') FROM events {filter} ORDER BY {order} LIMIT ?5 OFFSET ?6")) {
            Ok(s) => s,
            Err(_) => return (vec![], 0),
        };
        let rows = st.query_map(params![kind, like, since, until, limit, offset], |r| {
            Ok(Row {
                id: r.get(0)?,
                first: r.get(1)?,
                last: r.get(2)?,
                kind: r.get(3)?,
                device: r.get(4)?,
                text: r.get(5)?,
                count: r.get(6)?,
                handled: r.get::<_, i64>(7)? != 0,
                reason: r.get(8)?,
                remote: r.get(9)?,
                dir: r.get(10)?,
                ports: r.get(11)?,
                domain: r.get(12)?,
            })
        });
        (rows.map(|r| r.flatten().collect()).unwrap_or_default(), total)
    }

    /// Total blocked packets logged since `since`, the number shown on every page.
    pub fn blocked_between(&self, from: i64, to: i64) -> i64 {
        self.db().query_row(
            "SELECT COALESCE(SUM(count),0) FROM events WHERE kind='block' AND last >= ?1 AND last < ?2",
            params![from, to],
            |r| r.get(0),
        ).unwrap_or(0)
    }
    pub fn blocked_since(&self, since: i64) -> i64 {
        self.db().query_row("SELECT COALESCE(SUM(count),0) FROM events WHERE kind='block' AND last >= ?1", params![since], |r| r.get(0)).unwrap_or(0)
    }

    /// Block counts used for the "Likely attack" / higher-than-usual card.
    /// Skips expected policy noise: telemetry retries and devices set to
    /// Local Network Only / Block All hammering outbound (devlan/devblock).
    /// Inbound and list/country blocks still count.
    pub fn blocked_alarm_between(&self, from: i64, to: i64) -> i64 {
        self.db().query_row(
            "SELECT COALESCE(SUM(count),0) FROM events WHERE kind='block' AND last >= ?1 AND last < ?2              AND reason NOT IN ('telemetry','devlan','devblock')",
            params![from, to],
            |r| r.get(0),
        ).unwrap_or(0)
    }
    pub fn blocked_alarm_since(&self, since: i64) -> i64 {
        self.db().query_row(
            "SELECT COALESCE(SUM(count),0) FROM events WHERE kind='block' AND last >= ?1              AND reason NOT IN ('telemetry','devlan','devblock')",
            params![since],
            |r| r.get(0),
        ).unwrap_or(0)
    }

    /// Marks a device's alerts handled once the owner has set a policy for it.
    pub fn handle_device(&self, device: &str) {
        let _ = self.db().execute("UPDATE events SET handled = 1 WHERE device = ?1 AND kind IN ('device','alert')", params![device]);
    }

    /// A threat block is stopped by the rule itself, so its alert is handled.
    pub fn handle_device_alerts_blocked(&self, device: &str) {
        let _ = self.db().execute("UPDATE events SET handled = 1 WHERE device = ?1 AND kind = 'alert' AND text LIKE '%Blocked.'", params![device]);
    }

    /// Rough byte size of a Capture Log download for the given filter.
    pub fn download_bytes(&self, kind: &str, search: &str, since: i64, until: i64) -> i64 {
        let (_, total) = self.page(kind, search, since, until, "old", 0, 0);
        // ~120 bytes per line of TSV once written out.
        total.saturating_mul(120)
    }

    pub fn prune(&self, keep_days: i64) {
        let db = self.db();
        let _ = db.execute("DELETE FROM events WHERE last < ?1", params![now() - keep_days * 86400]);
        // Hand the WAL back to the main file and cut it to nothing, so it
        // can't creep up on a small flash disk.
        let _ = db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_block_grouped_newest_first() {
        let log = Log::open(":memory:").unwrap();
        log.add("block", "cam", "to 1.2.3.4 tcp/443, Black list", 1000, 0);
        log.add("block", "cam", "to 1.2.3.4 tcp/443, Black list", 1005, 0);
        log.add("block", "tv", "to 5.6.7.8 udp/123, telemetry", 1003, 0);
        let rows = log.rows("block", "", 0, 10);
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].device.as_str(), rows[0].count, rows[0].last), ("cam", 2, 1005));
        assert_eq!(log.blocked_since(0), 3);
        // A new day starts a new line.
        log.add("block", "cam", "to 1.2.3.4 tcp/443, Black list", 1000 + 86400, 0);
        assert_eq!(log.rows("block", "", 0, 10).len(), 3);
    }

    #[test]
    fn alarm_count_skips_telemetry_and_device_mode_noise() {
        let log = Log::open(":memory:").unwrap();
        let m = |reason: &str, dir: &str| Meta {
            reason: reason.into(),
            remote: "1.2.3.4".into(),
            proto: "tcp".into(),
            port: 443,
            dir: dir.into(),
            ..Default::default()
        };
        log.add_block("block", "a", "telemetry", 100, 0, &m("telemetry", "out"));
        log.add_block("block", "a", "devlan", 101, 0, &m("devlan", "out"));
        log.add_block("block", "a", "devblock", 102, 0, &m("devblock", "out"));
        log.add_block("block", "a", "country", 103, 0, &m("country", "in"));
        log.add_block("block", "a", "wan", 104, 0, &m("wan", "in"));
        assert_eq!(log.blocked_since(0), 5);
        assert_eq!(log.blocked_alarm_since(0), 2);
        assert_eq!(log.blocked_alarm_between(0, 200), 2);
    }

    #[test]
    fn handled_follows_the_device() {
        let log = Log::open(":memory:").unwrap();
        log.add("device", "aa:bb", "New device", 10, 0);
        log.handle_device("aa:bb");
        assert!(log.rows("", "", 0, 10)[0].handled);
    }

    #[test]
    fn audit_lines_group_and_get_dealt_with() {
        let log = Log::open(":memory:").unwrap();
        let m = |reason: &str, remote: &str, port: u16| Meta { reason: reason.into(), remote: remote.into(), proto: "tcp".into(), port, dir: "out".into(), ..Default::default() };
        log.add_block("audit", "aa:bb", "to 1.2.3.4 tcp/443, Black list", 100, 0, &m("black", "1.2.3.4", 443));
        log.add_block("audit", "aa:bb", "to 1.2.3.4 tcp/443, Black list", 110, 0, &m("black", "1.2.3.4", 443));
        log.add_block("audit", "aa:bb", "to 1.2.3.4 tcp/80, Black list", 120, 0, &m("black", "1.2.3.4", 80));
        log.add_block("audit", "cc:dd", "to 5.6.7.8 udp/53, country", 130, 0, &Meta { proto: "udp".into(), ..m("country", "5.6.7.8", 53) });
        log.add_block("block", "aa:bb", "to 9.9.9.9 tcp/443, Black list", 140, 0, &m("black", "9.9.9.9", 443));
        let (rows, total) = log.audit_list(0, 10);
        assert_eq!(total, 2);
        assert_eq!((rows[0].device.as_str(), rows[0].meta.reason.as_str()), ("cc:dd", "country"));
        // One line for the address, both ports on it, count the total.
        let a = rows.iter().find(|r| r.meta.remote == "1.2.3.4").unwrap();
        assert_eq!((a.count, a.ports.as_str()), (3, "tcp 443,tcp 80"));
        // Allowing the address covers every port on it.
        assert_eq!(log.handle_audit("aa:bb", "1.2.3.4", "", 0, &["black", "threat"]), 1);
        assert_eq!(log.audit_list(0, 10).1, 1);
        // The wrong reason leaves it alone; a repeat brings it back.
        assert_eq!(log.handle_audit("cc:dd", "5.6.7.8", "udp", 53, &["black"]), 0);
        log.add_block("audit", "aa:bb", "to 1.2.3.4 tcp/80, Black list", 150, 0, &m("black", "1.2.3.4", 80));
        assert_eq!(log.audit_list(0, 10).1, 2);
    }

    #[test]
    fn blocks_merge_per_device_and_address() {
        let log = Log::open(":memory:").unwrap();
        let m = |proto: &str, port: u16, domain: &str| Meta { reason: "telemetry".into(), remote: "51.132.193.107".into(), proto: proto.into(), port, dir: "out".into(), domain: domain.into() };
        let t = "Clunker to 51.132.193.107 (GB): telemetry";
        log.add_block("block", "aa", t, 100, 0, &m("tcp", 443, ""));
        log.add_block("block", "aa", t, 101, 0, &m("tcp", 443, "v10.events.data.microsoft.com"));
        log.add_block("block", "aa", t, 102, 0, &m("udp", 443, ""));
        log.add_block("block", "aa", t, 103, 0, &m("tcp", 80, ""));
        // Another device, and another address: their own lines.
        log.add_block("block", "bb", t, 104, 0, &m("tcp", 443, ""));
        log.add_block("block", "aa", t, 105, 0, &Meta { remote: "1.1.1.1".into(), ..m("tcp", 443, "") });
        let rows = log.rows("block", "", 0, 10);
        assert_eq!(rows.len(), 3);
        let r = rows.iter().find(|r| r.device == "aa" && r.remote == "51.132.193.107").unwrap();
        assert_eq!((r.count, r.ports.as_str(), r.domain.as_str()), (4, "tcp 443,udp 443,tcp 80", "v10.events.data.microsoft.com"));
        assert_eq!(port_list(&r.ports), vec![("tcp".into(), 443), ("udp".into(), 443), ("tcp".into(), 80)]);
        // The total still adds up.
        assert_eq!(log.blocked_since(0), 6);
        // A long port scan still counts every try but lists only so many ports.
        for p in 1000..1100 {
            log.add_block("block", "cc", t, 200, 0, &m("tcp", p, ""));
        }
        let r = log.rows("block", "", 0, 10).into_iter().find(|r| r.device == "cc").unwrap();
        assert_eq!((r.count, port_list(&r.ports).len()), (100, MAX_PORTS));
    }

    #[test]
    fn old_log_files_get_the_new_columns() {
        let path = std::env::temp_dir().join(format!("fgw-caplog-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch("CREATE TABLE events (id INTEGER PRIMARY KEY, first INTEGER, last INTEGER, day TEXT, kind TEXT, device TEXT, text TEXT, key TEXT, count INTEGER, handled INTEGER DEFAULT 0);
                INSERT INTO events (first, last, day, kind, device, text, key, count) VALUES (1, 1, '0', 'block', 'aa', 'old', 'k', 3);").unwrap();
        }
        let log = Log::open(path.to_str().unwrap()).unwrap();
        let rows = log.rows("block", "", 0, 10);
        assert_eq!((rows[0].text.as_str(), rows[0].count, rows[0].reason.as_str()), ("old", 3, ""));
        drop(log);
        // Opening again doesn't try to add them twice.
        assert!(Log::open(path.to_str().unwrap()).is_ok());
        let _ = std::fs::remove_file(&path);
    }
}
