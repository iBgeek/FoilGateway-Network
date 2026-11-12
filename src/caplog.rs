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
    pub outcome: String,
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
    pub outcome: String,
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

fn quiet_exists(db: &Connection, device: &str, remote: &str, proto: &str, port: u16, dir: &str, extra: &str) -> bool {
    db.query_row(
        "SELECT 1 FROM quiet WHERE device=?1 AND remote=?2 AND proto=?3 AND port=?4 AND dir=?5 AND extra=?6",
        params![device, remote, proto, port, dir, extra],
        |_| Ok(()),
    )
    .is_ok()
}

fn quiet_exists_tx(tx: &rusqlite::Transaction, device: &str, remote: &str, proto: &str, port: u16, dir: &str, extra: &str) -> bool {
    quiet_exists(tx, device, remote, proto, port, dir, extra)
}

fn silence_put(db: &Connection, device: &str, remote: &str, proto: &str, port: u16, dir: &str, extra: &str) {
    if remote.is_empty() && extra.is_empty() {
        return;
    }
    let _ = db.execute(
        "INSERT OR IGNORE INTO quiet (device, remote, proto, port, dir, extra, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![device, remote, proto, port, dir, extra, now()],
    );
}

/// Sign-in alerts: (user, source address) from the kept fields or the line's text.
fn auth_from_row(row: &Row) -> Option<(String, String)> {
    if row.reason == "auth" && !row.remote.is_empty() {
        return Some((row.domain.clone(), row.remote.clone()));
    }
    auth_from_text(&row.text)
}

fn auth_from_text(text: &str) -> Option<(String, String)> {
    if let Some(rest) = text.strip_prefix("Failed sign-in for ") {
        if let Some((user, ip)) = rest.rsplit_once(" from ") {
            let ip = ip.trim().trim_end_matches('.').to_string();
            if !ip.is_empty() {
                return Some((user.to_string(), ip));
            }
        }
    }
    if let Some(rest) = text.strip_prefix("A wrong API key was used from ") {
        let ip = rest.trim().trim_end_matches('.').to_string();
        if !ip.is_empty() {
            return Some((String::new(), ip));
        }
    }
    None
}

fn row_quiet_keys(row: &Row) -> Vec<(String, String, String, u16, String, String)> {
    if let Some((user, ip)) = auth_from_row(row) {
        return vec![(String::new(), ip, String::new(), 0, String::new(), user)];
    }
    if row.remote.is_empty() {
        return vec![];
    }
    let ports = port_list(&row.ports);
    if ports.is_empty() {
        return vec![];
    }
    ports
        .into_iter()
        .map(|(proto, port)| (row.device.clone(), row.remote.clone(), proto, port, row.dir.clone(), String::new()))
        .collect()
}

fn silence_row(db: &Connection, row: &Row) {
    for (device, remote, proto, port, dir, extra) in row_quiet_keys(row) {
        silence_put(db, &device, &remote, &proto, port, &dir, &extra);
    }
}

fn quiet_phrases(row: &Row) -> Vec<String> {
    row_quiet_keys(row)
        .into_iter()
        .map(|(device, remote, proto, port, dir, extra)| {
            if !extra.is_empty() || (device.is_empty() && port == 0) {
                if extra.is_empty() {
                    format!("sign-ins from {remote}")
                } else {
                    format!("sign-ins for {extra} from {remote}")
                }
            } else {
                let who = if device.is_empty() { "a device".into() } else { device };
                let port_s = if port == 0 { proto } else { format!("{proto} {port}") };
                let way = if dir.is_empty() { String::new() } else { format!(" {dir}") };
                format!("{who} to {remote} on {port_s}{way}")
            }
        })
        .collect()
}

fn get_row(db: &Connection, id: i64) -> Option<Row> {
    db.query_row(
        "SELECT id, first, last, kind, device, text, count, handled, COALESCE(reason, ''), COALESCE(remote, ''), COALESCE(dir, ''), CASE WHEN COALESCE(ports,'') != '' THEN ports WHEN port > 0 THEN proto || ' ' || port ELSE COALESCE(proto, '') END, COALESCE(domain, ''), COALESCE(outcome,'unknown') FROM events WHERE id = ?1",
        params![id],
        |r| Ok(Row {
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
            outcome: r.get(13)?,
        }),
    )
    .ok()
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
        for (col, ty) in [("reason", "TEXT DEFAULT ''"), ("remote", "TEXT DEFAULT ''"), ("proto", "TEXT DEFAULT ''"), ("port", "INTEGER DEFAULT 0"), ("dir", "TEXT DEFAULT ''"), ("ports", "TEXT DEFAULT ''"), ("domain", "TEXT DEFAULT ''"), ("outcome", "TEXT DEFAULT 'unknown'")] {
            if !have.iter().any(|c| c == col) {
                db.execute_batch(&format!("ALTER TABLE events ADD COLUMN {col} {ty}")).map_err(|e| e.to_string())?;
            }
        }
        db.execute_batch("CREATE INDEX IF NOT EXISTS ev_kind ON events(kind, handled, last);").map_err(|e| e.to_string())?;
        db.execute_batch("CREATE INDEX IF NOT EXISTS ev_flow ON events(device, remote, kind);").map_err(|e|e.to_string())?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS pattern_support(alert_id INTEGER, port INTEGER, dir TEXT, handled INTEGER DEFAULT 0, PRIMARY KEY(alert_id,port,dir)); UPDATE events SET outcome='dropped' WHERE kind='block'; UPDATE events SET outcome='audit_allowed' WHERE kind='audit';").map_err(|e|e.to_string())?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS pattern_flows(alert_id INTEGER, flow TEXT, port INTEGER, dir TEXT, handled INTEGER DEFAULT 0, PRIMARY KEY(alert_id,flow)); CREATE INDEX IF NOT EXISTS pattern_flow_key ON pattern_flows(flow,handled);").map_err(|e|e.to_string())?;
        // Lasting "don't tell me again" rules: one row per device, address, port and direction.
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS quiet (
               device TEXT NOT NULL,
               remote TEXT NOT NULL,
               proto TEXT NOT NULL,
               port INTEGER NOT NULL,
               dir TEXT NOT NULL,
               extra TEXT NOT NULL,
               at INTEGER NOT NULL,
               PRIMARY KEY (device, remote, proto, port, dir, extra)
             );
             CREATE INDEX IF NOT EXISTS quiet_lookup ON quiet(device, remote, proto, port);",
        )
        .map_err(|e| e.to_string())?;
        let log=Log { db: Mutex::new(db) };log.reconcile_stopped_ports();Ok(log)
    }

    fn reconcile_stopped_ports(&self) {
        let db=self.db();
        let Ok(mut st)=db.prepare("SELECT id, device, text, last FROM events NOT INDEXED WHERE kind='device' AND handled=0 AND COALESCE(reason,'')='' ORDER BY id") else{return};
        let Ok(rows)=st.query_map([],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(3)?)))else{return};
        for(id,device,text,latest)in rows.flatten() {
            if !text.ends_with("It's on the Ports list."){continue;}
            let Some((remote,rest))=text.split_once(" on the router side tried ")else{continue};
            if remote.parse::<std::net::IpAddr>().is_err(){continue;}
            let mut words=rest.split_whitespace();let proto=words.next().unwrap_or("");let Some(port)=words.next().and_then(|s|s.parse::<u16>().ok())else{continue};
            if !matches!(proto,"tcp"|"udp"){continue;}
            let stopped:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE kind='block' AND device=?1 AND remote=?2 AND dir='in' AND first>=?3 AND ((proto=?4 AND port=?5) OR instr(','||COALESCE(ports,'')||',',','||?4||' '||?5||',')>0))",params![device,remote,latest,proto,port],|r|r.get(0)).unwrap_or(false);
            if stopped {let _=db.execute("UPDATE events SET handled=1 WHERE id=?1",params![id]);}
        }
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
        }
        let outcome=if kind=="block"{"dropped"}else if kind=="audit"{"audit_allowed"}else{match m.outcome.as_str(){"forwarded"=>"forwarded","audit_allowed"=>"audit_allowed","dropped"=>"dropped",_=>"unknown"}};
        let _=db.execute("UPDATE events SET outcome=?1 WHERE day=?2 AND key=?3",params![outcome,day,key]);
        if kind=="block" && m.dir=="in" && matches!(m.proto.as_str(),"tcp"|"udp") && m.port>0 {
            let prefix=format!("{} on the router side tried {} {} on %",m.remote,m.proto,m.port);
            let _=db.execute("UPDATE events SET handled=1 WHERE kind='device' AND handled=0 AND device=?1 AND COALESCE(reason,'')='' AND text LIKE ?2 AND last<=?3",params![device,prefix,at]);
        }
        let id = found.as_ref().map(|(id, _, _)| *id).unwrap_or_else(|| db.last_insert_rowid());
        let quiet_this = quiet_exists(&db, device, &m.remote, &m.proto, m.port, &m.dir, "");
        let all_quiet = match get_row(&db, id) {
            Some(row) => {
                let keys = row_quiet_keys(&row);
                !keys.is_empty() && keys.iter().all(|(dev, rem, proto, port, dir, extra)| quiet_exists(&db, dev, rem, proto, *port, dir, extra))
            }
            None => quiet_this,
        };
        if all_quiet {
            let _ = db.execute("UPDATE events SET handled = 1 WHERE id = ?1", params![id]);
        } else if found.is_some() && !quiet_this {
            // A repeat is worth a look again only when this exact tuple was not marked quiet.
            let _ = db.execute("UPDATE events SET handled = 0 WHERE id = ?1 AND kind IN ('audit','alert','block')", params![id]);
        }
        drop(db);
        // Stopped alerts, port sightings and quiet tuples stay off the dashboard and out of notifications.
        if !quiet_this && !(kind == "alert" && outcome == "dropped") && !(kind == "device" && m.reason == "port_observed") {
            crate::notify::event_at(kind, device, text, Some(id));
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
                meta: Meta { reason: r.get(1)?, remote: r.get(2)?, proto: first.0, port: first.1, dir: r.get(3)?, domain: r.get(9)?, outcome:"audit_allowed".into() },
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

    /// Port-specific drops cannot settle warnings about another allowed port.
    pub fn handle_stopped_alerts(&self, device:&str, m:&Meta) {
        let db=self.db();
        let _=db.execute("UPDATE events SET handled=1 WHERE kind='alert' AND reason NOT IN ('port_sweep','tcp_failure') AND device=?1 AND remote=?2 AND ?2!='' AND proto=?3 AND port=?4 AND dir=?5",params![device,m.remote,m.proto,m.port,m.dir]);
        if m.proto=="tcp" {
            for table in ["pattern_support","pattern_flows"] {let _=db.execute(&format!("UPDATE {table} SET handled=1 WHERE port=?1 AND dir=?2 AND alert_id IN (SELECT id FROM events WHERE device=?3 AND remote=?4)"),params![m.port,m.dir,device,m.remote]);}
            let _=db.execute("UPDATE events SET handled=1 WHERE device=?1 AND remote=?2 AND reason IN ('port_sweep','tcp_failure') AND EXISTS(SELECT 1 FROM pattern_support WHERE alert_id=events.id) AND NOT EXISTS(SELECT 1 FROM pattern_support WHERE alert_id=events.id AND handled=0)",params![device,m.remote]);
        }
    }

    /// Successful SYN-ACK resolves its exact failed attempt, not a port sweep.
    pub fn resolve_tcp(&self, keys:&[String])->Result<(),String> {
        if keys.is_empty(){return Ok(());}
        let mut db=self.db();let tx=db.transaction().map_err(|e|e.to_string())?;let mut affected=std::collections::HashSet::new();
        for key in keys {
            let mut st=tx.prepare("SELECT f.alert_id FROM pattern_flows f JOIN events e ON e.id=f.alert_id WHERE f.flow=?1 AND f.handled=0 AND e.handled=0 AND e.reason='tcp_failure'").map_err(|e|e.to_string())?;
            let rows=st.query_map(params![key],|r|r.get::<_,i64>(0)).map_err(|e|e.to_string())?;
            for id in rows{affected.insert(id.map_err(|e|e.to_string())?);}
            tx.execute("UPDATE pattern_flows SET handled=1 WHERE flow=?1 AND alert_id IN (SELECT id FROM events WHERE reason='tcp_failure' AND handled=0)",params![key]).map_err(|e|e.to_string())?;
        }
        for id in affected {tx.execute("UPDATE events SET handled=1 WHERE id=?1 AND NOT EXISTS(SELECT 1 FROM pattern_flows WHERE alert_id=?1 AND handled=0)",params![id]).map_err(|e|e.to_string())?;}
        tx.commit().map_err(|e|e.to_string())?;Ok(())
    }

    /// An actual drop or successful Allow resolves alerts about that device/address.
    pub fn handle_resolved_alerts(&self, device: &str, remote: &str) {
        let _ = self.db().execute("UPDATE events SET handled = 1 WHERE kind = 'alert' AND device = ?1 AND ?2 != '' AND (remote = ?2 OR (COALESCE(remote,'') = '' AND instr(text, ?3) > 0))", params![device, remote, format!(" {remote}, which is on a threat list.")]);
    }

    pub fn pattern(&self, a: &crate::detection::Alert, at: i64, text: &str) -> Result<bool,String> {
        let ports = a.ports.iter().map(|p| format!("tcp {p}")).collect::<Vec<_>>().join(",");
        let dir = if a.outbound { "out" } else { "in" };
        let port = if a.ports.len() == 1 { a.ports[0] } else { 0 };
        let mut db = self.db();
        let tx=db.transaction().map_err(|e|e.to_string())?;
        // Persist the subject cooldown across observer/process restarts. Scope
        // includes direction and service; another remote/port remains visible.
        let recent: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE kind='alert' AND device=?1 AND remote=?2 AND reason=?3 AND dir=?4 AND port=?5 AND last>?6 AND last<=?7)", params![a.mac, a.remote, a.reason, dir, port, at.saturating_sub(300), at], |r| r.get(0)).map_err(|e|e.to_string())?;
        if recent { return Ok(false) }
        let key = format!("pattern|{}|{}|{}|{dir}|{port}|{at}", a.mac, a.remote, a.reason);
        tx.execute("INSERT INTO events(first,last,day,kind,device,text,key,count,reason,remote,proto,port,dir,ports,outcome) VALUES(?1,?1,?2,'alert',?3,?4,?5,?6,?7,?8,'tcp',?9,?10,?11,?12)", params![at, (at/86400).to_string(), a.mac, text, key, a.count as i64, a.reason, a.remote, port, dir, ports, if a.audit { "audit_allowed" } else { "forwarded" }]).map_err(|e|e.to_string())?;
        let id = tx.last_insert_rowid();
        for port in &a.ports {
            tx.execute("INSERT INTO pattern_support(alert_id,port,dir) VALUES(?1,?2,?3)", params![id, port, dir]).map_err(|e|e.to_string())?;
        }
        for signal in &a.support {
            tx.execute("INSERT OR IGNORE INTO pattern_flows(alert_id,flow,port,dir) VALUES(?1,?2,?3,?4)",params![id,signal.key(),signal.dport,dir]).map_err(|e|e.to_string())?;
        }
        let quiet_all = if a.ports.is_empty() {
            quiet_exists_tx(&tx, &a.mac, &a.remote, "tcp", port, dir, "")
        } else {
            a.ports.iter().all(|p| quiet_exists_tx(&tx, &a.mac, &a.remote, "tcp", *p, dir, ""))
        };
        if quiet_all {
            tx.execute("UPDATE events SET handled = 1 WHERE id = ?1", params![id]).map_err(|e|e.to_string())?;
        }
        tx.commit().map_err(|e|e.to_string())?;
        drop(db);
        if !quiet_all {
            crate::notify::event_at("alert", &a.mac, text, Some(id));
        }
        Ok(true)
    }

    /// Marks one alert, device, block or audit line dealt with, and records a
    /// lasting quiet rule when the line has a device, address and port.
    pub fn handle_id(&self, id: i64) -> usize {
        self.handle_ids(&[id])
    }

    /// True when every id is a line the dashboard shows as an alert
    /// (kind alert or device). Only those can be cleared in bulk.
    pub fn are_alerts(&self, ids: &[i64]) -> bool {
        self.ids_are(ids, "('alert', 'device')")
    }

    /// True when every id is a line Mark Handled / Keep It Blocked may take.
    pub fn can_handle(&self, ids: &[i64]) -> bool {
        self.ids_are(ids, "('alert', 'device', 'block', 'audit')")
    }

    fn ids_are(&self, ids: &[i64], kinds: &str) -> bool {
        let db = self.db();
        let Ok(mut st) = db.prepare(&format!("SELECT 1 FROM events WHERE id = ?1 AND kind IN {kinds}")) else { return false };
        !ids.is_empty() && ids.iter().all(|id| st.exists(params![id]).unwrap_or(false))
    }

    /// Marks several lines handled at once. Records a quiet rule for each
    /// line that has a device, address and port (or a sign-in address and user).
    /// Returns how many lines changed to handled.
    pub fn handle_ids(&self, ids: &[i64]) -> usize {
        let mut db = self.db();
        let Ok(tx) = db.transaction() else { return 0 };
        let mut n = 0;
        if let Ok(mut st) = tx.prepare("UPDATE events SET handled = 1 WHERE id = ?1 AND handled = 0 AND kind IN ('alert', 'device', 'block', 'audit')") {
            for id in ids {
                n += st.execute(params![id]).unwrap_or(0);
            }
        }
        for id in ids {
            if let Some(row) = get_row(&tx, *id) {
                silence_row(&tx, &row);
            }
        }
        if tx.commit().is_err() {
            return 0;
        }
        n
    }

    /// Short phrases for the quiet rules saved from these lines, for the log.
    pub fn quiet_notes(&self, ids: &[i64]) -> Vec<String> {
        let db = self.db();
        let mut out = Vec::new();
        for id in ids {
            if let Some(row) = get_row(&db, *id) {
                out.extend(quiet_phrases(&row));
            }
        }
        out
    }

    /// Whether any quiet rule matches this line's device, address and port.
    pub fn row_is_quiet(&self, row: &Row) -> bool {
        let db = self.db();
        row_quiet_keys(row).into_iter().any(|(device, remote, proto, port, dir, extra)| quiet_exists(&db, &device, &remote, &proto, port, &dir, &extra))
    }

    /// Removes quiet rules for this line and marks it unhandled, so later
    /// matches can raise an alert again.
    pub fn hear_again(&self, id: i64) -> bool {
        let mut db = self.db();
        let Ok(tx) = db.transaction() else { return false };
        let Some(row) = get_row(&tx, id) else { return false };
        for (device, remote, proto, port, dir, extra) in row_quiet_keys(&row) {
            let _ = tx.execute("DELETE FROM quiet WHERE device=?1 AND remote=?2 AND proto=?3 AND port=?4 AND dir=?5 AND extra=?6", params![device, remote, proto, port, dir, extra]);
        }
        let n = tx.execute("UPDATE events SET handled = 0 WHERE id = ?1 AND kind IN ('alert', 'device', 'block', 'audit')", params![id]).unwrap_or(0);
        tx.commit().is_ok() && (n > 0 || !row_quiet_keys(&row).is_empty())
    }

    /// Marks a device's sudden-blocks alerts dealt with.
    pub fn handle_surge(&self, device: &str) {
        let _ = self.db().execute("UPDATE events SET handled = 1 WHERE device = ?1 AND kind = 'alert' AND reason = 'surge'", params![device]);
    }

    /// Drops every quiet rule for a device (policy changed or the device was forgotten).
    pub fn clear_quiet_device(&self, device: &str) -> usize {
        if device.is_empty() {
            return 0;
        }
        self.db().execute("DELETE FROM quiet WHERE device = ?1", params![device]).unwrap_or(0)
    }

    /// Drops quiet rules for this device and address, or one port when given.
    pub fn clear_quiet_tuple(&self, device: &str, remote: &str, proto: &str, port: u16) -> usize {
        if remote.is_empty() {
            return 0;
        }
        let db = self.db();
        if proto.is_empty() || port == 0 {
            db.execute("DELETE FROM quiet WHERE device = ?1 AND remote = ?2", params![device, remote]).unwrap_or(0)
        } else {
            db.execute("DELETE FROM quiet WHERE device = ?1 AND remote = ?2 AND proto = ?3 AND port = ?4", params![device, remote, proto, port]).unwrap_or(0)
        }
    }

    /// Drops quiet rules for an address on every device (the address was allowed or blocked on a list).
    pub fn clear_quiet_remote(&self, remote: &str) -> usize {
        if remote.is_empty() {
            return 0;
        }
        self.db().execute("DELETE FROM quiet WHERE remote = ?1", params![remote]).unwrap_or(0)
    }

    /// A failed sign-in or wrong API key, with the source address (and user, when known) kept apart so a quiet rule can target them.
    pub fn auth_alert(&self, user: &str, ip: &str, text: &str) {
        if ip.is_empty() {
            self.note("alert", text);
            return;
        }
        let at = now();
        let day = (at / 86400).to_string();
        let key = format!("alert||auth|{user}|{ip}");
        let db = self.db();
        let bumped = db.execute("UPDATE events SET count = count + 1, last = ?1, text = ?2 WHERE day = ?3 AND key = ?4", params![at, text, day, key]).unwrap_or(0);
        if bumped == 0 {
            let _ = db.execute(
                "INSERT INTO events (first, last, day, kind, device, text, key, count, reason, remote, domain) VALUES (?1, ?1, ?2, 'alert', '', ?3, ?4, 1, 'auth', ?5, ?6)",
                params![at, day, text, key, ip, user],
            );
        }
        let id: i64 = db.query_row("SELECT id FROM events WHERE day = ?1 AND key = ?2", params![day, key], |r| r.get(0)).unwrap_or(0);
        let quiet = quiet_exists(&db, "", ip, "", 0, "", user);
        if quiet {
            let _ = db.execute("UPDATE events SET handled = 1 WHERE id = ?1", params![id]);
        } else if bumped > 0 {
            let _ = db.execute("UPDATE events SET handled = 0 WHERE id = ?1", params![id]);
        }
        drop(db);
        if !quiet {
            crate::notify::event_at("alert", "", text, (id > 0).then_some(id));
        }
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
        let id: i64 = db.query_row("SELECT id FROM events WHERE day = ?1 AND key = ?2", params![day, key], |r| r.get(0)).unwrap_or(0);
        drop(db);
        crate::notify::event_at(kind, device, text, (id > 0).then_some(id));
    }

    pub fn note(&self, kind: &str, text: &str) {
        self.add(kind, "", text, now(), 0);
    }

    /// A refused call: written down (an alert line with reason "refused"),
    /// but kept off the dashboard and out of notifications. `refused_summary`
    /// raises the alert people see.
    pub fn refused(&self, text: &str) {
        let at = now();
        let day = (at / 86400).to_string();
        let key = format!("alert||{text}");
        let db = self.db();
        let bumped = db.execute("UPDATE events SET count = count + 1, last = ?1 WHERE day = ?2 AND key = ?3", params![at, day, key]).unwrap_or(0);
        if bumped == 0 {
            let _ = db.execute(
                "INSERT INTO events (first, last, day, kind, device, text, key, count, reason) VALUES (?1, ?1, ?2, 'alert', '', ?3, ?4, 1, 'refused')",
                params![at, day, text, key],
            );
        }
    }

    /// The one dashboard alert for a user's refused calls. With `id`, that
    /// line gets the new text (no new alert, no new message); without, a new
    /// alert line is made and sent. Returns the line's id.
    pub fn refused_summary(&self, id: Option<i64>, text: &str) -> i64 {
        let at = now();
        let db = self.db();
        if let Some(id) = id {
            if db.execute("UPDATE events SET text = ?1, last = ?2 WHERE id = ?3", params![text, at, id]).unwrap_or(0) == 1 {
                return id;
            }
        }
        let day = (at / 86400).to_string();
        let _ = db.execute(
            "INSERT INTO events (first, last, day, kind, device, text, key, count) VALUES (?1, ?1, ?2, 'alert', '', ?3, ?4, 1)",
            params![at, day, text, format!("alert||refused|{at}|{text}")],
        );
        let id = db.last_insert_rowid();
        drop(db);
        crate::notify::event_at("alert", "", text, Some(id));
        id
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
        let actionable = "handled = 0 AND COALESCE(reason,'') NOT IN ('surge', 'refused') AND COALESCE(outcome,'unknown') != 'dropped' AND NOT (kind = 'device' AND COALESCE(reason,'') = 'port_observed')";
        // The Alerts filter still lists refused calls; Needs a Look leaves them out.
        let alert_rows = actionable.replace("NOT IN ('surge', 'refused')", "!= 'surge'");
        let filter = format!("WHERE ((?1 = 'look' AND kind IN ('alert','device') AND {actionable}) OR (?1 = 'alert' AND kind = 'alert' AND {alert_rows}) OR (?1 NOT IN ('look','alert') AND (?1 = '' OR kind = ?1))) AND (?2 = '%%' OR text LIKE ?2 OR device LIKE ?2) AND last >= ?3 AND last <= ?4");
        let total: i64 = db.query_row(&format!("SELECT COUNT(*) FROM events {filter}"), params![kind, like, since, until], |r| r.get(0)).unwrap_or(0);
        let mut st = match db.prepare(&format!("SELECT id, first, last, kind, device, text, count, handled, COALESCE(reason, ''), COALESCE(remote, ''), COALESCE(dir, ''), CASE WHEN COALESCE(ports,'') != '' THEN ports WHEN port > 0 THEN proto || ' ' || port ELSE COALESCE(proto, '') END, COALESCE(domain, ''), COALESCE(outcome,'unknown') FROM events {filter} ORDER BY {order} LIMIT ?5 OFFSET ?6")) {
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
                outcome:r.get(13)?,
            })
        });
        let mut rows:Vec<Row>=rows.map(|r|r.flatten().collect()).unwrap_or_default();
        if kind=="alert"||kind=="look" {
            for row in &mut rows {
                if row.reason!="port_sweep"&&row.reason!="tcp_failure"{continue;}
                let flow_count:i64=db.query_row("SELECT COUNT(*) FROM pattern_flows WHERE alert_id=?1",params![row.id],|r|r.get(0)).unwrap_or(0);
                let table=if flow_count>0{"pattern_flows"}else{"pattern_support"};
                if let Ok(mut st)=db.prepare(&format!("SELECT port FROM {table} WHERE alert_id=?1 AND handled=0 ORDER BY port")) {
                    if let Ok(ports)=st.query_map(params![row.id],|r|r.get::<_,u16>(0)) {
                        let mut active:Vec<_>=ports.flatten().collect();if active.is_empty(){continue;}
                        let attempts=active.len();active.dedup();let count=if row.reason=="port_sweep"{active.len()}else{attempts};let ports=active.iter().map(|p|format!("tcp {p}")).collect::<Vec<_>>().join(",");
                        if ports!=row.ports||(flow_count>0&&count as i64!=row.count){
                            let label=row.text.split_once(": ").map(|s|format!("{}: ",s.0)).unwrap_or_default();
                            row.text=format!("{label}{count} unresolved TCP {} {} {}.",if row.reason=="port_sweep"{"destination ports"}else{"connection failures"},if row.dir=="out"{"to"}else{"from"},row.remote);
                            row.count=count as i64;row.ports=ports;
                        }
                    }
                }
            }
        }
        (rows,total)
    }

    /// One line by id, or none if it isn't there.
    pub fn get(&self, id: i64) -> Option<Row> {
        let db = self.db();
        db.query_row(
            "SELECT id, first, last, kind, device, text, count, handled, COALESCE(reason, ''), COALESCE(remote, ''), COALESCE(dir, ''), CASE WHEN COALESCE(ports,'') != '' THEN ports WHEN port > 0 THEN proto || ' ' || port ELSE COALESCE(proto, '') END, COALESCE(domain, ''), COALESCE(outcome,'unknown') FROM events WHERE id = ?1",
            params![id],
            |r| Ok(Row {
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
                outcome: r.get(13)?,
            }),
        ).ok()
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

    /// Rough byte size of a Capture Log download for the given filter.
    pub fn download_bytes(&self, kind: &str, search: &str, since: i64, until: i64) -> i64 {
        let (_, total) = self.page(kind, search, since, until, "old", 0, 0);
        // ~120 bytes per line of TSV once written out.
        total.saturating_mul(120)
    }

    pub fn prune(&self, keep_days: i64) {
        let db = self.db();
        let _ = db.execute("DELETE FROM events WHERE last < ?1", params![now() - keep_days * 86400]);
        let _=db.execute_batch("DELETE FROM pattern_flows WHERE alert_id NOT IN (SELECT id FROM events); DELETE FROM pattern_support WHERE alert_id NOT IN (SELECT id FROM events);");
        // Hand the WAL back to the main file and cut it to nothing, so it
        // can't creep up on a small flash disk.
        let _ = db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]fn handled_port_is_removed_from_alert_presentation_not_raw_history(){let log=Log::open(":memory:").unwrap();let a=pattern_alert("8.8.8.8");log.pattern(&a,1000,"unresolved sweep").unwrap();log.handle_stopped_alerts(&a.mac,&Meta{remote:a.remote.clone(),proto:"tcp".into(),port:80,dir:"out".into(),..Default::default()});assert_eq!(log.rows("alert","",0,10)[0].ports,"tcp 443");assert_eq!(log.rows("","",0,10)[0].ports,"tcp 80,tcp 443");}
    #[test]fn pruning_old_events_removes_orphan_pattern_support(){let log=Log::open(":memory:").unwrap();log.pattern(&pattern_alert("8.8.8.8"),1,"old").unwrap();log.prune(1);assert_eq!(log.db().query_row("SELECT COUNT(*) FROM pattern_support",[],|r|r.get::<_,i64>(0)).unwrap(),0);assert_eq!(log.db().query_row("SELECT COUNT(*) FROM pattern_flows",[],|r|r.get::<_,i64>(0)).unwrap(),0);}
    #[test]fn pattern_storage_errors_are_reported(){let log=Log::open(":memory:").unwrap();log.db().execute_batch("PRAGMA query_only=ON;").unwrap();assert!(log.pattern(&pattern_alert("8.8.8.8"),1000,"cannot write").is_err());}
    fn pattern_alert(remote:&str)->crate::detection::Alert{crate::detection::Alert{mac:"aa:bb".into(),remote:remote.into(),outbound:true,audit:false,reason:"port_sweep".into(),ports:vec![80,443],count:12,support:vec![]}}
    #[test]fn pattern_subjects_do_not_collide_in_same_second(){let log=Log::open(":memory:").unwrap();log.pattern(&pattern_alert("8.8.8.8"),1000,"a").unwrap();log.pattern(&pattern_alert("1.1.1.1"),1000,"b").unwrap();assert_eq!(log.rows("alert","",0,10).len(),2);}
    #[test]fn stored_pattern_cooldown_survives_observer_restart(){let log=Log::open(":memory:").unwrap();let a=pattern_alert("8.8.8.8");log.pattern(&a,1000,"first detector").unwrap();log.pattern(&a,1030,"restarted detector").unwrap();assert_eq!(log.rows("alert","",0,10).len(),1);log.pattern(&a,1300,"new window").unwrap();assert_eq!(log.rows("alert","",0,10).len(),2);}
    #[test]fn sweep_partial_handling_preserves_other_port_and_raw_history(){let log=Log::open(":memory:").unwrap();let a=pattern_alert("8.8.8.8");log.pattern(&a,1000,"unresolved sweep").unwrap();let mut m=Meta{reason:"country".into(),remote:a.remote.clone(),proto:"tcp".into(),port:80,dir:"out".into(),outcome:"dropped".into(),..Default::default()};log.add_block("block",&a.mac,"raw drop evidence",1001,0,&m);log.handle_stopped_alerts(&a.mac,&m);assert!(!log.rows("alert","",0,10)[0].handled);m.port=443;m.dir="in".into();log.handle_stopped_alerts(&a.mac,&m);assert!(!log.rows("alert","",0,10)[0].handled);m.dir="out".into();log.handle_stopped_alerts(&a.mac,&m);assert!(log.rows("alert","",0,10).is_empty());assert!(log.rows("","",0,10).iter().any(|r|r.kind=="alert"&&r.handled));assert_eq!(log.rows("block","",0,10).len(),1);}
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
    fn blocked_counts_retain_all_policy_evidence() {
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
        let m = |proto: &str, port: u16, domain: &str| Meta { reason: "telemetry".into(), remote: "51.132.193.107".into(), proto: proto.into(), port, dir: "out".into(), domain: domain.into(), outcome:"unknown".into() };
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

#[cfg(test)]
mod handled_presentation {
    use super::*;
    #[test] fn needs_look_hides_stopped_and_resolved_but_preserves_raw_history() {
        let log=Log::open(":memory:").unwrap();
        log.add_block("alert","a","Stopped by enforcement.",1,0,&Meta{outcome:"dropped".into(),..Default::default()});
        log.add_block("alert","a","Blocked burst",2,0,&Meta{reason:"surge".into(),..Default::default()});
        log.add("device","a","WAN tried tcp 80. It's on the Ports list.",3,0);
        log.add("alert","a","Threat. Audit is on, so it was let through.",4,0);
        log.add("alert","","Bridged traffic isn't filtered",5,0);
        log.handle_id(log.rows("device","",0,20)[0].id);
        assert_eq!(log.rows("", "",0,20).len(),5);
        assert_eq!(log.rows("look", "",0,20).len(),2);
        assert_eq!(log.rows("alert", "",0,20).len(),2);
    }
    #[test] fn resolving_a_flow_is_exact_scoped_and_includes_legacy_text() {
        let log=Log::open(":memory:").unwrap();
        for (device,remote) in [("a","8.8.8.8"),("b","8.8.8.8"),("a","8.8.8.80")] {
            log.add_block("alert",device,&format!("Audit allowed {remote}"),1,0,&Meta{remote:remote.into(),..Default::default()});
        }
        log.add("alert","a","Camera reached to 8.8.8.8, which is on a threat list. Audit is on, so it was let through.",2,0);
        log.handle_resolved_alerts("a","8.8.8.8");
        let raw=log.rows("", "",0,20);assert_eq!(raw.len(),4);assert_eq!(raw.iter().filter(|r|r.handled).count(),2);
    }
}

#[cfg(test)]
mod legacy_port_evidence {
    use super::*;
    #[test] fn restart_uses_only_matching_inbound_drop_evidence_not_audit() {
        let p=std::env::temp_dir().join(format!("foilgw-legacy-port-{}",crate::auth::token()));
        {
            let log=Log::open(p.to_str().unwrap()).unwrap();
            for remote in ["8.8.8.8","8.8.4.4"] {log.add("device","a",&format!("{remote} on the router side tried tcp 80 on Camera. It's on the Ports list."),100,0);}
            for(kind,remote)in [("block","8.8.8.8"),("audit","8.8.4.4")] {log.add_block(kind,"a","Raw evidence",101,0,&Meta{remote:remote.into(),proto:"tcp".into(),port:80,dir:"in".into(),..Default::default()});}
            log.add("device","a","9.9.9.9 on the router side tried tcp 80 on Camera. It's on the Ports list.",100,0);
            log.add_block("block","a","Older stop",101,0,&Meta{remote:"9.9.9.9".into(),proto:"tcp".into(),port:80,dir:"in".into(),..Default::default()});
            log.add("device","a","9.9.9.9 on the router side tried tcp 80 on Camera. It's on the Ports list.",200,0);
            // Simulate a persisted pre-upgrade unclassified row.
            log.db().execute("UPDATE events SET handled=0 WHERE kind='device'",[]).unwrap();
        }
        {let log=Log::open(p.to_str().unwrap()).unwrap();let rows=log.rows("device","",0,10);assert_eq!(rows.len(),3);assert!(!rows.iter().find(|r|r.text.starts_with("9.9.9.9 ")).unwrap().handled);assert!(rows.iter().find(|r|r.text.starts_with("8.8.8.8 ")).unwrap().handled);assert!(!rows.iter().find(|r|r.text.starts_with("8.8.4.4 ")).unwrap().handled);assert_eq!(log.rows("","",0,10).len(),6);}
        let _=std::fs::remove_file(p);
    }
}
