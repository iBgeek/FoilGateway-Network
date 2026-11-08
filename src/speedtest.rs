//! One manual, bounded internet measurement. curl isolates resolver and I/O
//! cancellation so a stuck DNS lookup cannot leave a detached Rust worker.
use serde::Serialize;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

const ENDPOINT: &str = "https://speed.cloudflare.com";
#[derive(Clone, Serialize, Debug)]
pub struct ResultData {
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub latency_ms: f64,
    pub at: i64,
}
#[derive(Clone, Serialize, Debug)]
pub struct Snapshot {
    pub state: String,
    pub phase: String,
    pub progress: u8,
    pub elapsed_secs: u64,
    pub running: bool,
    pub error: String,
    pub last: Option<ResultData>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            state: "idle".into(),
            phase: String::new(),
            progress: 0,
            elapsed_secs: 0,
            running: false,
            error: String::new(),
            last: None,
        }
    }
}
#[derive(Default)]
pub struct SpeedTest {
    inner: Mutex<Snapshot>,
    cancel: AtomicBool,
    #[cfg(test)]
    test_target: Mutex<Option<String>>,
}
#[derive(Clone, Copy)]
struct Limits {
    download: u64,
    upload: u64,
    deadline: Duration,
    /// Longest download sample, timed from the first received byte.
    window: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            download: 64 * 1024 * 1024,
            upload: 16 * 1024 * 1024,
            deadline: Duration::from_secs(40),
            window: Duration::from_secs(8),
        }
    }
}
/// Rates exclude DNS, TCP and TLS setup. `response` is request sent to first
/// response byte (curl time_starttransfer - time_pretransfer).
struct Transfer {
    speed_down: f64,
    speed_up: f64,
    response: f64,
}
struct Reap(std::process::Child);
impl Reap {
    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl std::ops::Deref for Reap {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for Reap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for Reap {
    fn drop(&mut self) {
        self.stop();
    }
}

impl SpeedTest {
    pub fn snapshot(&self) -> Snapshot {
        self.inner.lock().unwrap().clone()
    }
    #[cfg(test)]
    pub(crate) fn local_fixture(endpoint: String) -> Self {
        Self {
            test_target: Mutex::new(Some(endpoint)),
            ..Default::default()
        }
    }
    pub fn start(self: &Arc<Self>) -> Result<(), String> {
        #[cfg(test)]
        if let Some(endpoint) = self.test_target.lock().unwrap().clone() {
            return self.start_with(
                endpoint,
                Limits {
                    download: 8192,
                    upload: 4096,
                    deadline: Duration::from_secs(3),
                    window: Duration::from_millis(400),
                },
            );
        }
        self.start_with(ENDPOINT.into(), Limits::default())
    }
    pub fn cancel(&self) {
        let mut s = self.inner.lock().unwrap();
        if s.running {
            self.cancel.store(true, Ordering::Release);
            s.state = "cancelling".into();
        }
    }
    fn start_with(self: &Arc<Self>, endpoint: String, limits: Limits) -> Result<(), String> {
        {
            let mut s = self.inner.lock().unwrap();
            if s.running {
                return Err("A speed test is already running or cancelling.".into());
            }
            let last = s.last.take();
            *s = Snapshot {
                state: "running".into(),
                phase: "Latency".into(),
                running: true,
                last,
                ..Default::default()
            };
            self.cancel.store(false, Ordering::Release);
        }
        let a = self.clone();
        if let Err(e) = std::thread::Builder::new()
            .name("internet-speed-test".into())
            .spawn(move || {
                let result = a.run(&endpoint, limits);
                let mut s = a.inner.lock().unwrap();
                if a.cancel.load(Ordering::Acquire) {
                    s.state = "cancelled".into();
                    s.error.clear();
                } else {
                    match result {
                        Ok(r) => {
                            s.last = Some(r);
                            s.state = "complete".into();
                            s.progress = 100;
                        }
                        Err(e) => {
                            s.state = "failed".into();
                            s.error = e;
                        }
                    }
                }
                s.running = false;
            })
        {
            let mut s = self.inner.lock().unwrap();
            s.running = false;
            s.state = "failed".into();
            s.error = format!("Could not start speed test: {e}");
            return Err(s.error.clone());
        }
        Ok(())
    }
    fn run(&self, endpoint: &str, limits: Limits) -> Result<ResultData, String> {
        let began = Instant::now();
        let end = began + limits.deadline;
        let mut latency = Vec::new();
        for i in 0..3 {
            let v = self.transfer(endpoint, 0, false, "Latency", i * 3, 3, None, began, end)?;
            latency.push(v.response * 1000.0);
        }
        latency.sort_by(f64::total_cmp);
        // One download up to the byte cap, sampled for a fixed window from its first byte,
        // so connection setup and slow start cannot size a tiny sample.
        let window = limits
            .window
            .min(end.saturating_duration_since(Instant::now()) / 3);
        let down = self.transfer(endpoint, limits.download, false, "Download", 10, 60, Some(window), began, end)?;
        let up_pilot = limits.upload.min(64 * 1024).min(limits.upload / 8);
        let pilot = self.transfer(endpoint, up_pilot, true, "Upload", 70, 5, None, began, end)?;
        let up_bytes = (pilot.speed_up * 3.0)
            .max(up_pilot as f64)
            .min((limits.upload - up_pilot) as f64) as u64;
        let up = self.transfer(endpoint, up_bytes, true, "Upload", 75, 24, None, began, end)?;
        Ok(ResultData {
            download_mbps: down.speed_down * 8.0 / 1_000_000.0,
            upload_mbps: up.speed_up * 8.0 / 1_000_000.0,
            latency_ms: latency[1],
            at: crate::caplog::now(),
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn transfer(
        &self,
        endpoint: &str,
        bytes: u64,
        upload: bool,
        phase: &str,
        base: u8,
        span: u8,
        sample: Option<Duration>,
        began: Instant,
        end: Instant,
    ) -> Result<Transfer, String> {
        if self.cancel.load(Ordering::Acquire) {
            return Err("Cancelled".into());
        }
        let left = end
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(15));
        if left.is_zero() {
            return Err("Speed test timed out.".into());
        }
        {
            let mut s = self.inner.lock().unwrap();
            s.phase = phase.into();
            s.progress = base;
        }
        let url = if upload {
            format!("{endpoint}/__up")
        } else {
            format!("{endpoint}/__down?bytes={bytes}")
        };
        let mut cmd = Command::new("curl");
        cmd.args(["--disable","--silent","--show-error","--fail","--noproxy","*","--connect-timeout","3","--max-time",&format!("{:.3}",left.as_secs_f64()),"--header","Accept-Encoding: identity","--write-out","%{stderr}\nFGRESULT %{http_code} %{speed_download} %{speed_upload} %{time_total} %{size_download} %{size_upload} %{time_pretransfer} %{time_starttransfer}\n"]);
        if upload {
            cmd.args([
                "--request",
                "POST",
                "--upload-file",
                "-",
                "--header",
                &format!("Content-Length: {bytes}"),
                "--header",
                "Expect:",
                "--header",
                "Transfer-Encoding:",
                "--header",
                "Content-Type: application/octet-stream",
            ]);
        }
        cmd.args([
            "--max-filesize",
            &if upload { 4096 } else { bytes.max(1) }.to_string(),
        ]);
        cmd.arg(url)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(if upload {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        let mut child = Reap(
            cmd.spawn()
                .map_err(|e| format!("Speed test needs curl: {e}"))?,
        );
        let progress = Arc::new(AtomicU64::new(0));
        let read_progress = progress.clone();
        let mut stdout = child.stdout.take().unwrap();
        let cap = if upload { 4096 } else { bytes };
        let opened = Instant::now();
        // Nanoseconds after `opened` of the first body byte; 0 = none yet.
        let first_at = Arc::new(AtomicU64::new(0));
        let read_first = first_at.clone();
        let reader = std::thread::Builder::new()
            .name("speed-read".into())
            .spawn(move || -> std::io::Result<Body> {
                let mut buf = [0u8; 32768];
                let mut count = 0;
                let mut first = 0;
                let mut start = opened;
                let mut last = opened;
                loop {
                    let room = (cap + 1 - count).min(buf.len() as u64) as usize;
                    if room == 0 {
                        break;
                    }
                    let n = stdout.read(&mut buf[..room])?;
                    if n == 0 {
                        break;
                    }
                    last = Instant::now();
                    if count == 0 {
                        first = n as u64;
                        start = last;
                        read_first.store((last - opened).as_nanos().max(1) as u64, Ordering::Release);
                    }
                    count += n as u64;
                    if !upload {
                        read_progress.store(count, Ordering::Relaxed);
                    }
                }
                Ok(Body { count, first, start: start - opened, last: last - opened })
            })
            .map_err(|e| format!("Could not start measurement reader: {e}"))?;
        let writer = if upload {
            let mut stdin = child.stdin.take().unwrap();
            let pr = progress.clone();
            match std::thread::Builder::new()
                .name("speed-write".into())
                .spawn(move || -> std::io::Result<()> {
                    let mut buf = [0u8; 32768];
                    getrandom::getrandom(&mut buf)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    let mut left = bytes;
                    while left > 0 {
                        let n = left.min(buf.len() as u64) as usize;
                        stdin.write_all(&buf[..n])?;
                        left -= n as u64;
                        pr.store(bytes - left, Ordering::Relaxed);
                    }
                    Ok(())
                }) {
                Ok(h) => Some(h),
                Err(e) => {
                    child.stop();
                    let _ = reader.join();
                    return Err(format!("Could not start measurement writer: {e}"));
                }
            }
        } else {
            None
        };
        let mut stderr = child.stderr.take().unwrap();
        let errors = match std::thread::Builder::new()
            .name("speed-errors".into())
            .spawn(move || {
                let mut v = Vec::new();
                let _ = stderr.by_ref().take(8192).read_to_end(&mut v);
                v
            }) {
            Ok(h) => h,
            Err(e) => {
                child.stop();
                let _ = reader.join();
                if let Some(h) = writer {
                    let _ = h.join();
                }
                return Err(format!("Could not start measurement error reader: {e}"));
            }
        };
        let mut sampled = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(e.to_string());
                }
                Ok(None) => {}
            }
            let first = first_at.load(Ordering::Acquire);
            if let (Some(window), true) = (sample, first > 0) {
                if opened.elapsed() >= Duration::from_nanos(first) + window {
                    // Sample complete: stop the transfer ourselves and reap curl.
                    child.stop();
                    sampled = true;
                    break child.wait().map_err(|e| e.to_string());
                }
            }
            if self.cancel.load(Ordering::Acquire) || Instant::now() >= end {
                let _ = child.kill();
                let _ = child.wait();
                break Err(if self.cancel.load(Ordering::Acquire) {
                    "Cancelled".into()
                } else {
                    "Speed test timed out.".into()
                });
            }
            {
                let mut s = self.inner.lock().unwrap();
                s.elapsed_secs = began.elapsed().as_secs();
                let by_bytes = (progress.load(Ordering::Relaxed).min(bytes) * span as u64)
                    .checked_div(bytes)
                    .unwrap_or(0);
                let by_time = match (sample, first) {
                    (Some(w), f) if f > 0 && !w.is_zero() => ((opened.elapsed().saturating_sub(Duration::from_nanos(f)).as_secs_f64()
                        / w.as_secs_f64())
                    .min(1.0)
                        * span as f64) as u64,
                    _ => 0,
                };
                s.progress = base + by_bytes.max(by_time).min(span as u64) as u8;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let read = reader
            .join()
            .map_err(|_| "Speed reader stopped unexpectedly".to_string())
            .and_then(|r| r.map_err(|e| e.to_string()));
        let written = writer
            .map(|h| {
                h.join()
                    .map_err(|_| "Speed writer stopped unexpectedly".to_string())
                    .and_then(|r| r.map_err(|e| e.to_string()))
            })
            .unwrap_or(Ok(()));
        let raw = errors.join().unwrap_or_default();
        let err = String::from_utf8_lossy(&raw);
        let status = status?;
        if sampled {
            // We ended the download at the sample window; use our own byte accounting.
            let body = read?;
            if body.count > bytes {
                return Err("Measurement server returned an unexpected body length.".into());
            }
            return body_rate(&body).map(|speed_down| Transfer {
                speed_down,
                speed_up: 0.0,
                response: 0.0,
            });
        }
        if !status.success() {
            return Err(format!(
                "Speed test failed (curl {}): {}",
                status.code().unwrap_or(-1),
                err.lines()
                    .filter(|l| !l.starts_with("FGRESULT"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
        }
        let body = read?;
        let count = body.count;
        written?;
        if (!upload && count != bytes) || (upload && count > 4096) {
            return Err("Measurement server returned an unexpected body length.".into());
        }
        let fields: Vec<_> = err
            .lines()
            .find_map(|l| l.strip_prefix("FGRESULT "))
            .ok_or("Measurement statistics missing.")?
            .split_whitespace()
            .collect();
        if fields.len() != 8 || !fields[0].starts_with('2') {
            return Err("Measurement server rejected the test.".into());
        }
        let n = |i: usize| -> Result<f64, String> {
            let v = fields[i]
                .parse::<f64>()
                .map_err(|_| "Invalid measurement.".to_string())?;
            if v.is_finite() && v >= 0.0 {
                Ok(v)
            } else {
                Err("Invalid measurement.".into())
            }
        };
        if upload && n(5)? as u64 != bytes {
            return Err("Upload was not fully sent.".into());
        }
        let (total, pre, start) = (n(3)?, n(6)?, n(7)?);
        if start < pre || total < start {
            return Err("Invalid measurement.".into());
        }
        let speed_down = if sample.is_some() { body_rate(&body)? } else { 0.0 };
        let speed_up = if upload {
            // Request start to finish, after connection setup.
            let t = total - pre;
            if t <= 0.0 {
                return Err("Invalid measurement.".into());
            }
            bytes as f64 / t
        } else {
            0.0
        };
        Ok(Transfer {
            speed_down,
            speed_up,
            response: start - pre,
        })
    }
}

/// What the reader saw: total bytes, bytes in the first read, time of the last read.
struct Body {
    count: u64,
    first: u64,
    start: Duration,
    last: Duration,
}
/// Bytes after the first read, over first-read to last-read time: excludes setup
/// and time to first byte.
fn body_rate(b: &Body) -> Result<f64, String> {
    let t = b.last.saturating_sub(b.start).as_secs_f64();
    let n = b.count.saturating_sub(b.first);
    if t <= 0.0 || n == 0 {
        return Err("Download ended too quickly to measure.".into());
    }
    Ok(n as f64 / t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    fn server(fail: bool, stall: bool) -> (String, std::thread::JoinHandle<()>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            for _ in 0..if fail || stall { 1 } else { 6 } {
                let (mut s, _) = l.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut head = Vec::new();
                let mut b = [0; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read_exact(&mut b).is_err() {
                        return;
                    }
                    head.push(b[0]);
                    assert!(head.len() < 8192);
                }
                if stall {
                    std::thread::sleep(Duration::from_millis(300));
                    return;
                }
                if fail {
                    let _ = s.write_all(
                        b"HTTP/1.1 503 Unavailable\r\nContent-Length:0\r\nConnection:close\r\n\r\n",
                    );
                    return;
                }
                let text = String::from_utf8_lossy(&head);
                let first = text.lines().next().unwrap();
                if first.starts_with("POST") {
                    let len = text
                        .lines()
                        .find_map(|l| {
                            l.to_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    let mut body = vec![0; len];
                    s.read_exact(&mut body).unwrap();
                    assert!(
                        len <= 3584,
                        "upload must use a small pilot, then stay within its total cap"
                    );
                    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nConnection:close\r\n\r\n")
                        .unwrap();
                } else {
                    let len = first
                        .split("bytes=")
                        .nth(1)
                        .unwrap()
                        .split(' ')
                        .next()
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    assert!(len <= 8192, "download must stay within its total cap");
                    write!(
                        s,
                        "HTTP/1.1 200 OK\r\nContent-Length:{len}\r\nConnection:close\r\n\r\n"
                    )
                    .unwrap();
                    // Paced in chunks so the sample has more than one read.
                    for c in vec![7; len].chunks(1024) {
                        if s.write_all(c).is_err() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            }
        });
        (format!("http://{addr}"), h)
    }
    fn limits() -> Limits {
        Limits {
            download: 8192,
            upload: 4096,
            deadline: Duration::from_millis(1500),
            window: Duration::from_millis(300),
        }
    }
    fn finished(s: &SpeedTest) -> Snapshot {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let v = s.snapshot();
            if !v.running {
                return v;
            }
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    fn local_success_and_restart_have_real_results() {
        let s = Arc::new(SpeedTest::default());
        let (u, h) = server(false, false);
        s.start_with(u, limits()).unwrap();
        let v = finished(&s);
        h.join().unwrap();
        assert_eq!(v.state, "complete", "{v:?}");
        let r = v.last.unwrap();
        assert!(r.download_mbps > 0.0 && r.upload_mbps > 0.0 && r.latency_ms > 0.0);
        assert_eq!(v.progress, 100);
        let (u, h) = server(false, false);
        s.start_with(u, limits()).unwrap();
        assert_eq!(finished(&s).state, "complete");
        h.join().unwrap();
    }
    #[test]
    fn failed_response_never_creates_a_result() {
        let s = Arc::new(SpeedTest::default());
        let (u, h) = server(true, false);
        s.start_with(u, limits()).unwrap();
        let v = finished(&s);
        h.join().unwrap();
        assert_eq!(v.state, "failed");
        assert!(v.last.is_none());
        assert!(!v.error.is_empty());
    }
    #[test]
    fn cancel_blocks_duplicate_start_until_worker_cleanup() {
        let s = Arc::new(SpeedTest::default());
        let (u, h) = server(false, true);
        s.start_with(u.clone(), limits()).unwrap();
        assert!(s.start_with(u.clone(), limits()).is_err());
        std::thread::sleep(Duration::from_millis(40));
        s.cancel();
        assert_eq!(finished(&s).state, "cancelled");
        h.join().unwrap();
        let (u, h) = server(false, false);
        s.start_with(u, limits()).unwrap();
        assert_eq!(finished(&s).state, "complete");
        h.join().unwrap();
    }
    #[test]
    fn timeout_cleans_up_without_partial_success() {
        let s = Arc::new(SpeedTest::default());
        let (u, h) = server(false, true);
        s.start_with(
            u,
            Limits {
                deadline: Duration::from_millis(70),
                ..limits()
            },
        )
        .unwrap();
        let v = finished(&s);
        h.join().unwrap();
        assert_eq!(v.state, "failed");
        assert!(v.last.is_none());
    }
}

#[cfg(test)]
mod invalid_transport {
    use super::*;
    #[test]
    fn extra_truncated_and_redirected_responses_are_not_measurements() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length:2\r\nConnection:close\r\n\r\nxx".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length:2\r\nConnection:close\r\n\r\nx".as_slice(),
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/forbidden\r\nContent-Length:0\r\nConnection:close\r\n\r\n".as_slice(),
        ] {
            let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap();let endpoint=format!("http://{}",listener.local_addr().unwrap());let response=response.to_vec();
            let h=std::thread::spawn(move||{let(mut s,_)=listener.accept().unwrap();let mut b=[0;4096];let _=s.read(&mut b);let _=s.write_all(&response);});
            let test=SpeedTest::default();let began=Instant::now();assert!(test.transfer(&endpoint,0,false,"Latency",0,3,None,began,began+Duration::from_secs(1)).is_err());h.join().unwrap();
        }
    }
}

#[cfg(test)]
mod cleanup_guard {
    use super::*;
    #[test]
    fn an_early_return_kills_and_reaps_its_owned_child() {
        let pid;
        {
            let child = Reap(
                Command::new("cat")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            pid = child.id();
        }
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }
}

#[cfg(test)]
mod measurement_accuracy {
    //! Controlled loopback endpoints: known pacing, known setup delays, counted bytes.
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicUsize;

    struct Endpoint {
        url: String,
        stop: Arc<AtomicBool>,
        sent: Arc<AtomicU64>,
        received: Arc<AtomicU64>,
        conns: Arc<AtomicUsize>,
        h: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Endpoint {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(h) = self.h.take() {
                let _ = h.join();
            }
        }
    }
    #[derive(Clone, Copy)]
    struct Shape {
        /// Delay before the response headers (time to first byte).
        ttfb: Duration,
        /// Delay before the TLS handshake starts (setup only), TLS endpoints only.
        handshake: Duration,
        /// Download pacing in bytes per second.
        rate: u64,
        /// Upload consumption pacing in bytes per second (0 = as fast as possible).
        up_rate: u64,
    }
    fn serve<S: Read + Write>(mut s: S, shape: Shape, sent: &AtomicU64, received: &AtomicU64, stop: &AtomicBool) {
        let mut head = Vec::new();
        let mut b = [0; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if s.read_exact(&mut b).is_err() || head.len() > 8192 {
                return;
            }
            head.push(b[0]);
        }
        let text = String::from_utf8_lossy(&head).to_string();
        let first = text.lines().next().unwrap_or("").to_string();
        if first.starts_with("POST") {
            let len = text
                .lines()
                .find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<u64>().unwrap()))
                .unwrap_or(0);
            let mut buf = [0u8; 16384];
            let mut got = 0;
            let began = Instant::now();
            while got < len {
                if shape.up_rate > 0 {
                    let due = Duration::from_secs_f64(got as f64 / shape.up_rate as f64);
                    if let Some(wait) = due.checked_sub(began.elapsed()) {
                        std::thread::sleep(wait);
                    }
                }
                let n = match s.read(&mut buf[..(len - got).min(16384) as usize]) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n as u64,
                };
                got += n;
                received.fetch_add(n, Ordering::Relaxed);
            }
            std::thread::sleep(shape.ttfb);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nConnection:close\r\n\r\n");
            let _ = s.flush();
            return;
        }
        let len: u64 = first.split("bytes=").nth(1).and_then(|v| v.split(' ').next()).and_then(|v| v.parse().ok()).unwrap_or(0);
        std::thread::sleep(shape.ttfb);
        if write!(s, "HTTP/1.1 200 OK\r\nContent-Length:{len}\r\nConnection:close\r\n\r\n").is_err() || s.flush().is_err() {
            return;
        }
        let chunk = vec![7u8; 8192];
        let start = Instant::now();
        let mut done = 0u64;
        while done < len && !stop.load(Ordering::Acquire) {
            let k = (len - done).min(chunk.len() as u64);
            if s.write_all(&chunk[..k as usize]).is_err() || s.flush().is_err() {
                return;
            }
            done += k;
            sent.fetch_add(k, Ordering::Relaxed);
            let due = Duration::from_secs_f64(done as f64 / shape.rate as f64);
            if let Some(wait) = due.checked_sub(start.elapsed()) {
                std::thread::sleep(wait);
            }
        }
    }
    fn endpoint(shape: Shape, tls: bool) -> Endpoint {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let port = l.local_addr().unwrap().port();
        let (stop, sent, received, conns) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)), Arc::new(AtomicUsize::new(0)));
        let config = tls.then(|| {
            let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let dir = std::env::temp_dir().join(format!("fg-speed-ca-{}-{port}.pem", std::process::id()));
            std::fs::write(&dir, c.cert.pem()).unwrap();
            std::env::set_var("CURL_CA_BUNDLE", &dir);
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(c.key_pair.serialize_der().into());
            Arc::new(
                rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(vec![c.cert.der().clone()], key)
                    .unwrap(),
            )
        });
        let (st, se, re, co) = (stop.clone(), sent.clone(), received.clone(), conns.clone());
        let h = std::thread::spawn(move || {
            let mut workers = Vec::new();
            while !st.load(Ordering::Acquire) {
                match l.accept() {
                    Ok((s, _)) => {
                        s.set_nonblocking(false).unwrap();
                        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                        co.fetch_add(1, Ordering::Relaxed);
                        let (st, se, re, config) = (st.clone(), se.clone(), re.clone(), config.clone());
                        workers.push(std::thread::spawn(move || match config {
                            Some(cfg) => {
                                std::thread::sleep(shape.handshake);
                                let conn = rustls::ServerConnection::new(cfg).unwrap();
                                serve(rustls::StreamOwned::new(conn, s), shape, &se, &re, &st)
                            }
                            None => serve::<TcpStream>(s, shape, &se, &re, &st),
                        }));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            for w in workers {
                let _ = w.join();
            }
        });
        let scheme = if tls { "https://localhost" } else { "http://127.0.0.1" };
        Endpoint { url: format!("{scheme}:{port}"), stop, sent, received, conns, h: Some(h) }
    }
    fn run(e: &Endpoint, limits: Limits) -> Snapshot {
        let s = Arc::new(SpeedTest::default());
        s.start_with(e.url.clone(), limits).unwrap();
        let end = Instant::now() + limits.deadline + Duration::from_secs(5);
        loop {
            let v = s.snapshot();
            if !v.running {
                return v;
            }
            assert!(Instant::now() < end, "worker did not finish");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    /// True when no child process of this test binary is still talking to `url`
    /// (other tests run curl in parallel against their own endpoints).
    fn no_children(url: &str) -> bool {
        std::fs::read_dir("/proc/self/task").unwrap().all(|t| {
            std::fs::read_to_string(t.unwrap().path().join("children"))
                .unwrap_or_default()
                .split_whitespace()
                .all(|pid| !std::fs::read(format!("/proc/{pid}/cmdline")).map(|c| String::from_utf8_lossy(&c).contains(url)).unwrap_or(false))
        })
    }

    #[test]
    fn slow_first_byte_does_not_shrink_a_fast_download_result() {
        // 2 MB/s link where every response waits 400 ms before its first byte.
        let e = endpoint(Shape { ttfb: Duration::from_millis(400), handshake: Duration::ZERO, rate: 2_000_000, up_rate: 0 }, false);
        let limits = Limits { download: 6 * 1024 * 1024, upload: 1024 * 1024, deadline: Duration::from_secs(12), ..Limits::default() };
        let v = run(&e, limits);
        assert_eq!(v.state, "complete", "{v:?}");
        let r = v.last.unwrap();
        let ratio = r.download_mbps / (2.0 * 8.0);
        eprintln!("MEASURED fast: {r:?} sent={} received={}", e.sent.load(Ordering::Relaxed), e.received.load(Ordering::Relaxed));
        assert!((0.75..=1.25).contains(&ratio), "download {:.2} Mbps vs 16 Mbps paced (ratio {ratio:.2})", r.download_mbps);
        assert!(e.sent.load(Ordering::Relaxed) <= limits.download, "download cap");
        assert!(e.received.load(Ordering::Relaxed) <= limits.upload, "upload cap");
    }

    #[test]
    fn paced_upload_with_reply_delay_is_measured_near_its_rate() {
        // Server reads the body at 500 KB/s, then waits 60 ms before replying.
        let e = endpoint(Shape { ttfb: Duration::from_millis(60), handshake: Duration::ZERO, rate: 4_000_000, up_rate: 500_000 }, false);
        let limits = Limits { download: 2 * 1024 * 1024, upload: 16 * 1024 * 1024, deadline: Duration::from_secs(15), ..Limits::default() };
        let v = run(&e, limits);
        assert_eq!(v.state, "complete", "{v:?}");
        let r = v.last.unwrap();
        let received = e.received.load(Ordering::Relaxed);
        eprintln!("MEASURED upload: {r:?} received={received}");
        let ratio = r.upload_mbps / (0.5 * 8.0);
        assert!((0.75..=1.25).contains(&ratio), "upload ratio {ratio:.2}");
        assert!(received > 1024 * 1024, "main upload must be sized from the pilot, not stay tiny");
        assert!(received <= limits.upload);
    }

    #[test]
    fn slow_link_is_measured_within_the_time_cap() {
        let e = endpoint(Shape { ttfb: Duration::from_millis(200), handshake: Duration::ZERO, rate: 150_000, up_rate: 0 }, false);
        let limits = Limits { download: 64 * 1024 * 1024, upload: 256 * 1024, deadline: Duration::from_secs(9), ..Limits::default() };
        let began = Instant::now();
        let v = run(&e, limits);
        assert!(began.elapsed() < limits.deadline + Duration::from_secs(1));
        assert_eq!(v.state, "complete", "{v:?}");
        eprintln!("MEASURED slow: {:?} sent={} elapsed={:?}", v.last, e.sent.load(Ordering::Relaxed), began.elapsed());
        let ratio = v.last.unwrap().download_mbps / (0.15 * 8.0);
        assert!((0.75..=1.25).contains(&ratio), "slow-link ratio {ratio:.2}");
        assert!(e.sent.load(Ordering::Relaxed) < 2 * 1024 * 1024, "time window, not the 64 MiB cap, must end a slow download");
        assert!(no_children(&e.url));
    }

    #[test]
    fn latency_excludes_tls_setup() {
        // 300 ms before the TLS handshake starts; the HTTP response itself is immediate.
        let e = endpoint(Shape { ttfb: Duration::ZERO, handshake: Duration::from_millis(300), rate: 4_000_000, up_rate: 0 }, true);
        let limits = Limits { download: 2 * 1024 * 1024, upload: 256 * 1024, deadline: Duration::from_secs(12), ..Limits::default() };
        let v = run(&e, limits);
        assert_eq!(v.state, "complete", "{v:?}");
        let r = v.last.unwrap();
        eprintln!("MEASURED tls: {r:?}");
        assert!(r.latency_ms < 150.0, "latency {:.1} ms includes TLS setup", r.latency_ms);
        assert!(r.latency_ms >= 0.0);
    }

    #[test]
    fn response_delay_is_still_reported_as_http_latency() {
        let e = endpoint(Shape { ttfb: Duration::from_millis(120), handshake: Duration::ZERO, rate: 4_000_000, up_rate: 0 }, false);
        let limits = Limits { download: 2 * 1024 * 1024, upload: 256 * 1024, deadline: Duration::from_secs(12), ..Limits::default() };
        let r = run(&e, limits).last.unwrap();
        eprintln!("MEASURED ttfb120: {r:?}");
        assert!((110.0..400.0).contains(&r.latency_ms), "latency {:.1}", r.latency_ms);
    }

    #[test]
    fn cancel_during_a_streaming_download_reaps_curl_and_allows_restart() {
        let e = endpoint(Shape { ttfb: Duration::ZERO, handshake: Duration::ZERO, rate: 200_000, up_rate: 0 }, false);
        let limits = Limits { download: 64 * 1024 * 1024, upload: 64 * 1024, deadline: Duration::from_secs(20), ..Limits::default() };
        let s = Arc::new(SpeedTest::default());
        s.start_with(e.url.clone(), limits).unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        while s.snapshot().phase != "Download" || e.sent.load(Ordering::Relaxed) == 0 {
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(s.start_with(e.url.clone(), limits).is_err(), "duplicate start");
        s.cancel();
        let end = Instant::now() + Duration::from_secs(3);
        while s.snapshot().running {
            assert!(Instant::now() < end, "cancel must finish promptly");
            std::thread::sleep(Duration::from_millis(10));
        }
        let v = s.snapshot();
        assert_eq!(v.state, "cancelled");
        assert!(v.last.is_none());
        assert!(no_children(&e.url), "curl must be reaped");
        assert!(e.conns.load(Ordering::Relaxed) >= 4);
    }
}
