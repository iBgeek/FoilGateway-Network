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
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            download: 64 * 1024 * 1024,
            upload: 16 * 1024 * 1024,
            deadline: Duration::from_secs(40),
        }
    }
}
struct Transfer {
    speed_down: f64,
    speed_up: f64,
    seconds: f64,
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
            let v = self.transfer(endpoint, 0, false, "Latency", i * 3, 3, began, end)?;
            latency.push(v.seconds * 1000.0);
        }
        latency.sort_by(f64::total_cmp);
        let down_pilot = limits.download.min(64 * 1024).min(limits.download / 8);
        let pilot = self.transfer(endpoint, down_pilot, false, "Download", 10, 5, began, end)?;
        let down_bytes = (pilot.speed_down * 3.0)
            .max(down_pilot as f64)
            .min((limits.download - down_pilot) as f64) as u64;
        let down = self.transfer(endpoint, down_bytes, false, "Download", 15, 55, began, end)?;
        let up_pilot = limits.upload.min(64 * 1024).min(limits.upload / 8);
        let pilot = self.transfer(endpoint, up_pilot, true, "Upload", 70, 5, began, end)?;
        let up_bytes = (pilot.speed_up * 3.0)
            .max(up_pilot as f64)
            .min((limits.upload - up_pilot) as f64) as u64;
        let up = self.transfer(endpoint, up_bytes, true, "Upload", 75, 24, began, end)?;
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
        cmd.args(["--disable","--silent","--show-error","--fail","--noproxy","*","--connect-timeout","3","--max-time",&format!("{:.3}",left.as_secs_f64()),"--header","Accept-Encoding: identity","--write-out","%{stderr}\nFGRESULT %{http_code} %{speed_download} %{speed_upload} %{time_total} %{size_download} %{size_upload}\n"]);
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
        let reader = std::thread::Builder::new()
            .name("speed-read".into())
            .spawn(move || -> std::io::Result<u64> {
                let mut buf = [0u8; 32768];
                let mut count = 0;
                loop {
                    let room = (cap + 1 - count).min(buf.len() as u64) as usize;
                    if room == 0 {
                        break;
                    }
                    let n = stdout.read(&mut buf[..room])?;
                    if n == 0 {
                        break;
                    }
                    count += n as u64;
                    if !upload {
                        read_progress.store(count, Ordering::Relaxed);
                    }
                }
                Ok(count)
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
                s.progress = base
                    + (progress.load(Ordering::Relaxed).min(bytes) * span as u64)
                        .checked_div(bytes)
                        .unwrap_or(0) as u8;
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
        let count = read?;
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
        if fields.len() != 6 || !fields[0].starts_with('2') {
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
        Ok(Transfer {
            speed_down: n(1)?,
            speed_up: n(2)?,
            seconds: n(3)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    fn server(fail: bool, stall: bool) -> (String, std::thread::JoinHandle<()>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            for _ in 0..if fail || stall { 1 } else { 7 } {
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
                    assert!(
                        len <= 7168,
                        "download must use a small pilot, then stay within its total cap"
                    );
                    write!(
                        s,
                        "HTTP/1.1 200 OK\r\nContent-Length:{len}\r\nConnection:close\r\n\r\n"
                    )
                    .unwrap();
                    s.write_all(&vec![7; len]).unwrap();
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
            let test=SpeedTest::default();let began=Instant::now();assert!(test.transfer(&endpoint,0,false,"Latency",0,3,began,began+Duration::from_secs(1)).is_err());h.join().unwrap();
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
