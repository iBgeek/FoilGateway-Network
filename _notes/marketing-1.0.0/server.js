"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const { status, home, flows, countries, conns, devices, alerts, geo, logRows, now } = require("./fixtures");
status.rollback_secs = 180;
status.safety = true;
status.now = now;

const ROOT = path.resolve(__dirname, "../../assets");
const PORT = Number(process.env.PORT || 8765);

const PAGE = fs.readFileSync(path.join(ROOT, "page.html"), "utf8");
const shells = {
  "/": ["dashboard", "Dashboard"],
  "/devices": ["devices", "Devices"],
  "/firewall": ["firewall", "Firewall"],
  "/firewall/mode": ["firewall", "Protection Mode"],
  "/firewall/presets": ["firewall", "Protection Levels"],
  "/log": ["log", "Capture Log"],
  "/settings/updates": ["settings", "Updates"],
  "/settings/about": ["settings", "About"],
};

function shell(name, title) {
  const extra = name === "dashboard" ? '<script src="/s/land.js"></script>\n' : "";
  return PAGE.replace("{title}", title).replace("{name}", name).replace("{extra}", extra);
}

function json(res, obj, code) {
  const body = JSON.stringify(obj);
  res.writeHead(code || 200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(body);
}

function file(res, rel, type) {
  const p = path.join(ROOT, rel);
  if (!p.startsWith(ROOT) || !fs.existsSync(p)) { res.writeHead(404); return res.end("missing"); }
  res.writeHead(200, { "Content-Type": type, "Cache-Control": "no-store" });
  fs.createReadStream(p).pipe(res);
}

const firewall = {
  status,
  mode: "normal",
  telemetry_all: false,
  threats: true,
  strict_outbound: false,
  block_ipv6: false,
  block_vpn: false,
  block_dot: false,
  white_expiry: 0,
  dns_proxy: false,
  sticky_identity: false,
  deep_detect: false,
  peer_filter: false,
  peer_filter_available: false,
  preset: "normal",
  preset_chip: "Normal",
  presets: [
    { id: "normal", label: "Normal", one_line: "Everyday protection.", diff: [], current: true },
    { id: "fortnox", label: "FortNox", one_line: "Strict outbound and telemetry blocked.", diff: [
      { label: "Block All Telemetry", from: "Off", to: "On", why: "FortNox turns telemetry blocking on." },
      { label: "Block Encrypted DNS (Port 853)", from: "Off", to: "On", why: "Keeps name-based blocks from being skipped by DNS over TLS. While On, devices set to require DNS over TLS (for example Android Private DNS set to a provider name) cannot look up names." },
      { label: "Strict Outbound", from: "Off", to: "On", why: "" },
    ], current: false },
    { id: "custom", label: "Custom", one_line: "Your mix of hardening switches.", diff: [], current: false },
  ],
  doh_warning: false,
  rdp_external: false,
  rdp_lan_blocked: false,
  white: [],
  black: [{ entry: "198.51.100.44", addresses: 1, site: false }],
  countries: [],
  all_countries: { US: "United States", GB: "United Kingdom", JP: "Japan", DE: "Germany", RU: "Russia" },
  new_devices: "normal",
  inbound: [],
  feeds: [],
  summary: { devices: devices.length, blocked_today: 47, white: 0, black: 1, countries: 0 },
  rules: "",
  feeds: [{ id: "spamhaus-drop", name: "Spamhaus DROP", entries: 1204, fetched_at: now - 3600, error: "" }],
  telemetry_hosts: 842,
  hardening: {
    threats: true, telemetry_all: false, strict_outbound: false, block_ipv6: false,
    block_vpn: false, block_dot: false, sticky_identity: false, deep_detect: false,
  },
};

const settings = {
  status,
  release: { current: "1.0.1", previous: "0.7.4", lost: [], schema_differs: false },
  cfg: {
    lan: ["eth1"], wan: "eth0", placement: "router_switch", safety: true,
    safety_hosts: ["192.0.2.21"], safety_ports: [22, 8443], admin_port: 8443,
    admin_from: "both", rollback_secs: 180, ip_mode: "dhcp", fixed: null,
  },
  bridge_ips: ["192.0.2.1/24"],
  log_days: 30, log_count: 1280, log_oldest: now - 20 * 86400,
  ports: [
    { name: "eth0", link: true, speed: "1 Gb/s", ips: ["192.0.2.1/24"], mac: "02:00:00:00:00:01" },
    { name: "eth1", link: true, speed: "1 Gb/s", ips: [], mac: "02:00:00:00:00:02" },
  ],
  users: [{ name: "admin", role: "admin" }],
  sessions: [{ id: "abcd", user: "admin", ip: "192.0.2.21", started: now - 600 }],
  geo, timezone: "America/Los_Angeles", hour12: true, date_fmt: "mdy",
  timezones: ["UTC", "America/Los_Angeles", "America/New_York", "Europe/London"],
};

const updates = {
  current: "1.0.1",
  latest: "1.0.1",
  newer: false,
  published_at: "2026-11-05T18:00:00Z",
  last_checked: now - 3600,
  notes: "FoilGateway Network 1.0.0\n\n- Initial release\n- Updates page\n- Protection levels Normal and FortNox\n",
  previous: "0.7.4",
  pending: null,
  error: "",
  progress: { busy: false, phase: "Idle", detail: "", error: "" },
};

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://127.0.0.1");
  const p = u.pathname;

  if (shells[p]) {
    const [name, title] = shells[p];
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(shell(name, title));
  }
  if (p === "/s/app.js") return file(res, "app.js", "application/javascript");
  if (p === "/s/style.css") return file(res, "style.css", "text/css");
  if (p === "/s/land.js") return file(res, "land.js", "application/javascript");
  if (p === "/s/icon.svg") return file(res, "icon.svg", "image/svg+xml");
  if (p === "/s/LICENSE") return file(res, "LICENSE", "text/plain; charset=utf-8");
  if (p === "/s/manual.html") return file(res, "manual.html", "text/html; charset=utf-8");
  if (p === "/s/help/bundle.json") return file(res, "help/bundle.json", "application/json");

  if (p === "/api/dashboard") {
    return json(res, {
      status, online: devices.filter((d) => d.online).length, device_count: devices.length, conns, map: { flows, countries, total: conns.length, unplaced: 0, unplaced_bytes: 0 },
      home, alerts, summary: firewall.summary, geo,
    });
  }
  if (p === "/api/devices") {
    return json(res, { status, devices, total: devices.length, all: devices.length, offset: 0, new_devices: "normal", detail: null });
  }
  if (p === "/api/firewall") {
    if (req.method === "POST") {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        let b = {};
        try { b = JSON.parse(raw || "{}"); } catch (e) {}
        if (b.preview) {
          const modeNames = { normal: "Normal", audit: "Audit", lan_only: "Local Network Only", block_all: "Block Everything" };
          const m = String(b.mode || "");
          const toMode = modeNames[m] || "Normal";
          const toLevel = m === "normal" ? "Normal" : (b.preset === "fortnox" ? "FortNox" : (m === "audit" ? "—" : "Custom"));
          const telTo = b.preset === "fortnox" ? "On" : "Off";
          const diff = [
            { label: "Protection Mode", from: "Normal", to: toMode, why: "" },
          ];
          if (m === "normal") {
            diff.push({ label: "Protection Level", from: "Custom", to: "Normal", why: "Mode Normal applies the Normal level." });
            diff.push({ label: "Block All Telemetry", from: "Off", to: "Off", why: "Normal leaves telemetry allowed." });
          } else if (m === "audit") {
            diff.push({ label: "Blocks", from: "Enforced", to: "Log only", why: "Audit lets traffic through and writes what would be blocked." });
          }
          return json(res, { diff });
        }
        json(res, { pending: false });
      });
      return;
    }
    return json(res, firewall);
  }
  if (p === "/api/log") {
    return json(res, { status, rows: logRows, total: logRows.length, offset: status.offset, download_bytes: 4096 });
  }
  if (p === "/api/settings") return json(res, settings);
  if (p === "/api/updates") return json(res, updates);
  if (p === "/api/updates/progress") return json(res, updates.progress);
  if (p === "/api/updates/ack") return json(res, { ok: true });
  if (p === "/api/certs") {
    return json(res, {
      status,
      ca_name: "FoilGateway Local CA",
      fingerprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
      not_after: now + 86400 * 365,
      names: ["foilgateway.local", "192.0.2.1"],
    });
  }
  if (p === "/api/ports") {
    return json(res, {
      status,
      global: [{ proto: "tcp", port: 443, name: "HTTPS", choice: "allow", risk: null, overrides: 0 }],
      devices: [], overrides: 0, set: true,
    });
  }
  if (p === "/api/ping") return json(res, { ok: true });

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found " + p);
});

server.listen(PORT, "127.0.0.1", () => console.log("marketing mock on http://127.0.0.1:" + PORT));
