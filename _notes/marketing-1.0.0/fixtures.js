"use strict";
// Dummy marketing data only. No real customer IPs/devices.
const now = Math.floor(Date.now() / 1000);
const port = (name, speed) => ({ name, link: true, speed, ips: ["192.0.2.1/24"], mac: "02:00:00:00:00:01" });

const status = {
  user: "admin",
  version: "1.0.1",
  os: "linux",
  arch: "riscv64",
  board: "Single-board computer",
  host: "foilgateway",
  in_path: true,
  path_note: "",
  mode: "normal",
  auditing: [],
  wan_bps: [12_500_000, 2_800_000],
  lan_bps: [11_200_000, 3_100_000],
  telemetry_all: false,
  wan: port("eth0", "1 Gb/s"),
  lan: port("eth1", "1 Gb/s"),
  wan_name: "eth0",
  lan_name: "eth1",
  lans: ["eth1"],
  filtering: true,
  bridge: true,
  uptime: 12 * 86400 + 4 * 3600,
  daemon_uptime: 3 * 86400 + 2 * 3600,
  cpu: 18,
  temp: 42.5,
  mem_used: 180 * 1024 * 1024,
  mem_total: 512 * 1024 * 1024,
  disk_used: 1.2 * 1024 * 1024 * 1024,
  disk_total: 8 * 1024 * 1024 * 1024,
  blocked_today: 47,
  blocked_usual: 40,
  blocked_alarm_today: 12,
  blocked_alarm_usual: 15,
  alarm_quiet: false,
  new_devices: 0,
  timezone: "America/Los_Angeles",
  hour12: true,
  date_fmt: "mdy",
  offset: -8 * 3600,
  cards: {},
  pending: null,
  admin_nudge: false,
  admin_from_wan: true,
  white_expiry: 0,
  safety: true,
  now: now,
};

const home = { lat: 37.77, lon: -122.42, country: "US" };

const flows = [
  { lat: 37.4, lon: -122.1, dir: "out", bytes: 8_000_000, n: 14, devices: ["Laptop"], names: ["cdn.example"], dest: "Mountain View" },
  { lat: 51.5, lon: -0.12, dir: "out", bytes: 2_400_000, n: 6, devices: ["Phone"], names: ["api.example"], dest: "London" },
  { lat: 35.68, lon: 139.69, dir: "out", bytes: 1_100_000, n: 3, devices: ["TV"], names: ["stream.example"], dest: "Tokyo" },
  { lat: 52.52, lon: 13.4, dir: "in", bytes: 900_000, n: 2, devices: ["NAS"], names: ["backup.example"], dest: "Berlin" },
  { lat: -33.87, lon: 151.21, dir: "out", bytes: 700_000, n: 4, devices: ["Laptop"], names: ["git.example"], dest: "Sydney" },
  { lat: 1.35, lon: 103.82, dir: "out", bytes: 500_000, n: 2, devices: ["Tablet"], names: ["cdn.asia.example"], dest: "Singapore" },
  { lat: 40.71, lon: -74.0, dir: "in", bytes: 1_500_000, n: 5, devices: ["Desktop"], names: ["mail.example"], dest: "New York" },
  { lat: 48.86, lon: 2.35, dir: "out", bytes: 350_000, n: 1, devices: ["Phone"], names: ["maps.example"], dest: "Paris" },
  { lat: 19.43, lon: -99.13, dir: "out", bytes: 280_000, n: 2, devices: ["Laptop"], names: ["shop.example"], dest: "Mexico City" },
  { lat: 55.75, lon: 37.62, dir: "in", bytes: 120_000, n: 1, devices: ["Printer"], names: ["probe.example"], dest: "Moscow" },
  { lat: -23.55, lon: -46.63, dir: "out", bytes: 640_000, n: 3, devices: ["Desktop"], names: ["cdn.br.example"], dest: "Sao Paulo" },
  { lat: 28.61, lon: 77.21, dir: "out", bytes: 410_000, n: 2, devices: ["Phone"], names: ["update.example"], dest: "New Delhi" },
  { lat: 41.9, lon: 12.5, dir: "out", bytes: 220_000, n: 1, devices: ["Laptop"], names: ["news.example"], dest: "Rome" },
  { lat: 59.33, lon: 18.07, dir: "out", bytes: 180_000, n: 1, devices: ["NAS"], names: ["mirror.example"], dest: "Stockholm" },
  { lat: 25.2, lon: 55.27, dir: "out", bytes: 310_000, n: 2, devices: ["TV"], names: ["vod.example"], dest: "Dubai" },
  { lat: 43.65, lon: -79.38, dir: "in", bytes: 760_000, n: 3, devices: ["Desktop"], names: ["vpn.example"], dest: "Toronto" },
  { lat: -26.2, lon: 28.04, dir: "out", bytes: 150_000, n: 1, devices: ["Phone"], names: ["cdn.za.example"], dest: "Johannesburg" },
  { lat: 37.57, lon: 126.98, dir: "out", bytes: 540_000, n: 2, devices: ["Laptop"], names: ["game.example"], dest: "Seoul" },
];

const countries = [
  { code: "US", name: "United States", n: 19 },
  { code: "GB", name: "United Kingdom", n: 6 },
  { code: "JP", name: "Japan", n: 3 },
  { code: "DE", name: "Germany", n: 2 },
  { code: "AU", name: "Australia", n: 4 },
  { code: "SG", name: "Singapore", n: 2 },
  { code: "FR", name: "France", n: 1 },
  { code: "MX", name: "Mexico", n: 2 },
  { code: "BR", name: "Brazil", n: 3 },
  { code: "IN", name: "India", n: 2 },
  { code: "CA", name: "Canada", n: 3 },
  { code: "KR", name: "South Korea", n: 2 },
];

const conns = [
  { key: "1", device: "Laptop", mac: "02:11:22:33:44:01", dir: "out", remote: "203.0.113.10", domain: "cdn.example", owner: "", proto: "tcp", port: 443, what: "HTTPS", place: { country: "United States", lat: 37.4, lon: -122.1 }, bytes: 4200000 },
  { key: "2", device: "Phone", mac: "02:11:22:33:44:02", dir: "out", remote: "198.51.100.20", domain: "api.example", owner: "", proto: "tcp", port: 443, what: "HTTPS", place: { country: "United Kingdom", lat: 51.5, lon: -0.12 }, bytes: 880000 },
  { key: "3", device: "TV", mac: "02:11:22:33:44:03", dir: "out", remote: "203.0.113.55", domain: "stream.example", owner: "", proto: "tcp", port: 443, what: "HTTPS", place: { country: "Japan", lat: 35.68, lon: 139.69 }, bytes: 6200000 },
  { key: "4", device: "NAS", mac: "02:11:22:33:44:04", dir: "in", remote: "198.51.100.90", domain: "backup.example", owner: "", proto: "tcp", port: 22, what: "SSH", place: { country: "Germany", lat: 52.52, lon: 13.4 }, bytes: 1500000 },
  { key: "5", device: "Desktop", mac: "02:11:22:33:44:05", dir: "out", remote: "203.0.113.77", domain: "mail.example", owner: "", proto: "tcp", port: 993, what: "IMAPS", place: { country: "United States", lat: 40.71, lon: -74.0 }, bytes: 210000 },
  { key: "6", device: "Laptop", mac: "02:11:22:33:44:01", dir: "out", remote: "198.51.100.33", domain: "git.example", owner: "", proto: "tcp", port: 443, what: "HTTPS", place: { country: "Australia", lat: -33.87, lon: 151.21 }, bytes: 980000 },
  { key: "7", device: "Phone", mac: "02:11:22:33:44:02", dir: "out", remote: "203.0.113.41", domain: "maps.example", owner: "", proto: "tcp", port: 443, what: "HTTPS", place: { country: "France", lat: 48.86, lon: 2.35 }, bytes: 340000 },
  { key: "8", device: "Desktop", mac: "02:11:22:33:44:05", dir: "out", remote: "198.51.100.70", domain: "update.example", owner: "", proto: "tcp", port: 443, what: "HTTPS", place: { country: "India", lat: 28.61, lon: 77.21 }, bytes: 1250000 },
  { key: "9", device: "TV", mac: "02:11:22:33:44:03", dir: "out", remote: "203.0.113.88", domain: "vod.example", owner: "", proto: "tcp", port: 443, what: "HTTPS", place: { country: "United Arab Emirates", lat: 25.2, lon: 55.27 }, bytes: 8900000 },
  { key: "10", device: "Printer", mac: "02:11:22:33:44:07", dir: "out", remote: "198.51.100.12", domain: "print.example", owner: "", proto: "tcp", port: 443, what: "HTTPS", place: { country: "United States", lat: 37.77, lon: -122.42 }, bytes: 45000 },
  { key: "11", device: "Tablet", mac: "02:11:22:33:44:08", dir: "out", remote: "203.0.113.19", domain: "cdn.asia.example", owner: "", proto: "tcp", port: 443, what: "HTTPS", place: { country: "Singapore", lat: 1.35, lon: 103.82 }, bytes: 670000 },
  { key: "12", device: "NAS", mac: "02:11:22:33:44:04", dir: "out", remote: "198.51.100.101", domain: "mirror.example", owner: "", proto: "tcp", port: 443, what: "HTTPS", place: { country: "Sweden", lat: 59.33, lon: 18.07 }, bytes: 2300000 },
];

const devices = [
  { mac: "02:11:22:33:44:01", label: "Laptop", sub: "Example Inc · 192.0.2.21 · 02:11:22:33:44:01", name: "Laptop", hostname: "laptop", ip: "192.0.2.21", vendor: "Example Inc", policy: "normal", telemetry: false, allow: [], deny: [], first_seen: now - 86400 * 30, last_seen: now - 5, new: false, up_rate: 120000, down_rate: 1800000, up: 5e9, down: 40e9, online: true, audit_until: 0, auditing: false },
  { mac: "02:11:22:33:44:02", label: "Phone", sub: "Phone Co · 192.0.2.22 · 02:11:22:33:44:02", name: "Phone", hostname: "phone", ip: "192.0.2.22", vendor: "Phone Co", policy: "normal", telemetry: false, allow: [], deny: [], first_seen: now - 86400 * 14, last_seen: now - 20, new: false, up_rate: 40000, down_rate: 500000, up: 1e9, down: 8e9, online: true, audit_until: 0, auditing: false },
  { mac: "02:11:22:33:44:03", label: "Living Room TV", sub: "Display Ltd · 192.0.2.30 · 02:11:22:33:44:03", name: "Living Room TV", hostname: "tv", ip: "192.0.2.30", vendor: "Display Ltd", policy: "normal", telemetry: true, allow: [], deny: [], first_seen: now - 86400 * 60, last_seen: now - 8, new: false, up_rate: 10000, down_rate: 4000000, up: 2e9, down: 90e9, online: true, audit_until: 0, auditing: false },
  { mac: "02:11:22:33:44:04", label: "NAS", sub: "Storage Co · 192.0.2.40 · 02:11:22:33:44:04", name: "NAS", hostname: "nas", ip: "192.0.2.40", vendor: "Storage Co", policy: "trusted", telemetry: false, allow: [], deny: [], first_seen: now - 86400 * 90, last_seen: now - 3, new: false, up_rate: 800000, down_rate: 200000, up: 20e9, down: 5e9, online: true, audit_until: 0, auditing: false },
  { mac: "02:11:22:33:44:05", label: "Desktop", sub: "192.0.2.25 · 02:11:22:33:44:05", name: "Desktop", hostname: "desk", ip: "192.0.2.25", vendor: "", policy: "normal", telemetry: false, allow: [], deny: [], first_seen: now - 86400 * 10, last_seen: now - 60, new: false, up_rate: 90000, down_rate: 700000, up: 3e9, down: 12e9, online: true, audit_until: 0, auditing: false },
  { mac: "02:11:22:33:44:06", label: "Guest Tablet", sub: "192.0.2.55 · 02:11:22:33:44:06", name: "Guest Tablet", hostname: "tablet", ip: "192.0.2.55", vendor: "", policy: "lan_only", telemetry: false, allow: [], deny: [], first_seen: now - 86400, last_seen: now - 400, new: true, up_rate: 0, down_rate: 0, up: 50e6, down: 200e6, online: false, audit_until: 0, auditing: false },
  { mac: "02:11:22:33:44:07", label: "Printer", sub: "Print Co · 192.0.2.60 · 02:11:22:33:44:07", name: "Printer", hostname: "printer", ip: "192.0.2.60", vendor: "Print Co", policy: "normal", telemetry: false, allow: [], deny: [], first_seen: now - 86400 * 45, last_seen: now - 90, new: false, up_rate: 5000, down_rate: 20000, up: 80e6, down: 200e6, online: true, audit_until: 0, auditing: false },
  { mac: "02:11:22:33:44:08", label: "Tablet", sub: "192.0.2.58 · 02:11:22:33:44:08", name: "Tablet", hostname: "tablet2", ip: "192.0.2.58", vendor: "", policy: "normal", telemetry: false, allow: [], deny: [], first_seen: now - 86400 * 7, last_seen: now - 15, new: false, up_rate: 30000, down_rate: 400000, up: 400e6, down: 3e9, online: true, audit_until: 0, auditing: false },
];

const alerts = [
  { id: 1, kind: "device", text: "Guest Tablet joined the network", device: "02:11:22:33:44:06", label: "Guest Tablet", reason: "new", last: now - 400, count: 1, handled: false },
  { id: 2, kind: "alert", text: "Laptop tried tcp/445 to 198.51.100.44", device: "02:11:22:33:44:01", label: "Laptop", reason: "port", last: now - 1200, count: 3, handled: false, link: "/devices/troubleshoot?mac=02:11:22:33:44:01" },
  { id: 3, kind: "alert", text: "Phone tried udp/1900 to 198.51.100.50", device: "02:11:22:33:44:02", label: "Phone", reason: "port", last: now - 2400, count: 2, handled: false, link: "/devices/troubleshoot?mac=02:11:22:33:44:02" },
  { id: 4, kind: "block", text: "blocked country RU from Guest Tablet", device: "02:11:22:33:44:06", label: "Guest Tablet", reason: "country", last: now - 800, count: 1, handled: false },
  { id: 5, kind: "alert", text: "Desktop tried tcp/3389 to 203.0.113.9", device: "02:11:22:33:44:05", label: "Desktop", reason: "port", last: now - 3600, count: 1, handled: false, link: "/devices/troubleshoot?mac=02:11:22:33:44:05" },
  { id: 6, kind: "device", text: "Printer joined the network", device: "02:11:22:33:44:07", label: "Printer", reason: "new", last: now - 7200, count: 1, handled: false },
  { id: 7, kind: "block", text: "blocked telemetry to metrics.example", device: "02:11:22:33:44:03", label: "Living Room TV", reason: "telemetry", last: now - 500, count: 8, handled: false },
  { id: 8, kind: "alert", text: "Tablet tried tcp/23 to 203.0.113.200", device: "02:11:22:33:44:08", label: "Tablet", reason: "port", last: now - 1800, count: 4, handled: false, link: "/devices/troubleshoot?mac=02:11:22:33:44:08" },
];

const geo = { on: true, loaded: true, phase: 0, done: 1, total: 1, size_note: "about 86 MB", source: "DB-IP", month: "2026-10", fetched_at: now - 86400, error: "", next_try: 0 };

const logRows = [
  { id: 10, kind: "block", text: "blocked tcp/445 to 198.51.100.44", device: "02:11:22:33:44:01", label: "Laptop", count: 3, last: now - 1200, handled: false, remote: "198.51.100.44", ports: "445", domain: "", dir: "out" },
  { id: 11, kind: "block", text: "blocked country RU", device: "02:11:22:33:44:06", label: "Guest Tablet", count: 1, last: now - 800, handled: false, remote: "203.0.113.200", ports: "443", domain: "probe.example", dir: "out" },
  { id: 12, kind: "device", text: "Guest Tablet joined the network", device: "02:11:22:33:44:06", label: "Guest Tablet", count: 1, last: now - 400, handled: false, remote: "", ports: "", domain: "", dir: "" },
  { id: 13, kind: "audit", text: "would block telemetry to metrics.example", device: "02:11:22:33:44:03", label: "Living Room TV", count: 12, last: now - 200, handled: false, remote: "203.0.113.88", ports: "443", domain: "metrics.example", dir: "out" },
];

module.exports = { now, status, home, flows, countries, conns, devices, alerts, geo, logRows };
