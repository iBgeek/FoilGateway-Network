// 1.2.0 pages in headless Chrome against the running gateway: admin and
// Custom users, every new page and dialog, at 1920x1200, 1024 and 390
// (the narrowest the stylesheet lays out for). Every shot also checks for
// cut-off text and sideways overflow, and the header for date/time only.
// Keys and signing secrets in dialogs are masked (same length) before a
// shot; the real ones go to STATE/secrets only.
// Usage: node ui120.cjs URL OUTDIR STATE
const puppeteer = require("puppeteer-core");
const fs = require("fs");
const path = require("path");
const { findClipped } = require("./clip.js");
const [base, OUT, ST] = process.argv.slice(2);
const PW = "correct horse battery", UPW = "custom-password-123";
const WIDTHS = [[1920, 1200], [1024, 900], [390, 844]];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const report = { shots: [], clipped: [], header: [], errors: {}, net4xx: {}, checks: [] };
const check = (name, ok, detail) => { report.checks.push({ name, ok: !!ok, detail }); console.log((ok ? "PASS " : "FAIL ") + name + (detail !== undefined ? "  " + JSON.stringify(detail).slice(0, 300) : "")); };
// Text wider than its own box (button, label, heading, cell ...), measured with a Range.
function rangeClip() {
  const bad = [];
  for (const el of document.querySelectorAll("button, label, h1, h2, h3, h4, th, td, .pill, a.btn, a.nav, .subnav a, summary, .head .when, .alert, .hint, p")) {
    const r0 = el.getBoundingClientRect();
    if (!r0.width || !r0.height || el.closest("[hidden]") || getComputedStyle(el).visibility === "hidden") continue;
    if (!el.textContent.trim()) continue;
    const r = document.createRange(); r.selectNodeContents(el); const t = r.getBoundingClientRect();
    if (t.right > r0.right + 1 || t.left < r0.left - 1 || t.bottom > r0.bottom + 1) bad.push(`${el.tagName.toLowerCase()}.${(el.className || "").toString().trim().replace(/\s+/g, ".")} "${el.textContent.trim().slice(0, 40)}": text ${Math.round(t.width)}x${Math.round(t.height)} box ${Math.round(r0.width)}x${Math.round(r0.height)}`);
    const cs = getComputedStyle(el);
    if (cs.textOverflow === "ellipsis" && el.scrollWidth > el.clientWidth) bad.push(`${el.tagName} "${el.textContent.trim().slice(0, 40)}": ellipsis`);
  }
  return bad;
}
async function shotAll(p, role, name, opts = {}) {
  const dir = path.join(OUT, role); fs.mkdirSync(dir, { recursive: true });
  for (const [w, hgt] of WIDTHS) {
    await p.setViewport({ width: w, height: hgt });
    await sleep(500);
    if (opts.before) await opts.before();
    const f = path.join(dir, `${name}-${w}.png`);
    await p.screenshot({ path: f, fullPage: w < 1100 });
    report.shots.push(f);
    const c = (await p.evaluate(findClipped)).concat(await p.evaluate(rangeClip));
    for (const x of [...new Set(c)]) report.clipped.push(`${role} ${name} @${w}: ${x}`);
  }
  await p.setViewport({ width: 1920, height: 1200 });
  await sleep(300);
}
async function headerOk(p, role, name, host) {
  const h = await p.evaluate(() => ({ when: document.querySelector(".head .when")?.textContent || "", head: document.querySelector(".head")?.innerText || "" }));
  const ok = h.when && !(host && h.head.includes(host)) && !h.when.includes("·") && /\d/.test(h.when);
  report.header.push({ role, page: name, when: h.when, ok });
  if (!ok) check(`header ${role} ${name}`, false, h);
}
const clickText = (p, text, scope = "body") => p.evaluate((t, s) => { const el = [...document.querySelector(s).querySelectorAll("button,a")].find((x) => x.textContent.trim() === t && x.offsetParent); if (el) el.click(); return !!el; }, text, scope);
const texts = (p, sel) => p.$$eval(sel, (els) => els.filter((e) => e.offsetParent).map((e) => e.textContent.trim()));
const maskInput = (p) => p.evaluate(() => { const i = document.querySelector(".overlay [readonly]"); if (i) i.value = i.value.replace(/^(fgk_)?(.*)$/, (m, a, b) => (a || "") + b.replace(/[0-9a-f]/g, "0")); });
const secretFile = (name, v) => { const f = path.join(ST, "secrets", name); fs.appendFileSync(f, v + "\n", { mode: 0o600 }); };

async function session(b, user, pw) {
  const ctx = await b.createBrowserContext();
  const p = await ctx.newPage();
  await p.setViewport({ width: 1920, height: 1200 });
  report.errors[user] = []; report.net4xx[user] = [];
  p.on("pageerror", (e) => report.errors[user].push(p.url() + " " + e.message));
  p.on("console", (m) => { if (m.type() === "error" && !/Failed to load resource/.test(m.text())) report.errors[user].push(p.url() + " " + m.text()); });
  p.on("response", (r) => { if (r.status() >= 400 && r.url().includes("/api/")) report.net4xx[user].push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname} on ${new URL(p.url()).pathname}`); });
  await p.goto(base + "/login", { waitUntil: "networkidle0" });
  await p.type("input[autocomplete=username]", user);
  await p.type("input[type=password]", pw);
  await clickText(p, "Sign in");
  await p.waitForFunction(() => location.pathname !== "/login", { timeout: 15000 });
  return { p, ctx };
}
async function open(p, url) {
  await p.goto(base + url, { waitUntil: "networkidle0" });
  await p.waitForSelector("main .head h1", { timeout: 15000 });
  await sleep(1200);
}
(async () => {
  const b = await puppeteer.launch({ executablePath: "/usr/bin/google-chrome", headless: true, acceptInsecureCerts: true, args: ["--no-sandbox", "--ignore-certificate-errors"] });
  // ---------- admin ----------
  let { p, ctx } = await session(b, "admin", PW);
  const host = (await p.evaluate(() => fetch("/api/status").then((r) => r.json()))).host || "";
  report.host = host;
  const api = (u, body) => p.evaluate((u, body) => fetch(u, body ? { method: "POST", headers: { "X-FG": "1", "Content-Type": "application/json" }, body: JSON.stringify(body) } : {}).then(async (r) => ({ s: r.status, j: await r.json().catch(() => null) })), u, body);
  // Keep the users table to the ones the pages are about.
  for (const u of (await api("/api/users")).j.users) if (u.name.startsWith("p_") || u.name === "both") await api("/api/users", { action: "remove", name: u.name });
  await api("/api/users", { action: "save", old_name: "", name: "helper", role: "custom", perms: ["status", "handle_alerts", "speed_view", "speed_run", "updates_view", "updates_check"], web: true, api: false, password: UPW });

  await open(p, "/");
  await headerOk(p, "admin", "dashboard", host);
  const clears = (await texts(p, "main .alert-row > button")).filter((t) => t === "Clear").length;
  const shown = await p.evaluate(() => document.querySelectorAll("main .alert-row").length);
  check("admin dashboard: a Clear button on every alert row", clears > 0 && clears === shown, { clears, shown });
  check("admin dashboard: Clear All Shown", (await texts(p, "main button")).includes("Clear All Shown"));
  await shotAll(p, "admin", "dashboard");
  // Clear All Shown on a filtered list: search, then only those go.
  await p.evaluate(() => { const i = document.querySelector("#alert-q"); i.value = "refused: GET /api/settings"; i.dispatchEvent(new Event("input", { bubbles: true })); });
  await sleep(3500);
  const filtered = await p.evaluate(() => document.querySelectorAll("main .alert-row").length);
  await clickText(p, "Clear All Shown");
  await sleep(400);
  const dlg = await p.evaluate(() => document.querySelector(".overlay:not([hidden]) h3")?.textContent);
  check("Clear All dialog title says Clear N Alerts?", dlg === `Clear ${filtered} Alert${filtered === 1 ? "" : "s"}?`, { dlg, filtered });
  await shotAll(p, "admin", "dashboard-clear-all-dialog");
  const before = (await api("/api/dashboard")).j.alerts.length;
  const ids = (await api("/api/dashboard")).j.alerts.filter((a) => a.text.toLowerCase().includes("refused: get /api/settings")).map((a) => a.id);
  await clickText(p, "Clear", ".overlay");
  await sleep(3500);
  const after = (await api("/api/dashboard")).j.alerts;
  const log = (await api("/api/log?q=" + encodeURIComponent("refused: GET /api/settings") + "&limit=1000")).j.rows;
  check("Clear All Shown: only the shown alerts leave the dashboard", ids.length === filtered && !after.some((a) => ids.includes(a.id)) && after.length >= before - filtered, { filtered, before, after: after.length });
  check("cleared alerts stay in the Capture Log marked handled", ids.every((id) => log.find((r) => r.id === id)?.handled === true), { rows: log.length });
  await open(p, "/log?q=" + encodeURIComponent("refused: GET /api/settings"));
  const pills = await p.evaluate(() => document.querySelectorAll("main .pill.handled").length);
  check("Capture Log page shows the cleared lines with a handled pill", pills >= ids.length, { pills, cleared: ids.length });
  await shotAll(p, "admin", "capture-log-handled");
  await open(p, "/");
  await p.evaluate(() => { const i = document.querySelector("#alert-q"); i.value = ""; i.dispatchEvent(new Event("input", { bubbles: true })); });
  await sleep(3500);
  const first = await p.evaluate(() => document.querySelector("main .alert-row")?.dataset.key);
  const firstId = (await api("/api/dashboard")).j.alerts[0]?.id;
  await p.evaluate(() => document.querySelector("main .alert-row > button").click());
  await sleep(3500);
  const still = await p.evaluate((k) => [...document.querySelectorAll("main .alert-row")].some((r) => r.dataset.key === k), first);
  const row1 = (await api("/api/log?limit=1000")).j.rows.find((r) => r.id === firstId);
  check("per-row Clear: row leaves the dashboard, log line handled", !still && row1 && row1.handled, { firstId });

  await open(p, "/settings/users");
  await headerOk(p, "admin", "users", host);
  check("Users page panels", JSON.stringify(await texts(p, "main .panel h2")) === JSON.stringify(["Users", "Your Password", "Signed In", "API Keys"]), await texts(p, "main .panel h2"));
  check("Users table columns", JSON.stringify(await texts(p, "main .panel:first-child th")), await texts(p, "main .panel:first-child th"));
  await shotAll(p, "admin", "users");
  // Edit User on jarvis
  await p.evaluate(() => [...document.querySelectorAll("main tr")].find((r) => r.dataset.key === "jarvis").querySelector("button").click());
  await sleep(500);
  const ed = await p.evaluate(() => ({ title: document.querySelector(".overlay h3")?.textContent, h4: [...document.querySelectorAll(".overlay h4")].map((x) => x.textContent), boxes: document.querySelectorAll(".overlay input[type=checkbox][value]").length, seg: [...document.querySelectorAll(".overlay .seg button")].map((x) => x.textContent + (x.classList.contains("on") ? "*" : "")), btns: [...document.querySelectorAll(".overlay button")].map((x) => x.textContent), cols: getComputedStyle(document.querySelector(".overlay .grid2")).gridTemplateColumns }));
  check("Edit User dialog: Who / How This User Gets In / Monitoring / Actions, 13 boxes, Admin|Custom, New Key + Revoke, two columns", ed.title === "Edit User: jarvis" && ed.boxes === 13 && ed.h4.join() === "Who,How This User Gets In,Monitoring,Actions" && ed.seg.join() === "Admin,Custom*" && ed.btns.includes("New Key") && ed.btns.includes("Revoke") && ed.cols.split(" ").length === 2, ed);
  await shotAll(p, "admin", "edit-user");
  // Typing in the dialog survives the page's 5 s refresh.
  await p.type("#ue-name", "x"); await sleep(6000);
  check("Edit dialog keeps typed text across the page refresh", (await p.$eval("#ue-name", (e) => e.value)) === "jarvisx");
  await p.$eval("#ue-name", (e) => (e.value = "jarvis"));
  await clickText(p, "New Key", ".overlay");
  await p.waitForFunction(() => document.querySelector(".overlay h3")?.textContent === "Copy the Key Now", { timeout: 10000 });
  const key = await p.$eval(".overlay [readonly]", (e) => e.value);
  check("Copy the Key Now shows an fgk_ key", /^fgk_[0-9a-f]{64}$/.test(key));
  secretFile("key-jarvis", key);
  const keyOk = await p.evaluate((k) => fetch("/api/me", { headers: { Authorization: "Bearer " + k } }).then((r) => r.status), key);
  check("the key from the dialog works", keyOk === 200);
  await maskInput(p);
  await shotAll(p, "admin", "copy-key-now", { before: async () => { const f = await p.$eval(".overlay [readonly]", (e) => ({ sh: e.scrollHeight, ch: e.clientHeight, sw: e.scrollWidth, cw: e.clientWidth })); if (f.sh > f.ch + 1 || f.sw > f.cw + 1) report.clipped.push("copy-key-now value not fully shown " + JSON.stringify(f)); } });
  await clickText(p, "Done", ".overlay"); await sleep(1500);
  // Add User dialog
  await clickText(p, "Add User"); await sleep(500);
  await shotAll(p, "admin", "add-user");
  await clickText(p, "Cancel", ".overlay"); await sleep(300);
  // Your Password: typed text survives the refresh.
  await p.type("#my-pw", "abc"); await sleep(6000);
  check("Your Password keeps typed text across the page refresh", (await p.$eval("#my-pw", (e) => e.value)) === "abc");
  await p.$eval("#my-pw", (e) => (e.value = ""));
  // Open the API Reference
  await clickText(p, "Open the API Reference");
  await p.waitForFunction(() => location.pathname === "/settings/api");
  await p.waitForSelector("main .head h1"); await sleep(1500);
  await headerOk(p, "admin", "api", host);
  const refRows = await p.evaluate(() => document.querySelectorAll("main .panel:first-child tbody tr").length);
  const refApi = (await api("/api/reference")).j.routes.length;
  check("API Reference renders every route from /api/reference", refRows === refApi, { refRows, refApi });
  check("API Reference: Users lit in the menu", (await texts(p, ".subnav a.on")).join() === "Users");
  await shotAll(p, "admin", "api-reference");
  // Notifications
  await open(p, "/settings/notify");
  await headerOk(p, "admin", "notify", host);
  check("Notifications panels", (await texts(p, "main .panel h2")).join("|"), await texts(p, "main .panel h2"));
  await shotAll(p, "admin", "notifications");
  await clickText(p, "Add Destination"); await sleep(600);
  await p.type("#nd-name", "Phone"); await p.type("#nd-url", "http://10.10.10.1:8797/phone");
  await clickText(p, "Save");
  await p.waitForFunction(() => /Signing Secret/i.test(document.querySelector(".overlay h3")?.textContent || ""), { timeout: 10000 });
  const sec = await p.$eval(".overlay [readonly]", (e) => e.value);
  check("Add Destination shows the signing secret once (64 hex)", /^[0-9a-f]{64}$/.test(sec), await p.$eval(".overlay h3", (e) => e.textContent));
  secretFile("notify-Phone", sec);
  await maskInput(p);
  await shotAll(p, "admin", "notify-secret-dialog", { before: async () => { const f = await p.$eval(".overlay [readonly]", (e) => ({ sh: e.scrollHeight, ch: e.clientHeight, sw: e.scrollWidth, cw: e.clientWidth })); if (f.sh > f.ch + 1 || f.sw > f.cw + 1) report.clipped.push("secret value not fully shown " + JSON.stringify(f)); } });
  await clickText(p, "Done", ".overlay"); await sleep(1200);
  // Send Test from the page, then Recent Sends shows it.
  const t0 = Date.now() / 1000;
  await p.evaluate(() => [...document.querySelectorAll("main tr")].find((r) => r.textContent.includes("Phone")).querySelectorAll("button")[1].click());
  await sleep(7000);
  const hk = fs.readFileSync(path.join(ST, "hooks.jsonl"), "utf8").trim().split("\n").map(JSON.parse).filter((h) => h.path === "/phone" && h.at >= t0 && h.headers["x-foilgateway-event"] === "test");
  const crypto = require("crypto");
  const vh = hk.find((h) => "sha256=" + crypto.createHmac("sha256", sec).update(h.headers["x-foilgateway-timestamp"] + "." + h.body).digest("hex") === h.headers["x-foilgateway-signature"]);
  check("Send Test (page) arrives and verifies with the dialog's secret", !!vh, { arrived: hk.length });
  // New Secret with confirm
  await p.evaluate(() => [...document.querySelectorAll("main tr")].find((r) => r.textContent.includes("Phone")).querySelector("button").click());
  await sleep(800);
  await clickText(p, "New Secret"); await sleep(400);
  const conf = await p.evaluate(() => document.querySelector(".overlay h3")?.textContent);
  check("New Secret asks first", conf === "Make a New Secret?", conf);
  await shotAll(p, "admin", "notify-new-secret-confirm");
  await clickText(p, "Make New Secret", ".overlay");
  await p.waitForFunction(() => /Signing Secret/i.test(document.querySelector(".overlay h3")?.textContent || ""), { timeout: 10000 });
  const sec2 = await p.$eval(".overlay [readonly]", (e) => e.value);
  secretFile("notify-Phone", sec2);
  check("New Secret gives a different secret", sec2 !== sec && /^[0-9a-f]{64}$/.test(sec2));
  await clickText(p, "Done", ".overlay"); await sleep(3000);
  await shotAll(p, "admin", "notifications-after");
  // Remove (with its confirm) from the page.
  await p.evaluate(() => [...document.querySelectorAll("main tr")].find((r) => r.textContent.includes("Phone")).querySelector("button").click());
  await sleep(800);
  await clickText(p, "Remove"); await sleep(400);
  const rmc = await p.evaluate(() => document.querySelector(".overlay:not([hidden]) h3")?.textContent || "");
  if (rmc) await clickText(p, rmc.startsWith("Remove") ? "Remove" : "OK", ".overlay");
  await sleep(2500);
  check("Remove (page) takes the destination off", !(await api("/api/notify")).j.dests.some((d) => d.name === "Phone"), rmc);
  // Speed test and Updates
  await open(p, "/settings");
  await headerOk(p, "admin", "settings", host);
  check("admin /settings has the speed panel with Run", !!(await p.$("#internet-speed-test")) && !(await p.$eval("#speed-test-action", (e) => e.hidden)));
  await shotAll(p, "admin", "settings-network-speed");
  await open(p, "/settings/updates");
  await headerOk(p, "admin", "updates", host);
  check("admin Updates: Check Now, Install Update, Roll Back", ["Check Now", "Install Update", "Roll Back To Previous Version"].every((t) => texts && true) && (await texts(p, "main button")).filter((t) => ["Check Now", "Install Update", "Roll Back To Previous Version"].includes(t)).length === 3, await texts(p, "main button"));
  await shotAll(p, "admin", "updates");
  for (const [u, n] of [["/devices", "devices"], ["/firewall", "firewall"], ["/ports", "ports"], ["/log", "log"], ["/settings/help", "help"], ["/settings/about", "about"], ["/settings/general", "general"], ["/settings/log", "settings-log"], ["/settings/certs", "certs"], ["/settings/view", "view"], ["/settings/setup", "setup"]]) { await open(p, u); await headerOk(p, "admin", n, host); }
  await ctx.close();

  // ---------- custom users ----------
  const ALL = ["Dashboard", "Devices", "Firewall", "Ports", "Capture Log", "Settings"];
  const roles = {
    jarvis: { perms: "monitoring + device_actions + block_list", nav: ALL, settingsSub: ["Speed Test", "Updates", "Help", "About"], run: false, check: false, clear: false },
    watcher: { perms: "monitoring only", nav: ALL, settingsSub: ["Speed Test", "Updates", "Help", "About"], run: false, check: false, clear: false },
    helper: { perms: "status, handle_alerts, speed_view, speed_run, updates_view, updates_check", nav: ["Dashboard", "Settings"], settingsSub: ["Speed Test", "Updates", "Help", "About"], run: true, check: true, clear: true },
  };
  for (const [role, want] of Object.entries(roles)) {
    ({ p, ctx } = await session(b, role, UPW));
    await open(p, "/");
    await headerOk(p, role, "dashboard", host);
    const nav = await texts(p, "aside a.nav");
    check(`${role}: sidebar shows only allowed pages`, nav.map((t) => t.replace(/\d+$/, "")).join() === want.nav.join(), nav);
    const clr = (await texts(p, "main button")).filter((t) => t === "Clear" || t === "Clear All Shown");
    check(`${role}: Clear buttons ${want.clear ? "shown" : "hidden"} (handle_alerts)`, want.clear ? clr.length > 1 : clr.length === 0, clr.length);
    await shotAll(p, role, "dashboard");
    if (want.clear) { await clickText(p, "Clear All Shown"); await sleep(400); await shotAll(p, role, "dashboard-clear-all-dialog"); await clickText(p, "Cancel", ".overlay"); }
    await open(p, "/settings");
    await headerOk(p, role, "speed-test", host);
    const sub = await texts(p, ".subnav a");
    check(`${role}: Settings shows only allowed subpages`, sub.join() === want.settingsSub.join(), sub);
    const st = await p.evaluate(() => ({ h1: document.querySelector("main h1")?.textContent, panels: [...document.querySelectorAll("main .panel h2")].map((x) => x.textContent), run: !!document.querySelector("#speed-test-action") && !document.querySelector("#speed-test-action").hidden }));
    check(`${role}: /settings is the Speed Test page, speed panel only, Run ${want.run ? "shown" : "hidden"}`, st.h1 === "Settings · Speed Test" && st.panels.length === 1 && st.run === want.run, st);
    await shotAll(p, role, "speed-test");
    await open(p, "/settings/updates");
    await headerOk(p, role, "updates", host);
    const ub = await texts(p, "main button");
    check(`${role}: Updates shows Check Now ${want.check ? "" : "not "}and never Install/Roll Back`, ub.includes("Check Now") === want.check && !ub.includes("Install Update") && !ub.includes("Roll Back To Previous Version"), ub);
    await shotAll(p, role, "updates");
    for (const [u, n] of [["/settings/users", "users"], ["/settings/notify", "notify"], ["/settings/api", "api"], ["/settings/general", "general"], ...(role === "helper" ? [["/devices", "devices"], ["/log", "log"]] : [])]) {
      await open(p, u);
      const t = await p.evaluate(() => ({ h1: document.querySelector("main h1")?.textContent, text: document.querySelector("main")?.innerText.slice(0, 200) }));
      check(`${role}: ${u} shows Not Available`, t.h1 === "Not Available", t.h1);
      await headerOk(p, role, n + "-not-available", host);
      if (n === "users") await shotAll(p, role, "not-available");
    }
    for (const [u, n] of [["/settings/help", "help"], ["/settings/about", "about"]]) { await open(p, u); const h1 = await p.$eval("main h1", (e) => e.textContent); check(`${role}: ${u} opens`, h1 !== "Not Available", h1); await headerOk(p, role, n, host); }
    if (role !== "helper") {
      for (const [u, n] of [["/devices", "devices"], ["/firewall", "firewall"], ["/firewall/black", "blacklist"], ["/ports", "ports"], ["/log", "log"], ["/devices/troubleshoot", "troubleshoot"], ["/firewall/audit", "audit"]]) {
        await open(p, u); await headerOk(p, role, n, host);
        const h1 = await p.$eval("main h1", (e) => e.textContent);
        check(`${role}: ${u} opens`, h1 !== "Not Available", h1);
        if (n === "devices" || n === "blacklist") await shotAll(p, role, n);
        if (n === "blacklist") {
          const add = (await texts(p, "main button")).includes("Add");
          check(`${role}: Black list Add ${role === "jarvis" ? "shown (block_list)" : "hidden"}`, add === (role === "jarvis"), add);
        }
        if (n === "devices") {
          await p.evaluate(() => document.querySelector("main tbody tr")?.click()); await sleep(1500);
          const bt = await p.$$eval("main button", (els) => els.filter((e) => e.offsetParent && !e.disabled).map((e) => e.textContent.trim()));
          check(`${role}: device detail ${role === "jarvis" ? "has Block All" : "has no enabled action buttons"}; never Forget`, bt.includes("Block All") === (role === "jarvis") && !bt.includes("Forget This Device"), bt.filter((t) => /Block|Forget|Save Name|Looks/.test(t)));
          await shotAll(p, role, "device-detail");
        }
      }
    }
    await ctx.close();
  }
  for (const [u, e] of Object.entries(report.errors)) check(`${u}: no JavaScript errors`, e.length === 0, e.slice(0, 5));
  check("header shows date/time only (no device name) on every page visited", report.header.every((h) => h.ok), `${report.header.length} page loads; host "${host}"`);
  fs.writeFileSync(path.join(OUT, "ui120-report.json"), JSON.stringify(report, null, 1));
  console.log(`\nshots ${report.shots.length}, clipped findings ${report.clipped.length}`);
  for (const c of report.clipped.slice(0, 80)) console.log("CLIP " + c);
  for (const [u, n] of Object.entries(report.net4xx)) console.log(`4xx for ${u}: ${n.length} ${[...new Set(n)].slice(0, 8).join("; ")}`);
  const failed = report.checks.filter((c) => !c.ok).length;
  console.log(`${report.checks.length - failed} passed, ${failed} failed`);
  await b.close();
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
