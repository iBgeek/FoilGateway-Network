// 1.2.0 round 3: one Custom user per permission (web on). Sign in as each
// in Chrome, record where they land, check that permission's own controls
// are there, count every 4xx and JS error, and screenshot the landing at 1920.
// Usage (in fgw-lap): node land120.cjs URL OUTDIR
const puppeteer = require("puppeteer-core");
const fs = require("fs"), path = require("path");
const [base, out, only] = process.argv.slice(2); // only: re-check one permission (user l2_<perm>, own json)
const shots = path.join(out, "landing"); fs.mkdirSync(shots, { recursive: true });
const PW = "correct horse battery", UPW = "custom-password-123";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Where each lands, and how to see its own controls there (or one menu click on).
const WANT = {
  status: "/", devices: "/devices", alerts: "/devices", log: "/log", firewall_view: "/firewall",
  speed_view: "/settings", updates_view: "/settings/updates", device_actions: "/devices", block_list: "/firewall",
  allow_list: "/firewall", handle_alerts: "/", speed_run: "/settings", updates_check: "/settings/updates",
};
// Runs in the page; returns { ok, detail }.
const CONTROLS = {
  status: () => ({ ok: !!document.querySelector("main .cards.stats") && document.querySelectorAll("main .alert-row").length > 0, detail: "stat cards + alert rows" }),
  devices: () => ({ ok: document.querySelectorAll("main table tbody tr").length > 0 && !!document.querySelector("#dev-q"), detail: "device table + search" }),
  alerts: () => ({ ok: vis([...document.querySelectorAll("a")].find((a) => a.textContent === "What's Blocked for It")) && vis(document.querySelector('.subnav a[href="/devices/troubleshoot"]')), detail: "What's Blocked for It + Troubleshooter menu" }),
  log: () => ({ ok: document.querySelectorAll("main table tbody tr").length > 0 && !!document.querySelector("main input"), detail: "log rows + search" }),
  firewall_view: () => ({ ok: vis(document.querySelector('.subnav a[href="/firewall/white"]')) && /Firewall Status/i.test(document.querySelector("main").textContent) && document.querySelectorAll("main .stat-grid > *").length >= 5, detail: "Firewall Status grid + sub-pages" }),
  speed_view: () => ({ ok: /Internet speed test/.test(document.querySelector("main").textContent) && !vis(btn("Run speed test")), detail: "speed panel, no Run" }),
  speed_run: () => ({ ok: vis(btn("Run speed test")), detail: "Run speed test button" }),
  updates_view: () => ({ ok: /Updates/.test(document.querySelector("main .head h1").textContent) && !vis(btn("Check for Updates")) && !vis(btn("Check Now")), detail: "updates panel, no Check" }),
  updates_check: () => ({ ok: [...document.querySelectorAll("main button")].some((b) => vis(b) && /Check/.test(b.textContent)), detail: "Check button" }),
  handle_alerts: () => ({ ok: [...document.querySelectorAll("main .alert-row > button")].some((b) => vis(b) && b.textContent === "Clear"), detail: "Clear on alert rows" }),
  device_actions: () => ({ ok: [...document.querySelectorAll("main .seg button")].filter((b) => vis(b) && !b.disabled).length >= 3, detail: "device policy buttons enabled" }),
  block_list: () => ({ ok: vis(document.querySelector('.subnav a[href="/firewall/black"]')), detail: "Blacklist menu" }),
  allow_list: () => ({ ok: vis(document.querySelector('.subnav a[href="/firewall/white"]')), detail: "Whitelist menu" }),
};
// The list users' controls are one click on, under Firewall.
const NEXT = { block_list: "/firewall/black", allow_list: "/firewall/white", alerts: "/devices/troubleshoot" };
const NEXT_OK = {
  block_list: () => ({ ok: vis(document.querySelector("main textarea")) && vis(btn("Add")), detail: "Blacklist add box + Add" }),
  allow_list: () => ({ ok: vis(document.querySelector("main textarea")) && vis(btn("Add")), detail: "Whitelist add box + Add" }),
  alerts: () => ({ ok: !/Not Available/.test(document.querySelector("main .head h1").textContent) && document.querySelector("main").textContent.length > 200, detail: "Troubleshooter opens" }),
};
const HELPERS = "window.vis = (e) => !!e && e.offsetParent !== null && !e.hidden; window.btn = (t) => [...document.querySelectorAll('main button')].find((b) => b.textContent.trim() === t);";
const rows = [];
(async () => {
  const b = await puppeteer.launch({ executablePath: "/usr/bin/google-chrome", headless: true, acceptInsecureCerts: true, args: ["--no-sandbox", "--ignore-certificate-errors"] });
  const login = async (ctx, user, pw, errs, bad) => {
    const p = await ctx.newPage();
    await p.setViewport({ width: 1920, height: 1200 });
    await p.evaluateOnNewDocument(HELPERS);
    p.on("pageerror", (e) => errs.push(p.url() + " " + e.message));
    p.on("console", (m) => { if (m.type() === "error") errs.push(p.url() + " " + m.text()); });
    p.on("response", (r) => { if (r.status() >= 400) bad.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`); });
    await p.goto(base + "/login", { waitUntil: "networkidle0" });
    await p.type("input[autocomplete=username]", user);
    await p.type("input[type=password]", pw);
    await Promise.all([p.waitForNavigation({ waitUntil: "networkidle0" }), p.evaluate(() => [...document.querySelectorAll("button")].find((x) => x.textContent.trim() === "Sign in").click())]);
    await p.waitForFunction(() => location.pathname !== "/login" && document.querySelector("main .head h1"), { timeout: 15000 });
    await sleep(2500);
    return p;
  };
  const actx = await b.createBrowserContext();
  const ap = await login(actx, "admin", PW, [], []);
  const api = (u, body) => ap.evaluate((u, body) => fetch(u, body ? { method: "POST", headers: { "X-FG": "1", "Content-Type": "application/json" }, body: JSON.stringify(body) } : {}).then(async (r) => ({ s: r.status, j: await r.json().catch(() => null) })), u, body);
  const perms = (await api("/api/users")).j.perms.map((x) => x.id);
  for (const perm of perms.filter((x) => !only || x === only)) {
    const name = (only ? "l2_" : "l_") + perm;
    const s = await api("/api/users", { action: "save", old_name: "", name, role: "custom", perms: [perm], web: true, api: false, password: UPW });
    const saved = ((await api("/api/users")).j.users.find((u) => u.name === name) || {}).perms;
    const errs = [], bad = [];
    const ctx = await b.createBrowserContext();
    let row = { perm, user: name, save: s.s, saved, want: WANT[perm] };
    try {
      const p = await login(ctx, name, UPW, errs, bad);
      row.landed = new URL(p.url()).pathname;
      row.title = await p.evaluate(() => document.querySelector("main .head h1").textContent);
      row.nav = await p.evaluate(() => [...document.querySelectorAll("aside a")].map((a) => a.getAttribute("href")));
      Object.assign(row, { controls: await p.evaluate(CONTROLS[perm]) });
      await p.screenshot({ path: path.join(shots, perm + ".png") });
      if (NEXT[perm]) {
        await p.goto(base + NEXT[perm], { waitUntil: "networkidle0" });
        await p.waitForSelector("main .head h1", { timeout: 15000 }); await sleep(2000);
        row.next = { url: NEXT[perm], ...(await p.evaluate(NEXT_OK[perm])) };
        await p.screenshot({ path: path.join(shots, perm + "-next.png") });
      }
    } catch (e) { row.error = String(e.message || e); }
    row.errors = errs; row.http4xx = bad;
    row.pass = !row.error && row.save === 200 && row.landed === row.want && row.title !== "Not Available" && row.controls && row.controls.ok && (!row.next || row.next.ok) && !errs.length && !bad.length;
    rows.push(row);
    console.log(`${row.pass ? "PASS" : "FAIL"} ${perm.padEnd(15)} -> ${row.landed} (${row.title}) controls=${row.controls && row.controls.ok}${row.next ? " next=" + row.next.ok : ""} 4xx=${bad.length} js=${errs.length}${row.error ? " ERR " + row.error : ""}`);
    await ctx.close();
  }
  if (only) { fs.writeFileSync(path.join(out, "land120-" + only + ".json"), JSON.stringify(rows, null, 1)); await b.close(); return; }
  // A direct link to a page the user can't open still says Not Available.
  const errs = [], bad = [];
  const ctx = await b.createBrowserContext();
  const p = await login(ctx, "l_speed_view", UPW, errs, bad);
  await p.goto(base + "/firewall", { waitUntil: "networkidle0" }); await sleep(1500);
  const na = await p.evaluate(() => document.querySelector("main .head h1").textContent);
  rows.push({ perm: "direct link /firewall as l_speed_view", landed: "/firewall", title: na, pass: na === "Not Available" && !bad.length && !errs.length, http4xx: bad, errors: errs });
  console.log(`${na === "Not Available" ? "PASS" : "FAIL"} direct /firewall as speed_view -> ${na}`);
  await p.screenshot({ path: path.join(shots, "direct-link-not-available.png") });
  await ctx.close();
  // An alerts-only user opens the Firewall Audit page (alerts brings Firewall view).
  { const errs = [], bad = [];
    const ctx = await b.createBrowserContext();
    const p = await login(ctx, "l_alerts", UPW, errs, bad);
    await p.goto(base + "/firewall/audit", { waitUntil: "networkidle0" }); await sleep(1500);
    const t = await p.evaluate(() => document.querySelector("main .head h1").textContent);
    const ok = t !== "Not Available" && !bad.length && !errs.length;
    rows.push({ perm: "alerts opens /firewall/audit", landed: "/firewall/audit", title: t, pass: ok, http4xx: bad, errors: errs });
    console.log(`${ok ? "PASS" : "FAIL"} alerts opens /firewall/audit -> ${t}`);
    await p.screenshot({ path: path.join(shots, "alerts-firewall-audit.png") });
    await ctx.close(); }
  fs.writeFileSync(path.join(out, "land120.json"), JSON.stringify(rows, null, 1));
  console.log(`${rows.filter((r) => r.pass).length}/${rows.length} passed`);
  await b.close();
})().catch((e) => { console.error(e); process.exit(1); });
