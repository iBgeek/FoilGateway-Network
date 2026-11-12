// 1.2.0 round 3: in Add User, ticking an action ticks its view and locks it; unticking unlocks.
// Usage (in fgw-lap): node lock120.cjs URL OUTDIR
const puppeteer = require("puppeteer-core");
const path = require("path"), fs = require("fs");
const [base, out] = process.argv.slice(2);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  const b = await puppeteer.launch({ executablePath: "/usr/bin/google-chrome", headless: true, acceptInsecureCerts: true, args: ["--no-sandbox", "--ignore-certificate-errors"] });
  const p = await b.newPage(); await p.setViewport({ width: 1920, height: 1200 });
  const errs = [], bad = [];
  p.on("pageerror", (e) => errs.push(e.message));
  p.on("response", (r) => { if (r.status() >= 400) bad.push(r.status() + " " + new URL(r.url()).pathname); });
  await p.goto(base + "/login", { waitUntil: "networkidle0" });
  await p.type("input[autocomplete=username]", "admin"); await p.type("input[type=password]", "correct horse battery");
  await Promise.all([p.waitForNavigation({ waitUntil: "networkidle0" }), p.evaluate(() => [...document.querySelectorAll("button")].find((x) => x.textContent.trim() === "Sign in").click())]);
  await p.goto(base + "/settings/users", { waitUntil: "networkidle0" }); await sleep(1500);
  await p.evaluate(() => [...document.querySelectorAll("main button")].find((x) => /Add User/.test(x.textContent)).click()); await sleep(800);
  const st = (id) => p.evaluate((id) => { const i = document.querySelector('.overlay input[value="' + id + '"]'); return { checked: i.checked, disabled: i.disabled }; }, id);
  const click = (id) => p.evaluate((id) => document.querySelector('.overlay input[value="' + id + '"]').click(), id);
  const res = [];
  const IMP = [["speed_run", "speed_view"], ["updates_check", "updates_view"], ["handle_alerts", "status"], ["device_actions", "devices"], ["block_list", "firewall_view"], ["allow_list", "firewall_view"], ["alerts", "devices"], ["alerts", "firewall_view"]];
  for (const [a, v] of IMP) {
    await click(a); const on = await st(v);
    if (a === "speed_run") await p.screenshot({ path: path.join(out, "landing", "add-user-speed-run-locks-view.png") });
    await click(a); const off = await st(v);
    if (off.checked) await click(v); // leave it clean for the next pair
    res.push({ action: a, view: v, ticked: on, unticked: off, pass: on.checked && on.disabled && !off.disabled });
  }
  // Both list actions hold Firewall view; one unticked still holds it.
  await click("block_list"); await click("allow_list"); await click("block_list");
  const held = await st("firewall_view"); await click("allow_list"); const freed = await st("firewall_view");
  res.push({ action: "block_list+allow_list, untick one", view: "firewall_view", held, freed, pass: held.checked && held.disabled && !freed.disabled });
  for (const r of res) console.log((r.pass ? "PASS " : "FAIL ") + r.action + " -> " + r.view);
  console.log(`js errors ${errs.length}, 4xx ${bad.length} ${bad.join(", ")}`);
  fs.writeFileSync(path.join(out, "lock120.json"), JSON.stringify({ res, errs, bad }, null, 1));
  await b.close();
})().catch((e) => { console.error(e); process.exit(1); });
