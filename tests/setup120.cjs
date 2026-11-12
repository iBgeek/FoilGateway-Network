// First setup through the real page (same steps as browser.js), then sign
// in and put something on the Black and White lists so the upgrade test
// has settings to compare. Usage: node setup120.cjs https://gw:8443 outdir
const puppeteer = require("puppeteer-core");
const fs = require("fs");
const [base, out] = process.argv.slice(2);
fs.mkdirSync(out, { recursive: true });
let P;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  const b = await puppeteer.launch({ executablePath: "/usr/bin/google-chrome", headless: true, acceptInsecureCerts: true, args: ["--no-sandbox", "--ignore-certificate-errors"] });
  const p = await b.newPage(); P = p;
  await p.setViewport({ width: 1440, height: 1000 });
  const errors = [];
  p.on("pageerror", (e) => errors.push(e.message));
  const click = async (text) => {
    const ok = await p.evaluate((t) => { const el = [...document.querySelectorAll("button,a")].find((x) => x.textContent.trim() === t); if (el) el.click(); return !!el; }, text);
    if (!ok) throw new Error("no button " + text);
    await sleep(300);
  };
  await p.goto(base + "/", { waitUntil: "networkidle0" });
  if (!p.url().endsWith("/setup")) throw new Error("first visit didn't go to setup: " + p.url());
  await click("Start");
  await p.waitForSelector("#su");
  const pw = await p.$$("input[type=password]");
  await p.$eval("#su", (el) => (el.value = ""));
  await p.type("#su", "admin");
  await pw[0].type("correct horse battery");
  await pw[1].type("correct horse battery");
  await click("Next");
  await p.waitForFunction(() => /bridge/i.test(document.body.innerText));
  await click("Next");
  await p.waitForSelector(".portrow");
  await sleep(600);
  await click("Next"); await click("Next"); await click("Next");
  await click("Apply");
  await p.waitForFunction(() => document.body.innerText.includes("The bridge stays") || document.body.innerText.includes("went back") || document.querySelector(".err")?.textContent, { timeout: 120000 });
  await p.screenshot({ path: out + "/setup-done.png" });
  if (!(await p.evaluate(() => document.body.innerText.includes("The bridge stays")))) throw new Error("setup didn't finish");
  await click("Sign in");
  await p.waitForFunction(() => location.pathname === "/login");
  await p.type("input[autocomplete=username]", "admin");
  await p.type("input[type=password]", "correct horse battery");
  await click("Sign in");
  await p.waitForFunction(() => location.pathname === "/");
  for (const [list, val] of [["black", "9.9.9.9"], ["white", "8.8.8.8"]]) {
    await p.goto(base + "/firewall/" + list, { waitUntil: "networkidle0" });
    await p.type("textarea", val);
    await click("Add");
    await p.waitForFunction((v) => document.querySelector(".overlay").hidden && document.body.innerText.includes(v), { timeout: 30000 }, val);
  }
  await p.goto(base + "/", { waitUntil: "networkidle0" });
  await sleep(1500);
  await p.screenshot({ path: out + "/dashboard.png" });
  // The same cut-off text check the 1.2.0 run uses, on this version's dashboard at 1920x1200.
  const { findClipped } = require("./clip.js");
  await p.setViewport({ width: 1920, height: 1200 }); await sleep(3500);
  console.log("dashboard 1920x1200 cut-off text:", JSON.stringify(await p.evaluate(findClipped)));
  await p.screenshot({ path: out + "/dashboard-1920.png" });
  console.log("setup done, lists set; page errors:", errors.length ? errors : "none");
  await b.close();
})().catch(async (e) => { console.error(e.message); try { await P.screenshot({ path: out + "/fail.png" }); console.error(await P.evaluate(() => document.body.innerText)); } catch (x) {} process.exit(1); });
