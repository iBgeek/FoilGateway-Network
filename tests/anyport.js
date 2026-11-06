// The setup wizard on a three-port gateway, with the cable moving and the
// service restarting part way. Called by anyport.sh, which sets ST.
const puppeteer = require("puppeteer-core");
const fs = require("fs");
const { execSync } = require("child_process");
const [base, out] = process.argv.slice(2);
const ST = process.env.ST;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failed = 0, page = null;
const ok = (name, cond) => { console.log((cond ? "ok   " : "FAIL ") + name); if (!cond) failed++; };
(async () => {
  const b = await puppeteer.launch({ executablePath: "/usr/bin/google-chrome", headless: true, acceptInsecureCerts: true, args: ["--no-sandbox", "--ignore-certificate-errors", "--window-size=1200,1000"] });
  const p = await b.newPage();
  page = p;
  await p.setViewport({ width: 1200, height: 1000 });
  const errors = [];
  p.on("pageerror", (e) => errors.push(e.message));
  const shot = async (name) => { const f = `${out}/ap-${name}.png`; await p.screenshot({ path: f, fullPage: true }); console.log("shot", f); };
  const text = () => p.evaluate(() => document.body.innerText);
  const waitText = (t, ms = 30000) => p.waitForFunction((t) => document.body.innerText.includes(t), { timeout: ms }, t);
  const click = async (t) => {
    const found = await p.evaluate((t) => { const el = [...document.querySelectorAll("button,a")].find((x) => x.textContent.trim() === t && !x.disabled); if (el) el.click(); return !!el; }, t);
    if (!found) throw new Error("no button " + t);
    await sleep(500);
  };
  const role = async (port, r) => {
    await p.evaluate((port, r) => { const row = [...document.querySelectorAll(".portrow")].find((x) => x.querySelector("b").textContent === port); [...row.querySelectorAll(".seg button")].find((x) => x.textContent === r).click(); }, port, r);
    await sleep(600);
  };
  const here = () => p.evaluate(() => { const r = document.querySelector(".portrow.here b"); return r ? r.textContent : ""; });
  const step = () => p.evaluate(() => { const s = document.querySelector(".steps span.on"); return s ? s.textContent : ""; });

  await p.goto(base + "/", { waitUntil: "networkidle0" });
  ok("first visit goes to setup", p.url().endsWith("/setup"));
  await waitText("Set up FoilGateway");
  await click("Start");
  await p.waitForSelector("input[type=password]");
  await p.$eval("#su", (el) => (el.value = "admin"));
  const pw = await p.$$("input[type=password]");
  await pw[0].type("correct horse battery");
  await pw[1].type("correct horse battery");
  await click("Next");
  await waitText("How it sits in your network");
  ok("Bridge picked, Router not ready", /Bridge[\s\S]*selected[\s\S]*Router[\s\S]*coming later/i.test(await text()));
  await click("Next");
  await waitText("Which port is which");
  await p.waitForFunction(() => document.body.innerText.includes("10.10.10.50"), { timeout: 20000 });
  ok("browser is on pa", (await here()) === "pa");
  const t1 = await text();
  ok("pc suggested as WAN", t1.includes("pc got its address from another router"));
  await click("Blink");
  await waitText("can't blink", 5000).catch(() => {});
  const t2 = await text();
  ok("Blink says why it can't", /ethtool isn't installed|can't blink|Blink didn't work/.test(t2));
  ok("Blink button greyed out", await p.evaluate(() => [...document.querySelectorAll(".portrow button")].filter((x) => x.textContent === "Blink" && x.disabled).length > 0));
  ok("no link-local address on the page", !t2.includes("169.254"));
  ok("says where to go without a router", t2.includes("If your network has no router handing out addresses, connect to https://192.168.30.1:8443"));
  ok("Blink reason shown once", (t2.match(/can't blink/g) || []).length === 1);
  await shot("ports");

  console.log("moving the cable from pa to pb");
  execSync(ST + "/move.sh");
  await p.waitForSelector(".panel.lost", { timeout: 15000 });
  await shot("reconnect");
  ok("reconnect list skips the link-local address", !(await text()).includes("169.254"));
  await p.waitForFunction(() => location.host.startsWith("169.254.42.1") && document.querySelector(".portrow.here"), { timeout: 90000 });
  await sleep(800);
  ok("picked up again (last-resort address)", p.url().startsWith("https://169.254.42.1:8443/setup"));
  ok("same step after the move", (await step()) === "Ports");
  ok("now on pb", (await here()) === "pb");
  await shot("resumed");

  console.log("restarting the service");
  execSync(ST + "/restart.sh");
  await p.waitForSelector(".panel.lost", { timeout: 15000 }).catch(() => {});
  await p.waitForFunction(() => document.querySelector(".portrow.here"), { timeout: 60000 });
  ok("same step after a restart", (await step()) === "Ports");

  // Wrong on purpose: LAN on pa while the browser sits on pb.
  await role("pa", "LAN"); await role("pb", "Not used"); await role("pc", "WAN");
  ok("tells which port to move to", (await text()).includes("move this computer's cable to pa"));
  await click("Next"); await sleep(400);
  await click("Next"); await sleep(400);
  await click("Next"); await waitText("Check before applying");
  await click("Apply");
  await waitText("Waiting for this page to check in", 15000);
  await shot("waiting");
  await waitText("went back to how it was", 60000);
  ok("undone when nobody confirms", (await step()) === "Review");
  ok("settings file gone again", !fs.existsSync(ST + "/gateway.conf"));
  ok("account taken back", JSON.parse(fs.readFileSync(ST + "/users.json", "utf8")).length === 0);
  await shot("undone");

  await click("Back"); await click("Back"); await click("Back");
  await waitText("Which port is which");
  await role("pb", "LAN"); await role("pa", "Not used");
  await click("Next"); await sleep(400);
  await click("Next"); await sleep(400);
  await click("Next"); await waitText("Check before applying");
  await click("Apply");
  await waitText("The bridge stays", 30000);
  ok("kept when the browser confirms through the bridge", true);
  await shot("done");
  await click("Sign in");
  await p.waitForFunction(() => location.pathname === "/login");
  await p.type("input[autocomplete=username]", "admin");
  await p.type("input[type=password]", "correct horse battery");
  await click("Sign in");
  await p.waitForFunction(() => location.pathname === "/", { timeout: 10000 });
  await sleep(1500);
  ok("signed in afterwards", (await text()).includes("Dashboard") || p.url().endsWith("/"));
  ok("no page errors", errors.length === 0);
  if (errors.length) console.log(errors.join("\n"));
  await b.close();
  process.exit(failed ? 1 : 0);
})().catch(async (e) => {
  console.error("FAILED", e.message);
  if (page) console.error((await page.evaluate(() => document.body.innerText).catch(() => "")).slice(0, 1500));
  process.exit(1);
});
