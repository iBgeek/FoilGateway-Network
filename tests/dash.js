// Sign in and load the dashboard the way a browser does: every asset and
// API call. Fails if the main area stays empty or a request never ends.
// usage: node dash.js https://addr:8443 user password
const puppeteer = require("puppeteer-core");
const [base, user, pass] = process.argv.slice(2);
(async () => {
  const b = await puppeteer.launch({ executablePath: "/usr/bin/google-chrome", headless: true, acceptInsecureCerts: true, args: ["--no-sandbox", "--ignore-certificate-errors", "--window-size=1440,1000"] });
  const p = await b.newPage();
  const open = new Map();
  p.on("request", (r) => open.set(r, Date.now()));
  p.on("requestfinished", (r) => open.delete(r));
  p.on("requestfailed", (r) => { console.log("failed " + r.url() + " " + (r.failure() || {}).errorText); open.delete(r); });
  let rc = 0;
  try {
    await p.goto(base + "/login", { waitUntil: "load", timeout: 15000 });
    await p.type("input[autocomplete=username]", user);
    await p.type("input[type=password]", pass);
    await p.keyboard.press("Enter");
    await p.waitForFunction(() => location.pathname === "/", { timeout: 10000 });
    await p.waitForFunction(() => { const m = document.querySelector("main"); return m && m.innerText.trim().length > 40; }, { timeout: 15000 });
    // A few refresh rounds, as someone leaving the tab open would.
    await new Promise((r) => setTimeout(r, 12000));
    const stuck = [...open].filter(([, t]) => Date.now() - t > 8000).map(([r]) => r.url());
    if (stuck.length) { console.log("never finished: " + stuck.join(" ")); rc = 1; }
    else console.log("dashboard loaded");
  } catch (e) {
    console.log("FAILED " + e.message);
    console.log((await p.evaluate(() => document.body.innerText).catch(() => "")).slice(0, 300));
    rc = 1;
  }
  await b.close();
  process.exit(rc);
})();
