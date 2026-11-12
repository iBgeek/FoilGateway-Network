// 1.2.0: About page with the Star on GitHub button, at 1920 and 1100 wide.
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
  const res = [];
  for (const w of [1920, 1100]) {
    await p.setViewport({ width: w, height: 900 });
    await p.goto(base + "/settings/about", { waitUntil: "networkidle0" }); await sleep(1200);
    const m = await p.evaluate(() => {
      const a = [...document.querySelectorAll("main a")];
      const dl = a.find((x) => x.textContent === "Download Manual"), st = a.find((x) => x.textContent === "Star on GitHub");
      if (!dl || !st) return { found: false };
      const r1 = dl.getBoundingClientRect(), r2 = st.getBoundingClientRect(), cs = (e) => getComputedStyle(e);
      const clipped = [...document.querySelectorAll("main *")].filter((e) => e.children.length === 0 && e.textContent.trim() && (e.scrollWidth > e.clientWidth + 1) && cs(e).overflow !== "visible").map((e) => e.textContent.trim().slice(0, 40));
      return { found: true, href: st.href, target: st.target, sameTop: Math.abs(r1.top - r2.top) < 1, sameHeight: Math.abs(r1.height - r2.height) < 1,
        sameFont: cs(dl).font === cs(st).font && cs(dl).color === cs(st).color, gap: Math.round(r2.left - r1.right), clipped };
    });
    await p.screenshot({ path: path.join(out, `about-${w}.png`) });
    m.width = w; m.pass = m.found && m.sameTop && m.sameHeight && m.sameFont && m.gap > 0 && !m.clipped.length && m.href === "https://github.com/iBgeek/FoilGateway-Network";
    res.push(m); console.log((m.pass ? "PASS " : "FAIL ") + JSON.stringify(m));
  }
  console.log(`js errors ${errs.length}, 4xx ${bad.length} ${bad.join(", ")}`);
  fs.writeFileSync(path.join(out, "about120.json"), JSON.stringify({ res, errs, bad }, null, 1));
  await b.close();
})().catch((e) => { console.error(e); process.exit(1); });
