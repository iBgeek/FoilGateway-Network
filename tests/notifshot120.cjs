// Screenshot of Settings > Notifications (Recent Sends) at 1920 and 390.
const puppeteer = require("puppeteer-core");
(async () => {
  const U = process.argv[2], OUT = process.argv[3];
  const b = await puppeteer.launch({ executablePath: "/usr/bin/google-chrome", args: ["--no-sandbox", "--ignore-certificate-errors"] });
  const p = await b.newPage(); await p.setViewport({ width: 1920, height: 1200 });
  await p.goto(U + "/", { waitUntil: "networkidle2" });
  await p.evaluate(async (u) => { await fetch(u + "/api/login", { method: "POST", headers: { "X-FG": "1", "Content-Type": "application/json" }, body: JSON.stringify({ user: "admin", password: "correct horse battery" }) }); }, U);
  for (const w of [1920, 390]) {
    await p.setViewport({ width: w, height: 1200 });
    await p.goto(U + "/settings/notify", { waitUntil: "networkidle2" }); await new Promise((r) => setTimeout(r, 800));
    await p.screenshot({ path: `${OUT}-${w}.png`, fullPage: w < 1100 });
    console.log(w, JSON.stringify(await p.evaluate(() => [...document.querySelectorAll("td.bad")].map((t) => t.textContent).slice(0, 3))));
  }
  await b.close();
})();
