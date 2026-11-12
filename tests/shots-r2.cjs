// Round 2 screenshots: Help (Settings: Users, Notifications; Daily use: Alerts), manual, dashboard alerts. 1920 and 390.
const puppeteer = require("puppeteer-core");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  const U = process.argv[2], OUT = process.argv[3];
  const b = await puppeteer.launch({ executablePath: "/usr/bin/google-chrome", args: ["--no-sandbox", "--ignore-certificate-errors"] });
  const p = await b.newPage(); const errs = []; p.on("pageerror", (e) => errs.push(e.message));
  await p.goto(U + "/", { waitUntil: "networkidle2" });
  await p.evaluate(async (u) => { await fetch(u + "/api/login", { method: "POST", headers: { "X-FG": "1", "Content-Type": "application/json" }, body: JSON.stringify({ user: "admin", password: "correct horse battery" }) }); }, U);
  const report = [];
  const over = () => p.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  for (const w of [1920, 390]) {
    await p.setViewport({ width: w, height: w > 1000 ? 1200 : 844 });
    for (const [tab, head, name] of [["Settings", "Users", "help-settings-users"], ["Settings", "Notifications", "help-settings-notifications"], ["Settings", "API Reference", "help-settings-api-reference"], ["Daily", "Alerts", "help-daily-alerts"]]) {
      await p.goto(U + "/settings/help", { waitUntil: "networkidle2" }); await sleep(600);
      const ok = await p.evaluate(async (tab, head) => {
        const t = [...document.querySelectorAll("button.help-tab")].find((x) => x.textContent.includes(tab)); if (!t) return "no tab";
        t.click(); await new Promise((r) => setTimeout(r, 700));
        const hh = [...document.querySelectorAll("article.help-article h2, article.help-article h3")].find((x) => x.textContent.trim() === head); if (!hh) return "no heading";
        hh.scrollIntoView({ block: "start" }); return "ok";
      }, tab, head);
      await sleep(300); const f = `${OUT}/${name}-${w}.png`; await p.screenshot({ path: f });
      report.push([f, ok, "overflow " + (await over())]);
    }
    await p.goto(U + "/s/manual.html", { waitUntil: "networkidle2" });
    await p.evaluate(() => { const hh = [...document.querySelectorAll("h2")].find((x) => x.textContent.trim() === "Users"); hh && hh.scrollIntoView({ block: "start" }); });
    await sleep(300); let f = `${OUT}/manual-users-${w}.png`; await p.screenshot({ path: f }); report.push([f, "ok", "overflow " + (await over())]);
    await p.goto(U + "/", { waitUntil: "networkidle2" }); await sleep(1200);
    await p.evaluate(() => { const a = document.querySelector(".alert-row"); a && a.scrollIntoView({ block: "center" }); });
    f = `${OUT}/dashboard-alerts-${w}.png`; await p.screenshot({ path: f, fullPage: false });
    const txt = await p.evaluate(() => [...document.querySelectorAll(".alert-row")].map((r) => r.textContent).filter((t) => /refused/.test(t)));
    report.push([f, JSON.stringify(txt), "overflow " + (await over())]);
  }
  for (const r of report) console.log(r.join("  "));
  console.log("page errors:", errs.length ? errs : "none");
  await b.close();
})();
