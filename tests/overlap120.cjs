const puppeteer = require("puppeteer-core");
(async () => {
  const U = process.argv[2], CSS = process.argv[3] || "";
  const b = await puppeteer.launch({ executablePath: "/usr/bin/google-chrome", args: ["--no-sandbox", "--ignore-certificate-errors"] });
  const p = await b.newPage(); await p.setViewport({ width: 1024, height: 900 });
  await p.goto(U + "/", { waitUntil: "networkidle2" });
  await p.evaluate(async (u) => { await fetch(u + "/api/login", { method: "POST", headers: { "X-FG": "1", "Content-Type": "application/json" }, body: JSON.stringify({ user: "admin", password: "correct horse battery" }) }); }, U);
  for (const path of ["/", "/devices", "/firewall", "/ports", "/log", "/settings", "/settings/users", "/settings/notify"]) for (const w of [1920, 1366, 1100, 1024, 700, 390]) {
    await p.setViewport({ width: w, height: 900 });
    await p.goto(U + path, { waitUntil: "networkidle2" });
    if (CSS) await p.evaluate((c) => { const s = [...document.styleSheets].find((x) => x.href && x.href.includes("style")); if (s) s.insertRule(c, s.cssRules.length); else document.adoptedStyleSheets = [...document.adoptedStyleSheets, Object.assign(new CSSStyleSheet(), {}).constructor === CSSStyleSheet ? (() => { const n = new CSSStyleSheet(); n.replaceSync(c); return n; })() : null]; }, CSS).catch((e) => console.log("css fail", path, w, e.message.slice(0, 80)));
    await new Promise(r => setTimeout(r, 700));
    if (path === "/" || path === "/settings" || path === "/settings/users") await p.screenshot({ path: `/workspace/fg120/versions/1.2.0/verification/ui/fix/${path.replace(/\//g, "_") || "_"}-${w}.png` });
    const r = await p.evaluate(() => {
      const ps = [...document.querySelectorAll("main .panel, main .cards")].filter(e => !e.parentElement.closest(".panel"));
      const bad = [];
      for (let i = 0; i < ps.length; i++) for (let j = i + 1; j < ps.length; j++) {
        const a = ps[i].getBoundingClientRect(), c = ps[j].getBoundingClientRect();
        const ov = Math.min(a.bottom, c.bottom) - Math.max(a.top, c.top), oh = Math.min(a.right, c.right) - Math.max(a.left, c.left);
        if (ov > 1 && oh > 1) bad.push(`${(ps[i].querySelector("h2,h3")?.textContent||ps[i].className).slice(0,14)} / ${(ps[j].querySelector("h2,h3")?.textContent||ps[j].className).slice(0,14)} ${Math.round(ov)}px`);
      }
      const big = [...document.querySelectorAll("main .grow")].map(e => Math.round(e.getBoundingClientRect().height));
      return { bad, big };
    });
    if (r.bad.length) console.log(path, w, JSON.stringify(r));
  }
  console.log("done");
  await b.close();
})();
