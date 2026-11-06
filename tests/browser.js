// Walks the first-connect wizard and every page in headless Chrome, saving
// screenshots. Usage: node browser.js https://192.168.50.1:8443 outdir
// Needs puppeteer-core (NODE_PATH) and google-chrome.
const puppeteer = require("puppeteer-core");
const { audit, WIDTHS } = require("./clip.js");
const fs = require("fs");
const [base, out] = process.argv.slice(2);
fs.mkdirSync(out, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let n = 0;
(async () => {
  const b = await puppeteer.launch({ executablePath: "/usr/bin/google-chrome", headless: true, acceptInsecureCerts: true, args: ["--no-sandbox", "--ignore-certificate-errors", "--window-size=1440,1000"] });
  const p = await b.newPage();
  await p.setViewport({ width: 1440, height: 1000 });
  const errors = [];
  p.on("pageerror", (e) => errors.push(e.message));
  p.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  // Every screenshot also checks for cut-off text at each width.
  const clipped = [];
  const shot = async (name, full = true) => { n++; const f = `${out}/${String(n).padStart(2, "0")}-${name}.png`; await p.screenshot({ path: f, fullPage: full }); console.log("shot", f); await audit(p, name, clipped); };
  const click = async (text) => {
    const ok = await p.evaluate((t) => { const el = [...document.querySelectorAll("button,a")].find((x) => x.textContent.trim() === t); if (el) el.click(); return !!el; }, text);
    if (!ok) throw new Error("no button " + text);
    await sleep(300);
  };
  const type = async (sel, val) => { await p.$eval(sel, (el) => (el.value = "")); await p.type(sel, val); };

  await p.goto(base + "/", { waitUntil: "networkidle0" });
  if (!p.url().endsWith("/setup")) throw new Error("first visit didn't go to setup: " + p.url());
  await shot("setup-welcome");
  await click("Start");
  const pw = await p.$$("input[type=password]");
  await p.waitForSelector("#su");
  await type("#su", "admin");
  await pw[0].type("correct horse battery");
  await pw[1].type("correct horse battery");
  await shot("setup-admin");
  await click("Next");
  // Back again: the password is set now, and the box says so.
  await p.waitForFunction(() => document.body.innerText.includes("Bridge"));
  await click("Back");
  await p.waitForSelector("#su");
  await shot("setup-admin-again");
  await click("Next");
  await p.waitForFunction(() => document.body.innerText.includes("Bridge"));
  await shot("setup-mode");
  await click("Next");
  await p.waitForSelector(".portrow");
  await sleep(600);
  await shot("setup-ports");
  await click("Next");
  await shot("setup-port");
  await click("Next");
  await shot("setup-safety");
  await click("Next");
  await shot("setup-review");
  await click("Apply");
  await p.waitForFunction(() => document.body.innerText.includes("The bridge stays") || document.body.innerText.includes("went back") || document.querySelector(".err")?.textContent, { timeout: 120000 });
  await shot("setup-done");
  if (!(await p.evaluate(() => document.body.innerText.includes("The bridge stays")))) throw new Error("setup didn't finish: " + (await p.evaluate(() => document.body.innerText)));
  // Setup gives no session; the new admin signs in like any other time.
  await click("Sign in");
  await p.waitForFunction(() => location.pathname === "/login");
  await p.type("input[autocomplete=username]", "admin");
  await p.type("input[type=password]", "correct horse battery");
  await click("Sign in");
  await p.waitForFunction(() => location.pathname === "/");

  // A Blacklist entry so there is something blocked to show.
  await p.goto(base + "/firewall/black", { waitUntil: "networkidle0" });
  await p.type("textarea", "9.9.9.9");
  await click("Add");
  await p.waitForFunction(() => document.querySelector(".overlay").hidden && document.body.innerText.includes("9.9.9.9"), { timeout: 30000 });
  fs.writeFileSync(out + "/.ready", "1");
  await sleep(Number(process.env.WAIT || 8000)); // the shell side makes traffic meanwhile

  // No page scrolls as a whole, and nothing scrolls sideways.
  const pages = [["/", "dashboard"], ["/devices", "devices"], ["/firewall", "firewall"], ["/firewall/geo", "geo"], ["/firewall/white", "whitelist"], ["/firewall/black", "blacklist"], ["/firewall/rules", "rules"], ["/ports", "ports"], ["/ports/devices", "ports-devices"], ["/log", "log"], ["/settings", "settings"], ["/settings/general", "settings-general"], ["/settings/log", "settings-log"], ["/settings/account", "settings-account"], ["/settings/setup", "settings-setup"]];
  const scrolls = [], groupsBad = [];
  for (const w of [1440, 1024, 768]) {
    await p.setViewport({ width: w, height: 900 });
    for (const [path, name] of pages) {
      await p.goto(base + path, { waitUntil: "networkidle0" });
      await sleep(500);
      const r = await p.evaluate(() => {
        const d = document.scrollingElement;
        const side = [...document.querySelectorAll("main *")].filter((e) => getComputedStyle(e).overflowX === "auto" || getComputedStyle(e).overflowX === "scroll").filter((e) => e.scrollWidth > e.clientWidth + 1 && !e.matches("pre.rules"));
        return { page: d.scrollHeight > d.clientHeight + 1, wide: d.scrollWidth > d.clientWidth + 1, side: side.map((e) => e.className).slice(0, 3) };
      });
      if (r.page || r.wide || r.side.length) scrolls.push(`${name}@${w}: ${JSON.stringify(r)}`);
      // Buttons in one group are one size, and no button carries a glyph prefix.
      const g = await p.evaluate(() => {
        const bad = [];
        for (const grp of document.querySelectorAll("main .seg, main .stack")) {
          const bs = [...grp.querySelectorAll(":scope > button")].filter((b) => b.offsetParent);
          if (bs.length < 2) continue;
          const ws = bs.map((b) => Math.round(b.getBoundingClientRect().width)), hs = bs.map((b) => Math.round(b.getBoundingClientRect().height));
          if (Math.max(...ws) - Math.min(...ws) > 1 || Math.max(...hs) - Math.min(...hs) > 1) bad.push(grp.className + " " + JSON.stringify([ws, hs, bs.map((b) => b.textContent)]));
        }
        // Protection mode: the lit On and every Turn on, across rows.
        const qs = [...document.querySelectorAll("main .qs > div:first-child > button")].filter((b) => b.offsetParent).map((b) => b.getBoundingClientRect());
        const qw = qs.map((x) => Math.round(x.width)), qh = qs.map((x) => Math.round(x.height));
        if (qs.length > 1 && (Math.max(...qw) - Math.min(...qw) > 1 || Math.max(...qh) - Math.min(...qh) > 1)) bad.push("qs column " + JSON.stringify([qw, qh]));
        const glyph = [...document.querySelectorAll("button, [role=button], .btn")].filter((b) => b.offsetParent).map((b) => b.textContent.trim()).filter((t) => t && /^[^\p{L}\p{N}]/u.test(t));
        return { bad, glyph };
      });
      if (g.bad.length || g.glyph.length) groupsBad.push(`${name}@${w}: ${JSON.stringify(g)}`);
      if (w === 1440) await shot(name, false);
    }
  }
  console.log(groupsBad.length ? "button groups:\n  " + groupsBad.join("\n  ") : "button groups equal size, no glyph prefixes, on " + pages.length + " pages at 1440, 1024 and 768px");
  if (groupsBad.length) throw new Error("button groups differ");
  console.log(scrolls.length ? "page scroll:\n  " + scrolls.join("\n  ") : "no page scroll at 1440, 1024 and 768px");
  await p.setViewport({ width: 1440, height: 1000 });
  // The sidebar: sub-items only under the page you're on, the current one lit.
  await p.goto(base + "/firewall/white", { waitUntil: "networkidle0" });
  const nav = await p.evaluate(() => ({ subs: [...document.querySelectorAll(".subnav a")].map((a) => a.textContent), on: document.querySelector(".subnav a.on")?.textContent }));
  console.log("sidebar on Whitelist:", JSON.stringify(nav));
  if (nav.on !== "Whitelist" || nav.subs.length !== 5 || !nav.subs.includes("Audit")) throw new Error("firewall sub-menu wrong");
  // The dashboard's Blocked today card goes to today's blocks.
  await p.goto(base + "/", { waitUntil: "networkidle0" });
  const bt = await p.evaluate(() => [...document.querySelectorAll("a.card")].find((a) => /Blocked today/i.test(a.innerText))?.getAttribute("href"));
  console.log("Blocked today links to", bt);
  // 0.5.2 layout. Each check throws, so a regression fails the run.
  const must = (ok, what) => { if (!ok) throw new Error(what); };
  // Stats across the top (11 cards may wrap to two rows), typed alike.
  const stats = await p.evaluate(() => {
    const cards = [...document.querySelectorAll(".cards.stats .card")];
    const pick = (e) => { if (!e) return null; const c = getComputedStyle(e); return [c.fontFamily, c.fontSize, c.fontWeight, c.color, c.letterSpacing, c.textTransform].join("|"); };
    return { names: cards.map((c) => c.querySelector("h2").textContent), tops: cards.map((c) => Math.round(c.getBoundingClientRect().top)),
      h2: cards.map((c) => pick(c.querySelector("h2"))), big: cards.map((c) => pick(c.querySelector(".big"))),
      sub: cards.filter((c) => !c.querySelector(".sub.warn,.sub.bad")).map((c) => pick(c.querySelector(".sub"))),
      above: cards.length && document.querySelector(".map-panel") ? cards[0].getBoundingClientRect().bottom <= document.querySelector(".map-panel").getBoundingClientRect().top : true,
      temp: [...document.querySelectorAll(".cards.stats .card")].find((c) => /CPU temp/.test(c.innerText))?.querySelector(".sub").textContent.trim() };
  });
  console.log("stats:", stats.names.join(", "));
  must(stats.names.join(",") === "Mode,Traffic Path,WAN,LAN,Countries Now,Devices,CPU,CPU Temp,Disk,Memory,Blocked Today", "stats order " + stats.names);
  // Live lists don't move: across refreshes the same row elements stay, in
  // the same order, and the boxes keep their size.
  const snap = () => p.evaluate(() => {
    // Alert rows only: live connection keys churn under the test's background probes.
    const rows = [...document.querySelectorAll("main [data-key]")].filter((r) => !/^tcp |^udp /.test(r.dataset.key || ""));
    rows.forEach((r, i) => { if (!r._mark) r._mark = "m" + Math.random(); });
    const box = (k) => { const e = document.querySelector('[data-k="' + k + '"]'); return e ? Math.round(e.getBoundingClientRect().height) : -1; };
    return { keys: rows.map((r) => r.dataset.key), marks: rows.map((r) => r._mark), boxes: [box("alerts"), box("conns")] };
  });
  const s0 = await snap();
  let moved = [];
  for (let i = 0; i < 4; i++) {
    await sleep(3500);
    const s1 = await snap();
    const both = s0.keys.filter((k) => s1.keys.includes(k));
    const order0 = both.join("\n"), order1 = s1.keys.filter((k) => both.includes(k)).join("\n");
    if (order0 !== order1) moved.push("order changed on refresh " + (i + 1));
    both.forEach((k) => { if (s0.marks[s0.keys.indexOf(k)] !== s1.marks[s1.keys.indexOf(k)]) moved.push("row redrawn: " + k); });
    if (s1.boxes.join() !== s0.boxes.join()) moved.push("box size " + s0.boxes + " -> " + s1.boxes);
  }
  console.log("dashboard rows across 4 refreshes:", s0.keys.length, "rows,", moved.length ? JSON.stringify(moved.slice(0, 5)) : "none moved, boxes same size");
  must(s0.keys.length > 0 && !moved.length, "dashboard rows move on refresh");
  must(new Set(stats.tops).size <= 2, "stats wrap too much " + stats.tops);
  must(stats.above, "stats not above the map");
  for (const k of ["h2", "big", "sub"]) must(new Set(stats[k]).size === 1, "stat " + k + " styles differ: " + [...new Set(stats[k])].join(" / "));
  must(!/chip/.test(stats.temp || ""), "CPU temp still has a caption: " + stats.temp);
  // Signed-in user and Sign out only at the top right; no Live marker.
  const top = await p.evaluate(() => { const b = document.querySelector(".head #signout"), r = b?.getBoundingClientRect();
    return { head: !!b, right: r ? innerWidth - r.right : -1, side: [...document.querySelectorAll("aside button")].some((x) => /Sign out/.test(x.textContent)), live: /● Live/.test(document.body.innerText) }; });
  must(top.head && top.right < 40 && !top.side && !top.live, "header user/sign out wrong " + JSON.stringify(top));
  // Nothing on the page grows without bound while it refreshes.
  const nodes0 = await p.evaluate(() => document.getElementsByTagName("*").length);
  await sleep(9500);
  const nodes1 = await p.evaluate(() => ({ n: document.getElementsByTagName("*").length, map: window.__map ? { on: !!document.querySelector("canvas#map"), running: window.__map.running() } : null, cals: document.querySelectorAll("canvas").length }));
  console.log("dashboard nodes", nodes0, "->", nodes1.n, "map", JSON.stringify(nodes1.map), "canvases", nodes1.cals);
  must(nodes1.n < nodes0 * 1.2 + 50 && nodes1.cals <= 1, "dashboard DOM grows");
  if (nodes1.map && nodes1.map.on) must(nodes1.map.running, "map not animating");
  // The map animates and its loop stops once the canvas leaves the page.
  // The test gateway has no location database, so feed it two places.
  const anim = await p.evaluate(async () => {
    const m = window.__map, wait = (ms) => new Promise((r) => setTimeout(r, ms));
    m.cv.style.cssText = "position:fixed;left:0;top:0;width:400px;height:200px"; document.body.append(m.cv);
    m.set([{ place: { lat: 50, lon: 8 }, dir: "in", bytes: 900 }, { place: { lat: 40, lon: -74 }, dir: "out", bytes: 50 }], { lat: 52, lon: 13 });
    await wait(400);
    const snap = () => { const d = m.cv.getContext("2d").getImageData(0, 0, m.cv.width, m.cv.height).data; let x = 0; for (let i = 0; i < d.length; i += 7) x = (x * 31 + d[i]) | 0; return x; };
    const a = snap(); await wait(300); const b = snap();
    const out = { running: m.running(), flows: m.count(), moved: a !== b };
    m.cv.remove(); await wait(300);
    out.stopped = !m.running();
    return out;
  });
  console.log("map animation:", JSON.stringify(anim));
  must(anim.running && anim.flows === 2 && anim.moved && anim.stopped, "map animation wrong");
  // Same role, same look, on every page.
  const ROLES = { title: ".head h1", panelHead: ".panel h2", primary: "main button:not(.quiet):not(.danger):not(.small):not(.chip):not(.isOn):not(.on):not(.seg button):not(.cal button):not(.tools-row button):not(.panel-head button):not(.modepick button)", quiet: "main button.quiet:not(.small)", hint: "main .hint", th: "main th", td: "main tr:not(.sel) td", who: ".head .who span", when: ".head .when", nav: "aside a.nav:not(.on)", label: "main label:not(.check)" };
  const seenRole = {};
  const drift = [];
  for (const [path, name] of pages) {
    await p.goto(base + path, { waitUntil: "networkidle0" });
    await sleep(400);
    const got = await p.evaluate((ROLES) => {
      const o = {};
      for (const [k, sel] of Object.entries(ROLES)) {
        const e = [...document.querySelectorAll(sel)].find((x) => {
          if (!x.offsetParent) return false;
          if (k === "primary" && x.closest(".seg, .stack, .tools-row, .panel-head, .chips, .modepick, .cal, .map-panel")) return false;
          return true;
        });
        if (e) { const c = getComputedStyle(e); o[k] = [c.fontFamily, c.fontSize, c.fontWeight, c.color, c.backgroundColor, c.borderTopColor].join("|"); }
      }
      return o;
    }, ROLES);
    for (const [k, v] of Object.entries(got)) {
      if (k === "primary" && name === "dashboard") continue; // dashboard has no primary action buttons
      if (!seenRole[k]) seenRole[k] = [name, v]; else if (seenRole[k][1] !== v) drift.push(`${k}: ${seenRole[k][0]} ${seenRole[k][1]} vs ${name} ${v}`);
    }
    // No text smaller than the theme's smallest size anywhere.
    const tiny = await p.evaluate(() => [...document.querySelectorAll("body *")].filter((e) => e.offsetParent && [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim()) && parseFloat(getComputedStyle(e).fontSize) < 12).map((e) => e.tagName + "." + e.className).slice(0, 3));
    if (tiny.length) drift.push(`${name}: text under 12px: ${tiny.join(", ")}`);
  }
  console.log(drift.length ? "theme drift:\n  " + drift.join("\n  ") : "same-role styles match on " + pages.length + " pages: " + Object.keys(seenRole).join(", "));
  must(!drift.length, "theme drift");
  // Firewall: protection On is lit, New devices is two stacked buttons.
  await p.goto(base + "/firewall", { waitUntil: "networkidle0" });
  const fw = await p.evaluate(() => {
    const on = [...document.querySelectorAll("button.isOn")].find((b) => /On/.test(b.textContent)), c = on && getComputedStyle(on);
    const nb = [...document.querySelectorAll("#newdev button")].map((b) => b.getBoundingClientRect());
    return { on: !!on, opacity: c && c.opacity, bg: c && c.backgroundColor, n: nb.length, stacked: nb.length === 2 && Math.abs(nb[0].left - nb[1].left) < 2 && nb[1].top >= nb[0].bottom, same: nb.length === 2 && Math.abs(nb[0].width - nb[1].width) < 2 };
  });
  console.log("firewall buttons:", JSON.stringify(fw));
  must(fw.on && fw.opacity === "1" && fw.bg !== "rgba(0, 0, 0, 0)" && fw.n === 2 && fw.stacked && fw.same, "firewall buttons wrong");
  // Geo applies on tick; no Save.
  await p.goto(base + "/firewall/geo", { waitUntil: "networkidle0" });
  must(!(await p.evaluate(() => /Save countries/.test(document.body.innerText))), "geo still has a Save button");
  // Devices: no "New devices get" there any more.
  await p.goto(base + "/devices", { waitUntil: "networkidle0" });
  must(!(await p.evaluate(() => /New devices get/.test(document.body.innerText))), "Devices still has New devices get");
  const dup = await p.evaluate(() => [...document.querySelectorAll("tbody tr")].filter((r) => { const t = r.querySelector("td"); const sub = t?.querySelector(".mute")?.textContent || ""; const head = (t?.textContent || "").replace(sub, ""); const v = sub.split(" · ")[0]; return v.length > 3 && head.includes(v) && !/\d/.test(v); }).length);
  must(dup === 0, "a device shows its maker twice");
  // Capture Log: our calendar, small date boxes, Today Only and Download All on one line.
  await p.goto(base + "/log", { waitUntil: "networkidle0" });
  await p.click("#log-from");
  await p.waitForSelector(".cal .cal-grid button");
  await shot("log-calendar", false);
  const cal = await p.evaluate(() => { const c = getComputedStyle(document.querySelector(".cal")); return { bg: c.backgroundColor, days: document.querySelectorAll(".cal .cal-grid button").length }; });
  await p.evaluate(() => [...document.querySelectorAll(".cal .cal-grid button")].find((b) => b.textContent === "1").click());
  await sleep(600);
  const lg = await p.evaluate(() => { const r = (e) => e.getBoundingClientRect(); const today = [...document.querySelectorAll("label.check")].find((l) => /Today Only/.test(l.textContent)), dl = document.querySelector("#log-dl");
    return { val: document.querySelector("#log-from").value, open: !!document.querySelector(".cal"), w: r(document.querySelector("#log-from")).width, todayH: r(today).height, line: Math.abs(r(today).top + r(today).height / 2 - (r(dl).top + r(dl).height / 2)) < 6 }; });
  console.log("calendar:", JSON.stringify(cal), JSON.stringify(lg));
  must(cal.days >= 28 && /^\d{4}-\d\d-01$/.test(lg.val) && !lg.open && lg.w < 150 && lg.todayH < 30 && lg.line, "log dates wrong");
  // A device change through the page: name it and set Local Network Only.
  await p.goto(base + "/devices", { waitUntil: "networkidle0" });
  await sleep(800);
  const hasDev = await p.$(".detail input");
  let mac = "";
  if (hasDev) {
    mac = await p.evaluate(() => document.querySelector(".detail").innerText.match(/([0-9a-f]{2}:){5}[0-9a-f]{2}/)?.[0] || "");
    await type(".detail input", "Test laptop");
    await click("Save Name");
    await p.waitForFunction(() => document.querySelector(".overlay").hidden, { timeout: 60000 });
    await sleep(400);
    await p.evaluate(() => [...document.querySelectorAll(".detail .seg button")].find((b) => b.textContent === "Local Network Only").click());
    await p.waitForSelector(".overlay .acts button:not(.quiet)");
    await click("Activate");
    await p.waitForFunction(() => document.querySelector(".overlay").hidden && document.querySelector(".seg button.on.lan_only"), { timeout: 30000 });
    await sleep(500);
    await shot("device-lan-only");
    await p.evaluate(() => [...document.querySelectorAll(".detail .seg button")].find((b) => b.textContent === "Normal").click());
    await p.waitForSelector(".overlay .acts button:not(.quiet)");
    await click("Activate");
    await p.waitForFunction(() => document.querySelector(".overlay").hidden && document.querySelector(".seg button.on.normal"), { timeout: 30000 });
  } else console.log("no device row to edit");
  // Troubleshooter deep link: the named device must be front and center.
  if (mac) {
    await p.goto(base + "/devices/troubleshoot?mac=" + encodeURIComponent(mac), { waitUntil: "networkidle0" });
    await sleep(800);
    const ts = await p.evaluate((mac) => {
      const sel = document.querySelector("#ts-dev");
      const focus = document.querySelector(".ts-focus");
      const who = document.querySelector(".ts-who");
      const title = document.querySelector("main h2, main .panel h2, main .panel > h3, main h1 + * h2");
      const panelHead = [...document.querySelectorAll(".panel h2, .panel > div > h2, section.panel h2, .panel .head, .panel h3")].map((e) => e.textContent.trim());
      // Panel title is the first h2/h3 inside the grow panel after the page h1.
      const heads = [...document.querySelectorAll("main h2")].map((e) => e.textContent.trim());
      return {
        sel: sel && sel.value,
        hasFocus: !!focus,
        who: who && who.textContent.trim(),
        looking: focus && /Looking at/i.test(focus.innerText),
        heads,
        bodyHas: /Blocked for Test laptop/i.test(document.body.innerText),
        oldTip: /Allow it on the Troubleshooter/i.test(document.body.innerText),
      };
    }, mac);
    console.log("troubleshoot deep link:", JSON.stringify(ts));
    if (ts.sel !== mac) throw new Error("troubleshoot did not select linked device");
    if (!ts.hasFocus || !ts.looking || ts.who !== "Test laptop") throw new Error("troubleshoot focus banner missing");
    if (!ts.bodyHas) throw new Error("troubleshoot panel title missing device");
    if (ts.oldTip) throw new Error("old culprit tip still present");
    await shot("troubleshoot-focus");
  } else console.log("no mac for troubleshoot deep link");
  // Ports: the four choices on a seen port, then one by hand.
  await p.goto(base + "/ports", { waitUntil: "networkidle0" });
  await sleep(800);
  const seen = await p.evaluate(() => [...document.querySelectorAll("tr")].map((r) => r.innerText.replace(/\s+/g, " ")).filter((t) => /TCP (445|3389)/.test(t)));
  console.log("ports rows:", JSON.stringify(seen));
  const pickIn = (re, label) => p.evaluate((re, label) => { const r = [...document.querySelectorAll("tr")].find((r) => new RegExp(re).test(r.innerText)); const b = r && [...r.querySelectorAll("button")].find((b) => b.textContent === label); if (b) b.click(); return !!b; }, re, label);
  if (await pickIn("TCP 445\\b", "Block Both")) { await p.waitForFunction(() => document.querySelector(".overlay").hidden && [...document.querySelectorAll("tr")].some((r) => /TCP 445\b/.test(r.innerText) && r.querySelector("button.on.block_both")), { timeout: 30000 }); console.log("445 set to Block Both"); }
  else console.log("no 445 row");
  await click("Add a Port by Hand");
  await p.type("input[type=number]", "5000");
  await click("Add");
  await p.waitForFunction(() => document.querySelector(".overlay").hidden && document.body.innerText.includes("TCP 5000"), { timeout: 30000 });
  await sleep(500);
  await shot("ports-after");
  // Host names: the LAN PC sends no DHCP host name, so its name has to come
  // from the router's PTR (the walk above gave it a name of its own, so ask the API).
  let hn = [];
  for (let i = 0; i < 50 && !hn.some((x) => /^lanpc\d+$/.test(x)); i++) {
    hn = await p.evaluate(async () => (await (await fetch("/api/devices?limit=100")).json()).devices.map((d) => d.hostname || ""));
    if (!hn.some((x) => /^lanpc\d+$/.test(x))) await sleep(3000);
  }
  console.log("device host names:", JSON.stringify(hn));
  if (!hn.some((x) => /^lanpc\d+$/.test(x))) throw new Error("no host name from the router's PTR");
  // Per device: every device listed without a search; a row opens in place.
  await p.goto(base + "/ports/devices", { waitUntil: "networkidle0" });
  await sleep(600);
  const pd = await p.evaluate(() => ({ rows: document.querySelectorAll(".devports").length, open: document.querySelectorAll(".devports.open").length }));
  console.log("per device rows without search:", JSON.stringify(pd));
  if (!pd.rows || pd.open) throw new Error("per device page doesn't list every device");
  await p.evaluate(() => document.querySelector(".devhead").click());
  await p.waitForFunction(() => document.querySelector(".devports.open .prow"), { timeout: 10000 });
  const opened = await p.evaluate(() => { const r = document.querySelector(".devports.open .prow"); return { port: r.dataset.port, text: r.innerText, choices: [...r.querySelectorAll(".seg button")].map((b) => b.textContent) }; });
  console.log("opened device, first port:", JSON.stringify(opened));
  if (opened.choices.join("|") !== "Same as Global|Allow|Block from WAN|Block from LAN|Block Both") throw new Error("per device choices wrong");
  await p.evaluate(() => [...document.querySelector(".devports.open .prow").querySelectorAll("button")].find((b) => b.textContent === "Block Both").click());
  await p.waitForFunction(() => document.querySelector(".overlay").hidden && document.querySelector(".devports.open .prow.own button.on.block_both"), { timeout: 30000 });
  const own = await p.evaluate(() => document.querySelector(".devports.open .devhead").innerText);
  console.log("after Block Both, row says:", own.replace(/\n/g, " | "));
  if (!/1 own setting/i.test(own)) throw new Error("own count not shown");
  await shot("ports-devices-open");
  await p.evaluate(() => [...document.querySelector(".devports.open .prow.own").querySelectorAll("button")].find((b) => b.textContent === "Same as Global").click());
  await p.waitForFunction(() => document.querySelector(".overlay").hidden && !document.querySelector(".devports.open .prow.own"), { timeout: 30000 });
  // Per device: give the device its own 445, which the global one beats.
  if (mac) {
    await p.goto(base + "/ports/devices?q=" + mac, { waitUntil: "networkidle0" });
    await sleep(600);
    await p.type(".devports input[type=text]", "tcp 445");
    await click("Add");
    await p.waitForFunction(() => document.querySelector(".overlay").hidden && document.querySelector(".prow.own"), { timeout: 30000 });
    await sleep(500);
    const al = await p.evaluate(() => document.querySelector(".prow.own .note.warn")?.textContent || "");
    console.log("per device alert:", al);
    if (!al) throw new Error("no alert for a device setting the global one beats");
    await shot("ports-devices-after");
    await p.goto(base + "/", { waitUntil: "networkidle0" });
    await sleep(800);
    const da = await p.evaluate(() => document.body.innerText.includes("TCP 445"));
    console.log("dashboard alert for it:", da);
  }
  // Settings: WAN locked until unlocked, and the setup popup wants YES.
  await p.goto(base + "/settings", { waitUntil: "networkidle0" });
  await sleep(500);
  const locked = await p.evaluate(() => [...document.querySelectorAll(".portrow .seg button")].filter((b) => b.textContent === "WAN" && b.disabled).length);
  console.log("WAN buttons locked:", locked);
  const ub = await p.evaluate(() => { const u = [...document.querySelectorAll("button")].find((b) => b.textContent === "Unlock WAN"), s = [...document.querySelectorAll("button")].find((b) => b.textContent === "Save Ports"); if (!u || !s) throw new Error("missing Unlock WAN or Save Ports"); return [u.getBoundingClientRect().height, s.getBoundingClientRect().height, getComputedStyle(u).fontSize, getComputedStyle(s).fontSize]; });
  console.log("Unlock WAN vs Save ports:", JSON.stringify(ub));
  if (Math.abs(ub[0] - ub[1]) > 1 || ub[2] !== ub[3]) throw new Error("Unlock WAN isn't a normal button");
  await click("Unlock WAN");
  await shot("settings-unlock", false);
  await click("Unlock");
  const subs = await p.evaluate(() => [...document.querySelectorAll(".subnav a")].map((a) => a.textContent).join("|"));
  console.log("settings sub-menu:", subs);
  if (subs !== "Network & Access|Certificates|Time and Location|Capture Log|Account|View|Setup") throw new Error("settings sub-menu wrong");
  await p.goto(base + "/settings/setup", { waitUntil: "networkidle0" });
  await sleep(500);
  await click("Run Setup Again");
  const yesOff = await p.evaluate(() => [...document.querySelectorAll(".overlay button")].find((b) => /Run Setup/.test(b.textContent)).disabled);
  console.log("setup button off before YES:", yesOff);
  await shot("settings-rerun", false);
  await click("Cancel");
  await p.goto(base + "/log?kind=block&today=1", { waitUntil: "networkidle0" });
  await sleep(600);
  await shot("log-blocked-today", false);
  // Location setting stays off until asked; just show the panel.
  await p.goto(base + "/settings/general#geo", { waitUntil: "networkidle0" });
  await sleep(600);
  await shot("settings-geo", false);
  await click("Sign out");
  await p.waitForFunction(() => location.pathname === "/login");
  await shot("login");
  await type("input[autocomplete=username]", "admin");
  await p.type("input[type=password]", "wrong password!!");
  await click("Sign in");
  await sleep(500);
  await shot("login-wrong");
  await p.$eval("input[type=password]", (el) => (el.value = ""));
  await p.type("input[type=password]", "correct horse battery");
  await click("Sign in");
  await p.waitForFunction(() => location.pathname === "/");
  await p.setViewport({ width: 820, height: 1000 });
  await sleep(1500);
  await shot("dashboard-narrow");
  console.log(errors.length ? "page errors:\n" + errors.join("\n") : "no page errors");
  console.log(clipped.length ? `cut-off text (${clipped.length}):\n  ` + clipped.join("\n  ") : `no cut-off text on ${n} views at ${WIDTHS.join(", ")}px`);
  await b.close();
  if (clipped.length) process.exit(2);
})().catch((e) => { console.error("FAILED", e.message); process.exit(1); });
