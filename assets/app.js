"use strict";
// One script for every page. The page name is on <body data-page>.
(function () {
  const PAGE = document.body.dataset.page;
  const $ = (s, r) => (r || document).querySelector(s);

  // Small element builder: h("div.card", {onclick}, child, "text", ...)
  function h(tag, attrs, ...kids) {
    // {perm: "id"} or {perm: "admin"}: left out for users without it.
    if (attrs && typeof attrs === "object" && !(attrs instanceof Node) && !Array.isArray(attrs) && "perm" in attrs) {
      if (!can(attrs.perm)) return null;
      attrs = Object.assign({}, attrs);
      delete attrs.perm;
    }
    const [name, ...cls] = tag.split(".");
    const el = document.createElement(name || "div");
    if (cls.length) el.className = cls.join(" ");
    if (attrs && (typeof attrs !== "object" || attrs instanceof Node || Array.isArray(attrs))) { kids.unshift(attrs); attrs = null; }
    for (const k in attrs || {}) {
      const v = attrs[k];
      if (v === undefined || v === null || v === false) continue;
      if (k.startsWith("on")) on(el, k.slice(2), v);
      else if (k === "class") el.className += " " + v;
      else if (k === "value") el.value = v;
      else if (k === "style") el.style.cssText = v;
      else if (k === "checked" || k === "disabled" || k === "selected") el[k] = !!v;
      else el.setAttribute(k, v === true ? "" : v);
    }
    const add = (c) => {
      if (c === null || c === undefined || c === false) return;
      if (Array.isArray(c)) c.forEach(add);
      else el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    };
    kids.forEach(add);
    return el;
  }

  // What the signed-in user may do. Filled from every status reply; the
  // gateway checks each request again, this only hides what would be refused.
  let ME = { admin: false, perms: [] };
  function can(p) {
    if (Array.isArray(p)) return p.every(can);
    return ME.admin || (p !== "admin" && ME.perms.includes(p));
  }
  // Settings for admins; status only for everyone else.
  async function settingsOrStatus() { return ME.admin ? api("/api/settings") : { status: await api("/api/status") }; }

  // Handlers go through el._on so a redraw can hand an element that stays
  // on the page the new closures (see morph).
  function on(el, type, fn) {
    if (!el._on) el._on = {};
    if (!el._on[type]) el.addEventListener(type, (e) => el._on[type] && el._on[type](e));
    el._on[type] = fn;
  }
  // Updates `old` in place to look like `nu`: same elements stay, so rows
  // don't jump, scroll boxes keep their place and focus stays put. Children
  // with data-key are matched by key, the rest by position and tag. Form
  // fields and anything marked data-ref (code keeps a handle on it) are
  // swapped for the new one, as before.
  const keyOf = (n) => n.nodeType === 1 ? n.getAttribute("data-key") : null;
  function morph(old, nu) {
    if (old === nu) return old;
    if (old.nodeType !== nu.nodeType || old.nodeName !== nu.nodeName || keyOf(old) !== keyOf(nu) || old.nodeName === "CANVAS" || /^(INPUT|SELECT|TEXTAREA)$/.test(old.nodeName) || (nu.nodeType === 1 && nu.hasAttribute("data-ref"))) { old.replaceWith(nu); return nu; }
    if (old.nodeType === 3) { if (old.nodeValue !== nu.nodeValue) old.nodeValue = nu.nodeValue; return old; }
    if (old.nodeType !== 1) { old.replaceWith(nu); return nu; }
    for (const a of [...old.attributes]) if (!nu.hasAttribute(a.name)) old.removeAttribute(a.name);
    // style through the CSSOM: the page's CSP blocks style attributes.
    for (const a of [...nu.attributes]) if (old.getAttribute(a.name) !== a.value) { if (a.name === "style") old.style.cssText = nu.style.cssText; else old.setAttribute(a.name, a.value); }
    for (const k of ["checked", "disabled", "selected"]) if (k in nu && old[k] !== nu[k]) old[k] = nu[k];
    if ("value" in nu && old !== document.activeElement && old.value !== nu.value && old.type !== "file") old.value = nu.value;
    for (const t in old._on || {}) if (!(nu._on || {})[t]) old._on[t] = null;
    for (const t in nu._on || {}) on(old, t, nu._on[t]);
    morphKids(old, [...nu.childNodes]);
    return old;
  }
  function morphKids(el, kids) {
    const olds = [...el.childNodes], byKey = new Map();
    olds.forEach((n) => { const k = keyOf(n); if (k != null) byKey.set(k, n); });
    let i = 0;
    const used = new Set();
    kids.forEach((nu, at) => {
      const k = keyOf(nu);
      let m = k != null ? byKey.get(k) : null;
      if (k == null) { while (i < olds.length && (used.has(olds[i]) || keyOf(olds[i]) != null)) i++; if (i < olds.length && olds[i].nodeName === nu.nodeName) m = olds[i++]; }
      let n;
      if (m && !used.has(m)) { used.add(m); n = morph(m, nu); } else n = nu;
      if (el.childNodes[at] !== n) el.insertBefore(n, el.childNodes[at] || null);
    });
    while (el.childNodes.length > kids.length) el.lastChild.remove();
  }
  // Keeps a live list's rows where they were across refreshes: rows already
  // shown keep their order, new ones go on top (or the end), gone ones drop.
  // A new `ctx` (sort, filter, search) starts over in the server's order.
  const orders = {};
  function stable(name, ctx, list, keyFn, newAtEnd) {
    // Two rows with the same text (two connections to one place) get #2, #3.
    const seen = {};
    list.forEach((x) => { const k = keyFn(x); seen[k] = (seen[k] || 0) + 1; x._key = seen[k] > 1 ? k + " #" + seen[k] : k; });
    const key = (x) => x._key;
    const o = orders[name];
    const by = new Map(list.map((x) => [key(x), x]));
    if (!o || o.ctx !== ctx) { orders[name] = { ctx, keys: list.map(key) }; return list; }
    const kept = o.keys.filter((k) => by.has(k)), fresh = list.map(key).filter((k) => !o.keys.includes(k));
    o.keys = newAtEnd ? kept.concat(fresh) : fresh.concat(kept);
    return o.keys.map((k) => by.get(k));
  }

  // Replace an element's children, skipping empty parts.
  function fill(el, ...kids) { el.replaceChildren(); el.append(...kids.flat().filter((k) => k !== null && k !== undefined && k !== false)); }

  // Immediate press acknowledgement for Firewall / Settings / Devices API
  // controls. Capture the control on mousedown/click so POST handlers can
  // light it as pending and block a second tap until the request finishes.
  let lastTap = null, apiBusy = false, changeBusy = false;
  document.addEventListener("pointerdown", (e) => {
    const el = e.target && e.target.closest && e.target.closest("button, a.btn, [role=button], label.check");
    if (el) lastTap = el;
  }, true);
  function markBusy(el) {
    if (!el || !el.isConnected) return null;
    if (el.tagName === "LABEL") {
      const inp = el.querySelector("input");
      if (inp) { inp.disabled = true; inp.setAttribute("aria-busy", "true"); }
      el.classList.add("busy");
      return el;
    }
    el.classList.add("busy");
    el.setAttribute("aria-busy", "true");
    if ("disabled" in el) {
      if (el.dataset.wasDisabled === undefined) el.dataset.wasDisabled = el.disabled ? "1" : "0";
      el.disabled = true;
    }
    // Optimistic selected look for segmented / stacked choices (new-device
    // policy, time prefs, card on/off) so the tap reads as taken at once.
    if (el.closest(".seg, .stack, .seg.onoff") && !el.classList.contains("on") && !el.classList.contains("isOn")) {
      el.classList.add("pending");
    }
    return el;
  }
  function clearBusy(el) {
    if (!el) return;
    el.classList.remove("busy", "pending");
    el.removeAttribute("aria-busy");
    if (el.tagName === "LABEL") {
      const inp = el.querySelector("input");
      if (inp) { inp.disabled = false; inp.removeAttribute("aria-busy"); }
      return;
    }
    if ("disabled" in el && el.dataset.wasDisabled !== undefined) {
      el.disabled = el.dataset.wasDisabled === "1";
      delete el.dataset.wasDisabled;
    }
  }
  async function api(path, body) {
    const writing = body !== undefined;
    if (writing && apiBusy) throw new Error("Still applying…");
    const tap = writing ? lastTap : null;
    if (writing) { apiBusy = true; markBusy(tap); document.documentElement.classList.add("api-busy"); }
    try {
      const opt = writing ? { method: "POST", headers: { "X-FG": "1", "Content-Type": "application/json" }, body: JSON.stringify(body) } : {};
      const r = await fetch(path, Object.assign({ credentials: "same-origin", cache: "no-store" }, opt));
      let data = {};
      try { data = await r.json(); } catch (e) { data = {}; }
      if (r.status === 401 && data.redirect && location.pathname !== "/login") {
        let dest = data.redirect;
        if (dest === "/login" || dest.startsWith("/login?")) {
          const here = sameSitePath(location.pathname + location.search);
          if (here && here !== "/login") dest = "/login?next=" + encodeURIComponent(here);
        }
        if (location.pathname + location.search !== dest) location.href = dest;
        throw new Error("redirect");
      }
      if (!r.ok) throw new Error(data.error || ("The gateway answered " + r.status + "."));
      return data;
    } finally {
      if (writing) {
        apiBusy = false;
        document.documentElement.classList.remove("api-busy");
        // change() keeps the pressed look through confirmChange; only clear
        // here for direct api() POSTs (Settings address save, etc.).
        if (!changeBusy && tap && tap.isConnected) clearBusy(tap);
      }
    }
  }

  // ---------- formatting ----------
  let OFFSET = 0;
  const pad = (n) => String(n).padStart(2, "0");
  function local(t) { const d = new Date((t + OFFSET) * 1000); return d; }
  // Time/date display. Prefs live on the gateway (status.hour12, status.date_fmt).
  let HOUR12 = true, DATE_FMT = "ymd"; // ymd | mdy | dmy
  function applyTimePrefs(st) {
    if (!st) return;
    if (st.hour12 != null) HOUR12 = !!st.hour12;
    if (st.date_fmt) DATE_FMT = st.date_fmt;
  }
  function fmtTime(d) {
    let h = d.getUTCHours(), m = pad(d.getUTCMinutes());
    if (!HOUR12) return pad(h) + ":" + m;
    const ap = h >= 12 ? " PM" : " AM";
    h = h % 12; if (!h) h = 12;
    return h + ":" + m + ap;
  }
  function fmtDate(d) {
    const y = d.getUTCFullYear(), mo = pad(d.getUTCMonth() + 1), day = pad(d.getUTCDate());
    if (DATE_FMT === "mdy") return mo + "/" + day + "/" + y;
    if (DATE_FMT === "dmy") return day + "/" + mo + "/" + y;
    return y + "-" + mo + "-" + day;
  }
  function when(t) {
    if (!t) return "never";
    const d = local(t), today = local(Math.floor(Date.now() / 1000));
    const hm = fmtTime(d);
    const same = d.toISOString().slice(0, 10) === today.toISOString().slice(0, 10);
    const yday = local(Math.floor(Date.now() / 1000) - 86400);
    const isYday = d.toISOString().slice(0, 10) === yday.toISOString().slice(0, 10);
    if (same) return "Today " + hm;
    if (isYday) return "Yesterday " + hm;
    return fmtDate(d) + " " + hm;
  }
  function bytes(n) {
    n = Number(n) || 0;
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(n < 10 ? 1 : 0) : Math.round(n)) + " " + u[i];
  }
  const rate = (n) => bytes(n) + "/s";
  function dur(s) {
    s = Number(s) || 0;
    const d = Math.floor(s / 86400), hr = Math.floor(s / 3600) % 24, m = Math.floor(s / 60) % 60;
    if (d) return d + "d " + hr + "h";
    if (hr) return hr + "h " + m + "m";
    return m + "m";
  }
  // Device = host /proc/uptime; FoilGateway = daemon process uptime.
  function dualUp(st) {
    const dev = "Device Up " + dur(st && st.uptime);
    if (st && st.daemon_uptime != null) return dev + " · FoilGateway Up " + dur(st.daemon_uptime);
    return dev;
  }

  const GLOSS = {
    WAN: "The port with the cable to your router.",
    LAN: "The side toward your switch, Wi-Fi and devices.",
    SSH: "A way to log in to the gateway from a terminal.",
    MAC: "A device’s hardware address on the network.",
    CIDR: "A way to write a range of addresses, like 10.0.0.0/8.",
    HTTPS: "The encrypted web address for this settings page.",
  };
  function gloss(word) {
    const tip = GLOSS[word];
    if (!tip) return word;
    return h("span.gloss", { title: tip, tabindex: 0 }, word, h("span.gloss-tip", h("b", word), tip));
  }

  const POLICY = { trusted: "Trusted", normal: "Normal", lan_only: "Local Network Only", block: "Block All" };
  const MODE = { normal: "Normal", audit: "Audit", lan_only: "Local Network Only", block_all: "Block Everything" };
  // Dashboard top cards, in order. A new card is one line here plus its
  // builder in dashboard(); Settings > View lists these. The server keeps
  // only the owner's on/off choices (status.cards), by id.
  const CARDS = [
    { id: "mode", label: "Mode", on: true },
    { id: "path", label: "Traffic Path", on: true },
    { id: "wan", label: "WAN speed", on: true },
    { id: "lan", label: "LAN speed", on: true },
    { id: "countries", label: "Countries Now", on: true },
    { id: "devices", label: "Devices online", on: true },
    { id: "cpu", label: "CPU load", on: true },
    { id: "temp", label: "CPU Temperature", on: true },
    { id: "disk", label: "Disk", on: true },
    { id: "memory", label: "Memory", on: true },
    { id: "blocked", label: "Blocked Today", on: true },
  ];
  const cardOn = (st, c) => (st.cards && c.id in st.cards ? st.cards[c.id] : c.on);
  // Narrowest a card gets before its value would be hard to read.
  const CARD_MIN = 145, CARD_GAP = 8;
  // As few rows as fit at a readable width, then spread evenly over those
  // rows (11 cards: 6+5, 4+4+3), so no row ends with one card on its own.
  function cardCols(n, width) {
    if (n <= 1) return 1;
    const fit = Math.max(1, Math.min(n, Math.floor((width + CARD_GAP) / (CARD_MIN + CARD_GAP))));
    return Math.ceil(n / Math.ceil(n / fit));
  }
  function layCards(el) {
    if (!el) return;
    const n = el.children.length, cols = cardCols(n, el.clientWidth);
    const v = "repeat(" + cols + ", minmax(0, 1fr))";
    if (el.style.gridTemplateColumns !== v) el.style.gridTemplateColumns = v;
    // Two across with an odd count: the last card takes the whole row.
    [...el.children].forEach((c, i) => c.classList.toggle("span", cols > 1 && n % cols === 1 && i === n - 1));
  }
  const qp0 = new URLSearchParams(location.search);
  // Link rate still in bits for captions; live throughput uses fixed-width In/Out.
  function bits(n) {
    n = Number(n) || 0;
    const u = ["b/s", "kb/s", "Mb/s", "Gb/s"];
    let i = 0;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    return (i ? n.toFixed(n < 10 ? 1 : 0) : Math.round(n)) + " " + u[i];
  }
  // Bytes/sec: digit column is always 4 + ".xx" (NBSP pad, never zeros); unit column is always 4ch.
  // So the decimal point stays put when the rate grows or the unit steps B/s→KB/s→MB/s.
  function thrPut(bps) {
    let n = (Number(bps) || 0) / 8;
    const u = ["B/s", "KB/s", "MB/s", "GB/s"];
    let i = 0;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    const whole = Math.floor(n + 1e-9);
    const frac = ((n - whole) + 1e-9).toFixed(2).slice(1); // ".xx"
    const nb = " ";
    const digits = String(whole).padStart(4, nb) + frac;
    const unit = (u[i] + nb + nb + nb + nb).slice(0, 4);
    return h("span.thr-val", h("span.thr-digits", digits), h("span.thr-unit", unit));
  }
  function speedLines(p, bps) {
    if (!(p && p.link)) return portMissing(p);
    return h("div.thr",
      h("div.thr-row", h("span.thr-lab", "In"), h("span.thr-num.in", thrPut(bps[0]))),
      h("div.thr-row", h("span.thr-lab", "Out"), h("span.thr-num.out", thrPut(bps[1]))));
  }
  function portMissing(p) { return p ? (p.link ? (p.speed || "link") : "no cable") : "missing"; }
  const pill = (p) => h("span.pill." + p, POLICY[p] || p);

  // ---------- applying changes ----------
  // A change that touches the firewall is undone by the gateway unless this
  // browser can still reach it afterwards. We ask from a fresh connection.
  const overlay = h("div.overlay", { hidden: true });
  document.body.append(overlay);
  function showBox(...kids) { overlay.replaceChildren(h("div.box", kids)); overlay.hidden = false; }
  function hideBox() { overlay.hidden = true; overlay.replaceChildren(); }
  // Expand/collapse sticky across poll refresh. User must click again to collapse.
  const openFolds = new Set();
  function foldKeyToggle(key, ev) {
    if (ev) { ev.preventDefault(); ev.stopPropagation(); }
    if (openFolds.has(key)) { openFolds.delete(key); openFolds.add(key + ":seen"); }
    else { openFolds.add(key); openFolds.add(key + ":seen"); }
  }
  function foldEl(key, summaryText, bodyKids, cls) {
    const open = openFolds.has(key);
    const tag = "details." + (cls || "fold");
    return h(tag, open ? { open: true, "data-fold": key } : { "data-fold": key },
      h("summary", { onclick: (e) => { foldKeyToggle(key, e); const d = e.currentTarget.parentElement; if (d) d.open = openFolds.has(key); } }, summaryText),
      ...(Array.isArray(bodyKids) ? bodyKids : [bodyKids]));
  }

  // H8: short recovery help, linked from confirm dialogs that can lock you out.
  function helpReach() {
    showBox(
      h("h3", "If You Can’t Reach This Page"),
      h("p", "Use these in order. Most lockouts clear on their own."),
      h("ol.help",
        h("li", h("b", "Use a safety computer. "), "The computer you added during setup can always open this page, whatever else you changed."),
        h("li", h("b", "Wait about 3 minutes. "), "A change that cuts you off undoes itself within the rollback timer (usually 3 minutes) if this browser can’t reach the gateway."),
        h("li", h("b", "Log in over SSH, then run: "), h("code", "foilgw rollback"), " to put the last good settings back, or ", h("code", "foilgw rollback-version"), " to go to the previous release."),
        h("li", h("b", "Pulling the power is safe. "), "Unplug the gateway, wait a few seconds, plug it back in. Settings stay; only the running state restarts.")),
      h("p.hint", "This help is linked from every confirm dialog that can lock you out."),
      h("div.acts", h("button", { onclick: hideBox }, "Close")));
  }
  function helpLink() {
    return h("p.hint", h("a", { href: "#", onclick: (e) => { e.preventDefault(); helpReach(); } }, "If you can’t reach this page"));
  }

  // Undo timer copy: always say how long.
  function undoHint(secs) {
    const n = Number(secs) || 180;
    const label = n >= 60 ? (Math.round(n / 60) + " minute" + (Math.round(n / 60) === 1 ? "" : "s")) : (n + " seconds");
    return "If this page can’t reach the gateway afterwards, the change undoes itself within " + label + ".";
  }

  // H2: pick a mode (explanation updates), then Activate. H1: Block Everything needs BLOCK.
  const MODE_HELP = {
    normal: "Applies the Normal protection level. Settings can be changed afterward.",
    audit: "Lets all traffic through and logs what would have been blocked.",
    lan_only: "Blocks traffic between the LAN and the internet.",
    block_all: "Blocks all traffic to and through the gateway. Safety computers can open the settings pages and connect over SSH. Both require signing in.",
  };
  function diffTable(rows) {
    if (!rows || !rows.length) return h("p.hint", "No settings change.");
    return h("table.compact.diff-why",
      h("thead", h("tr", h("th", "Setting"), h("th", "Now"), h("th", "After"))),
      h("tbody", rows.map((x) => h("tr",
        h("td", h("div", x.label), x.why ? h("div.hint", x.why) : null),
        h("td.mute", x.from),
        h("td", x.to)))));
  }
  // Preview old→new for mode / level / Leave Audit. Nothing applies until OK.
  async function previewAsk(title, applyBody, opts) {
    opts = opts || {};
    const danger = !!opts.danger;
    let prev;
    try {
      prev = await api("/api/firewall", Object.assign({ preview: true }, applyBody));
    } catch (e) {
      showBox(h("h3", title), h("p.bad", (e && e.message) || "Could not preview."), h("div.acts", h("button.quiet", { onclick: hideBox }, "Cancel")));
      return;
    }
    const rows = (prev && prev.diff) || [];
    const go = h("button" + (danger ? ".danger" : ""), { onclick: () => {
      hideBox();
      if (opts.afterOk) return opts.afterOk();
      change("/api/firewall", applyBody);
    } }, "OK");
    showBox(h("div.dlg",
      h("h3", title),
      opts.lead ? h("p", opts.lead) : null,
      h("p.hint", "These settings will change:"),
      diffTable(rows),
      opts.extra || null,
      helpLink(),
      h("div.acts", h("button.quiet", { onclick: hideBox }, "Cancel"), go)));
  }
  function modeAsk(start, secs) {
    let pick = start || "audit";
    const body = h("div");
    const draw = () => {
      const danger = pick === "block_all" || pick === "lan_only";
      body.replaceChildren(
        h("h3", "Protection Mode"),
        h("p", "Pick a mode. The note below updates. Activate shows what will change."),
        h("div.seg.modepick", ["normal", "audit", "lan_only", "block_all"].map((m) =>
          h("button" + (pick === m ? ".on" + (m === "block_all" ? ".block" : "") : ""), { type: "button", onclick: () => { pick = m; draw(); } }, MODE[m]))),
        h("div.explain" + (pick === "block_all" ? ".badish" : pick === "lan_only" ? ".warnish" : ""), MODE_HELP[pick]),
        pick === "block_all" ? h("p.hint", "OK then asks you to type BLOCK before it takes effect.") : null,
        helpLink(),
        h("div.acts",
          h("button.quiet", { onclick: hideBox }, "Cancel"),
          h("button" + (danger ? ".danger" : ""), { onclick: () => {
            const applyBody = { mode: pick };
            hideBox();
            previewAsk("Apply " + MODE[pick] + "?", applyBody, {
              danger,
              lead: pick === "normal" ? "Protection Mode Normal sets the Normal protection level. You can fine-tune afterward." : null,
              afterOk: pick === "block_all" ? () => blockAsk(secs) : null,
            });
          } }, "Activate")));
    };
    showBox(body);
    draw();
  }
  function blockAsk(secs) {
    const typed = h("input", { placeholder: "BLOCK", autocomplete: "off" });
    const go = h("button.danger", { disabled: true, onclick: () => { hideBox(); change("/api/firewall", { mode: "block_all" }); } }, "Block Everything");
    typed.addEventListener("input", () => { go.disabled = typed.value.trim() !== "BLOCK"; });
    showBox(
      h("h3", "Block Everything?"),
      h("ul.warn",
        h("li", "Blocks all traffic to and through the gateway."),
        h("li", "Safety computers can open the settings pages and connect over SSH. Both require signing in.")),
      h("label", "Type BLOCK to go on"), typed,
      helpLink(),
      h("div.acts", h("button.quiet", { onclick: hideBox }, "Cancel"), go));
    typed.focus();
  }

  // H6: device Block All warns, then Activate.
  function policyAsk(mac, label, cur, set) {
    let pick = cur;
    const body = h("div");
    const draw = () => {
      body.replaceChildren(
        h("h3", label + " · Policy"),
        h("p", "Pick a policy. The note below updates. Activate turns it on."),
        h("div.seg.modepick", ["trusted", "normal", "lan_only", "block"].map((p) =>
          h("button" + (pick === p ? ".on" + (p === "block" ? ".block" : "") : ""), { type: "button", onclick: () => { pick = p; draw(); } }, POLICY[p]))),
        h("div.explain" + (pick === "block" ? ".badish" : pick === "lan_only" ? ".warnish" : ""),
          pick === "block" ? (label + " loses traffic to and through the gateway until you change this policy again.")
          : pick === "lan_only" ? (label + " can reach other devices and the gateway, but not the internet.")
          : pick === "trusted" ? "Trusted skips the Black list, threat lists and countries."
          : "This device uses the internet under the network rules."),
        h("div.acts",
          h("button.quiet", { onclick: hideBox }, "Cancel"),
          h("button" + (pick === "block" ? ".danger" : ""), { onclick: () => { hideBox(); set({ policy: pick }); } }, "Activate")));
    };
    showBox(body);
    draw();
  }


  // Settings > Setup: restart the service, then wait for it and reload.
  function restartAsk() {
    const err = h("div.err");
    const go = h("button.danger", { id: "restart-go", onclick: async () => {
      go.disabled = true;
      try { await api("/api/restart", {}); } catch (e) { err.textContent = e.message; go.disabled = false; return; }
      restartWait();
    } }, "Restart now");
    showBox(h("h3", "Restart FoilGateway?"),
      h("p", "While it restarts:"),
      h("ul.warn",
        h("li", "Every device behind the gateway loses the internet for a few seconds."),
        h("li", "Open connections, calls and downloads drop and have to start again."),
        h("li", "Everyone signed in to this page has to sign in again.")),
      h("p.hint", "This page reconnects on its own when the gateway is back."), err,
      h("div.acts", h("button.quiet", { onclick: hideBox }, "Cancel"), go));
  }
  // Settings > Setup: go back to the version kept at the last update.
  function rollbackAsk(rel) {
    const err = h("div.err");
    const go = h("button.danger", { id: "rollback-go", onclick: async () => {
      go.disabled = true;
      try { await api("/api/rollback-version", {}); } catch (e) { err.textContent = e.message; go.disabled = false; return; }
      restartWait("Rolling Back to " + rel.previous);
    } }, "Roll Back Now");
    const lost = (rel.lost || []);
    showBox(h("h3", "Roll Back to FoilGateway " + rel.previous + "?"),
      h("p", "Puts back the version from before the last update and restarts."),
      h("ul.warn",
        h("li", "Every device loses the internet for a few seconds."),
        h("li", "Open connections, calls and downloads drop."),
        h("li", "Everyone signed in has to sign in again."),
        lost.length ? h("li", "These changes since the update go back:", h("ul", lost.map((x) => h("li", x))))
          : (rel.schema_differs ? h("li", "Settings changed since the update may not carry over: settings go back to how they were when " + rel.current + " was installed.") : null)),
      h("p.hint", "You can come forward to " + rel.current + " again the same way. This page reconnects on its own."),
      helpLink(), err,
      h("div.acts",
        h("button.quiet", { onclick: hideBox }, "Cancel"),
        h("a.btn.quiet", { href: "/api/backup" }, "Download Backup First"),
        go));
  }
  async function restartWait(title) {
    const line = h("p.hint", "Waiting for it to stop…");
    showBox(h("h3", title || "Restarting"), h("p", "FoilGateway is restarting. Devices get the internet back in a few seconds."), line);
    const t0 = Date.now();
    let down = false;
    for (;;) {
      await new Promise((r) => setTimeout(r, 700));
      let up = false;
      try {
        const c = new AbortController(), k = setTimeout(() => c.abort(), 1500);
        up = (await fetch("/api/ping", { cache: "no-store", signal: c.signal })).ok;
        clearTimeout(k);
      } catch (e) { up = false; }
      if (!up && !down) { down = true; line.textContent = "Stopped. Waiting for it to come back…"; }
      // Back after being seen down; or never seen down but long past the restart.
      if (up && (down || Date.now() - t0 > 15000)) { line.textContent = "Back. Reloading…"; location.reload(); return; }
      if (Date.now() - t0 > 120000) { line.textContent = "It hasn't come back after two minutes. Check the gateway, then reload this page."; return; }
    }
  }
  // Important = disruptive. Silent success for the rest; failures still dialog.
  function changeImportance(body) {
    if (!body || typeof body !== "object") return null;
    if (body.leave_audit || body.mode === "normal") return { title: "Normal Protection Is On", text: "Threat Lists and Whitelist Expiry are On. You can fine-tune any of these under Firewall → Hardening." };
    if (body.preset === "fortnox" || body.preset === "FortNox") return { title: "FortNox Applied", text: "Block All Telemetry and Strict Outbound are on, and Remote Desktop is blocked on the home network too. Unusual apps may need Allow on the Troubleshooter." };
    if (body.mode === "block_all") return { title: "Block Everything Is On", text: "All traffic to and through the gateway is blocked. Safety computers can open the settings pages and connect over SSH. Both require signing in. Turn this off from Firewall → Protection Mode when you are ready." };
    if (body.mode === "lan_only") return { title: "Local Network Only Is On", text: "Traffic between the LAN and the internet through the gateway is blocked. Devices can still reach FoilGateway. Turn this off from Firewall → Protection Mode when you are ready." };
    if (body.strict_outbound === true) return { title: "Strict Outbound Is On", text: "Only new outbound that matches your rules gets through. Odd apps may need Allow. Turn it off under Firewall → Hardening if something breaks." };
    if (body.block_vpn === true) return { title: "VPN Ports Are Blocked", text: "Common VPN / WireGuard ports are stopped. VPN apps on phones or PCs will fail until you turn this off under Firewall → Hardening." };
    if (body.block_ipv6 === true) return { title: "Block IPv6 Is On", text: "IPv6 forwarding is blocked across the gateway, including discovery and DHCPv6. Local discovery to the gateway itself still works. Turn it off under Firewall → Hardening if a device needs IPv6." };
    if (body.admin_from === "lan") return { title: "Settings: Local Network Only", text: "This page now answers only from devices behind the gateway. The router / internet side can no longer open it." };
    // Best Practices Accept of a disruptive tip.
    if (body.accept === "strict") return { title: "FortNox Applied", text: "Block All Telemetry and Strict Outbound are on, and Remote Desktop is blocked on the home network too. Unusual apps may need Allow on the Troubleshooter." };
    if (body.accept === "leave_audit") return { title: "Left Audit", text: "Everyday Normal protection is on now: threat lists and whitelist expiry." };
    if (body.accept === "admin_lan") return { title: "Settings: Local Network Only", text: "This page now answers only from devices behind the gateway. The router / internet side can no longer open it." };
    if (body.accept === "block_ipv6" || body.accept === "ipv6_off") return { title: "Block IPv6 Is On", text: "IPv6 forwarding is blocked across the gateway, including discovery and DHCPv6. Local discovery to the gateway itself still works. Turn it off under Firewall → Hardening if a device needs IPv6." };
    if (body.accept === "block_vpn") return { title: "VPN Ports Are Blocked", text: "Common VPN / WireGuard ports are stopped. VPN apps on phones or PCs will fail until you turn this off under Firewall → Hardening." };
    return null;
  }
  function ackKept(info) {
    return new Promise((resolve) => {
      showBox(h("h3", info.title), h("p", info.text), h("div.acts", h("button", { onclick: () => { hideBox(); resolve(true); } }, "OK")));
    });
  }
  async function confirmChange(res, port, importance) {
    const ack = async (kept) => {
      if (kept && importance) await ackKept(importance);
      else if (!importance) hideBox();
      return !!kept;
    };
    if (!res || !res.pending) return ack(true);
    const base = port && String(port) !== location.port && !(location.port === "" && port === 443) ? location.protocol + "//" + location.hostname + ":" + port : "";
    const end = Date.now() + (res.secs || 60) * 1000 - 3000;
    // Silent confirm in the background. pendingNote on the page covers the wait.
    // No flash popup  -  that worried people when it vanished too fast.
    while (!base && Date.now() < end) {
      try {
        const r = await fetch(base + "/api/confirm", { method: "POST", headers: { "X-FG": "1" }, credentials: base ? "include" : "same-origin", cache: "no-store", mode: base ? "cors" : "same-origin" });
        if (r.ok) { const d = await r.json(); if (d.kept) return ack(true); break; }
      } catch (e) { /* not reachable yet, try again */ }
      await new Promise((r) => setTimeout(r, 1500));
    }
    if (base) {
      showBox(h("h3", "Open the new address"), h("p", "Settings now answer on port " + port + ". Open it within the countdown and sign in to keep the change, or it goes back to the old port."),
        h("div.acts", h("a.btn", { href: base + "/settings?confirm=1" }, "Open " + base)));
      return false;
    }
    showBox(h("h3", "The change was undone"), h("p", "This browser couldn't reach the gateway with the new rules, so the old ones are back."), h("div.acts", h("button", { onclick: () => location.reload() }, "OK")));
    return false;
  }

  async function change(path, body, after) {
    if (changeBusy || apiBusy) return;
    changeBusy = true;
    const tap = lastTap;
    markBusy(tap);
    const importance = changeImportance(body);
    try {
      const res = await api(path, body);
      if (res.redirect) { location.href = res.redirect; return res; }
      await confirmChange(res, res.port, importance);
      if (after) after(res); else refresh();
      return res;
    } catch (e) {
      if (e.message !== "redirect" && e.message !== "Still applying…") showBox(h("h3", "That didn't go in"), h("p", e.message), h("div.acts", h("button", { onclick: hideBox }, "OK")));
      if (e.message === "Still applying…") return;
      throw e;
    } finally {
      changeBusy = false;
      if (tap && tap.isConnected) clearBusy(tap);
    }
  }

  // ---------- page shell ----------
  const ICONS = {
    dashboard: "M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z",
    devices: "M4 5h16v10H4zM2 19h20M9 15v4M15 15v4",
    firewall: "M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z",
    log: "M5 3h14v18H5zM8 8h8M8 12h8M8 16h5",
    ports: "M4 4h16v16H4zM8 8v4M12 8v4M16 8v4M7 16h10",
    settings: "M12 8a4 4 0 100 8 4 4 0 000-8zM3 12h3M18 12h3M12 3v3M12 18v3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1",
  };
  // Sub-menus open under their page only, like the Windows app. The parent
  // opens the page's main view.
  const SUBS = {
    devices: [["/devices", "All Devices"], ["/devices/troubleshoot", "Troubleshooter"]],
    firewall: [["/firewall", "Status"], ["/firewall/mode", "Protection Mode"], ["/firewall/presets", "Protection Levels"], ["/firewall/hardening", "Hardening"], ["/firewall/coach", "Best Practices"], ["/firewall/geo", "Geo-Blocking"], ["/firewall/white", "Whitelist"], ["/firewall/black", "Blacklist"], ["/firewall/audit", "Audit"], ["/firewall/rules", "Rules as loaded"]],
    ports: [["/ports", "Global"], ["/ports/devices", "Per Device"]],
    // One entry per topic; a later topic (or a panel such as Certificates
    // under Network & access) is one line here plus its panels in settings().
    settings: [["/settings", "Network & Access"], ["/settings/certs", "Certificates"], ["/settings/general", "Time and Location"], ["/settings/log", "Capture Log"], ["/settings/users", "Users"], ["/settings/notify", "Notifications"], ["/settings/view", "View"], ["/settings/setup", "Setup"], ["/settings/updates", "Updates"], ["/settings/help", "Help"], ["/settings/about", "About"]],
  };
  const PATH = location.pathname.replace(/\/+$/, "") || "/";
  const icon = (k) => { const s = document.createElementNS("http://www.w3.org/2000/svg", "svg"); s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("class", "ico"); s.innerHTML = '<path d="' + ICONS[k] + '" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>'; return s; };
  // Which permission opens each page and sub-page. Admins see all.
  const PAGE_PERM = { dashboard: "status", devices: "devices", firewall: "firewall_view", ports: "firewall_view", log: "log" };
  const SUB_PERM = {
    "/devices/troubleshoot": "alerts", "/firewall/audit": "alerts",
    "/settings": "speed_view", "/settings/updates": "updates_view", "/settings/help": "any", "/settings/about": "any",
    "/firewall/coach": "admin",
  };
  const subOk = (u) => ME.admin || (SUB_PERM[u] ? SUB_PERM[u] === "any" || can(SUB_PERM[u]) : !u.startsWith("/settings"));
  const pageOk = (k) => ME.admin || (k === "settings" ? SUBS.settings.some(([u]) => subOk(u)) : can(PAGE_PERM[k]));
  // The first page a user can open: the main pages in menu order, then
  // the settings pages (Speed Test, Updates, Help) in their menu order.
  const firstPage = () => {
    const main = [["dashboard", "/"], ["devices", "/devices"], ["firewall", "/firewall"], ["ports", "/ports"], ["log", "/log"]].find(([k]) => pageOk(k));
    return main ? main[1] : (SUBS.settings.find(([u]) => subOk(u)) || ["/settings/help"])[0];
  };
  // The API Reference opens from Users and lights Users in the menu.
  const navPath = PATH === "/settings/api" ? "/settings/users" : PATH === "/settings/account" ? "/settings/users" : PATH;
  function sideNav() {
    const nav = [["dashboard", "/", "Dashboard"], ["devices", "/devices", "Devices"], ["firewall", "/firewall", "Firewall"], ["ports", "/ports", "Ports"], ["log", "/log", "Capture Log"], ["settings", "/settings", "Settings"]];
    const first = (k, href) => k === "settings" && !ME.admin ? ((SUBS.settings.find(([u]) => subOk(u)) || [href])[0]) : href;
    return h("aside" + (SUBS[PAGE] ? ".subs" : ""),
      h("div.brand", h("img", { src: "/s/icon.svg", alt: "" }), h("div", h("b", "FoilGateway"), h("small", "Network edition"))),
      nav.filter(([k]) => pageOk(k)).map(([k, href, label]) => [h("a.nav" + (k === PAGE ? ".on" : ""), { href: first(k, href), id: "nav-" + k }, icon(k), label),
        k === PAGE && SUBS[k] ? h("div.subnav", SUBS[k].filter(([u]) => subOk(u)).map(([u, t]) => h("a" + (u === navPath ? ".on" : ""), { href: u }, !ME.admin && u === "/settings" ? "Speed Test" : t))) : null]),
      h("div.status", { id: "sysbox" }),
      h("div.ver", h("span", { id: "ver" })));
  }
  let side = null, mainEl = null;
  function shell(title) {
    side = sideNav();
    mainEl = h("main");
    $("#app").replaceChildren(h("div.shell", side, mainEl));
    document.title = title + " - FoilGateway";
  }
  function statusBox(st) {
    if (st && typeof st.admin === "boolean") {
      const was = JSON.stringify(ME);
      ME = { admin: st.admin, perms: st.perms || [] };
      // Permissions changed while the page was open: draw the menu again.
      if (was !== JSON.stringify(ME) && side) { const s2 = sideNav(); side.replaceWith(s2); side = s2; }
    }
    applyTimePrefs(st);
    window.__fgWhiteExpiry = !!(st && st.white_expiry);
    OFFSET = st.offset || 0;
    $("#ver").textContent = "Version " + st.version;
    const nd = $("#nav-devices");
    if (nd) {
      nd.querySelector(".count")?.remove();
      if (st.new_devices) nd.append(h("span.count", String(st.new_devices)));
    }
    const lk = (p, name) => p ? h("span." + (p.link ? "ok" : "bad"), name + " " + p.name + (p.link ? " link" : " no cable")) : h("span.bad", name + " " + "missing");
    $("#sysbox").replaceChildren(
      h("h2", "System status"),
      h("div.dot." + (st.in_path ? "ok" : "warn"), st.in_path ? "In the traffic path" : "Not in path yet"),
      h("div", "Mode ", h("b", MODE[st.mode] || st.mode)),
      h("div", lk(st.wan, "WAN")), h("div", lk(st.lan, "LAN")),
      h("div", "Safety ", st.safety ? h("span.ok", "on") : h("span.bad", "off")),
      h("div.why", dualUp(st) + (st.temp != null ? " · " + st.temp.toFixed(0) + "°C" : "")));
  }
  function header(title, st, tools) {
    return h("div.head", h("h1", title), h("span.when", when(st.now)), h("span.offline", { id: "offline", hidden: true }, "Can't reach the gateway"),
      h("div.tools", tools), h("div.who", h("span", { title: "Signed in" }, st.user || ""), h("button.quiet", { id: "signout", onclick: async () => { await api("/api/logout", {}); location.href = "/login"; } }, "Sign out")));
  }
  // Shown on every page while anything is in audit, so nobody forgets
  // that blocks are only being written down.
  const untilText = (t) => t > 4e18 ? "until turned off" : "until " + when(t);
  function auditNote(st) {
    const devs = st.auditing || [];
    if (st.mode !== "audit" && !devs.length) return null;
    const what = st.mode === "audit" ? "Audit is on for the whole network. Nothing is blocked; what would be is written down."
      : "Audit is on for " + (devs.length === 1 ? devs[0].label + " " + untilText(devs[0].until) : devs.length + " devices") + ". What would be blocked for " + (devs.length === 1 ? "it" : "them") + " is written down and let through.";
    return h("p.notice.audit", what, " ", can(["alerts", "firewall_view"]) ? h("a", { href: "/firewall/audit" }, "See what would be blocked") : null,
      st.mode === "audit" && can("admin") ? [" · ", h("a", { href: "/firewall#mode" }, "Change protection mode")] : null);
  }
  // Shown on every page while a newer release is known. Opens Updates; never installs.
  function updateNote(st) {
    if (!st || !st.update_available || PATH === "/settings/updates") return null;
    return h("p.notice", { id: "update-notice" }, h("b", "FoilGateway " + st.update_available + " is available. "),
      h("a", { perm: "updates_view", href: "/settings/updates" }, "Open Updates"));
  }
  function pendingNote(st) {
    const a = [auditNote(st), updateNote(st)];
    if (!st.pending) return a;
    return [...a, h("p.notice", "A change is waiting to be kept (" + st.pending.what + "). It goes back in " + st.pending.left + " s unless this browser confirms it.", " ",
      h("button.small", { perm: "admin", onclick: async () => { await api("/api/confirm", {}); refresh(); } }, "Keep it"))];
  }
  function pathNote(st) {
    return st.in_path ? null : h("p.notice", h("b", "Not in the traffic path yet. "), st.path_note.replace(/^Not in the traffic path yet: /, "").replace(/^./, (c) => c.toUpperCase()));
  }
  // Persistent until LAN-only or Keep Both (Normal default is LAN-only).
  function adminNudge(st) {
    if (!st || !st.admin_nudge || !can("admin")) return null;
    return h("p.notice", { "data-k": "admin-nudge" },
      h("b", "Settings still open from the router side. "),
      "Strangers on the internet side could open FoilGateway pages. Switch to Local Network Only, or keep both if you still need outside access.",
      h("div.row", { style: "margin-top:8px" },
        h("button.small", { onclick: () => change("/api/firewall", { admin_from: "lan" }) }, "Switch To Local Network Only"),
        h("button.small.quiet", { onclick: () => change("/api/firewall", { admin_keep_both: true }) }, "Keep Both")));
  }

  // Redraws keep each scroll box where it was and the cursor in the box
  // being typed in.
  function render(...kids) {
    const keep = {};
    mainEl.querySelectorAll("[data-k]").forEach((e) => { keep[e.dataset.k] = e.scrollTop; });
    const a = document.activeElement, focusId = a && a.id && mainEl.contains(a) ? a.id : null;
    const sel = focusId && a.selectionStart != null ? [a.selectionStart, a.selectionEnd] : null;
    morphKids(mainEl, kids.flat().filter((k) => k !== null && k !== undefined && k !== false));
    mainEl.querySelectorAll("[data-k]").forEach((e) => { if (keep[e.dataset.k]) e.scrollTop = keep[e.dataset.k]; });
    if (focusId) { const b = document.getElementById(focusId); if (b) { b.focus(); if (sel && b.setSelectionRange) try { b.setSelectionRange(sel[0], sel[1]); } catch (e) { /* number inputs */ } } }
  }
  // A scroll box that asks for more rows when it nears the bottom.
  function scroller(key, more, ...kids) {
    const el = h("div.scroll", { "data-k": key }, kids);
    if (more) el.addEventListener("scroll", () => { if (el.scrollTop + el.clientHeight > el.scrollHeight - 80) more(); });
    return el;
  }
  const shownOf = (n, total, what) => h("div.foot", total > n ? "Showing " + n + " of " + total + " " + what + ". Scroll down for more." : total + " " + what + ".");
  // A search box that waits for a pause in typing.
  function searchBox(id, value, set, hint) {
    let t = null;
    return h("input", { id, type: "search", placeholder: hint || "Search", value, oninput: (e) => { clearTimeout(t); t = setTimeout(() => set(e.target.value), 250); } });
  }

  let refresh = () => {};
  let geoSoon = 0, bridgeIps = [];
  let timer = null;
  function every(ms, fn) {
    refresh = async () => {
      try { await fn(); if ($("#offline")) $("#offline").hidden = true; }
      catch (e) { if ($("#offline")) $("#offline").hidden = false; }
    };
    refresh();
    clearInterval(timer);
    if (ms) timer = setInterval(() => { if (!document.hidden && overlay.hidden && !document.querySelector(".cal") && !document.activeElement?.matches("input:not([type=search]),textarea,select")) refresh(); }, ms);
  }
  const panel = (title, extra, ...kids) => h("section.panel", h("div.panel-head", h("h2", title), extra), kids);
  const grow = (el) => { el.classList.add("grow"); return el; };
  const table = (heads, rows, empty) => rows.length ? h("table", h("thead", h("tr", heads.map((x) => h("th" + (x.endsWith("#") ? ".num" : ""), x.replace(/#$/, ""))))), h("tbody", rows)) : h("p.empty", empty);
  // A date box with our own calendar, so it matches the rest of the page.
  // Value is "YYYY-MM-DD" or "". Only one calendar is open at a time.
  const ymd = (d) => d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate());
  function closeCal() { document.querySelectorAll(".cal").forEach((c) => c.remove()); }
  document.addEventListener("mousedown", (e) => { if (!e.target.closest(".datewrap")) closeCal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeCal(); });
  function datePicker(id, value, onpick) {
    const field = h("input.datefield", { id, readonly: true, value, placeholder: "Any day", "aria-haspopup": "dialog" });
    const wrap = h("span.datewrap", { "data-ref": "" }, field);
    let shown = value ? new Date(value + "T00:00") : new Date();
    const pick = (v) => { field.value = v; closeCal(); onpick(v); };
    const draw = () => {
      closeCal();
      const y = shown.getFullYear(), m = shown.getMonth(), first = (new Date(y, m, 1).getDay() + 6) % 7, days = new Date(y, m + 1, 0).getDate(), today = ymd(new Date());
      const cells = [];
      for (let i = 0; i < first; i++) cells.push(h("span"));
      for (let d = 1; d <= days; d++) {
        const v = y + "-" + pad(m + 1) + "-" + pad(d);
        cells.push(h("button" + (v === field.value ? ".isOn" : "") + (v === today ? ".today" : ""), { type: "button", onclick: () => pick(v) }, String(d)));
      }
      const step = (n) => { shown = new Date(y, m + n, 1); draw(); };
      wrap.append(h("div.cal", { role: "dialog" },
        h("div.cal-head", h("button.small.quiet", { type: "button", onclick: () => step(-1), "aria-label": "Previous month" }, "‹"), shown.toLocaleDateString(undefined, { month: "long", year: "numeric" }), h("button.small.quiet", { type: "button", onclick: () => step(1), "aria-label": "Next month" }, "›")),
        h("div.cal-grid", ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"].map((d) => h("span", d)), cells),
        h("div.row", { style: "margin-top:8px;justify-content:space-between" }, h("button.small.quiet", { type: "button", onclick: () => pick(today) }, "Today"), h("button.small.quiet", { type: "button", onclick: () => pick("") }, "Clear"))));
    };
    field.addEventListener("click", () => (wrap.querySelector(".cal") ? closeCal() : draw()));
    return wrap;
  }
  function ask(title, text, okLabel, onok, danger) {
    showBox(h("h3", title), h("p", text), h("div.acts", h("button.quiet", { onclick: hideBox }, "Cancel"), h("button" + (danger ? ".danger" : ""), { onclick: () => { hideBox(); onok(); } }, okLabel)));
  }
  function sameSitePath(p) {
    if (typeof p !== "string") return "";
    p = p.trim();
    if (!p.startsWith("/") || p.startsWith("//") || p.startsWith("/\\")) return "";
    if (p.includes("\\") || p.includes("://") || /[\s\x00-\x1f\x7f]/.test(p)) return "";
    return p;
  }

  // ---------- Dashboard ----------
  // Which list stopped it, what the list covers, and what usually breaks
  // (only when the list says so).
  function listLine(i, would) {
    if (!i || !i.list) return null;
    const l = i.list;
    return h("div.mute.why", (would ? "Would be blocked by " : "Blocked by ") + l.list + (l.covers ? ", which covers " + l.covers : "") + ". ",
      h("span", "What usually breaks: " + l.breaks + "."), l.link ? [" ", h("a", { href: l.link, target: "_blank", rel: "noopener" }, "About this list")] : null);
  }
  // The plain line for a block (device, name looked up, owner, ports and
  // what they're for), with the list under it. Older lines have text only.
  const blockWhat = (b, would) => b.info ? [h("div", b.info.desc), listLine(b.info, would)] : b.text;
  function blockedRows(list) {
    return list.map((b) => h("tr", { "data-key": String(b.id) }, h("td.when", h("span.mute", when(b.last))), h("td", blockWhat(b)), h("td.num", h("span.count", "×" + b.count))));
  }
  // The kernel's own tuple (addresses and both ports), so two connections
  // to one place are still two rows that keep their places.
  const connKey = (c) => c.key || [c.device, c.dir, c.remote, c.proto, c.port].join(" ");
  // A connection opens its device with the connection picked out; one with
  // no known device opens the log for that address.
  const connHref = (c) => c.mac ? "/devices?" + new URLSearchParams({ conn: c.key || "", remote: c.remote }) + "#" + c.mac : "/log?" + new URLSearchParams({ q: c.remote });
  function connRows(list, pick) {
    return list.map((c) => h("tr" + (pick ? (pick(c) ? ".sel" : "") : ".click"), { "data-key": c._key || connKey(c), onclick: pick ? null : () => { location.href = connHref(c); } }, h("td", { title: c.desc || "" }, c.device), h("td", { title: c.desc || "" }, h("span." + c.dir, c.dir === "out" ? "→" : "←"), " ", c.domain || c.remote, h("div.mute", c.domain ? c.remote + (c.owner ? " · " + c.owner : "") : c.owner || "")), h("td", c.proto + (c.port ? "/" + c.port : ""), c.port ? h("div.mute", c.what) : null), h("td", c.place ? c.place.country : h("span.mute", "-")), h("td.num", bytes(c.bytes))));
  }
  function geoProgress(g) {
    const pct = g.total ? Math.round(g.done * 100 / g.total) : 0;
    const what = g.phase === 2 ? "Building the location database" : g.done ? "Downloading the location database" : "Connecting to " + g.source;
    return h("div", { style: "width:70%" }, h("b", what), h("div.track", h("span", { style: "width:" + (g.phase === 2 ? 100 : pct) + "%" })),
      h("div.mute", g.phase === 2 ? "Downloaded " + bytes(g.done) + ", sorting it for lookups. This takes a few minutes on the gateway." : g.total ? bytes(g.done) + " of " + bytes(g.total) + " (" + pct + "%)" : g.done ? bytes(g.done) : "Waiting for the server…"));
  }
  function geoFailed(g) {
    const next = g.next_try && g.next_try * 1000 > Date.now() ? " Trying again at " + when(g.next_try) + "." : "";
    return h("div", h("b.bad", "The location download failed."), h("div", g.error), h("div.mute", next));
  }
  function geoRetry() {
    return h("button", { perm: "admin", onclick: () => change("/api/settings", { action: "geo", on: true }) }, "Try now");
  }
  function geoCard(g, conns, home) {
    if (!g.on || !g.loaded) {
      if (g.on && (g.phase === 1 || g.phase === 2)) return h("div.map-off", geoProgress(g));
      return h("div.map-off",
        h("div", g.on ? (g.error ? geoFailed(g) : "Location database is on but not downloaded yet.") : "The map needs the free DB-IP location database. It's off until you turn it on, and it is " + g.size_note + " to download."),
        g.on && g.error ? geoRetry() : h("a.btn", { href: "/settings/general#geo" }, "Location settings"));
    }
    map.set(conns, home);
    return h("div", h("div.map-stage", map.cv), h("div.legend", h("span", h("i.sw.out"), "Outbound from your network"), h("span", h("i.sw.in"), "Inbound to your network"), home ? h("span", h("i.sw.home"), "This gateway") : null, h("span.hint", "Hover a dot to see devices and destination · " + (conns && conns.blocked ? "stopped attempts, last minute (log rate-limited)" : "fresh forwarded activity"))),
      h("div.attr", "IP locations by ", h("a", { href: "https://db-ip.com", target: "_blank", rel: "noopener" }, "DB-IP"), " (" + (g.month || "") + ")"));
  }
  // The live map, drawn the way the Windows app draws it: an arc from here
  // to each place, a dot running along it at a speed set by its traffic,
  // and a ring pulsing at home. One canvas and one animation loop for the
  // page; each refresh only swaps the list of connections.
  const map = (() => {
    const RGB = { in: "62, 198, 255", out: "255, 138, 61" };
    const cv = h("canvas", { id: "map" });
    let flows = [], home = null, raf = 0, last = 0, clock = 0, land = null, size = "", anim = true;
    function set(conns, at) {
      home = at && at.lat != null ? at : null;
      const old = new Map(flows.map((f) => [f.key, f]));
      // Gateway sends { flows: [...] }; tests (and older callers) may pass an array of
      // { place, dir, bytes } instead.
      const list = Array.isArray(conns) ? conns : ((conns && conns.flows) || []);
      flows = list.map((f) => {
        const lat = f.lat != null ? f.lat : (f.place && f.place.lat);
        const lon = f.lon != null ? f.lon : (f.place && f.place.lon);
        const key = Number(lat).toFixed(1) + "," + Number(lon).toFixed(1) + "," + f.dir;
        return { ...f, lat, lon, key, t: old.get(key)?.t ?? Math.random() };
      }).filter((f) => f.lat != null && f.lon != null);
      if (!raf) raf = requestAnimationFrame(frame);
    }
    function frame(ms) {
      raf = 0;
      if (!cv.isConnected) return; // the page moved on; nothing keeps running
      const dt = anim && last ? Math.min(0.1, (ms - last) / 1000) : 0;
      last = ms; if (anim) clock += dt;
      draw(anim ? dt : 0);
      raf = requestAnimationFrame(frame);
    }
    function draw(dt) {
      const w = cv.clientWidth, ht = cv.clientHeight, sc = window.devicePixelRatio || 1;
      if (!w || !ht) return;
      if (size !== w + "x" + ht + "x" + sc) { size = w + "x" + ht + "x" + sc; cv.width = w * sc; cv.height = ht * sc; land = null; }
      const o = cv.getContext("2d");
      o.setTransform(sc, 0, 0, sc, 0, 0);
      const worldW = Math.min(w, ht * 2), worldH = worldW / 2;
      const ox = (w - worldW) / 2, oy = (ht - worldH) / 2;
      const P = (lon, lat) => [ox + (lon + 180) / 360 * worldW, oy + (90 - lat) / 180 * worldH];
      o.fillStyle = "#071018"; o.fillRect(0, 0, w, ht);
      if (typeof LAND !== "undefined") {
        if (!land) {
          land = new Path2D();
          for (const ring of LAND) {
            ring.forEach((pt, i) => { const [x, y] = P(pt[0], pt[1]); if (i === 0 || Math.abs(pt[0] - ring[i - 1][0]) > 180) land.moveTo(x, y); else land.lineTo(x, y); });
            land.closePath();
          }
        }
        o.fillStyle = "#13304a"; o.fill(land);
        o.strokeStyle = "rgba(125, 211, 252, 0.5)"; o.lineWidth = 0.6; o.stroke(land);
      }
      const maxB = Math.max(1, ...flows.map((f) => f.bytes));
      const hx = home ? P(home.lon, home.lat) : null;
      for (const f of flows) {
        const [x, y] = P(f.lon, f.lat), rgb = RGB[f.dir] || RGB.out;
        f.x = x; f.y = y;
        f.t = (f.t + dt * 0.4 * (0.5 + 0.9 * Math.sqrt(Math.min(1, f.bytes / maxB)))) % 1;
        if (hx) {
          const span = Math.hypot(x - hx[0], y - hx[1]);
          const cx = (x + hx[0]) / 2, cy = (y + hx[1]) / 2 - span * 0.35;
          o.strokeStyle = "rgba(" + rgb + ", 0.35)"; o.lineWidth = 0.8;
          o.beginPath(); o.moveTo(hx[0], hx[1]); o.quadraticCurveTo(cx, cy, x, y); o.stroke();
          // Outgoing runs from home to the far end, incoming the other way.
          const t = f.dir === "in" ? 1 - f.t : f.t, u = 1 - t;
          const px = u * u * hx[0] + 2 * u * t * cx + t * t * x, py = u * u * hx[1] + 2 * u * t * cy + t * t * y;
          o.fillStyle = "rgba(" + rgb + ", 0.95)";
          o.beginPath(); o.arc(px, py, 1.8, 0, 7); o.fill();
        } else {
          o.strokeStyle = "rgba(" + rgb + ", " + (0.6 * (1 - f.t)).toFixed(2) + ")"; o.lineWidth = 1;
          o.beginPath(); o.arc(x, y, 2.4 + f.t * 9, 0, 7); o.stroke();
        }
        o.shadowColor = "rgb(" + rgb + ")"; o.shadowBlur = 7;
        o.fillStyle = "rgb(" + rgb + ")";
        o.beginPath(); o.arc(x, y, 2.4, 0, 7); o.fill();
        o.shadowBlur = 0;
      }
      if (hx) {
        const pulse = (clock % 2) / 2;
        o.strokeStyle = "rgba(255, 255, 255, " + (0.7 * (1 - pulse)).toFixed(2) + ")"; o.lineWidth = 1.2;
        o.beginPath(); o.arc(hx[0], hx[1], 3 + pulse * 12, 0, 7); o.stroke();
        o.fillStyle = "#fff"; o.beginPath(); o.arc(hx[0], hx[1], 3, 0, 7); o.fill();
      }
    }
    // Hovering a place says who is there: the busiest names, the direction
    // and how much.
    const tip = h("div.maptip", { hidden: true });
    document.body.append(tip);
    cv.addEventListener("mousemove", (e) => {
      const r = cv.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
      let best = null, bd = 100; // within 10px
      for (const f of flows) {
        if (f.x == null) continue;
        const d = (f.x - mx) ** 2 + (f.y - my) ** 2;
        if (d < bd) { bd = d; best = f; }
      }
      if (!best) { tip.hidden = true; return; }
      const who = (best.devices && best.devices.length) ? best.devices.join(", ") : "Unknown device";
      const dest = (best.names && best.names.length) ? best.names.join(", ") : (best.dest || "unknown place");
      const dir = best.dir === "in" ? "Inbound to your network" : "Outbound from your network";
      // Two-column rows so labels sit on one vertical edge and values share
      // another; the direction swatch shares the first row's baseline.
      tip.replaceChildren(
        h("div.tip-row", h("i.sw." + (best.dir === "in" ? "in" : "out"), { "aria-hidden": "true" }), h("span.tip-k", "Devices"), h("span.tip-v", who)),
        h("div.tip-row", h("span.tip-gap"), h("span.tip-k", "Destination"), h("span.tip-v", dest)),
        h("div.tip-row.tip-meta", h("span.tip-gap"), h("span.tip-v", (best.blocked ? "Stopped attempt · " : "") + dir + " · " + best.n + (best.blocked ? (best.n === 1 ? " logged attempt" : " logged attempts") : (best.n === 1 ? " active path" : " active paths")) + (best.blocked ? "" : " · " + bytes(best.bytes)))));
      tip.hidden = false;
      // Pin to the destination dot (not the cursor), vertically centered on it
      // and just to its right  -  so tip text lines up with the dot to its left.
      const tw = tip.offsetWidth, th = tip.offsetHeight;
      const dx = r.left + best.x, dy = r.top + best.y;
      let left = dx + 14;
      if (left + tw > innerWidth - 4) left = dx - tw - 14;
      left = Math.max(4, Math.min(innerWidth - tw - 4, left));
      let top = dy - th / 2;
      top = Math.max(4, Math.min(innerHeight - th - 4, top));
      tip.style.left = left + "px";
      tip.style.top = top + "px";
    });
    cv.addEventListener("mouseleave", () => { tip.hidden = true; });
    return { cv, set, setAnim: (on) => { anim = !!on; }, running: () => raf !== 0, count: () => flows.length };
  })();
  window.__map = map;
  // Full screen map, like the Windows app: a button toggles it, Esc leaves.
  let mapFull = false, mapAnim = true, mapView = "traffic";
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && mapFull) { mapFull = false; refresh(); } });
  // The countries live connections reach, full names, most used first.
  function countryBox(list) {
    const body = list.length
      ? h("div.scroll.clist", h("table.countries-now", h("thead", h("tr", h("th", "Country"), h("th.num", "Connections"))), h("tbody", list.map((c) => h("tr", h("td.name", c.name), h("td.num", String(c.n)))))))
      : h("p.empty", "No live connections reach another country right now.");
    showBox(h("h3", "Countries now"), h("div.countries-now-box", body), h("div.acts", h("button", { onclick: hideBox }, "Close")));
  }
  // What kind of alert a line is, for the filter and the label.
  function alertKind(a) {
    if (a.kind === "device") return / tried (tcp|udp) /.test(a.text) ? "port" : "device";
    return "block";
  }
  const ALERT = { device: "new device", port: "new port", block: "suspicious" };
  const alertKey = (a) => [alertKind(a), a.device || "", a.text].join(" ");
  // Where an alert link goes, if this user may open that page.
  const linkOk = (href) => {
    const path = (href || "").split(/[?#]/)[0];
    const page = path === "/" ? "dashboard" : path.split("/")[1];
    return pageOk(page) && (!SUB_PERM[path] || subOk(path));
  };
  // Clear marks alerts handled: they leave the dashboard and stay in the
  // Capture Log marked handled.
  async function clearAlerts(ids) {
    await change("/api/alerts/clear", { ids });
  }
  function clearAllAsk(list) {
    const go = h("button", { onclick: async () => { hideBox(); await clearAlerts(list.map((a) => a.id)); } }, "Clear");
    showBox(h("h3", "Clear " + list.length + (list.length === 1 ? " Alert?" : " Alerts?")),
      h("p", (list.length === 1 ? "It leaves" : "They leave") + " the dashboard. The Capture Log still has every line, marked handled."),
      h("div.acts", h("button.quiet", { onclick: hideBox }, "Cancel"), go));
  }
  function alertRows(list) {
    if (!list.length) return h("p.empty.padded", "All good, nothing to do.");
    return list.map((a) => {
      const k = alertKind(a);
      const who = a.label || a.device || "";
      const tip = a.guess ? (" · " + a.guess) : "";
      const href = a.link || (a.id ? "/?alert=" + a.id : "/log?kind=alert");
      const open = linkOk(href);
      // An alert opens in a popup over the dashboard; other links go to their page.
      const pop = a.id && /^\/(\?alert=|log\?focus=)\d+$/.test(href);
      const line = h(open ? "a.alert" : "div.alert", open ? (pop ? { href: "/?alert=" + a.id, onclick: (e) => { e.preventDefault(); openAlert(a.id); } } : { href }) : null,
        h("span.sev." + (k === "block" ? "bad" : "warn"), ALERT[k]),
        (who ? who + ": " : "") + a.text + tip + " ",
        h("span.t", when(a.last)), a.count > 1 ? h("span.count", { style: "margin-left:6px" }, "×" + a.count) : null);
      return h("div.alert-row", { "data-key": a._key || alertKey(a) }, line,
        h("button.small.quiet", { perm: "handle_alerts", onclick: () => clearAlerts([a.id]) }, "Clear"));
    });
  }
  // Fetches one alert's log line and shows it in the popup over the dashboard.
  async function openAlert(id) {
    const done = () => { if (new URLSearchParams(location.search).has("alert")) history.replaceState(null, "", "/"); };
    const d = await api("/api/log?" + new URLSearchParams({ focus: id, limit: 1 }));
    const r = (d.rows || []).find((x) => x.id === id);
    if (r) return alertPopup(r, done);
    showBox(h("h3", "Alert Not Found"), h("p", "That alert is no longer in the Capture Log."), h("div.acts", h("button", { onclick: () => { hideBox(); done(); } }, "Close")));
  }
  function dashboard() {
    shell("Dashboard");
    const startAlert = Number(qp0.get("alert")) || 0;
    if (startAlert) openAlert(startAlert).catch(() => {});
    // One observer for the page: a width change re-spreads the cards
    // without waiting for the next poll.
    new ResizeObserver(() => layCards($(".cards.stats"))).observe(mainEl);
    let aq = "", ak = "";
    every(3000, async () => {
      const requestedView = mapView;
      const d = await api("/api/dashboard?map_view=" + requestedView);
      if (requestedView !== mapView) return;
      const st = d.status;
      statusBox(st);
      const memPct = st.mem_total ? Math.round(st.mem_used * 100 / st.mem_total) : 0;
      const diskPct = st.disk_total ? Math.round(st.disk_used * 100 / st.disk_total) : 0;
      const card = (t, big, cls, sub, bar, href) => h((href ? (typeof href === "function" ? "button" : "a") : "div") + ".card", typeof href === "function" ? { type: "button", onclick: href } : { href }, h("h2", t), h("div.card-body", h("div.big", big), bar != null ? h("div.track", h("span", { style: "width:" + bar + "%" })) : null), h("div.sub" + (cls ? "." + cls : ""), sub || "\u00a0"));
      // Live throughput: In/Out on two lines, fixed digit slots (no layout jump).
      const speedSub = (p, name) => (p && p.link ? (p.speed || "link") : (name || portMissing(p)));
      const countries = (cardOn(st, CARDS[4]) && (d.countries_now || (d.map && d.map.countries))) || [];
      const q = aq.toLowerCase();
      const alerts = stable("alerts", ak + "|" + q, d.alerts, alertKey).filter((a) => (!ak || alertKind(a) === ak) && (!q || (a.text + " " + (a.device || "")).toLowerCase().includes(q)));
      const chip = (k, label) => h("button.chip" + (ak === k ? ".on" : ""), { onclick: () => { ak = k; refresh(); } }, label);
      render(
        header("Dashboard", st),
        pendingNote(st), pathNote(st), adminNudge(st),
        (() => {
          const make = {
            mode: () => card("Mode", MODE[st.mode], "", st.telemetry_all ? "telemetry blocked" : "telemetry allowed"),
            path: () => card("Traffic Path", st.in_path ? "In path" : "Not in path", "", st.bridge ? (st.filtering ? "filtering on" : "filtering off") : "no bridge yet"),
            wan: () => card("WAN", speedLines(st.wan, st.wan_bps || [0, 0]), "", speedSub(st.wan, st.wan_name)),
            lan: () => card("LAN", speedLines(st.lan, st.lan_bps || [0, 0]), "", speedSub(st.lan, st.lan_name)),
            countries: () => card("Countries Now", String(countries.length), "", "Click for the country names", null, () => countryBox(countries)),
            devices: () => card("Devices", String(d.online), "", "online of " + d.device_count, null, "/devices"),
            cpu: () => card("CPU", Math.round(st.cpu) + "%", "", "load", Math.round(st.cpu)),
            temp: () => card("CPU Temp", st.temp != null ? st.temp.toFixed(1) + " °C" : "n/a", st.temp >= 85 ? "bad" : st.temp >= 75 ? "warn" : "", st.temp >= 85 ? "critical, too hot" : st.temp >= 75 ? "running hot" : "OK"),
            disk: () => card("Disk", diskPct + "%", "", st.disk_total ? bytes(st.disk_used) + " of " + bytes(st.disk_total) : "n/a", diskPct),
            memory: () => card("Memory", memPct + "%", "", bytes(st.mem_used) + " of " + bytes(st.mem_total), memPct),
            blocked: () => card("Blocked Today", String(st.blocked_today || 0), "ok", "Open the log", null, "/log?kind=block&today=1"),
          };
          // Only cards that are on get built; the server skips their data too.
          const shown = CARDS.filter((c) => cardOn(st, c) && make[c.id]).map((c) => { const e = make[c.id](); e.dataset.key = c.id; return e; });
          if (!shown.length) return null;
          const w = ($(".cards.stats") || mainEl).clientWidth - ($(".cards.stats") ? 0 : 28);
          return h("div.cards.stats", { style: "grid-template-columns:repeat(" + cardCols(shown.length, w) + ", minmax(0, 1fr))" }, shown);
        })(),
        h("div.body.dash",
          h("div.col",
            grow(panel("Alerts", [h("span.mute", alerts.length + " shown"),
              alerts.length ? h("button.small.quiet.push", { perm: "handle_alerts", onclick: () => clearAllAsk(alerts) }, "Clear All Shown") : null],
              h("div.tools-row", searchBox("alert-q", aq, (v) => { aq = v; refresh(); }, "Search alerts"), chip("", "All"), chip("device", "New devices"), chip("port", "New ports"), chip("block", "Suspicious")),
              scroller("alerts", null, alertRows(alerts)))),
            grow(panel("Connections", h("span.mute", d.conns.length + " open"), scroller("conns", null, table(["Device", "Remote", "Proto", "Country", "Bytes#"], connRows(stable("conns", "", d.conns, connKey, true)), "No connections tracked right now."))))),
          h("div.mapcol", h("section.panel.map-panel" + (mapFull ? ".full" : ""), h("div.panel-head", h("h2", "Map"),
            [["traffic", "Traffic Only"], ["blocked", "Blocked Connection Attempts"]].map(([key, label]) => h("button.small" + (mapView === key ? ".isOn" : ".quiet"), { id: "map-view-" + key, "aria-pressed": String(mapView === key), disabled: mapView === key, onclick: () => { mapView = key; map.set({ flows: [] }, d.home); const tip = $(".maptip"); if (tip) tip.hidden = true; refresh(); } }, label + (mapView === key ? " · On" : ""))),
            h("button.small.quiet", { id: "map-anim", onclick: () => { mapAnim = !mapAnim; map.setAnim(mapAnim); refresh(); } }, mapAnim ? "Pause Motion" : "Play Motion"),
            h("button.small.quiet", { id: "map-full", onclick: () => { mapFull = !mapFull; refresh(); } }, mapFull ? "Exit Full Screen" : "Full Screen")), geoCard(d.geo, d.map, d.home)))));
      layCards($(".cards.stats"));
    });
  }

  // ---------- Devices ----------
  let selected = decodeURIComponent(location.hash.slice(1));
  // Websites and addresses for one device, in one list: each line is
  // either always allowed or always blocked.
  function siteRules(v, set, bare) {
    // Blocking needs the Block list permission, allowing the Allow list one.
    const LIST_PERM = { deny: "block_list", allow: "allow_list" };
    const hows = [["deny", "Block it"], ["allow", "Allow it"]].filter(([k]) => can(LIST_PERM[k]));
    let how = hows.length ? hows[0][0] : "deny";
    const input = h("input", { id: "site-add", placeholder: "example.com or 1.2.3.4", style: "flex:1 1 200px;min-width:0" });
    const seg = h("div.seg", { "data-ref": "" }, hows.map(([k, t]) => h("button" + (k === how ? ".on" : ""), { type: "button", "data-how": k, onclick: (e) => { how = k; seg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b === e.currentTarget)); } }, t)));
    const add = () => {
      const items = input.value.split(/[\s,]+/).filter(Boolean);
      if (!items.length) return;
      const other = how === "deny" ? "allow" : "deny";
      const body = { [how]: v[how].concat(items.filter((x) => !v[how].includes(x))) };
      // Only touch the other list when an item moves out of it.
      if (v[other].some((x) => items.includes(x))) body[other] = v[other].filter((x) => !items.includes(x));
      set(body);
    };
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") add(); });
    const rows = v.deny.map((e) => ["deny", e]).concat(v.allow.map((e) => ["allow", e])).sort((x, y) => x[1].localeCompare(y[1]));
    const body = [
      h("p.hint", "Pick a website or address this device should always be stopped from, or always let through. Blocking is the usual choice. An allowed one gets through even when the device is set to Block All."),
      hows.length ? h("div.row", { style: "margin-top:6px" }, seg, input, h("button", { onclick: add }, "Add")) : null,
      rows.length ? h("ul.entries.rules-list", rows.map(([k, e]) => h("li", h("span", e), h("span.pill.tag." + (k === "allow" ? "trusted" : "block"), k === "allow" ? "Always Allowed" : "Always Blocked"),
        h("button.small.quiet", { perm: LIST_PERM[k], onclick: () => set({ [k]: v[k].filter((x) => x !== e) }) }, "Remove")))) : h("p.empty.padded", "Nothing set. This device follows its Policy and the firewall lists."),
    ];
    if (bare) return h("div.fold-body", body);
    return h("div.sect", h("h4", "Websites And Addresses"), body);
  }
  // The connection the dashboard was clicked on, if it opened this page.
  const connPick = { key: qp0.get("conn") || "", remote: qp0.get("remote") || "" };
  const AUDIT_FOR = [[10, "10 minutes"], [60, "1 hour"], [-1, "Until turned off"]];
  // Likely-culprit strip with Allow right beside it (device Audit + Troubleshooter).
  function culpritStrip(mac, culprit, opts) {
    if (!culprit || !culprit.what) return null;
    const o = opts || {};
    const times = culprit.count ? (" (" + culprit.count + (culprit.count === 1 ? " time" : " times") + ")") : "";
    const canAllow = !!(culprit.reason && culprit.remote && !["mode", "lanonly"].includes(culprit.reason));
    const goAllow = () => change("/api/allow", { mac, reason: culprit.reason, remote: culprit.remote, proto: culprit.proto || "", port: culprit.port || 0, dir: culprit.dir || "out" });
    const whoBits = o.who
      ? [h("b", o.who + ": "), " likely culprit is ", h("b", culprit.what), times + "."]
      : ["Likely culprit so far: ", h("b", culprit.what), times + "."];
    return h("div.notice.culprit" + (o.focus ? ".focus" : ""),
      h("div.culprit-line",
        h("span", ...whoBits),
        canAllow
          ? h("button.small", { perm: allowPerm(culprit.reason), onclick: goAllow }, "Allow This")
          : (culprit.reason === "mode" || culprit.reason === "lanonly"
            ? h("a.btn.small.quiet", { perm: "firewall_view", href: "/firewall" }, "Open Firewall")
            : null)),
      canAllow && can("allow_list") ? h("p.hint", { style: "margin:6px 0 0" }, "If that broke something, allow it here. It stays allowed for this device.") : null);
  }
  function auditSect(v, culprit) {
    const go = (m) => change("/api/audit", { mac: v.mac, minutes: m });
    return h("div.sect", h("h4", "Audit"),
      v.auditing ? h("p", h("span.warn", "On " + untilText(v.audit_until) + ". "), "Blocks for this device are written down and let through. Safety rules and the whole-network mode still apply.") : h("p.hint", "Lets everything this device does through for a while and writes down what would have been blocked, so you can allow what it needs."),
      culpritStrip(v.mac, culprit),
      h("div.row.same", v.auditing ? h("button", { perm: "admin", onclick: () => go(0) }, "Turn Audit Off") : AUDIT_FOR.map(([m, t]) => h("button.quiet", { perm: "admin", onclick: () => go(m) }, t)),
        PATH === "/devices/troubleshoot" ? null : h("a.btn.quiet", { perm: "alerts", href: "/devices/troubleshoot?mac=" + encodeURIComponent(v.mac) }, "What's Blocked for It")));
  }
  function profileSect(v, list) {
    if (!list || !list.length) return null;
    return h("div.sect", h("h4", "Known device"),
      list.map((p) => h("div.profile", { "data-key": p.id },
        h("div", h("b", p.name), " ", p.applied ? h("span.pill.handled", "in place") : null),
        h("p.hint", p.what),
        h("div.mute", "Opens " + p.ports.join(", ") + (p.discovery.length ? " for this device, and " + p.discovery.join(", ") + " for every device so it can be found." : " for this device.")),
        p.note ? h("div.mute", p.note) : null,
        p.risky.length ? h("div.warn", "Opening " + p.risky.join(", ") + " has a risk; see the Ports page.") : null,
        h("div.mute", "From ", h("a", { href: p.source, target: "_blank", rel: "noopener" }, "the maker's own list"), "."),
        p.applied ? null : h("div.row", { style: "margin-top:6px" }, h("button.small", { perm: "admin", onclick: () => change("/api/profile", { mac: v.mac, id: p.id }) }, "Allow what it needs")))));
  }
  function connSect(det, v, set) {
    if (!connPick.remote || location.hash.slice(1) !== v.mac) return null;
    const live = det.conns.find((c) => (connPick.key && c.key === connPick.key) || c.remote === connPick.remote);
    const r = connPick.remote;
    return h("div.sect.picked", h("h4", "Connection to " + r),
      live ? h("p", (live.dir === "out" ? "Going out to " : "Coming in from ") + r + " on " + live.proto + (live.port ? " " + live.port : "") + (live.place ? ", " + live.place.country : "") + ". " + bytes(live.bytes) + " so far.")
        : h("p.notice", "That connection has ended. You can still block the address."),
      h("div.row.same", h("button", { perm: ["block_list", "allow_list"], onclick: () => set({ deny: v.deny.concat(v.deny.includes(r) ? [] : [r]), allow: v.allow.filter((x) => x !== r) }) }, "Block this address for this device"),
        h("button.quiet", { perm: "block_list", onclick: () => change("/api/list", { list: "black", add: r }) }, "Black list it")));
  }
  function deviceDetail(det) {
    const v = det.device;
    const set = (b) => change("/api/device", Object.assign({ mac: v.mac }, b));
    const canAct = can("device_actions");
    const name = h("input", { disabled: !canAct, value: v.name, placeholder: v.hostname || v.vendor || v.mac, style: "min-width:0;flex:1 1 180px" });
    const seg = h("div.seg", { "data-ref": "" }, ["trusted", "normal", "lan_only", "block"].map((p) => h("button" + (v.policy === p ? ".on." + p : ""), { disabled: !canAct, onclick: () => policyAsk(v.mac, v.label, p, set) }, POLICY[p])));
    const nConn = (det.conns || []).length;
    const nBlock = (det.blocked || []).length;
    const nRules = (v.deny || []).length + (v.allow || []).length;
    // Keep folds open across refresh; seed Websites open once when there are rules.
    { const k = "dev:" + v.mac + ":sites"; if (nRules && !openFolds.has(k) && !openFolds.has(k + ":seen")) { openFolds.add(k); openFolds.add(k + ":seen"); } }
    return h("section.panel.detail",
      h("h3", v.label, pill(v.policy), v.new ? h("span.pill.new", "New") : null, v.telemetry ? h("span.pill.tel", "Telemetry Blocked") : null),
      h("div.meta",
        h("div", v.sub || v.mac),
        h("div", (v.online ? "Online" : "Offline") + " · Last Seen " + when(v.last_seen)),
        h("div.mute", "Up ", h("span.out", rate(v.up_rate)), " · Down ", h("span.in", rate(v.down_rate)), " · Total " + bytes(v.up) + " up, " + bytes(v.down) + " down")),
      v.new ? h("p.notice", "New on the network. It got the default for new devices. Pick a Policy or mark it looked at. ", h("button.small", { perm: "device_actions", onclick: () => set({ seen: true }) }, "Looks Fine")) : null,
      h("div.sect", h("h4", "Name"), h("div.row", name, h("button", { perm: "device_actions", onclick: () => set({ name: name.value }) }, "Save Name"))),
      h("div.sect", h("h4", "Policy"), seg, h("p.hint", "Trusted skips Black list, threat lists, and countries. Local Network Only and Block All stop this device except its own Allow list. Confirm before a Policy applies.")),
      h("div.sect", h("h4", "Telemetry"),
        h("label.check", h("input", { type: "checkbox", disabled: !canAct, checked: v.telemetry, onchange: (e) => set({ telemetry: e.target.checked }) }), "Block Telemetry For This Device"),
        h("p.hint", "Stops usage and tracking phone-home. The device usually keeps working.")),
      auditSect(v, det.culprit),
      connSect(det, v, set),
      profileSect(v, det.profiles),
      can("firewall_view") ? h("div.sect", h("h4", "Ports"), h("a", { href: "/ports/devices?q=" + encodeURIComponent(v.mac) }, "Port Settings For This Device")) : null,
      foldEl("dev:" + v.mac + ":sites", "Websites And Addresses" + (nRules ? " (" + nRules + ")" : ""), siteRules(v, set, true)),
      foldEl("dev:" + v.mac + ":conns", "Connections Now" + (nConn ? " (" + nConn + ")" : ""),
        nConn ? table(["Device", "Remote", "Proto", "Country", "Bytes#"], connRows(det.conns, (c) => connPick.remote && ((connPick.key && c.key === connPick.key) || c.remote === connPick.remote)), "") : h("p.empty.padded", "None right now.")),
      foldEl("dev:" + v.mac + ":blocked", "Blocked Today" + (nBlock ? " (" + nBlock + ")" : ""),
        nBlock ? h("table", h("tbody", blockedRows(det.blocked))) : h("p.empty.padded", "Nothing blocked for this device today.")),
      foldEl("dev:" + v.mac + ":more", "More", [
        h("p.hint", can("admin") ? "Forget removes its name and settings. Block All cuts it off until you change the Policy." : canAct ? "Block All cuts it off until you change the Policy." : "This user can view this device but not change it."),
        h("div.row",
          h("button.danger", { perm: "device_actions", onclick: () => policyAsk(v.mac, v.label, "block", set) }, "Block All"),
          h("button.danger", { perm: "admin", onclick: () => { if (confirm("Forget " + v.label + "? It shows up as new next time and loses its settings.")) set({ forget: true }).then(() => { selected = ""; }); } }, "Forget This Device"))], "more"));
  }

  function devices() {
    if (PATH === "/devices/troubleshoot") return troubleshooter();
    shell("Devices");
    let q = "", filter = "", sort = "name", limit = 100, total = 0;
    const more = () => { if (limit < total) { limit += 100; refresh(); } };
    every(4000, async () => {
      const d = await api("/api/devices?" + new URLSearchParams({ q, filter, sort, limit, mac: selected }));
      statusBox(d.status);
      total = d.total;
      if (!selected && d.devices.length) { selected = d.devices[0].mac; return refresh(); }
      const sel = (val, opts, set) => h("select", { onchange: (e) => { set(e.target.value); limit = 100; refresh(); } }, opts.map(([k, t]) => h("option", { value: k, selected: k === val }, t)));
      render(
        header("Devices", d.status),
        pendingNote(d.status), pathNote(d.status), adminNudge(d.status),
        h("div.body.two",
          grow(panel("All Devices", h("span.mute", d.all + " known"),
            h("div.tools-row", searchBox("dev-q", q, (v) => { q = v; limit = 100; refresh(); }, "Search devices"),
              sel(filter, [["", "All"], ["online", "Online"], ["new", "New"], ["blocked", "Blocked or Local Network Only"], ["trusted", "Trusted"]], (v) => { filter = v; }),
              sel(sort, [["name", "By name"], ["ip", "By address"], ["seen", "Last seen"], ["traffic", "Most traffic"]], (v) => { sort = v; })),
            scroller("devs", more, table(["Device", "Address", "Policy", "Last Seen", "Total#"], d.devices.map((x) => {
              const unnamed = !x.name && (/^Device /i.test(x.label) || x.label === x.mac);
              return h("tr.click" + (x.mac === selected ? ".sel" : ""), { "data-key": x.mac, onclick: () => { selected = x.mac; history.replaceState(null, "", "/devices#" + x.mac); connPick.remote = ""; refresh(); } },
                h("td", h("span." + (x.online ? "ok" : "mute"), "● "), x.label, x.new ? [" ", h("span.pill.new", "new")] : null,
                  h("div.mute", x.sub || (x.vendor || "")),
                  unnamed ? h("div.hint", "Name it: check the sticker or its settings. ", h("button.small.quiet", { onclick: (e) => { e.stopPropagation(); selected = x.mac; refresh(); } }, "Give It a Name")) : null),
                h("td", x.ip || "-"), h("td", pill(x.policy)), h("td", when(x.last_seen)), h("td.num", bytes(x.up + x.down)));
            }), q || filter ? "No device matches." : "No devices seen yet. They show up here as soon as they talk on the LAN.")),
            shownOf(d.devices.length, d.total, "devices"))),
          h("div.col", { "data-k": "detail" }, d.detail ? deviceDetail(d.detail) : panel("Device", null, h("p.empty", "Pick a device.")))));
      // Opened for one device (a link or an alert): bring its row into view once.
      if (!shownSel && selected) { shownSel = true; mainEl.querySelector("tr.sel")?.scrollIntoView({ block: "nearest" }); mainEl.querySelector(".sect.picked")?.scrollIntoView({ block: "nearest" }); }
    });
  }
  let shownSel = false;

  // ---------- Troubleshooter ----------
  // Everything blocked for one device in the last hour, by reason, with a
  // way to allow each one.
  // Allowing a device deny-list entry takes it off a block list, so it needs both.
  const allowPerm = (reason) => (reason === "devdeny" ? ["allow_list", "block_list"] : "allow_list");
  const allowPayload = (mac, e, reason, permanent) => ({ mac, reason, remote: e.remote, proto: e.proto, port: e.port, dir: e.dir, permanent: !!permanent });
  const allowBtn = (mac, e, reason, label, permanent) => e.action && e.action.allow
    ? h("button.small", { perm: allowPerm(reason), onclick: () => change("/api/allow", allowPayload(mac, e, reason, permanent !== false && (permanent || label === "Allow · Permanent" || !(window.__fgWhiteExpiry)))) }, label || e.action.allow)
    : e.action && e.action.href ? h("a", { href: e.action.href, title: e.action.why }, "Change it here") : h("span.mute", (e.action && e.action.why) || "");
  // When whitelist expiry is on: primary = 30 days, secondary = Permanent.
  const allowBtns = (mac, e, reason, label) => {
    const one = (ee, lab, perm) => allowBtn(mac, ee, reason, lab, perm);
    const row = (ee) => {
      if (!(ee.action && ee.action.allow)) return one(ee);
      if (window.__fgWhiteExpiry && !label) {
        return h("div.row.same",
          h("button.small", { perm: allowPerm(reason), onclick: () => change("/api/allow", allowPayload(mac, ee, reason, false)) }, "Allow · 30 Days"),
          h("button.small.quiet", { perm: allowPerm(reason), onclick: () => change("/api/allow", allowPayload(mac, ee, reason, true)) }, "Allow · Permanent"));
      }
      return one(ee, label || (window.__fgWhiteExpiry ? "Allow · Permanent" : ee.action.allow), true);
    };
    if (e.actions && e.actions.length > 1) {
      return h("div.stack.ports-act", e.actions.map((a) => h("div.row", h("span.mute", a.proto + " " + a.port), row({ ...e, proto: a.proto, port: a.port, action: a.action }))));
    }
    return row(e.actions && e.actions.length ? { ...e, proto: e.actions[0].proto, port: e.actions[0].port, action: e.actions[0].action } : e);
  };
  function troubleshooter() {
    shell("Troubleshooter");
    let mac = (qp0.get("mac") || "").toLowerCase();
    let outcome = ["stopped", "audit"].includes(qp0.get("outcome")) ? qp0.get("outcome") : "all";
    const remember = () => history.replaceState(null, "", "/devices/troubleshoot?" + new URLSearchParams(Object.assign(mac ? { mac } : {}, outcome === "all" ? {} : { outcome })));
    let focusedOnce = false;
    every(5000, async () => {
      const requestedOutcome = outcome;
      const d = await api("/api/troubleshoot?" + new URLSearchParams({ mac, outcome }));
      if (requestedOutcome !== outcome) return;
      statusBox(d.status);
      const v = d.device;
      const label = (v && v.label) || (d.devices.find((x) => x.mac === mac) || {}).label || "";
      // Put the linked device first in the list so it isn't buried.
      const ordered = mac
        ? d.devices.filter((x) => x.mac === mac).concat(d.devices.filter((x) => x.mac !== mac))
        : d.devices;
      const pick = h("select", { id: "ts-dev", "aria-label": "Device", onchange: (e) => { mac = e.target.value; focusedOnce = false; remember(); refresh(); } },
        h("option", { value: "" }, "Pick a Device"), ordered.map((x) => h("option", { value: x.mac, selected: x.mac === mac }, x.label)));
      const outcomePick = h("select", { id: "ts-outcome", "aria-label": "Attempt outcome", onchange: (e) => { outcome = e.target.value; remember(); refresh(); } },
        [["all", "All attempts"], ["stopped", "Stopped only"], ["audit", "Audit allowed only"]].map(([value, label]) => h("option", { value, selected: outcome === value }, label)));
      const groups = d.groups.map((g) => h("div.sect", { "data-key": g.reason }, h("h4", g.label, " ", h("span.count", "×" + g.count)),
        table(["What", "Last", "Times#", ""], g.entries.map((e) => h("tr", { "data-key": e.remote + "|" + e.audit },
          h("td", h("div", e.info.desc, e.audit ? [" ", h("span.pill.tag.audit", "let through")] : null), listLine(e.info, e.audit)), h("td.when", when(e.last)), h("td.num", String(e.count)), h("td.act", allowBtns(mac, e, g.reason)))), "")));
      const title = mac && label ? ("Recent attempts for " + label) : "Recent Attempts for a Device";
      const focusBanner = mac && label
        ? h("div.notice.focus.ts-focus", { "data-k": "ts-focus" },
            h("div", h("b", "Looking at "), h("b.ts-who", label), h("span.mute", " · last hour")),
            h("p.hint", { style: "margin:4px 0 0" }, "This is the device you were sent here for. Allow what broke it below, or pick another device."))
        : null;
      render(
        header("Troubleshooter", d.status), pendingNote(d.status), pathNote(d.status), adminNudge(d.status),
        mac ? null : h("p.hint", "Pick the device that isn’t working. Lines separate stopped attempts from attempts let through by Audit. Allow the one that matches what broke."),
        h("div.body.one", grow(panel(title, h("span.mute", mac ? (label || mac) : "last hour"),
          focusBanner,
          h("div.tools-row", pick, outcomePick, v ? h("a.btn.quiet", { perm: "devices", href: "/devices#" + v.mac }, "Device Settings") : null),
          d.alerts.length ? h("p.notice", d.alerts[0].text, " The lines below show what, and how to allow it if it should work.") : null,
          culpritStrip(mac, d.culprit, { focus: true }),
          v ? auditSect(v, null) : null,
          scroller("ts", null, !mac ? h("p.empty", "Pick a device to see its stopped and Audit-allowed attempts in the last hour.") : groups.length ? groups : h("p.empty", "No " + (outcome === "stopped" ? "stopped" : outcome === "audit" ? "Audit-allowed" : "logged") + " attempts for this device in the last hour.")),
          mac && !d.names_seen ? h("p.hint", "No name lookups seen yet, so lines show addresses. Names show up once devices look sites up through the gateway.") : null))));
      // Deep link / banner: put the chosen device front and center once.
      if (mac && !focusedOnce) {
        focusedOnce = true;
        const el = mainEl.querySelector(".ts-focus") || mainEl.querySelector("#ts-dev");
        el?.scrollIntoView({ block: "start", behavior: "smooth" });
        const sel = mainEl.querySelector("#ts-dev");
        if (sel) sel.focus({ preventScroll: true });
      }
    });
  }

  // ---------- Audit list ----------
  function auditList(d) {
    const rows = stable("audit", "", d.rows, (r) => r.key, true);
    // Keep blocking covers every port on the address.
    const keep = (r) => change("/api/audit", { action: "keep", mac: r.mac, reason: r.reason, remote: r.remote, proto: "", port: 0 });
    const culprits = (d.auditing || []).filter((x) => x.culprit && x.culprit.what);
    return grow(panel("Would Have Been Blocked", h("span.mute", d.total + " to look at"),
      h("p.hint", "While Audit is on these were let through. Allow the ones a device needs for good, or keep blocking them once Audit is off."),
      culprits.length ? h("div", culprits.map((x) => culpritStrip(x.mac, x.culprit, { who: x.label }))) : null,
      scroller("aud", null, table(["Device", "What", "Last", "Times#", ""], rows.map((r) => h("tr", { "data-key": r.key },
        h("td", r.device, h("div.mute", r.why.replace(/^./, (c) => c.toUpperCase()))), h("td", blockWhat(r, true)), h("td.when", when(r.last)), h("td.num", String(r.count)),
        h("td.act", h("div.row.same", allowBtns(r.mac, r, r.reason, "Allow · Permanent"), h("button.small.quiet", { perm: "handle_alerts", onclick: () => keep(r) }, "Keep blocking"))))),
      "Nothing so far. Lines show up here while audit is on.")),
      shownOf(rows.length, d.total, "lines")));
  }

  // ---------- Firewall ----------
  // The background load of the country rules: what it is doing, in plain words.
  let geoPoll = 0;
  function geoJobLine(j) {
    clearTimeout(geoPoll);
    if (!j || !j.state) return h("p.hint", "\u00a0");
    if (j.state === "applying") { geoPoll = setTimeout(refresh, 1000); return h("p.hint", "Loading the rules for " + j.countries + " countries… You can keep using the page."); }
    if (j.state === "failed") return h("p.bad", "Couldn't load the country rules: " + j.error);
    return h("p.hint", "In force: " + j.countries + " countries, " + j.ranges.toLocaleString() + " address ranges, loaded in " + (j.ms / 1000).toFixed(1) + " s.");
  }
  function presetAsk(p, secs) {
    const applyBody = { preset: p.id };
    // Fresh server-side preview so the list matches current policy.
    previewAsk("Apply " + p.label + "?", applyBody, {
      lead: p.one_line || null,
      danger: p.id === "fortnox",
      extra: p.id === "fortnox" ? h("p.notice", "Strict Outbound will turn on, and Remote Desktop is blocked on the home network too. Unusual apps may need Allow. ", undoHint(secs)) : null,
    });
  }



  function coachPage(d) {
    // Landing + popup wizard. Answers only fill `answers`; settings change only when
    // the owner Applies one suggestion at the end.
    const answers = {};
    const dismissed = new Set((d.dismissed || []));
    const box = h("div.body.two");
    const startBtn = () => h("button", { onclick: () => runWizard() }, "Start Best Practices Check");
    const landing = () => {
      box.replaceChildren(
        h("div.col", { "data-k": "coach-land" },
          panel("Best Practices", h("span.pill", d.preset_chip || "Custom"),
            h("p", "You will be presented with several questions. After which you will be given a list of best practices that match your answers and an opportunity to instate those changes or ignore the recommendations."),
            h("div.row", { style: "margin-top:12px" }, startBtn()))),
        h("div.col", { "data-k": "coach-side" },
          panel("Why This Helps", null,
            h("p.hint", "Questions your settings already answer are skipped. Recommendations follow your current Normal, FortNox, or Custom level."))));
    };
    const explainQ = (q) => q.explain || q.hint || "";
    async function fetchCoach() {
      return api("/api/coach", { answers });
    }
    async function runWizard() {
      let data = await api("/api/coach");
      d.questions = data.questions || [];
      d.preset_chip = data.preset_chip || d.preset_chip;
      const qs = (d.questions || []).filter((q) => !q.skip);
      let i = 0;
      const step = async () => {
        if (i >= qs.length) return showResults();
        const q = qs[i];
        const body = h("div.dlg.coach-wiz");
        body.replaceChildren(
          h("h3", "Best Practices · " + (i + 1) + " of " + qs.length),
          h("p.mute", "Level: " + (d.preset_chip || "Custom")),
          h("b.coach-q", q.text),
          h("p.coach-explain", explainQ(q)),
          h("div.acts.coach-acts",
            h("button.quiet", { onclick: () => { hideBox(); } }, "Cancel"),
            h("button.quiet", { onclick: () => { answers[q.id] = false; i++; step(); } }, "No"),
            h("button", { onclick: () => { answers[q.id] = true; i++; step(); } }, "Yes")));
        showBox(body);
      };
      const showResults = async () => {
        const r = await fetchCoach();
        let list = (r.suggestions || []).filter((s) => !dismissed.has(s.id));
        const body = h("div.dlg.coach-wiz");
        const redraw = () => {
          const cards = list.map((s) => h("div.qs.coach-card",
            h("div", h("b", s.title), h("p", s.why),
              s.placement_block ? h("p.notice", s.placement_block) : null,
              s.risky && !s.placement_block ? h("p.hint", undoHint(d.status && d.status.rollback_secs)) : null),
            h("div.stack",
              s.placement_block
                ? h("button.quiet", { disabled: true }, "Not Available For Your Placement")
                : h("button", { onclick: () => change("/api/coach", { accept: s.id, answers }).then(() => { list = list.filter((x) => x.id !== s.id); redraw(); }) }, "Apply"),
              h("button.quiet", { onclick: () => change("/api/coach", { dismiss: s.id, answers }).then(() => { dismissed.add(s.id); list = list.filter((x) => x.id !== s.id); redraw(); }) }, "Skip"))));
          body.replaceChildren(
            h("h3", "Suggested Changes"),
            h("p.hint", list.length
              ? ("Based on " + (d.preset_chip || "Custom") + " and your answers. Nothing is on until you Apply one item.")
              : "All good, nothing to do."),
            list.length ? h("div.scroll", { style: "max-height:50vh" }, cards) : h("p.empty.padded", "All good, nothing to do."),
            h("div.acts.coach-acts",
              h("button.quiet", { onclick: () => { hideBox(); landing(); } }, "Done")));
        };
        showBox(body);
        redraw();
      };
      step();
    }
    landing();
    return box;
  }

  function firewall() {
    const view = { "/firewall/audit": "audit", "/firewall/geo": "geo", "/firewall/white": "white", "/firewall/black": "black", "/firewall/rules": "rules", "/firewall/presets": "presets", "/firewall/coach": "coach", "/firewall/mode": "mode", "/firewall/hardening": "hardening" }[PATH] || "main";
    const TITLE = { audit: "Audit", main: "Firewall", mode: "Protection Mode", hardening: "Hardening", geo: "Geo-Blocking", white: "Whitelist", black: "Blacklist", rules: "Rules as loaded", presets: "Protection Levels", coach: "Best Practices" };
    shell(TITLE[view]);
    every(view === "audit" ? 5000 : view === "hardening" ? 2000 : 0, async () => {
      if (view === "coach") {
        const d = await api("/api/coach");
        statusBox(d.status);
        render(header("Best Practices", d.status), pendingNote(d.status), pathNote(d.status), adminNudge(d.status), coachPage(d));
        return;
      }
      const d = await api(view === "audit" ? "/api/audit" : "/api/firewall" + (view === "rules" ? "?rules=1" : ""));
      statusBox(d.status);
      const modeRow = (m, title, text) => h("div.qs", h("div", d.mode === m ? h("button.isOn", { disabled: true, "aria-pressed": "true" }, "On") : h("button.quiet", { perm: "admin", onclick: () => modeAsk(m, d.status && d.status.rollback_secs) }, "Turn On")), h("div", h("b", title), h("p", text)));
      const toggle = (key, val, title, text) => h("div.qs", h("div", h("button" + (val ? ".danger" : ""), { perm: "admin", onclick: () => change("/api/firewall", { [key]: !val }) }, val ? "Turn Off" : "Turn On")), h("div", h("b", title, " ", val ? h("span.ok", "On") : h("span.mute", "Off")), h("p", text)));
      const listPanel = (which, title, text, entries) => {
        const lp = which === "white" ? "allow_list" : "block_list";
        const input = can(lp) ? h("textarea", { placeholder: "One per line: example.com, https://site.org/page, 1.2.3.4, 10.0.0.0/8" }) : null;
        return grow(panel(title, h("span.mute", entries.length + " entries"), h("p.hint", text), input, input ? h("div.row", { style: "margin:6px 0" }, h("button", { onclick: () => input.value.trim() && change("/api/list", { list: which, add: input.value }) }, "Add")) : null,
          scroller("list-" + which, null, entries.length ? h("ul.entries", entries.map((e) => h("li", h("span", e.entry), e.site ? h("span.mute", { style: "flex:none" }, e.addresses + " address" + (e.addresses === 1 ? "" : "es") + " seen") : null, h("button.small.quiet", { perm: lp, onclick: () => change("/api/list", { list: which, remove: e.entry }) }, "Remove")))) : h("p.empty", "Empty."))));
      };
      const presetCards = () => h("div.preset-grid", (d.presets || []).map((p) => h("div.preset-card" + (p.current ? ".on" : ""),
        h("div.row.same", h("b", p.label), p.current ? h("span.pill.ok", "Current") : null),
        h("p", p.one_line),
        p.current ? h("button.isOn", { disabled: true }, "Applied") : h("button", { perm: "admin", onclick: () => presetAsk(p, d.status && d.status.rollback_secs) }, "Review And Apply"))));
      let body;
      const onOff = (on) => on ? h("span.ok", "On") : h("span.mute", "Off");
      const statusRow = (label, val) => h("div.stat-row", h("span", label), h("span", val));
      const modeName = { audit: "Audit", normal: "Normal", lan_only: "Local Network Only", block_all: "Block Everything" };
      if (view === "audit") {
        const leave = d.mode === "audit" ? h("button", { perm: "admin", onclick: () => previewAsk("Leave Audit · Apply Normal?", { leave_audit: true }, { lead: "Applies the Normal protection level. You can fine-tune afterward." }) }, "Leave Audit · Apply Normal") : null;
        body = h("div.body.two",
          h("div.col", { "data-k": "fw-audit" }, auditList(d)),
          h("div.col", { "data-k": "fw-audit-side" },
            panel("About Audit", null,
              h("p.hint", "Test mode: nothing is blocked; we write down what would be."),
              leave ? h("div", leave, h("p.hint", "Turns on everyday Normal protection.")) : null,
              d.mode !== "audit" && !(d.auditing || []).length ? h("p.hint", "Audit is off. Turn it on for the whole network in ", h("a", { href: "/firewall/mode" }, "Firewall → Protection Mode"), ", or for one device on its page.") : null)));
      } else if (view === "presets") {
        body = h("div.body.two",
          h("div.col", { "data-k": "fw-presets" },
            panel("Protection Levels", h("span.pill", d.preset_chip || "Custom"),
              h("p.hint", "Normal and FortNox are the named starting points. Custom means you changed something afterward. Leave Audit lands on Normal."),
              presetCards())),
          can("admin") ? h("div.col", { "data-k": "fw-presets-side" },
            panel("Apply A Level", null,
              h("p.hint", "Review And Apply lists every setting that will change. Nothing applies until you press OK. You can fine-tune any toggle afterward."),
              h("div.stack",
                h("button.quiet", { onclick: () => previewAsk("Reset To Normal?", { preset: "normal" }, { lead: "Applies the Normal protection level. You can fine-tune afterward." }) }, "Reset To Normal"),
                h("a.btn", { href: "/firewall/coach" }, "Best Practices")))) : null);
      } else if (view === "mode") {
        body = h("div.body.two",
          h("div.col", { "data-k": "fw-mode" },
            h("div", { id: "mode" }, panel("Protection Mode", h("span.pill", modeName[d.mode] || d.mode),
              h("p.hint", "Turn On opens a picker: the note updates as you choose, then Activate applies it."),
              modeRow("normal", "Normal", MODE_HELP.normal),
              modeRow("audit", "Audit", MODE_HELP.audit),
              modeRow("lan_only", "Local Network Only", MODE_HELP.lan_only),
              modeRow("block_all", "Block Everything", MODE_HELP.block_all)))),
          h("div.col", { "data-k": "fw-mode-side" },
            panel("About Modes", null,
              h("p.hint", "Normal applies the Normal protection level. Settings can be changed afterward under Hardening."))));
      } else if (view === "hardening") {
        body = h("div.body.two",
          h("div.col", { "data-k": "fw-hard" },
            panel("Hardening", h("span.pill", d.preset_chip || "Custom"),
              toggle("telemetry_all", d.telemetry_all, "Block All Telemetry", "Stops known tracking and telemetry addresses for every device, both ways. " + d.telemetry_hosts + " names known from the lists."),
              toggle("threats", d.threats, "Threat Lists", "Stops known bad networks (Spamhaus DROP and DROPv6) and botnet servers (abuse.ch Feodo), both ways. Downloaded once a day."),
              toggle("block_dot", d.block_dot, "Block Encrypted DNS (Port 853)", "Keeps name-based blocks from being skipped by DNS over TLS. While On, devices set to require DNS over TLS (for example Android Private DNS set to a provider name) cannot look up names."),
              (d.threats || d.block_dot || d.doh_warning) ? h("p.notice", "Some apps use encrypted DNS on port 443. FoilGateway may not learn new names from those apps. Names already on your lists still become address blocks." + (d.block_dot ? " Encrypted DNS on port 853 is blocked while Block Encrypted DNS is On." : "")) : null,
              toggle("strict_outbound", d.strict_outbound, "Strict Outbound", "Only allows new outbound that matches your rules. Stronger; odd apps may need Allow. On in FortNox."),
              toggle("block_vpn", d.block_vpn, "Block VPN Ports", "Stops common VPN / WireGuard ports. Off by default, including in FortNox."),
              toggle("block_ipv6", d.block_ipv6, "Block IPv6", "On: no IPv6 traffic passes the gateway onto the LAN. Off: IPv6 is allowed, with the same hardening as IPv4. Default Off."),
              toggle("white_expiry", d.white_expiry, "Whitelist Expiry For Auto Allows", "When On, Allows created from Audit or the Troubleshooter expire after 30 days. Allow · Permanent makes an Allow that does not expire. Default Off; On in the Normal protection level."),
              (d.threats || d.block_dot) ? h("p.notice", "Some apps use encrypted DNS on port 443. FoilGateway may not learn new names from those apps. Names already on your lists still become address blocks." + (d.block_dot ? " Encrypted DNS on port 853 is blocked while Block Encrypted DNS is On." : "")) : null,
              toggle("sticky_identity", d.sticky_identity, "Stronger Device Identity", "Remembers hostname and DHCP fingerprint hints when a phone rotates its private MAC. Default Off."),
              toggle("deep_detect", d.deep_detect, "Deeper Detection", "Checks unhandled forwarded TCP traffic for port sweeps and repeated connection failures. No alerts for blocked or already handled traffic. Default Off."),
              d.deep_detect ? h("p.hint", "Observation: " + ((d.detection || {}).state || "unavailable") + (((d.detection || {}).detail) ? ". " + d.detection.detail : "")) : null,
              h("div.qs", h("div.stack", { id: "newdev" }, ["normal", "lan_only"].map((p) => d.new_devices === p ? h("button.isOn", { disabled: true, "aria-pressed": "true" }, POLICY[p]) : h("button.quiet", { disabled: !can("admin"), onclick: () => change("/api/firewall", { new_devices: p }) }, POLICY[p]))), h("div", h("b", "New Devices"), h("p", "What a device gets the first time it shows up. It's flagged as new either way."))))),
          h("div.col", { "data-k": "fw-hard-side" },
            panel("Lists Downloaded", null, d.feeds.length ? table(["List", "Entries#", "Fetched"], d.feeds.map((f) => h("tr", h("td", f.name, f.error ? h("div.bad", f.error) : null), h("td.num", f.entries), h("td", when(f.fetched_at)))), "") : h("p.empty.padded", "Nothing downloaded. Lists download when you turn on a feature that needs them.")),
            panel("About Hardening", null,
              h("p.hint", "These toggles are what Normal and FortNox set. Changing one moves you to Custom."),
              h("p.hint", "Stronger Identity and Deeper Detection default Off. Read what each does before turning it on."))));
      } else if (view === "main") {
        const st = d.status || {};
        const chip = d.preset_chip || "Custom";
        body = h("div.body.two",
          h("div.col", { "data-k": "fw-status" },
            panel("Firewall Status", h("span.pill", chip),
              h("div.stat-grid",
                statusRow("Protection Mode", modeName[d.mode] || d.mode),
                statusRow("Protection Level", chip),
                statusRow("Threat Lists", onOff(d.threats)),
                statusRow("Telemetry Block", onOff(d.telemetry_all)),
                statusRow("Encrypted DNS (DoT 853)", onOff(d.block_dot)),
                statusRow("Strict Outbound", onOff(d.strict_outbound)),
                statusRow("Block VPN Ports", onOff(d.block_vpn)),
                statusRow("Block IPv6", onOff(!!d.block_ipv6)),
                statusRow("Whitelist Expiry", onOff(d.white_expiry)),
                statusRow("Stronger Identity", onOff(d.sticky_identity)),
                statusRow("Deeper Detection", onOff(d.deep_detect)),
                statusRow("Remote Desktop Outside", d.rdp_external ? h("span.warn", "Allowed") : h("span.ok", "Blocked")),
                statusRow("Remote Desktop On LAN", d.rdp_lan_blocked ? h("span.ok", "Blocked") : h("span.mute", "Allowed"))),
              (d.threats || d.block_dot) ? h("p.notice", { style: "margin-top:10px" }, "Some apps use encrypted DNS on port 443. FoilGateway may not learn new names from those apps. Names already on your lists still become address blocks." + (d.block_dot ? " Encrypted DNS on port 853 is blocked while Block Encrypted DNS is On." : "")) : null))),
          h("div.col", { "data-k": "fw-health" },
            panel("Network Health", null,
              h("div.stat-grid",
                statusRow("In Path", st.in_path ? h("span.ok", "Yes") : h("span.warn", "Not Yet")),
                statusRow("Filtering", st.filtering ? h("span.ok", "On") : h("span.mute", "Off")),
                statusRow("Bridge", st.bridge ? h("span.ok", "Up") : h("span.mute", "None")),
                statusRow("Settings Reachable From", d.admin_from === "lan" ? "Local Network Only" : "Home Network Or Router Side"),
                statusRow("Pending Undo", st.pending ? (st.pending.what + " · " + st.pending.left + " s") : h("span.mute", "None"))),
              h("p.hint", dualUp(st))));
      } else if (view === "geo") {
        const geoReady = d.geo.loaded;
        const chosen = new Set(d.countries);
        const names = Object.entries(d.all_countries).sort((a, b) => a[1].localeCompare(b[1]));
        // A tick applies straight away; ticks close together go as one change.
        const apply = () => { clearTimeout(geoSoon); geoSoon = setTimeout(() => change("/api/firewall", { countries: [...ctry.querySelectorAll("input:checked")].map((i) => i.value) }), 400); };
        const ctry = h("div.countries" + (geoReady ? "" : ".off"), { "data-k": "ctry", "data-ref": "" }, names.map(([code, name]) => h("label.check", h("input", { type: "checkbox", disabled: !can("admin"), checked: chosen.has(code), value: code, onchange: apply }), name)));
        body = h("div.body.two",
          h("div.col", { "data-k": "fw-geo" }, grow(panel("Countries", geoReady && can("admin") ? h("span.mute", "Changes apply as you tick") : null, h("div.fillin", ctry)))),
          h("div.col", { "data-k": "fw-geo-side" },
            panel("About Geo-Blocking", null,
              geoReady ? h("div", h("p.hint", "Traffic to and from ticked countries is stopped, both ways. Trusted devices skip this. " + chosen.size + " ticked."), h("p.notice", "Big sites use servers in many countries. If something breaks after ticking, check the Troubleshooter.")) : h("p.notice", "Country blocking needs the location database. ", h("a", { href: "/settings/general#geo" }, "Turn It On in Settings → Time and Location"), "."),
              geoJobLine(d.geo_job))));
      } else if (view === "white") {
        body = h("div.body.two",
          h("div.col", { "data-k": "fw-white" }, listPanel("white", "Whitelist", "Always let these through.", d.white)),
          h("div.col", { "data-k": "fw-white-side" }, panel("About Whitelist", null, h("p.hint", "Beats telemetry, Black list, threat lists and countries, but not Local Network Only or Block Everything. Names are looked up again every few minutes and every address they ever had stays in."))));
      } else if (view === "black") {
        body = h("div.body.two",
          h("div.col", { "data-k": "fw-black" }, listPanel("black", "Blacklist", "Always stop these, both ways.", d.black)),
          h("div.col", { "data-k": "fw-black-side" }, panel("About Blacklist", null, h("p.hint", "Trusted devices skip the Black list. Use Allow on a device when one address should still get through."))));
      } else {
        body = h("div.body.two",
          h("div.col", { "data-k": "fw-rules" }, grow(panel("Rules As Loaded", h("span.mute", "nftables table inet foilgateway"), h("pre.rules.scroll", { "data-k": "rules" }, d.rules)))),
          h("div.col", { "data-k": "fw-rules-side" }, panel("About Rules", null, h("p.hint", "What the gateway loaded into the kernel. Useful for support. Everyday changes stay on Firewall and Ports."))));
      }
      render(header(TITLE[view], d.status), pendingNote(d.status), pathNote(d.status), adminNudge(d.status), body);
    });
  }

  // ---------- Ports ----------
  const CHOICE_NAME = { allow: "Allow", block_wan: "Block from WAN", block_lan: "Block from LAN", block_both: "Block Both" };
  const CHOICE = [["allow", "Allow"], ["block_wan", "Block from WAN"], ["block_lan", "Block from LAN"], ["block_both", "Block Both"]];
  function choiceSeg(cur, pick, withGlobal) {
    const opts = withGlobal ? [["global", "Same as Global"]].concat(CHOICE) : CHOICE;
    return h("div.seg.choice", opts.map(([k, t]) => h("button" + (cur === k ? ".on." + k : ""), { disabled: !can("admin"), onclick: () => cur !== k && pick(k) }, t)));
  }
  function ports() {
    const perDevice = PATH === "/ports/devices";
    let hot0 = qp0.has("port");
    shell(perDevice ? "Ports per device" : "Ports");
    let q = new URLSearchParams(location.search).get("q") || "", limit = 100, total = 0, adding = false, show = "", sort = "own", openMac = "";
    if (perDevice && /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(q)) { openMac = q.toLowerCase(); q = ""; }
    const more = () => { if (limit < total) { limit += 100; refresh(); } };
    every(5000, async () => {
      const d = await api("/api/ports?" + new URLSearchParams(perDevice ? { tab: "devices", q, limit, show, sort, open: openMac } : { tab: "global", q, limit }));
      statusBox(d.status);
      total = d.total;
      const mode = d.status.mode;
      const set = (p, mac, choice) => change("/api/ports", { action: "choice", proto: p.proto, port: p.port, mac, choice });
      const absolute = mode !== "normal" && mode !== "audit" ? h("p.notice", h("b", MODE[mode] + " is on. "), "Nothing gets through while it is, whatever is set here.") : null;
      let body;
      if (!perDevice) {
        const rows = d.ports.map((p) => h("tr",
          h("td", h("b", p.label), p.new ? [" ", h("span.pill.new", "new")] : null, h("div.mute", p.name || (p.custom ? "added by hand" : ""))),
          h("td", p.direction),
          h("td", p.hits ? p.hits + " tr" + (p.hits === 1 ? "y" : "ies") + " from the router side" : h("span.mute", "no tries from the router side"), p.last_seen ? h("div.mute", "last " + when(p.last_seen) + (p.from ? " from " + p.from : "")) : null),
          h("td", p.risk ? h("div.warn", p.risk) : null,
            p.set ? null : h("div.mute", "Not set yet, so it's blocked from WAN."),
            p.overrides ? h("div", h("a", { href: "/ports/devices" }, p.overrides + " device" + (p.overrides === 1 ? " has" : "s have") + " its own setting"), p.set ? "; the global rule applies to it." : ".") : null),
          h("td", choiceSeg(p.set ? p.choice : "", (c) => set(p, "", c)),
            p.custom && can("admin") ? [" ", h("button.small.quiet", { onclick: () => change("/api/ports", { action: "remove", proto: p.proto, port: p.port, mac: "" }) }, "Remove")] : null)));
        const proto = h("select", h("option", { value: "tcp" }, "TCP"), h("option", { value: "udp" }, "UDP"));
        const port = h("input", { type: "number", min: 1, max: 65535, placeholder: "Port", style: "width:100px" });
        const ch = h("select", CHOICE.map(([k, t]) => h("option", { value: k }, t)));
        const add = !can("admin") ? null : adding
          ? h("div.row", { style: "margin-top:8px" }, proto, port, ch,
            h("button", { onclick: () => port.value && change("/api/ports", { action: "add", proto: proto.value, port: port.value, mac: "", choice: ch.value }, () => { adding = false; refresh(); }) }, "Add"),
            h("button.quiet", { onclick: () => { adding = false; refresh(); } }, "Cancel"))
          : h("div", { style: "margin-top:8px" }, h("button.small.quiet", { onclick: () => { adding = true; refresh(); } }, "Add a Port by Hand"));
        body = h("div.body.one", grow(panel("Every device", searchBox("port-q", q, (v) => { q = v; refresh(); }, "Search ports"),
          h("p.hint", "Allow lets the router side start connections to your devices on that port. Block From LAN stops your own devices starting them. These settings win over any device's own. Remote Desktop from outside stays blocked by default; on your home network it still works unless you (or FortNox) block it."),
          scroller("ports", null, table(["Port", "Direction", "Seen", "Note", "Setting"], rows, q ? "No port matches." : "Nothing here yet.")), add)));
      } else {
        // Every device; own settings first. One opens in place with every port.
        const known = d.known;
        const hot = (qp0.get("port") || "").toLowerCase();
        const portRow = (v, p) => h("div.prow" + (p.choice !== "global" ? ".own" : "") + (hot === p.proto + "-" + p.port && v.mac === openMac ? ".picked" : ""), { "data-port": p.proto + " " + p.port },
          h("div", h("b", p.label), p.new ? [" ", h("span.pill.new", "new")] : null, h("div.mute", [p.name, p.direction, p.choice === "global" ? "global: " + CHOICE_NAME[p.global] : null].filter(Boolean).join(" · "))),
          choiceSeg(p.choice, (c) => set(p, v.mac, c), true),
          p.alert ? h("div.note.warn", "⚠ " + p.alert) : null,
          p.risk && (p.choice === "allow" || (p.choice === "global" && p.global === "allow")) ? h("div.note.warn", p.risk) : null);
        const addRow = (v) => {
          const other = h("input", { type: "text", placeholder: "tcp 8080", style: "width:110px" });
          const addOne = () => {
            const m = other.value.trim().toLowerCase().match(/^(tcp|udp)\s*[ /]?\s*(\d+)$/);
            if (!m) { showBox(h("h3", "Which port?"), h("p", "Type it like tcp 8080."), h("div.acts", h("button", { onclick: hideBox }, "OK"))); return; }
            change("/api/ports", { action: "add", proto: m[1], port: Number(m[2]), mac: v.mac, choice: "block_wan" });
          };
          return h("div.row", { style: "margin-top:6px" }, h("span.mute", "Another port:"), other, h("button.small", { onclick: addOne }, "Add"));
        };
        const devRow = (v) => {
          const isOpen = v.mac === openMac;
          return h("div.devports" + (isOpen ? ".open" : ""), { "data-mac": v.mac, "data-key": v.mac },
            h("div.devhead", { role: "button", tabindex: 0, "aria-expanded": String(isOpen), onclick: () => { openMac = isOpen ? "" : v.mac; refresh(); } },
              h("div", h("b", v.label), h("div.mute", v.ip || v.mac)),
              h("span" + (v.own ? ".pill.own" : ".mute"), v.own ? v.own + " own setting" + (v.own === 1 ? "" : "s") : "same as global")),
            isOpen ? [v.shut ? h("div.mute", "Set to " + POLICY[v.shut] + ", so ports stay shut for it anyway.") : null,
              v.ports && v.ports.length ? v.ports.map((p) => portRow(v, p)) : h("p.empty", "No ports seen yet."), can("admin") ? addRow(v) : null] : null);
        };
        const sel = (val, opts, setv) => h("select", { onchange: (e) => { setv(e.target.value); limit = 100; refresh(); } }, opts.map(([k, t]) => h("option", { value: k, selected: k === val }, t)));
        body = h("div.body.one", grow(panel("Per Device", h("span.mute", d.with_own + " with their own settings"),
          h("div.tools-row", searchBox("pd-q", q, (v) => { q = v; limit = 100; refresh(); }, "Search devices"),
            sel(show, [["", "All"], ["own", "With Own Settings"], ["none", "Same as Global"]], (v) => { show = v; }),
            sel(sort, [["own", "Own settings first"], ["name", "By name"], ["ip", "By address"], ["seen", "Last seen"]], (v) => { sort = v; })),
          h("p.hint", "Click a device to see its ports. Where a port also has a setting for every device, the global rule applies. Changes apply at once."),
          scroller("pd", more, d.devices.length ? d.devices.map(devRow) : h("p.empty", q || show ? "No device matches." : "No devices seen yet.")),
          shownOf(d.devices.length, d.total, "devices"))));
      }
      render(header(perDevice ? "Ports per device" : "Ports", d.status), pendingNote(d.status), pathNote(d.status), adminNudge(d.status), absolute, body);
      if (hot0 && perDevice) { hot0 = false; mainEl.querySelector(".prow.picked")?.scrollIntoView({ block: "center" }); }
    });
  }

  // Actions for the Capture Log line opened from an alert or a message.
  function rowName(r) { return r.label || r.device || "This device"; }
  function rowIp(text) { const m = String(text || "").match(/ from ([0-9a-fA-F:.]+)\.?$/); return m ? m[1] : ""; }
  function rowPort(r) {
    const m = String(r.text || "").match(/tried (tcp|udp) (\d+)/i);
    if (m) return { proto: m[1].toLowerCase(), port: Number(m[2]) };
    const p = String(r.ports || "").split(",")[0].trim().match(/^(tcp|udp)\s+(\d+)$/i);
    if (p) return { proto: p[1].toLowerCase(), port: Number(p[2]) };
    const i = r.info && r.info.ports && r.info.ports[0];
    return i && i.proto && i.port ? { proto: i.proto, port: i.port } : null;
  }
  const ALLOW_IP = { devblock: 1, devlan: 1, telemetry: 1, black: 1, threat: 1, country: 1 };
  function timesPhrase(r) {
    const n = r.count || 1;
    const today = when(r.last).indexOf("Today ") === 0;
    const times = n === 1 ? "once" : (n + " times");
    return today ? times + " today" : times;
  }
  function destPhrase(r) {
    const domain = (r.domain || (r.info && r.info.domain) || "").trim();
    const remote = (r.remote || "").trim();
    if (domain && remote && domain !== remote) return domain + " (" + remote + ")";
    return domain || remote || "that address";
  }
  function confirmRun(title, text, okLabel, danger, go) {
    ask(title, text, okLabel, go, danger);
  }
  // Block one address or port for one device: adds it to that device's own
  // deny list and takes it off that device's allow list. Other devices are unchanged.
  async function blockForDevice(mac, entry) {
    const d = await api("/api/devices?" + new URLSearchParams({ q: mac, limit: 500 }));
    const v = (d.devices || []).find((x) => x.mac === mac);
    if (!v) { showBox(h("h3", "That didn't go in"), h("p", "That device isn't on the gateway any more."), h("div.acts", h("button", { onclick: hideBox }, "OK"))); return; }
    const deny = (v.deny || []).includes(entry) ? v.deny : (v.deny || []).concat([entry]);
    return change("/api/device", { mac, deny, allow: (v.allow || []).filter((x) => x !== entry) }, () => {});
  }
  function actPanel(r) {
    // In the alert popup a choice applies at once; the popup closes as it starts.
    const confirmRun = (title, text, okLabel, danger, go) => go();
    const name = rowName(r);
    const mac = r.device || "";
    const remote = (r.remote || "").trim();
    const port = rowPort(r);
    const buttons = [];
    let says = "";
    const handled = { perm: "handle_alerts", onclick: () => change("/api/alert", { id: r.id }) };
    // Allow and Block both settle the alert too, so it doesn't come back for this device, address and port.
    const settle = (run) => async () => { const res = await run(); if (res !== undefined) await change("/api/alert", { id: r.id }); };
    const closePort = (pt) => change("/api/ports", { action: "choice", proto: pt.proto, port: pt.port, mac, choice: "block_both" }, () => {});
    const portTry = r.kind === "device" && / tried (tcp|udp) /i.test(r.text || "");
    const authIp = (r.kind === "alert" && (/Failed sign-in/.test(r.text) || /wrong API key/.test(r.text))) ? rowIp(r.text) : "";
    const suspicious = r.kind === "alert" && mac && (r.reason === "surge" || r.reason === "port_sweep" || r.reason === "tcp_failure" || /threat list/.test(r.text || "") || /TCP (destination ports|connection failures)/.test(r.text || ""));
    const fgProblem = r.kind === "alert" && !authIp && !suspicious && !remote && !mac;
    if (portTry && port) {
      says = name + " tried to use " + port.proto + " " + port.port + ", which isn't open for it.";
      buttons.push(h("button", { perm: "admin", onclick: () => confirmRun("Open " + port.proto + " " + port.port + " for " + name + "?", name + " will accept connections on " + port.proto + " " + port.port + " from the router side until you change it on the Ports page.", "Open Port", false, settle(() => change("/api/ports", { action: "choice", proto: port.proto, port: port.port, mac, choice: "allow" }, () => {}))) }, "Open " + port.proto + " " + port.port + " for " + name));
      buttons.push(h("button", { perm: "admin", onclick: () => confirmRun("Block " + port.proto + " " + port.port + " for " + name + "?", port.proto + " " + port.port + " stays closed on " + name + " from the router side and the LAN side until you change it on the Ports page. Other devices are not affected.", "Block", true, settle(() => closePort(port))) }, "Block " + port.proto + " " + port.port + " for " + name));
      buttons.push(h("button.quiet", { perm: "handle_alerts", onclick: async () => { await change("/api/ports", { action: "seen", proto: port.proto, port: port.port, mac }, () => {}); await change("/api/alert", { id: r.id }); } }, "Mark as Looked At"));
    } else if (r.kind === "device") {
      const pol = r.policy ? ({ trusted: "Trusted", normal: "Normal", lan_only: "Local Network Only", block: "Block All" }[r.policy] || r.policy) : "Normal";
      says = name + " is new on the network. It is set to " + pol + ".";
      const setPol = (policy, title, text, danger, label) => h("button" + (danger ? ".danger" : ".quiet"), { perm: "device_actions", onclick: () => confirmRun(title, text, label, danger, () => change("/api/device", { mac, policy })) }, label);
      // Trusted and LAN Only / Block change access; Normal can also, so ask for all four.
      buttons.push(setPol("trusted", "Set " + name + " to Trusted?", name + " skips the Black list, threat lists and countries until you change it on the Devices page.", false, "Trusted"));
      buttons.push(setPol("normal", "Set " + name + " to Normal?", name + " uses the internet under the network rules.", false, "Normal"));
      buttons.push(setPol("lan_only", "Set " + name + " to LAN Only?", name + " can reach other devices and the gateway, but not the internet, until you set it back on the Devices page.", false, "LAN Only"));
      buttons.push(setPol("block", "Block " + name + "?", name + " loses all network access until you set it back on the Devices page.", true, "Block"));
      buttons.push(h("button.quiet", { perm: "device_actions", onclick: () => {
        const inp = h("input", { value: name === mac ? "" : name, maxlength: 48, placeholder: "Name" });
        showBox(h("h3", "Rename " + name + "?"), inp, h("div.acts", h("button.quiet", { onclick: hideBox }, "Cancel"), h("button", { onclick: () => { hideBox(); change("/api/device", { mac, name: inp.value }); } }, "Rename")));
        inp.focus();
      } }, "Rename"));
      buttons.push(h("button", { perm: can("device_actions") ? "device_actions" : "handle_alerts", onclick: () => change(can("device_actions") ? "/api/device" : "/api/alert", can("device_actions") ? { mac, seen: true } : { id: r.id }) }, "Mark Handled"));
    } else if (authIp) {
      says = /wrong API key/.test(r.text) ? ("Someone at " + authIp + " used a wrong API key.") : ("Someone at " + authIp + " used a wrong password" + ((r.text.match(/Failed sign-in for (.+) from /) || [])[1] ? " for " + r.text.match(/Failed sign-in for (.+) from /)[1] : "") + ".");
      buttons.push(h("button.danger", { perm: "block_list", onclick: () => confirmRun("Block " + authIp + "?", "Connections from " + authIp + " are stopped until you take it off the Black list.", "Block", true, () => change("/api/list", { list: "black", add: authIp })) }, "Block " + authIp));
      buttons.push(h("button", handled, "Mark Handled"));
    } else if (suspicious) {
      says = /threat list/.test(r.text || "") ? (name + " contacted an address on a threat list.") : (name + " showed suspicious behavior" + (remote ? " involving " + remote : "") + ".");
      if (mac && remote) {
        buttons.push(h("button", { perm: "allow_list", onclick: () => confirmRun("Allow " + remote + " for " + name + "?", remote + " will be allowed for " + name + " only, until you take it off that device's allow list. Other devices are not affected.", "Allow", false, settle(() => change("/api/allow", { mac, reason: "black", remote, proto: (port && port.proto) || "", port: (port && port.port) || 0, permanent: true }, () => {}))) }, "Allow " + remote + " for " + name));
      }
      if (mac && remote) {
        buttons.push(h("button", { perm: ["block_list", "allow_list"], onclick: () => confirmRun("Block " + remote + " for " + name + "?", name + " can't reach " + remote + " until you take it off that device's block list. Other devices are not affected.", "Block", true, settle(() => blockForDevice(mac, remote))) }, "Block " + remote + " for " + name));
      }
      if (mac) {
        buttons.push(h("button.quiet", { perm: "device_actions", onclick: () => confirmRun("Set " + name + " to LAN Only?", name + " can reach other devices and the gateway, but not the internet, until you set it back on the Devices page.", "Set to LAN Only", false, () => change("/api/device", { mac, policy: "lan_only" })) }, "Set " + name + " to LAN Only"));
        buttons.push(h("button.danger", { perm: "device_actions", onclick: () => confirmRun("Block " + name + "?", name + " loses all network access until you set it back on the Devices page.", "Block", true, () => change("/api/device", { mac, policy: "block" })) }, "Block " + name));
        buttons.push(h("a.btn.quiet", { perm: "alerts", href: "/devices/troubleshoot?mac=" + encodeURIComponent(mac) }, "Open the Troubleshooter"));
      }
      buttons.push(h("button.quiet", handled, "Mark Handled"));
    } else if (fgProblem || (r.kind === "alert" && !mac && !authIp && !remote)) {
      const update = /update|previous version failed|checksum/i.test(r.text || "");
      const cert = /certificate/i.test(r.text || "");
      says = update ? "The update was not installed. The running version is unchanged." : (r.text || "Something needs a look on the gateway.");
      if (cert) buttons.push(h("a.btn", { perm: "admin", href: "/settings/certs" }, "Open Certificates"));
      else if (update) buttons.push(h("a.btn", { perm: "updates_view", href: "/settings/updates" }, "Open Updates"));
      else buttons.push(h("a.btn", { perm: "firewall_view", href: "/firewall" }, "Open Firewall"));
      buttons.push(h("button.quiet", handled, "Mark Handled"));
    } else if (r.kind === "block" || r.kind === "audit" || (r.kind === "alert" && (remote || mac))) {
      const pt = port ? (port.proto + " " + port.port) : "";
      says = name + " was stopped from reaching " + destPhrase(r) + (pt ? " on " + pt : "") + ", " + timesPhrase(r) + ".";
      const reason = r.reason || "black";
      const pBody = { mac, reason, remote, proto: (port && port.proto) || "", port: (port && port.port) || 0, permanent: true };
      const allowBtn = (label, text) => h("button", { perm: "allow_list", onclick: () => confirmRun(label + "?", text, "Allow", false, settle(() => change("/api/allow", pBody, () => {}))) }, label);
      const portOnly = mac && port && (reason === "wan" || reason === "lanport");
      if (portOnly) {
        const pt2 = port.proto + " " + port.port;
        buttons.push(allowBtn("Allow " + pt2 + " for " + name, reason === "wan" ? (name + " will accept connections on " + pt2 + " from the router side until you change it on the Ports page. Other devices are not affected.") : ("Devices on the LAN side may reach " + name + " on " + pt2 + " until you change it on the Ports page. Other devices are not affected.")));
        buttons.push(h("button", { perm: "admin", onclick: () => confirmRun("Block " + pt2 + " for " + name + "?", pt2 + " stays closed on " + name + " from the router side and the LAN side until you change it on the Ports page. Other devices are not affected.", "Block", true, settle(() => closePort(port))) }, "Block " + pt2 + " for " + name));
      } else if (mac && remote && (ALLOW_IP[reason] || reason === "devdeny")) {
        buttons.push(allowBtn("Allow " + remote + " for " + name, remote + " will be allowed for " + name + " only, until you take it off that device's allow list. Other devices are not affected."));
        buttons.push(h("button", { perm: ["block_list", "allow_list"], onclick: () => confirmRun("Block " + remote + " for " + name + "?", name + " can't reach " + remote + " until you take it off that device's block list. Other devices are not affected.", "Block", true, settle(() => blockForDevice(mac, remote))) }, "Block " + remote + " for " + name));
      } else if (reason === "mode" || reason === "lanonly") {
        buttons.push(h("a.btn", { perm: "firewall_view", href: "/firewall" }, "Change the Firewall Mode"));
      }

      if (r.kind === "alert" || r.kind === "block" || r.kind === "audit") buttons.push(h("button.quiet", handled, "Keep It Blocked"));
      if (mac) buttons.push(h("button.danger", { perm: "device_actions", onclick: () => confirmRun("Block " + name + "?", name + " loses all network access until you set it back on the Devices page.", "Block", true, () => change("/api/device", { mac, policy: "block" })) }, "Block " + name));
    } else if (r.kind === "audit") {
      says = r.text || (name + " would have been stopped.");
      buttons.push(h("button.quiet", handled, "Keep It Blocked"));
    } else if ((r.kind === "alert" || r.kind === "device") && !r.handled) {
      buttons.push(h("button", handled, "Mark Handled"));
      says = r.text || "This line still needs a look.";
    }
    const canQuiet = (r.kind === "alert" || r.kind === "block" || r.kind === "audit") && !!(remote || authIp || r.reason === "auth" || /Failed sign-in|wrong API key/.test(r.text || ""));
    if (r.quiet) buttons.push(h("button.quiet", { perm: "handle_alerts", onclick: () => change("/api/alert", { id: r.id, action: "hear" }) }, "Hear About This Again"));
    const shown = buttons.filter(Boolean);
    if (!shown.length) return null;
    return h("div.actbox", h("h4", "What to do about this"), says ? h("p", says) : null, h("div.acts", shown), canQuiet ? h("p.hint", "Allow, Block, Mark Handled and Keep It Blocked stop alerts for this device, address and port.") : null);
  }

  // ---------- Capture Log ----------
  // One alert in a large popup: everything known about it and what can be done.
  // Any choice applies and closes the popup.
  function alertPopup(r, closed) {
    const port = rowPort(r);
    const close = () => { hideBox(); closed(); };
    const facts = [
      ["What happened", r.text || blockWhat(r, r.kind === "audit")],
      ["Device", (r.label || r.device || "-") + (r.label && r.device && r.label !== r.device ? " (" + r.device + ")" : "")],
      r.remote ? ["Remote address", r.remote + (r.domain && r.domain !== r.remote ? " (" + r.domain + ")" : "")] : null,
      port ? ["Port", port.proto + " " + port.port] : null,
      ["Kind", r.kind],
      ["First seen", when(r.first)],
      ["Last seen", when(r.last)],
      ["Times", String(r.count || 1)],
      r.handled ? ["Status", "Handled"] : null,
    ].filter(Boolean);
    const acts = actPanel(r);
    showBox(
      h("h3", (r.kind === "alert" ? "Alert" : r.kind === "device" ? "Device" : "Blocked") + ": " + rowName(r)),
      h("dl.review", facts.flatMap(([k, v]) => [h("dt", k), h("dd", v)])),
      acts || h("p.mute", "There is nothing to change for this one."),
      h("div.acts", h("button.quiet", { onclick: close }, "Close")));
    const box = overlay.firstChild;
    if (box) {
      box.classList.add("big");
      // A choice in the popup closes it; the change itself carries on.
      box.addEventListener("click", (e) => { const b = e.target.closest(".actbox button, .actbox a"); if (b) close(); }, true);
    }
  }
  function log() {
    shell("Capture Log");
    const qp = new URLSearchParams(location.search);
    let kind = qp.get("kind") || "", today = qp.has("today"), q = qp.get("q") || "", sort = qp.get("sort") || "new", from = qp.get("from") || "", to = qp.get("to") || "", limit = 200, total = 0;
    let focus = Number(qp.get("focus")) || 0, focused = false;
    // The filter lives in the address, so Back and a reload land on the same view.
    const keepUrl = () => {
      const u = new URLSearchParams();
      if (kind) u.set("kind", kind);
      if (today) u.set("today", "1");
      if (q) u.set("q", q);
      if (sort !== "new") u.set("sort", sort);
      if (from) u.set("from", from);
      if (to) u.set("to", to);
      if (focus) u.set("focus", focus);
      const s = u.toString();
      if (s !== location.search.slice(1)) history.replaceState(null, "", "/log" + (s ? "?" + s : ""));
    };
    const more = () => { if (limit < total) { limit += 200; refresh(); } };
    every(5000, async () => {
      keepUrl();
      const args = { kind: kind === "look" ? "look" : kind, q, sort, from, to, limit };
      if (today) args.today = 1;
      if (focus) args.focus = focus;
      const d = await api("/api/log?" + new URLSearchParams(args));
      statusBox(d.status);
      total = d.total;
      const chip = (k, label) => h("button.chip" + (kind === k ? ".on" : ""), { onclick: () => { kind = k; limit = 200; refresh(); } }, label);
      const date = (id, v, setv) => datePicker(id, v, (x) => { setv(x); limit = 200; refresh(); });
      const dl = "/api/log.txt?" + new URLSearchParams({ kind, from, to });
      render(
        header("Capture Log", d.status), pendingNote(d.status),
        h("div.body.one", grow(panel("Events",
          h("div.row", h("button" + (kind === "look" ? ".isOn" : ""), { onclick: () => { kind = "look"; limit = 200; refresh(); } }, "Needs a Look"), h("button.quiet" + (kind === "" ? ".isOn" : ""), { onclick: () => { kind = ""; limit = 200; refresh(); } }, "Everything")),
          h("div.tools-row", searchBox("log-q", q, (v) => { q = v; limit = 200; refresh(); }), "From", date("log-from", from, (v) => { from = v; }), "to", date("log-to", to, (v) => { to = v; }),
            h("select", { onchange: (e) => { sort = e.target.value; refresh(); } }, [["new", "Newest First"], ["old", "Oldest First"], ["count", "Most Often"]].map(([k, t]) => h("option", { value: k, selected: k === sort }, t))),
            h("label.check", h("input", { type: "checkbox", checked: today, onchange: (e) => { today = e.target.checked; refresh(); } }), "Today Only"),
            h("a.btn.quiet", { id: "log-dl", href: dl }, from || to || kind ? "Download These" : ("Download All" + (d.download_bytes ? " (" + bytes(d.download_bytes) + ")" : "")))),
          h("div.legend.key",
            h("span", h("b", "block"), " · stopped"),
            h("span", h("b", "audit"), " · would be stopped"),
            h("span", h("b", "alert"), " · worth a look"),
            h("span", h("b", "device"), " · new or changed")),
          h("div.chips", chip("look", "Needs a Look"), chip("", "All"), chip("block", "Blocked"), chip("device", "Devices"), chip("alert", "Alerts"), chip("audit", "Audit"), chip("dhcp", "DHCP"), chip("setting", "Settings"), chip("download", "Downloads")),
          scroller("log", more, table(["Last", "First", "Kind", "Device", "What", "Count#", ""], d.rows.flatMap((r) => {
            return [h("tr" + (r.id === focus ? ".sel" : ""), { "data-key": String(r.id) }, h("td", when(r.last)), h("td.mute", when(r.first)), h("td", r.kind), h("td", r.label || r.device || "-"), h("td", blockWhat(r, r.kind === "audit")), h("td.num", r.count), h("td", r.handled ? h("span.pill.handled", "handled") : ""))];
          }), "All good, nothing to do.")),
          shownOf(d.rows.length, d.total, "lines. The same thing on the same day is one line with a count")))));
      if (focus && !focused) {
        focused = true;
        mainEl.querySelector("tr.sel")?.scrollIntoView({ block: "center" });
        const r = d.rows.find((x) => x.id === focus);
        if (r) alertPopup(r, () => { focus = 0; keepUrl(); });
      }
    });
  }

  // ---------- Settings ----------
  // One row per port with WAN / LAN / Not used. lan is a list: every LAN
  // port joins the same bridge. With lockWan the WAN role can't move.
  function portPicker(ports, lan, wan, onpick, blink, lockWan) {
    const role = (n) => n === wan ? "wan" : lan.includes(n) ? "lan" : "off";
    return h("div.ports", ports.map((p) => h("div.portrow" + (p.here ? ".here" : ""),
      h("div", h("b", p.name), h("div." + (p.link ? "ok" : "mute"), p.link ? "● cable in" : "○ no cable")),
      h("div.mute",
        p.here ? h("span.pill.here", "You are here") : null, p.here ? " " : null,
        [p.link && p.speed ? p.speed + " now" : null, p.max_speed ? "up to " + p.max_speed : null, p.bus || null].filter(Boolean).join(" · ") || null, h("br"),
        p.ips.length ? p.ips.join(", ") : p.master ? "in bridge " + p.master + (bridgeIps && bridgeIps.length ? " (" + bridgeIps.join(", ") + ")" : "") : "no address", " · ", p.mac || "",
        blink && p.no_blink ? h("div.hint", p.no_blink) : null),
      h("div.acts",
        h("div.seg", [["wan", "WAN"], ["lan", "LAN"], ["off", "Not used"]].map(([k, t]) => h("button" + (role(p.name) === k ? ".on" : ""), { disabled: lockWan && (k === "wan" || p.name === wan) && role(p.name) !== k, onclick: () => onpick(p.name, k) }, t))),
        blink ? h("button.small.quiet", { disabled: !!p.no_blink || p.blinking, title: p.no_blink || "Flash this port's lights for 5 seconds", onclick: () => blink(p.name) }, p.blinking ? "Blinking…" : "Blink") : null))));
  }
  function pickRole(sel, name, role) {
    sel.lan = sel.lan.filter((x) => x !== name);
    if (sel.wan === name) sel.wan = "";
    if (role === "wan") sel.wan = name;
    if (role === "lan") sel.lan.push(name);
  }
  function geoPanel(g) {
    let body;
    if (g.on && (g.phase === 1 || g.phase === 2)) {
      body = [geoProgress(g)];
    } else {
      body = [h("p", "The free DB-IP City Lite database puts connections on the map and makes country blocking possible. It's about " + g.size_note.replace(/^about /, "") + ", is never downloaded unless you turn this on, and updates once a month."),
        g.loaded ? h("p.ok", "Loaded: " + g.month + (g.fetched_at ? " (fetched " + when(g.fetched_at) + ")" : "")) : null,
        g.on && g.error ? geoFailed(g) : null,
        g.on && g.error && !g.loaded ? geoRetry() : null, " ",
        h("button" + (g.on ? ".danger" : ""), { onclick: () => change("/api/settings", { action: "geo", on: !g.on }) }, g.on ? "Turn off" : "Turn on and download")];
    }
    return panel("Location database", null, body, h("div.attr", "Source ", g.source));
  }

  // Help manual: Markdown subset for in-app chapters (trusted local content).
  let helpBundle = null, helpQ = "", helpTab = "getting-started";
  function mdInline(s) {
    s = String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/(^|[^*])\*([^*]+)\*(?![*])/g, "$1<em>$2</em>");
    s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
    return s;
  }
  function mdToHtml(md) {
    const lines = String(md || "").replace(/\r\n/g, "\n").split("\n");
    const out = [];
    let i = 0, inCode = false, code = [], inUl = false, inOl = false, table = [];
    const closeLists = () => { if (inUl) { out.push("</ul>"); inUl = false; } if (inOl) { out.push("</ol>"); inOl = false; } };
    const flushTable = () => {
      if (!table.length) return;
      out.push('<table class="help-table">');
      table.forEach((row, ri) => {
        if (ri === 1 && row.every((c) => /^:?-{3,}:?$/.test(c.trim()))) return;
        const tag = ri === 0 ? "th" : "td";
        out.push("<tr>" + row.map((c) => "<" + tag + ">" + mdInline(c.trim()) + "</" + tag + ">").join("") + "</tr>");
      });
      out.push("</table>");
      table = [];
    };
    while (i < lines.length) {
      const line = lines[i];
      if (line.startsWith("```")) {
        closeLists(); flushTable();
        if (inCode) { out.push('<pre class="help-pre"><code>' + code.join("\n").replace(/&/g, "&amp;").replace(/</g, "&lt;") + "</code></pre>"); code = []; inCode = false; }
        else inCode = true;
        i++; continue;
      }
      if (inCode) { code.push(line); i++; continue; }
      if (/^\|.+\|$/.test(line.trim())) {
        closeLists();
        table.push(line.trim().replace(/^\||\|$/g, "").split("|"));
        i++; continue;
      }
      if (table.length) flushTable();
      if (!line.trim()) { closeLists(); i++; continue; }
      if (line.startsWith("# ")) { closeLists(); out.push("<h1>" + mdInline(line.slice(2).trim()) + "</h1>"); i++; continue; }
      if (line.startsWith("## ")) { closeLists(); out.push("<h2>" + mdInline(line.slice(3).trim()) + "</h2>"); i++; continue; }
      if (line.startsWith("### ")) { closeLists(); out.push("<h3>" + mdInline(line.slice(4).trim()) + "</h3>"); i++; continue; }
      const om = line.match(/^(\d+)\.\s+(.*)$/);
      if (om) { if (inUl) { out.push("</ul>"); inUl = false; } if (!inOl) { out.push("<ol>"); inOl = true; } out.push("<li>" + mdInline(om[2]) + "</li>"); i++; continue; }
      if (/^[-*]\s+/.test(line)) { if (inOl) { out.push("</ol>"); inOl = false; } if (!inUl) { out.push("<ul>"); inUl = true; } out.push("<li>" + mdInline(line.replace(/^[-*]\s+/, "")) + "</li>"); i++; continue; }
      closeLists();
      out.push("<p>" + mdInline(line.trim()) + "</p>");
      i++;
    }
    closeLists(); flushTable();
    if (inCode) out.push('<pre class="help-pre"><code>' + code.join("\n").replace(/&/g, "&amp;").replace(/</g, "&lt;") + "</code></pre>");
    return out.join("\n");
  }
  function highlightHtml(htmlStr, q) {
    if (!q) return htmlStr;
    const esc = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    try {
      return htmlStr.replace(/(<[^>]+>)|([^<]+)/g, (m, tag, text) => {
        if (tag) return tag;
        return text.replace(new RegExp("(" + esc + ")", "ig"), '<mark class="help-hit">$1</mark>');
      });
    } catch (e) { return htmlStr; }
  }
  async function loadHelp() {
    if (helpBundle) return helpBundle;
    const r = await fetch("/s/help/bundle.json", { cache: "no-store" });
    if (!r.ok) throw new Error("Couldn't load Help.");
    helpBundle = await r.json();
    return helpBundle;
  }

  function updatesPage() {
    every(2000, async () => {
      const d = await settingsOrStatus();
      const st = d.status || {};
      statusBox(st);
      let u;
      try { u = await api("/api/updates"); } catch (e) {
        render(header("Settings · Updates", st), h("p.notice", e.message || String(e)));
        return;
      }
      // Confirm new build so the post-install rollback timer clears.
      if (u.pending) { try { await api("/api/updates/ack", {}); u.pending = null; } catch (e) {} }
      const prog = u.progress || {};
      const whenChecked = u.last_checked ? when(u.last_checked) : "Never";
      const pub = u.published_at ? u.published_at.replace("T", " ").replace("Z", " UTC") : "—";
      const err = u.error || prog.error || "";
      const busy = !!prog.busy;
      const canInstall = u.newer && !busy && u.latest;
      const checkBtn = h("button", {
        perm: "updates_check",
        disabled: busy,
        onclick: async () => {
          try {
            await api("/api/updates/check", {});
            refresh();
          } catch (e) { showBox(h("h3", "Check Failed"), h("p", e.message || String(e)), h("div.acts", h("button", { onclick: hideBox }, "Close"))); }
        }
      }, "Check Now");
      const installBtn = h("button", {
        perm: "admin",
        disabled: !canInstall,
        onclick: () => updateInstallAsk(u)
      }, "Install Update");
      const rollBtn = h("button.quiet", {
        perm: "admin",
        disabled: !u.previous || busy,
        title: u.previous ? "" : "No earlier version kept",
        onclick: () => rollbackAsk({ previous: u.previous, current: u.current, lost: (d.release && d.release.lost) || [], schema_differs: !!(d.release && d.release.schema_differs) })
      }, "Roll Back To Previous Version");
      const notes = (u.notes || "").trim();
      render(
        header("Settings · Updates", st),
        h("div.body.two",
          h("div.col", { "data-k": "upd-main" },
            panel("Updates", h("span.pill", u.newer ? "Update Available" : "Up To Date"),
              h("div.stat-grid",
                h("div.kv-row", h("span.mute", "Current Version"), h("span", u.current || "—")),
                h("div.kv-row", h("span.mute", "Latest Version"), h("span", u.latest || "—")),
                h("div.kv-row", h("span.mute", "Release Date"), h("span", pub)),
                h("div.kv-row", h("span.mute", "Last Checked"), h("span", whenChecked)),
                u.previous ? h("div.kv-row", h("span.mute", "Previous Version"), h("span", u.previous)) : null),
              err ? h("p.notice", err) : null,
              prog.phase && prog.phase !== "Idle" ? h("p.hint", h("b", prog.phase + (prog.detail ? " — " : "")), prog.detail || "") : null,
              u.pending ? h("p.notice", "This update is waiting to be kept. Stay on this page so FoilGateway knows it came back; otherwise it rolls back within the undo timer.") : null,
              h("div.row.same", { style: "margin-top:12px;gap:8px;flex-wrap:wrap" }, checkBtn, installBtn, rollBtn))),
          h("div.col", { "data-k": "upd-notes" },
            grow(panel("Release Notes", u.latest ? h("span.mute", u.latest) : null,
              notes ? h("pre.help-pre", { style: "white-space:pre-wrap;max-height:none" }, notes)
                : h("p.empty", "Check Now to load the latest release notes."))),
            panel("About Updates", null,
              h("p.hint", "FoilGateway checks GitHub Releases shortly after it starts, every hour after that, and when you tap Check Now. If a check fails it tries again sooner. Installs only when you ask. After Install Update, the previous version is kept for Roll Back To Previous Version. If this page does not come back after a restart, the previous version is restored automatically.")))));
    });
  }
  function updateInstallAsk(u) {
    const err = h("div.err");
    const go = h("button", { onclick: async () => {
      go.disabled = true;
      try {
        await api("/api/updates/install", {});
        // Poll progress until restart
        const line = h("p.hint", "Starting…");
        showBox(h("h3", "Installing Update"), line, h("p.hint", "Do not close this page."));
        const t0 = Date.now();
        for (;;) {
          await new Promise((r) => setTimeout(r, 800));
          let p = {};
          try { p = await api("/api/updates/progress"); } catch (e) { /* restarting */ p = { phase: "Restarting" }; }
          line.textContent = (p.phase || "") + (p.detail ? " — " + p.detail : "") + (p.error ? " — " + p.error : "");
          if (p.phase === "Failed" || p.error) {
            err.textContent = p.error || "Update failed.";
            showBox(h("h3", "Update Failed"), h("p", err.textContent), h("div.acts", h("button", { onclick: hideBox }, "Close")));
            return;
          }
          if (p.phase === "Restarting" || Date.now() - t0 > 5000) {
            restartWait("Updating to " + u.latest);
            return;
          }
        }
      } catch (e) {
        err.textContent = e.message || String(e);
        go.disabled = false;
      }
    } }, "Install Update");
    showBox(h("h3", "Install FoilGateway " + u.latest + "?"),
      h("p", "Updates from " + u.current + " to " + u.latest + ". The gateway restarts."),
      h("ul.warn",
        h("li", "Every device behind the gateway loses the internet for a few seconds."),
        h("li", "Everyone signed in to this page has to sign in again."),
        h("li", "The current version is kept so you can roll back."),
        h("li", "If this page does not come back, FoilGateway restores the previous version within the undo timer.")),
      err,
      h("div.acts", h("button.quiet", { onclick: hideBox }, "Cancel"), go));
  }

  function helpPage() {
    every(0, async () => {
      const d = await settingsOrStatus();
      const st = d.status || {};
      statusBox(st);
      let bundle;
      try { bundle = await loadHelp(); } catch (e) {
        render(header("Settings · Help", st), h("p.notice", e.message || String(e)));
        return;
      }
      const chapters = bundle.chapters || [];
      if (!chapters.some((c) => c.id === helpTab)) helpTab = (chapters[0] && chapters[0].id) || "getting-started";
      const q = (helpQ || "").trim().toLowerCase();
      const matches = !q ? chapters : chapters.filter((c) => (c.title + " " + (c.search || c.markdown || "")).toLowerCase().includes(q));
      const active = matches.find((c) => c.id === helpTab) || matches[0] || null;
      if (active) helpTab = active.id;
      const tabs = h("div.help-tabs", { "data-ref": "", role: "tablist" },
        matches.length ? matches.map((c) => h("button.help-tab" + (c.id === helpTab ? ".on" : ""), {
          type: "button", role: "tab", "aria-selected": String(c.id === helpTab),
          onclick: () => { helpTab = c.id; refresh(); }
        }, c.title)) : h("p.empty", "No matches."));
      const bodyHtml = active ? highlightHtml(mdToHtml(active.markdown), q) : "";
      const article = h("article.help-article", { "data-k": "help-body" });
      article.innerHTML = bodyHtml || '<p class="empty">No matches.</p>';
      const tools = h("div.help-tools",
        searchBox("help-q", helpQ, (v) => { helpQ = v; refresh(); }, "Search Help"),
        h("a.btn.quiet", { href: "/s/manual.html", download: "foilgateway-manual.html" }, "Download Manual"));
      render(
        header("Settings · Help", st), updateNote(st),
        h("p.hint", "Copyright (C) 2026 iBGeek · Manual matches this build."),
        h("div.body.one", grow(panel("Help", tools, h("div.help-layout", tabs, h("div.help-scroll.fillin", { "data-k": "help-scroll" }, article))))));
    });
  }
  function aboutPage() {
    every(0, async () => {
      const d = await settingsOrStatus();
      const s = d.status || {};
      statusBox(s);
      let license = "";
      try {
        const r = await fetch("/s/LICENSE", { cache: "no-store" });
        if (r.ok) license = await r.text();
      } catch (e) {}
      const kv = (label, val) => h("div.kv-row", h("span.mute", label), h("span", val || h("span.mute", "—")));
      render(
        header("Settings · About", s), updateNote(s),
        h("div.body.two",
          h("div.col", { "data-k": "about-l" },
            panel("FoilGateway Network", h("div.row",
              h("a.btn.quiet", { href: "/s/manual.html", download: "foilgateway-manual.html" }, "Download Manual"),
              h("a.btn.quiet", { href: "https://github.com/iBgeek/FoilGateway-Network", target: "_blank", rel: "noopener" }, "Star on GitHub")),
              h("div.stat-grid",
                kv("Product", "FoilGateway Network"),
                kv("Version", s.version || d.release && d.release.current || ""),
                kv("OS", s.os || ""),
                kv("Architecture", s.arch || ""),
                kv("Board", s.board || ""),
                kv("Host", s.host || "")),
              h("p.hint", dualUp(s)),
              h("p.hint", "Copyright (C) 2026 iBGeek. For commercial licensing, contact iBGeek."),
              h("p.hint", h("a", { href: "https://github.com/iBgeek/FoilGateway-Network/discussions/1", target: "_blank", rel: "noopener" }, "Support")))),
          h("div.col", { "data-k": "about-r" },
            grow(panel("Software License", null,
              h("pre.help-pre.license", { "data-k": "license" }, license || "License text unavailable."))))));
    });
  }

  function speedTestPanel() {
    let state = null, polling = false, next = null, actionError = "";
    const action = h("button", { id: "speed-test-action", onclick: async () => {
      action.disabled = true;
      actionError = "";
      try { await api("/api/speed-test", { action: state && state.running ? "cancel" : "run" }); }
      catch (e) { actionError = e.message; message.textContent = actionError; }
      finally { action.disabled = false; clearTimeout(next); await poll(); }
    } }, "Run speed test");
    action.hidden = !can("speed_run");
    const values = h("div.row", { style: "justify-content:space-between;gap:16px;margin:12px 0" });
    const message = h("p.hint", { style: "margin-bottom:0", "aria-live": "polite" }, "Loading test status…");
    const progress = h("progress", { max: 100, value: 0, hidden: true, style: "width:100%;accent-color:var(--blue)" });
    const root = panel("Internet speed test", action,
      h("p.hint", "Tests gateway internet, not client Wi-Fi; uses up to 80 MiB and may slow other traffic."), values, progress, message);
    root.id = "internet-speed-test";
    root.setAttribute("data-ref", "");
    const metric = (name, number, unit) => h("div", h("span.mute", name), h("div", { style: "font-size:var(--fs-value);font-weight:var(--fw-bold);color:var(--strong)" }, number, h("span", { style: "font-size:var(--fs-body)" }, " " + unit)));
    async function poll() {
      if (!root.isConnected || polling) return;
      polling = true;
      try {
        const v = await api("/api/speed-test");
        if (!root.isConnected) return;
        state = v;
        action.textContent = v.running ? "Cancel" : "Run speed test";
        action.className = v.running ? "quiet" : "";
        action.disabled = v.state === "cancelling";
        progress.hidden = !v.running;
        progress.value = v.progress;
        const r = v.running ? null : v.last;
        values.replaceChildren(metric("Download", r ? r.download_mbps.toFixed(1) : "—", "Mbps"), metric("Upload", r ? r.upload_mbps.toFixed(1) : "—", "Mbps"), metric("HTTP response latency", r ? r.latency_ms.toFixed(0) : "—", "ms"));
        let text = v.running ? (v.state === "cancelling" ? "Cancelling…" : v.phase + " · " + v.progress + "% · " + v.elapsed_secs + " s")
          : v.state === "failed" ? "Test failed: " + v.error
          : v.state === "cancelled" ? "Test cancelled. No partial result saved."
          : v.last ? "Last run: " + when(v.last.at) : "Not run yet.";
        if (v.last && (v.state === "failed" || v.state === "cancelled")) text += " Last completed result: " + when(v.last.at) + ".";
        message.textContent = actionError || text;
      } catch (e) { if (root.isConnected) message.textContent = "Cannot read speed-test status: " + e.message; }
      finally { polling = false; if (root.isConnected) next = setTimeout(poll, state && state.running ? 500 : 5000); }
    }
    next = setTimeout(poll, 0);
    return root;
  }

  // ---------- Users ----------
  const yesMark = () => h("span.ok", "✓");
  const noMark = () => h("span.mute", "-");
  const dayOf = (t) => t ? fmtDate(local(t)) : "";
  function copyText(input, btn) {
    const done = () => { btn.textContent = "Copied"; };
    input.select();
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(input.value).then(done, () => { document.execCommand("copy"); done(); });
    else { document.execCommand("copy"); done(); }
  }
  // Shown once when a key or signing secret is made; it can't be read back.
  function copyNowBox(title, text, value) {
    // The whole value stays in view: it wraps instead of scrolling sideways.
    const input = h("textarea.copyval", { readonly: true, rows: 1, spellcheck: false }, value);
    const copy = h("button", { onclick: () => copyText(input, copy) }, "Copy");
    showBox(h("h3", title), h("p", text), h("div.row", input, copy), h("div.acts", h("button", { onclick: () => { hideBox(); refresh(); } }, "Done")));
    const fit = () => { input.style.height = "auto"; input.style.height = input.scrollHeight + 2 + "px"; };
    fit();
    new ResizeObserver(fit).observe(overlay.firstChild);
    input.focus(); input.select();
  }
  function keyBox(key) {
    copyNowBox("Copy the Key Now", "This is the only time the whole key is shown. Paste it where the API will be used, such as Jarvis.", key);
  }
  function usersPage() {
    const err = h("p.err");
    every(5000, async () => {
      const [st, d] = await Promise.all([api("/api/status"), api("/api/users")]);
      statusBox(st);
      const pw = h("input", { id: "my-pw", type: "password", placeholder: "New password", autocomplete: "new-password", style: "flex:1 1 auto" });
      const users = d.users.map((u) => h("tr", { "data-key": u.name },
        h("td", u.name, u.name === d.me ? [" ", h("span.mute", "(you)")] : null),
        h("td", h("span.pill." + (u.role === "admin" ? "trusted" : "normal"), u.role === "admin" ? "Admin" : "Custom")),
        h("td", u.web ? yesMark() : noMark()), h("td", u.api ? yesMark() : noMark()),
        h("td.num", h("button.small.quiet", { onclick: () => userEdit(d, u) }, "Edit"),
          u.name === d.me ? null : [" ", h("button.small.danger", { onclick: () => ask("Remove " + u.name + "?", "Their sign-ins end and their API key stops working at once.", "Remove", () => userPost({ action: "remove", name: u.name })) }, "Remove")])));
      const sessions = d.sessions.map((x) => h("tr", { "data-key": x.id },
        h("td", x.user), h("td", x.ip), h("td", when(x.started)),
        h("td.num", h("button.small.quiet", { onclick: () => userPost({ action: "end_session", id: x.id }) }, "Sign out"))));
      const keys = d.users.filter((u) => u.has_key).map((u) => h("tr", { "data-key": u.name },
        h("td", u.name), h("td", u.key_hint), h("td", u.key_used ? when(u.key_used) : "never"), h("td", u.key_from || h("span.mute", "-")),
        h("td.num", h("button.small.danger", { onclick: () => ask("Revoke the key for " + u.name + "?", "Anything using this key stops working at once.", "Revoke", () => userPost({ action: "revoke_key", name: u.name })) }, "Revoke"))));
      render(
        header("Settings · Users", st), pendingNote(st), err.textContent ? err : null,
        h("div.body.two",
          h("div.col", { "data-k": "users-l" },
            panel("Users", h("button", { onclick: () => userEdit(d, null) }, "Add User"),
              table(["Name", "Type", "Web", "API", "#"], users, "No users."),
              h("p.hint", "Admins can do everything. Custom users can only do what you tick for them. Each user can sign in on this page, use the API with a key, or both.")),
            grow(panel("Your Password", null,
              h("label", { for: "my-pw" }, "New password (10 or more characters)"),
              h("div.row", pw, h("button", { onclick: async () => { if (await userPost({ action: "password", password: pw.value })) { pw.value = ""; showBox(h("h3", "Password Changed"), h("p", "Use the new password next time you sign in."), h("div.acts", h("button", { onclick: hideBox }, "OK"))); } } }, "Change"))))),
          h("div.col", { "data-k": "users-r" },
            panel("Signed In", null, table(["User", "From", "Since", "#"], sessions, "Nobody is signed in.")),
            grow(panel("API Keys", null,
              table(["User", "Key", "Last used", "From", "#"], keys, "No API keys yet. Edit a user and turn on Use the API with a key."),
              h("p.hint", "A key works until it's revoked or its user is removed. The whole key is shown once, when it's made. Send it in the Authorization header as ", h("b", "Bearer fgk_…")),
              h("div.row", { style: "margin-top:8px" }, h("a.btn.quiet", { href: "/settings/api" }, "Open the API Reference")))))));
      async function userPost(body) {
        err.textContent = "";
        try { await api("/api/users", body); refresh(); return true; }
        catch (e) { err.textContent = e.message; return false; }
      }
    });
  }
  // Add (u = null) or edit one user. Nothing changes until Save.
  function userEdit(d, u) {
    const isNew = !u;
    u = u || { name: "", role: "custom", perms: [], web: false, api: true, has_password: false, has_key: false };
    let role = u.role;
    const err = h("p.err");
    const name = h("input", { id: "ue-name", value: u.name, autocomplete: "off" });
    const web = h("input", { type: "checkbox", checked: u.web });
    const apiOn = h("input", { type: "checkbox", checked: u.api });
    const pw = h("input", { id: "ue-pw", type: "password", autocomplete: "new-password", placeholder: u.has_password ? "Leave empty to keep the current one" : "10 or more characters", disabled: !u.web });
    web.addEventListener("change", () => { pw.disabled = !web.checked; });
    const segBtn = (k, t) => h("button" + (role === k ? ".on.isOn" : ""), { type: "button", "data-role": k, onclick: (e) => {
      role = k;
      seg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b === e.currentTarget));
      seg.querySelectorAll("button").forEach((b) => b.classList.toggle("isOn", b === e.currentTarget));
      lockViews();
    } }, t);
    const seg = h("div.seg", segBtn("admin", "Admin"), segBtn("custom", "Custom"));
    const chk = (p) => h("label.check", h("input", { type: "checkbox", value: p.id, checked: u.perms.includes(p.id), disabled: role === "admin" }), " " + p.label);
    const group = (g) => [h("h4", g), d.perms.filter((p) => p.group === g).map(chk)];
    const permBox = h("div", group("Monitoring"), group("Actions"));
    // An action needs its view (d.implies: [action, view]): a ticked action
    // ticks its view and holds it on until the action is unticked.
    const lockViews = () => {
      const box = (id) => permBox.querySelector('input[value="' + id + '"]');
      permBox.querySelectorAll("input").forEach((i) => { i.disabled = role === "admin"; i.parentNode.title = ""; });
      if (role === "admin") return;
      (d.implies || []).forEach(([a, v]) => {
        const ai = box(a), vi = box(v);
        if (ai && vi && ai.checked) { vi.checked = true; vi.disabled = true; vi.parentNode.title = "Needed by another ticked permission"; }
      });
    };
    permBox.addEventListener("change", lockViews);
    lockViews();
    const keyLine = isNew ? h("div.row", h("span.mute", "A key is made when you save."))
      : h("div.row", h("span.mute", u.has_key ? u.key_hint + ", made " + dayOf(u.key_made) : "No key yet"));
    const keyBtns = isNew ? null : h("div.row", { style: "margin-top:6px" },
      h("button.small.quiet", { type: "button", onclick: async () => {
        err.textContent = "";
        try { const r = await api("/api/users", { action: "new_key", name: u.name }); keyBox(r.key); } catch (e) { err.textContent = e.message; }
      } }, "New Key"),
      u.has_key ? h("button.small.danger", { type: "button", onclick: async () => {
        err.textContent = "";
        try { await api("/api/users", { action: "revoke_key", name: u.name }); hideBox(); refresh(); } catch (e) { err.textContent = e.message; }
      } }, "Revoke") : null);
    const save = h("button", { onclick: async () => {
      err.textContent = "";
      const perms = [...permBox.querySelectorAll("input:checked")].map((i) => i.value);
      const body = { action: "save", old_name: isNew ? "" : u.name, name: name.value.trim(), role, perms: role === "admin" ? [] : perms, web: web.checked, api: apiOn.checked, password: web.checked ? pw.value : "" };
      try {
        await api("/api/users", body);
        // A new user with the API switched on gets a key straight away.
        if (isNew && apiOn.checked) { const r = await api("/api/users", { action: "new_key", name: body.name }); keyBox(r.key); return; }
        hideBox(); refresh();
      } catch (e) { err.textContent = e.message; }
    } }, "Save");
    showBox(h("h3", isNew ? "Add User" : "Edit User: " + u.name),
      h("div.grid2",
        h("div",
          h("h4", "Who"), h("label", { for: "ue-name" }, "Name"), name,
          h("label", "Type"), seg,
          h("h4", "How This User Gets In"),
          h("label.check", web, " Sign in on this page"), h("label.check", apiOn, " Use the API with a key"),
          h("label", { for: "ue-pw" }, "Password (for signing in on this page)"), pw,
          h("label", "API key"), keyLine, keyBtns),
        permBox),
      h("p.hint", "Firewall mode, ports, settings, updates, backup, certificates and users stay with admins."),
      err,
      h("div.acts", h("button.quiet", { onclick: hideBox }, "Cancel"), save));
    overlay.firstChild.classList.add("wide");
  }

  // ---------- Notifications ----------
  const EVENT_TEXT = {
    new_device: ["New device on the network", "A device that hasn't been seen before."],
    look: ["Needs a look", "Alerts the gateway thinks you should check: threats, scans, bursts."],
    blocked: ["Blocked connections", "Every stopped connection. This can be many per minute."],
    audit: ["Audit (would have been blocked)", ""],
    settings: ["Settings changed", "Who changed what, and whether it was kept."],
    update: ["Update available", ""],
    started: ["Gateway started", "After a restart or power loss."],
  };
  const shortWhen = (t) => {
    if (!t) return "never";
    const today = local(Math.floor(Date.now() / 1000)).toISOString().slice(0, 10);
    return local(t).toISOString().slice(0, 10) === today ? fmtTime(local(t)) : when(t);
  };
  const hostOf = (u) => { try { return new URL(u).host; } catch (e) { return u; } };
  function sendResult(r) {
    if (r.result === "delivered") return r.tries > 1 ? h("td.warn", "Retried, delivered " + shortWhen(r.done_at)) : h("td.ok", "Delivered");
    if (r.result === "retrying") return h("td.warn", "Retrying", r.error ? ": " + r.error : "");
    if (r.result === "failed") return h("td.bad", "Not delivered", r.error ? ": " + r.error : "");
    return h("td.bad", "Dropped", r.error ? ": " + r.error : "");
  }
  function notifyPage() {
    const err = h("p.err");
    let sel = null, draft = null;
    every(5000, async () => {
      const [st, d] = await Promise.all([api("/api/status"), api("/api/notify")]);
      statusBox(st);
      if (sel !== "new" && !d.dests.some((x) => x.id === sel)) { sel = d.dests.length ? d.dests[0].id : "new"; draft = null; }
      const saved = d.dests.find((x) => x.id === sel) || { id: "", name: "", url: "", events: ["new_device", "look", "settings", "update", "started"], secret_made: 0 };
      if (!draft) draft = { name: saved.name, url: saved.url, pin: saved.pin || "", events: saved.events.slice() };
      const pick = (id) => { sel = id; draft = null; err.textContent = ""; refresh(); };
      const post = async (body) => {
        err.textContent = "";
        try { const r = await api("/api/notify", body); return r; } catch (e) { err.textContent = e.message; refresh(); return null; }
      };
      const secretBox = (sec) => copyNowBox("Copy the Signing Secret Now", "This is the only time the secret is shown. Paste it into the receiver, such as Jarvis, so it can check each message.", sec);
      const dests = d.dests.map((x) => h("tr" + (x.id === sel ? ".on" : ""), { "data-key": x.id },
        h("td", x.name), h("td.nowrap", hostOf(x.url)),
        h("td.nowrap" + (x.last_result === "delivered" ? ".ok" : x.last_result === "retrying" ? ".warn" : x.last_result ? ".bad" : ""),
          x.last_sent ? shortWhen(x.last_sent) + ", " + (x.last_result === "failed" ? "not delivered" : x.last_result) : "never"),
        h("td.num", h("button.small.quiet", { onclick: () => pick(x.id) }, "Edit"), " ",
          h("button.small.quiet", { onclick: async () => { if (await post({ action: "test", id: x.id })) refresh(); } }, "Send Test"))));
      const recent = d.recent.map((r) => h("tr", { "data-key": "r" + r.seq },
        h("td.nowrap", shortWhen(r.at)), h("td.nowrap", r.to), h("td", r.what), sendResult(r)));
      const name = h("input", { id: "nd-name", value: draft.name, style: "width:100%", oninput: (e) => { draft.name = e.target.value; } });
      const url = h("input", { id: "nd-url", value: draft.url, placeholder: "http://192.168.1.40:8797/foilgateway", style: "width:100%", oninput: (e) => { draft.url = e.target.value; } });
      const pin = h("input", { id: "nd-pin", value: draft.pin, placeholder: "Optional", spellcheck: "false", style: "width:100%", oninput: (e) => { draft.pin = e.target.value; } });
      const evs = d.events.map((ev) => {
        const [label, hint] = EVENT_TEXT[ev.id] || [ev.title, ""];
        const box = h("input", { type: "checkbox", checked: draft.events.includes(ev.id), onchange: (e) => {
          draft.events = draft.events.filter((x) => x !== ev.id);
          if (e.target.checked) draft.events.push(ev.id);
        } });
        return [h("label.check", box, " " + label), hint ? h("div.hint", { style: "margin:-4px 0 4px 26px" }, hint) : null];
      });
      const isNew = sel === "new";
      const save = async () => {
        const r = await post({ action: "save", id: saved.id, name: draft.name, url: draft.url, pin: draft.pin, events: draft.events });
        if (!r) return;
        if (isNew) { sel = (r.dests.find((x) => x.name.toLowerCase() === draft.name.trim().toLowerCase()) || {}).id || null; draft = null; secretBox(r.secret); }
        else { draft = null; refresh(); }
      };
      render(
        header("Settings · Notifications", st), pendingNote(st), err.textContent ? err : null,
        h("div.body.two",
          h("div.col", { "data-k": "notify-l" },
            panel("Where Notifications Go", h("button", { onclick: () => pick("new") }, "Add Destination"),
              table(["Name", "Address", "Last sent", "#"], dests, "No destinations yet."),
              h("p.hint", "When something happens, the gateway sends it to each address straight away as a short JSON message. New devices, needs-a-look and blocked messages go once per device every 5 minutes; the rest of those 5 minutes arrive as one message with a count. Sign-ins aren't sent. If an address can't be reached, the gateway tries again for 10 minutes. Email comes in a later version.")),
            grow(panel("Recent Sends", null, table(["When", "To", "What", "Result"], recent, "Nothing sent yet.")))),
          h("div.col", { "data-k": "notify-r" },
            grow(panel(isNew ? "New Destination" : "Destination: " + saved.name, null,
              h("label", { for: "nd-name" }, "Name"), name,
              h("label", { for: "nd-url" }, "Address"), url,
              h("label", { for: "nd-pin" }, "Certificate fingerprint"), pin,
              h("p.hint", "Only for an https:// address whose receiver uses its own certificate, such as Jarvis. Paste the SHA-256 fingerprint the receiver shows, with or without colons. The gateway then sends only to that certificate. Leave empty to use the usual public certificates."),
              h("label", "Signing secret"),
              h("div.row", isNew ? h("span.mute", "Made when you save") : [h("span.mute", "Set " + dayOf(saved.secret_made)),
                h("button.small.quiet", { onclick: () => ask("Make a New Secret?", "The old secret stops working at once. Messages are rejected until the receiver has the new one.", "Make New Secret", async () => { const r = await post({ action: "new_secret", id: saved.id }); if (r) secretBox(r.secret); }) }, "New Secret")]),
              h("p.hint", "Each message is signed with this secret so the receiver can tell it came from this gateway."),
              h("label", "Send these"), evs,
              h("div.row", { style: "margin-top:14px;justify-content:flex-end" },
                isNew ? null : h("button.danger", { onclick: () => ask("Remove " + saved.name + "?", "Nothing more is sent to this address.", "Remove", async () => { if (await post({ action: "remove", id: saved.id })) { sel = null; draft = null; refresh(); } }) }, "Remove"),
                h("button.quiet", { onclick: () => { if (isNew) sel = null; draft = null; err.textContent = ""; refresh(); } }, "Cancel"),
                h("button", { onclick: save }, "Save")))))));
    });
  }
  // ---------- API Reference ----------
  function apiRefPage() {
    every(0, async () => {
      const [st, d] = await Promise.all([api("/api/status"), api("/api/reference")]);
      statusBox(st);
      const label = {};
      d.perms.forEach((p) => { label[p.id] = p.label; });
      const needs = (n) => n === "any" ? h("span.mute", "Anyone signed in") : h("code", n);
      render(
        header("Settings · API Reference", st),
        h("div.body.two",
          h("div.col", { "data-k": "ref-l" },
            grow(panel("Calls", null,
              table(["Method", "Path", "Needs", "What it does"], d.routes.map((r) => h("tr", h("td", r.method), h("td.nowrap", h("code", r.path)), h("td.nowrap", needs(r.needs)), h("td", r.what))), "No calls."),
              h("p.hint", "Admins can make every call, including ones not listed here. Anything not listed is for admins only. A call the key's user isn't allowed to make gets 403.")))),
          h("div.col", { "data-k": "ref-r" },
            panel("Using a Key", null,
              h("p", "Send the key in the Authorization header as ", h("b", "Bearer fgk_…"), ". Make a key in Settings, Users. The user must have Use the API with a key turned on."),
              h("p.hint", "Wrong keys count toward the same lockout as wrong passwords. Answers are JSON. Calls that change something take a JSON body.")),
            panel("Permissions", null,
              table(["Name", "Group", "Lets the user"], d.perms.map((p) => h("tr", h("td.nowrap", h("code", p.id)), h("td", p.group), h("td", p.label))), "")),
            grow(panel("Notifications", null,
              h("p", "Each message is a POST with a JSON body: gateway, version, event, title, text, device and at (Unix time)."),
              h("p", "Headers: ", h("code", "X-FoilGateway-Event"), ", ", h("code", "X-FoilGateway-Timestamp"), " and ", h("code", "X-FoilGateway-Signature"), "."),
              h("p.hint", "The signature is sha256= followed by the HMAC-SHA256, in hex, of the timestamp, a dot, and the raw body, keyed with the destination's signing secret. An https:// destination with a certificate fingerprint is sent only to the certificate whose SHA-256 matches it. Events: " + Object.keys(EVENT_TEXT).join(", ") + ", and test from Send Test. For new_device, look and blocked, the first message for a device goes at once; later ones within 5 minutes come as one message whose text starts with the count."))))));
    });
  }
  // ---------- Settings for custom users: the speed test only ----------
  function speedOnlyPage() {
    every(0, async () => {
      const st = await api("/api/status");
      statusBox(st);
      render(header("Settings · Speed Test", st), h("div.body.two", h("div.col", { "data-k": "speed-l" }, speedTestPanel()), h("div.col", { "data-k": "speed-r" })));
    });
  }

  function settings() {
    shell("Settings");
    if (PATH === "/settings/help") return helpPage();
    if (PATH === "/settings/about") return aboutPage();
    if (PATH === "/settings/updates") return updatesPage();
    if (PATH === "/settings/users" || PATH === "/settings/account") return usersPage();
    if (PATH === "/settings/notify") return notifyPage();
    if (PATH === "/settings/api") return apiRefPage();
    if (!ME.admin) return speedOnlyPage();
    if (new URLSearchParams(location.search).has("confirm")) api("/api/confirm", {}).catch(() => {});
    let picked = null, unlocked = false, addr = null;
    every(0, async () => {
      const d = await api("/api/settings");
      const cd = PATH === "/settings/certs" ? await api("/api/certs") : null;
      bridgeIps = d.bridge_ips || [];
      statusBox(d.status);
      const c = d.cfg || {};
      picked = picked || { lan: (c.lan || []).slice(), wan: c.wan };
      addr = addr || Object.assign({ mode: c.ip_mode || "dhcp" }, c.fixed || { ip: "", mask: "255.255.255.0", gateway: "", dns: "" });
      const errBox = h("div.err", { "data-ref": "" });
      const run = (body) => change("/api/settings", body).catch((e) => { errBox.textContent = e.message; });
      const hosts = h("input", { value: (c.safety_hosts || []).join(", "), style: "min-width:0;flex:1 1 220px" });
      const safeOn = h("input", { type: "checkbox", checked: c.safety });
      const sure = h("input", { type: "checkbox" });
      const port = h("input", { type: "number", min: 1, max: 65535, value: c.admin_port, style: "width:110px" });
      const tz = h("select", d.timezones.map((z) => h("option", { value: z, selected: z === d.timezone }, z)));
      const file = h("input", { type: "file", accept: ".json,application/json" });
      const savePorts = () => {
        const moved = picked.wan !== c.wan;
        const go = () => run({ action: "ports", lan: picked.lan, wan: picked.wan, wan_unlocked: moved });
        if (moved) ask("Move WAN to " + picked.wan + "?", "The gateway’s link to your router moves from " + c.wan + " to " + picked.wan + ". " + undoHint(c.rollback_secs) + " Moving this can cut every device off.", "Move WAN", go);
        else go();
      };
      const wanLock = unlocked
        ? h("button.quiet", { onclick: () => { unlocked = false; picked.wan = c.wan; refresh(); } }, "Lock WAN Again")
        : h("button.quiet", { onclick: () => ask("Unlock the Port to Your Router (WAN)?", "Moving this can cut every device off. " + undoHint(c.rollback_secs), "Unlock", () => { unlocked = true; refresh(); }) }, "Unlock WAN");
      const fld = (k, label, ph) => h("div", h("label", label), h("input", { id: "addr-" + k, value: addr[k], placeholder: ph, disabled: addr.mode !== "fixed", oninput: (e) => { addr[k] = e.target.value; } }));
      const saveAddr = async () => {
        errBox.textContent = "";
        const body = { action: "address", ip_mode: addr.mode, ip: addr.ip, mask: addr.mask, gateway: addr.gateway, dns: addr.dns };
        let res;
        try { res = await api("/api/settings", body); } catch (e) { errBox.textContent = e.message; return; }
        // A new address can only be confirmed from the new address.
        const viaOld = (d.bridge_ips || []).some((x) => x.split("/")[0] === location.hostname);
        if (res.pending && addr.mode === "fixed" && viaOld && location.hostname !== addr.ip) {
          const base = location.protocol + "//" + addr.ip + (location.port ? ":" + location.port : "");
          showBox(h("h3", "Open the new address"), h("p", "The gateway now uses " + addr.ip + ". Open it within " + res.secs + " seconds and sign in to keep the change. " + undoHint(res.secs)), h("div.acts", h("a.btn", { href: base + "/settings?confirm=1" }, "Open " + base)));
          return;
        }
        await confirmChange(res);
        refresh();
      };
      const keep = h("input", { type: "number", min: 1, max: 3650, value: d.log_days, style: "width:90px" });
      let lfv = "", ltv = "";
      const lf = datePicker("dl-from", "", (v) => { lfv = v; }), lt = datePicker("dl-to", "", (v) => { ltv = v; });
      const rerun = () => {
        const yes = h("input", { placeholder: "YES", autocomplete: "off" });
        const go = h("button.danger", { disabled: true, onclick: () => { hideBox(); run({ action: "rerun_setup", confirm: yes.value }); } }, "Run Setup");
        yes.addEventListener("input", () => { go.disabled = yes.value.trim() !== "YES"; });
        showBox(h("h3", "Run Setup Again?"),
          h("p", "Devices keep working until the last step, and that step undoes itself within the rollback timer (usually 3 minutes) if this browser loses the gateway. Admins stay as they are."),
          h("label", "Type YES to go on"), yes, helpLink(),
          h("div.acts", h("button.quiet", { onclick: hideBox }, "Cancel"), go));
        yes.focus();
      };
      // Panels by topic: [left column, right column] for each sub-menu.
      const P = {
        speed: () => speedTestPanel(),
        ports: () => panel("Ports", wanLock, h("p.hint", gloss("WAN"), " is the cable to your router; ", gloss("LAN"), " goes to your switch or devices. You can have more than one LAN port. The WAN port is locked until you unlock it. ", gloss("SSH"), " answers from both sides" + (c.admin_from === "lan" ? "; this page only from the LAN." : ", and so does this page.")),
              portPicker(d.ports, picked.lan, picked.wan, (n, r) => { pickRole(picked, n, r); refresh(); }, null, !unlocked),
              h("div.row", { style: "margin-top:10px" }, h("button", { onclick: savePorts }, "Save Ports"))),
        address: () => panel("Gateway address", null, h("p.hint", "The gateway's own address on your network. Now: " + ((d.bridge_ips || []).join(", ") || "none") + ". A fixed address goes in with the same countdown as other changes and comes back if this page can't reach it."),
              h("label.check", h("input", { type: "radio", name: "ipm", checked: addr.mode === "dhcp", onchange: () => { addr.mode = "dhcp"; refresh(); } }), "From the router (DHCP)"),
              h("label.check", h("input", { type: "radio", name: "ipm", checked: addr.mode === "fixed", onchange: () => { addr.mode = "fixed"; refresh(); } }), "Fixed address"),
              h("div.fixed", fld("ip", "Address", "10.10.10.5"), fld("mask", "Mask", "255.255.255.0"), fld("gateway", "Gateway", "10.10.10.1"), fld("dns", "DNS servers", "10.10.10.1, 9.9.9.9")),
              h("div.row", { style: "margin-top:10px" }, h("button", { onclick: saveAddr }, "Save address"))),
        safety: () => panel("Management safety", null, h("p.hint", "Add at least the computer you’re using now. It can always open this page and SSH, whatever else you change later  -  but it does not get a free pass to the internet. Ports: " + (c.safety_ports || []).join(", ") + "."),
              h("label.check", safeOn, "Safety on"), h("label", "Always-allowed computers (IPv4, comma separated)"), h("div.row", hosts),
              h("label.check", sure, "I understand turning safety off can lock everyone out"),
              h("div.row", { style: "margin-top:8px" }, h("button", { onclick: () => run({ action: "safety", safety: safeOn.checked, safety_hosts: hosts.value, confirm_off: sure.checked }) }, "Save safety"))),
        who: () => panel("Who Can Open This Page", null, h("p.hint", "Anyone on the home network or the router side is the default. Only devices behind the gateway is safer: a stranger on your home network (router side) can't even see the sign-in page. SSH still answers both sides, and the safety computers always get in."),
              h("label.check", h("input", { type: "radio", name: "af", checked: c.admin_from !== "lan", onchange: () => run({ action: "admin_from", admin_from: "both" }) }), "Anyone on the Home Network or the Router Side"),
              h("label.check", h("input", { type: "radio", name: "af", checked: c.admin_from === "lan", onchange: () => run({ action: "admin_from", admin_from: "lan" }) }), "Only Devices Behind the Gateway (Safer)")),
        adminport: () => panel("Settings port", null, h("p.hint", "The HTTPS port for this page. It’s kept open for the safety computers. After a change, open the new address within the countdown  -  " + undoHint(c.rollback_secs)), h("div.row", port, h("button", { onclick: () => run({ action: "admin_port", admin_port: Number(port.value) }) }, "Change Port"))),
        geo: () => h("div", { id: "geo" }, geoPanel(d.geo)),
        tz: () => panel("Time and Formats", null,
              h("p.hint", "Used for times on these pages and for when “today” starts."),
              h("label", "Time Zone"), h("div.row", tz, h("button", { onclick: () => run({ action: "timezone", timezone: tz.value }) }, "Save")),
              h("label", "Clock"), h("div.seg",
                h("button" + (d.hour12 !== false ? ".on" : ""), { onclick: () => run({ action: "time_prefs", hour12: true }) }, "12-Hour"),
                h("button" + (d.hour12 === false ? ".on" : ""), { onclick: () => run({ action: "time_prefs", hour12: false }) }, "24-Hour")),
              h("label", "Date Format"), h("div.seg",
                [["ymd", "2026-11-04"], ["mdy", "11/04/2026"], ["dmy", "04/11/2026"]].map(([k, lab]) =>
                  h("button" + ((d.date_fmt || "ymd") === k ? ".on" : ""), { onclick: () => run({ action: "time_prefs", date_fmt: k }) }, lab))),
              h("p.hint", dualUp(d.status))),
        log: () => panel("Capture Log", h("a.btn.quiet", { href: "/log" }, "View"),
              h("p.hint", d.log_count + " lines kept" + (d.log_oldest ? ", the oldest from " + when(d.log_oldest) : "") + "."),
              h("label", "Keep lines for (days)"), h("div.row", keep, h("button", { onclick: () => run({ action: "log_days", days: Number(keep.value) }) }, "Save")),
              h("label", "Download"), h("div.row", h("a.btn.quiet", { href: "/api/log.txt" }, "Everything"), "or from", lf, "to", lt,
                h("button.quiet", { onclick: () => { location.href = "/api/log.txt?" + new URLSearchParams({ from: lfv, to: ltv }); } }, "Download range"))),
        backup: () => panel("Backup and Restore", null, h("p.hint", "Ports, safety, firewall settings, lists and devices in one file. Admins and passwords aren’t in it."),
              h("div.row", h("a.btn.quiet", { href: "/api/backup" }, "Download Backup"), file, h("button", { onclick: async () => {
                const f = file.files[0]; if (!f) return;
                let j; try { j = JSON.parse(await f.text()); } catch (e) { errBox.textContent = "That file isn’t a backup."; return; }
                const stamp = f.name || "the chosen file";
                const go = h("button.danger", { onclick: () => { hideBox(); change("/api/restore", j).catch((e) => { errBox.textContent = e.message; }); } }, "Restore");
                showBox(
                  h("h3", "Replace Your Settings?"),
                  h("p", "Settings go back to ", h("b", stamp), ". Anything changed since then is lost."),
                  h("ul.warn",
                    h("li", "Ports, safety, firewall, lists and device policies are replaced."),
                    h("li", "Admin accounts and passwords stay as they are.")),
                  h("p.hint", "Download today’s settings first if you want a copy before they are replaced."),
                  helpLink(),
                  h("div.acts",
                    h("button.quiet", { onclick: hideBox }, "Cancel"),
                    h("a.btn.quiet", { href: "/api/backup" }, "Download Current First"),
                    go));
              } }, "Restore"))),
        certs: () => {
          const day = (t) => t ? new Date(t * 1000).toLocaleDateString() : "no end date";
          const info = (title, c, rows) => c ? h("div.sect", h("h4", title),
            h("div.kv", h("span.mute", "Runs out"), h("span", day(c.not_after)),
              h("span.mute", "SHA-256"), h("code.fp", c.sha256),
              c.names && c.names.length ? [h("span.mute", "Names"), h("span", c.names.join(", "))] : null, rows)) : h("p.empty", title + ": none yet.");
          const renew = () => ask("Make a new certificate?", "The gateway issues a new certificate for this page from its own certificate authority, for " + cd.names.join(", ") + ". Computers that installed the gateway's certificate trust it straight away; others show a browser warning until they install it.", "Make a new certificate", async () => {
            try { await api("/api/certs", { action: "new" }); } catch (e) { errBox.textContent = e.message; return; }
            showBox(h("h3", "New certificate in use"), h("p", "New connections to this page use it now. Reload the page if your browser asks."), h("div.acts", h("button", { onclick: () => { hideBox(); refresh(); } }, "OK")));
          });
          return [
            panel("This gateway's certificate authority", null,
              h("p.hint", "The gateway makes its own certificates. Its private key stays on the gateway and is never downloaded. Install the certificate below on a computer once, and that computer trusts this page without a warning, at any of the gateway's addresses."),
              info("Certificate authority", cd.ca, cd.ca_thumbprint ? [h("span.mute", "Windows thumbprint"), h("code.fp", cd.ca_thumbprint)] : null),
              h("div.row", { style: "margin-top:10px" },
                // No download attribute: on a page whose certificate the browser doesn't trust yet,
                // Edge/Chrome cancel <a download> ("Couldn't download - Network issue"); the
                // server's Content-Disposition: attachment saves the file instead.
                h("a.btn", { href: "/api/certs/foilgateway-ca.crt" }, "Download certificate (.crt)"),
                h("a.btn.quiet", { href: "/api/certs/foilgateway-ca.cer" }, "Download certificate (.cer)")),
              h("p", "Do this once per computer to stop the browser’s security warning."),
              h("div.sect.howto", h("h4", "Install It on Windows"),
                h("ol.howto-steps",
                  h("li", "Open the downloaded ", h("b", "foilgateway-ca.crt"), "."),
                  h("li", "Choose ", h("b", "Install Certificate…"), "."),
                  h("li", "Store Location: ", h("b", "Current User"), ", then ", h("b", "Next"), "."),
                  h("li", "Choose ", h("b", "Place all certificates in the following store"), ", then ", h("b", "Browse…"), "."),
                  h("li", "Pick ", h("b", "Trusted Root Certification Authorities"), ", ", h("b", "OK"), ", ", h("b", "Next"), ", ", h("b", "Finish"), "."),
                  h("li", "Windows warns that you are about to install a certificate. Check that the Thumbprint it shows matches the Windows thumbprint above, then choose ", h("b", "Yes"), "."),
                  h("li", "Close every browser window and open this page again.")),
                h("h4", "Mac"),
                h("p.hint", "Open the .crt (it goes into Keychain Access), double-click FoilGateway local CA, open Trust and set When using this certificate to Always Trust."),
                h("h4", "Phones and tablets"),
                h("p.hint", "iPhone/iPad: open the .crt, install the profile in Settings, then turn it on under General > About > Certificate Trust Settings. Android: Settings > Security > Encryption & credentials > Install a certificate > CA certificate, and pick the .crt."))),
            panel("This page's certificate", null,
              info("Page certificate", cd.server),
              h("div.row", { style: "margin-top:10px" }, h("button.quiet", { onclick: renew }, "Make a new certificate"))),
          ];
        },
        view: () => panel("Dashboard cards", null, h("p.hint", "Pick which cards show along the top of the dashboard. This is saved on the gateway, so it's the same in every browser. Turning a card off also stops any measuring only that card needs."),
              table(["Card", ""], CARDS.map((c) => {
                const on = cardOn(d.status, c);
                return h("tr", { "data-key": c.id }, h("td", c.label), h("td.num", h("div.seg.onoff", h("button" + (on ? ".on" : ""), { type: "button", "aria-pressed": String(on), onclick: () => on || run({ action: "card", id: c.id, on: true }) }, "On"), h("button" + (on ? "" : ".on"), { type: "button", "aria-pressed": String(!on), onclick: () => !on || run({ action: "card", id: c.id, on: false }) }, "Off"))));
              }), "")),
        setup: () => panel("Setup", null,
              h("p.hint", "Go through ports, the settings port and safety again. Admin accounts aren't changed."), h("button.quiet", { onclick: rerun }, "Run Setup Again"),
              h("div.ver", { id: "versions" }, h("div.ok", h("span.vl", "Active version:"), " " + d.release.current),
                d.release.previous ? h("div.warn", h("span.vl", "Roll back version:"), " " + d.release.previous) : h("div.hint", "Nothing to roll back to yet. The current version is kept at the next update.")),
              h("p.hint", "Restart is only needed after an update, or if support asks. Roll back if this version misbehaves."),
              h("div.row.same", h("button.danger", { id: "restart", onclick: restartAsk }, "Restart"),
                h("button.danger", { id: "rollback", disabled: !d.release.previous, title: d.release.previous ? "" : "No earlier version kept", onclick: () => rollbackAsk(d.release) }, "Roll back"))),
      };
      const TOPICS = {
        // Primary left, secondary/detail right  -  same pattern as Devices.
        "/settings": [["ports", "address", "speed"], ["who", "adminport", "safety"]],
        "/settings/certs": [["certs"], []],
        "/settings/general": [["tz"], ["geo"]],
        "/settings/log": [["log"], []],
        "/settings/setup": [["setup"], ["backup"]],
        "/settings/view": [["view"], []],
      };
      const [left, right] = TOPICS[PATH] || TOPICS["/settings"];
      const title = (SUBS.settings.find(([u]) => u === PATH) || SUBS.settings[0])[1];
      const tips = {
        "/settings/certs": panel("About Certificates", null, h("p.hint", "Install the gateway's certificate authority on each computer once so the browser trusts this page without a warning.")),
        "/settings/log": panel("About Capture Log", null, h("p.hint", "Download or trim kept lines here. Open the full log from Capture Log in the sidebar.")),
        "/settings/view": panel("About View", null, h("p.hint", "Cards you turn off stop measuring work the dashboard no longer shows. Saved on the gateway for every browser.")),
      };
      const rightKids = right.length ? right.map((k) => P[k]()) : (tips[PATH] ? [tips[PATH]] : []);
      render(
        header("Settings · " + title, d.status), pendingNote(d.status), pathNote(d.status), adminNudge(d.status), errBox,
        h("div.body.two",
          h("div.col", { "data-k": "set-l" }, left.map((k) => P[k]())),
          h("div.col", { "data-k": "set-r" }, rightKids)));
      if (location.hash === "#geo" && $("#geo")) $("#geo").scrollIntoView();
      clearTimeout(geoSoon);
      if (d.geo.on && (d.geo.phase === 1 || d.geo.phase === 2)) geoSoon = setTimeout(refresh, 1500);
    });
  }

  // ---------- Sign in ----------
  function login() {
    document.title = "Sign in - FoilGateway";
    const u = h("input", { autocomplete: "username", placeholder: "Name" }), p = h("input", { type: "password", autocomplete: "current-password", placeholder: "Password" });
    const err = h("div.err", { "data-ref": "" });
    const next = sameSitePath(new URLSearchParams(location.search).get("next") || "") || "/";
    const go = async (e) => { e.preventDefault(); err.textContent = ""; try { await api("/api/login", { user: u.value, password: p.value }); location.href = next; } catch (x) { err.textContent = x.message; } };
    $("#app").replaceChildren(h("div.solo", h("form.login", { onsubmit: go },
      h("div.brand", h("img", { src: "/s/icon.svg", alt: "" }), h("div", h("b", "FoilGateway"), h("small", "Network edition"))),
      h("section.panel", h("h2", "Sign in"), h("label", "Name"), u, h("label", "Password"), p, err, h("div", { style: "margin-top:12px" }, h("button", { type: "submit" }, "Sign in"))))));
    u.focus();
  }

  // ---------- First-connect setup ----------
  // Where the wizard is lives on the gateway, so the page can lose the
  // gateway (a cable moved, the service restarted) and pick up again on
  // the same step, even from another address.
  function setup() {
    document.title = "Setup - FoilGateway";
    const STEPS = ["Welcome", "Admin", "Mode", "Ports", "Settings port", "Safety", "Review", "Apply"];
    const F = { password: "", password2: "" };
    let I = null, W = null, err = "", lost = 0, seen = "", confirming = false, done = null;
    const root = h("div.solo");
    $("#app").replaceChildren(root);
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const listing = (l) => l.length > 1 ? l.slice(0, -1).join(", ") + " or " + l[l.length - 1] : l[0] || "";
    const steps = () => W.first ? STEPS : STEPS.filter((x) => x !== "Admin");

    async function timed(url, opt, ms) {
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), ms);
      try { return await fetch(url, Object.assign({ cache: "no-store", signal: c.signal }, opt)); } finally { clearTimeout(t); }
    }
    async function info() {
      const r = await timed("/api/setup/info", { credentials: "same-origin" }, 3000);
      const d = await r.json().catch(() => ({}));
      if (r.status === 401 && d.redirect) {
        if (done || confirming) return null;
        location.href = d.redirect; return null;
      }
      if (!r.ok) throw new Error(d.error || "The gateway answered " + r.status + ".");
      return d;
    }
    async function save(fields) {
      err = "";
      try { W = await api("/api/setup/state", fields); } catch (e) { if (e.message !== "redirect") err = e.message; }
      draw();
    }
    let go = (step, fields) => save(Object.assign({ step }, fields || {}));

    function moveNote(when) {
      if (!I.here || !W.lan.length || W.lan.includes(I.here) || W.wan === I.here || I.here === "br-fgw") return null;
      return h("p.notice", "This computer is on " + I.here + ", which you haven't picked. ", when, h("b", "move this computer's cable to " + listing(W.lan)),
        ". The page finds the gateway again by itself. It can take your computer up to a minute to get an address there.");
    }

    function stepBody(name) {
      if (name === "Welcome") {
        return [h("h2", "Set up FoilGateway"), h("p", "FoilGateway sits in the cable path and filters what crosses it. Next you choose whether it sits between the internet and your switch, or between your existing router and your switch."),
          h("p", "Until setup is done, every port answers, so it doesn't matter where the cable is right now. You pick which port does what in a moment."),
          h("p", "Nothing on the network changes until the last step, and that step undoes itself unless this browser can still reach the gateway afterwards."),
          h("p.mute", "Connected from " + I.client_ip + (I.here ? " on " + I.here : "") + ". Gateway " + (I.hostname || "") + ".")];
      }
      if (name === "Admin") {
        const u = h("input", { value: W.user || "admin", autocomplete: "username", id: "su", style: "width:100%" });
        const p1 = h("input", { type: "password", value: F.password, oninput: (e) => F.password = e.target.value, autocomplete: "new-password", style: "width:100%" });
        const p2 = h("input", { type: "password", value: F.password2, oninput: (e) => F.password2 = e.target.value, autocomplete: "new-password", style: "width:100%" });
        return [h("h2", "Admin account"), h("p", "This is who signs in to these pages. You can add more admins later."), h("label", "Name"), u, h("label", "Password (at least 10 characters)"), p1, W.has_password ? h("p.hint", "Already set. Leave both boxes empty to keep it.") : null, h("label", "Same password again"), p2];
      }
      if (name === "Mode") {
        const pick = (id) => () => save({ placement: id });
        const card = (id, label, plain, when, pros, cons, see, no) => {
          const on = (W.placement || "router_switch") === id;
          return h("div.portrow" + (on ? ".here" : ""), { onclick: pick(id), role: "button", tabindex: 0 },
            h("b", label),
            h("div",
              h("div", plain),
              h("div.mute", when),
              h("div", { style: "margin-top:6px" }, h("b", "Pros"), h("ul.compact", pros.map((x) => h("li", x)))),
              h("div", h("b", "Cons"), h("ul.compact", cons.map((x) => h("li", x)))),
              h("p.hint", "Can see: " + see),
              h("p.hint", "Cannot see: " + no)),
            h("div.acts", on ? h("span.pill.handled", "Selected") : h("button.quiet", { onclick: (e) => { e.stopPropagation(); pick(id)(); } }, "Select")));
        };
        return [h("h2", "Where Does FoilGateway Sit?"),
          h("p", "Both options place FoilGateway as a bridge. Everything downstream of the LAN port (switches, Wi-Fi, all devices behind it) is protected. Anything upstream of the WAN port is not."),
          h("div.ports",
            card("internet_switch", "Between Internet And Switch",
              "Modem / ONT → FoilGateway → switch (and Wi-Fi access points).",
              "Pick this when the modem or ONT feeds FoilGateway directly, then your switch and access points.",
              ["WAN faces the modem / ONT", "LAN faces your switch and Wi-Fi", "Devices behind the LAN port are protected"],
              ["Place the cables correctly; a WAN/LAN swap means no path through", "Anything still upstream of the WAN port is not filtered"],
              "Everything downstream of the LAN port: switches, Wi-Fi, and all devices behind FoilGateway.",
              "Anything upstream of the WAN port."),
            card("router_switch", "Between Router And Switch",
              "Modem / ONT → existing router → FoilGateway → switch / Wi-Fi.",
              "Pick this when you already have a home router for Wi-Fi, DHCP, and NAT.",
              ["WAN faces your existing router", "LAN faces your switch and Wi-Fi", "Devices behind the LAN port are protected"],
              ["Anything upstream of the WAN port (including the router and its upstream) is not filtered", "Devices that stay only on the router's own Wi-Fi never reach the LAN port"],
              "Everything downstream of the LAN port: switches, Wi-Fi, and all devices behind FoilGateway.",
              "Anything upstream of the WAN port (including the router and its own upstream).")),
          h("p.mute", "You can change cables later; re-run Setup if ports move.")];
      }
      if (name === "Ports") {
        const guess = I.wan_guess ? h("p.hint", I.wan_guess + " got its address from another router, so it's picked as WAN. Change it if that's wrong.") : null;
        return [h("h2", "Which port is which"),
          h("p", h("b", "WAN"), " is the cable to your router. ", h("b", "LAN"), " is the cable to your switch, Wi-Fi access point, or a single computer. You can pick more than one LAN port. Use Blink to see which socket is which."),
          h("p.hint", "Your devices keep the addresses your router gives them. Settings and SSH answer from both sides."),
          h("div", { id: "portlist" }, portPicker(I.ports, W.lan, W.wan, (n, r) => { const sel = { lan: W.lan.slice(), wan: W.wan }; pickRole(sel, n, r); save(sel); }, blink)),
          guess,
          W.wan && !(I.ports.find((p) => p.name === W.wan) || {}).link ? h("p.hint", "No cable in " + W.wan + " yet. That's fine; plug it in whenever you like.") : null,
          moveNote("After you press Apply, ")];
      }
      if (name === "Settings port") {
        return [h("h2", "Settings port"), h("p", "These pages answer over HTTPS on this port. 8443 is fine unless something else uses it."),
          h("input", { type: "number", min: 1, max: 65535, value: W.admin_port, id: "sp" }),
          h("p.hint", "The certificate is made on the gateway itself, so the browser warns about it once for each address. That's expected.")];
      }
      if (name === "Safety") {
        return [h("h2", "Management safety"), h("p", "The computers listed here always reach the gateway (SSH and these pages) and the internet, whatever rules you set later. Their rules come first and can't be overridden from these pages."),
          h("p.notice", "Add at least the computer you’re using now. It can always get back in, whatever you change later. Safety computers can open the settings pages and connect over SSH. Both require signing in."),
          h("label.check", h("input", { type: "checkbox", checked: W.safety, onchange: (e) => save({ safety: e.target.checked, safety_hosts: $("#sh").value }) }), "Keep Management Safety On (Recommended)"),
          h("label", "Always-Allowed Computers"), h("input", { value: W.safety_hosts || (I.client_ip.includes(".") ? I.client_ip : ""), id: "sh", style: "width:100%" }),
          h("p.hint", "Filled in with this computer (" + I.client_ip + "). Add more separated by commas. SSH to the gateway stays open either way."),
          h("label", "New devices get"), h("div.seg", ["normal", "lan_only"].map((p) => h("button" + ((W.new_devices || "normal") === p ? ".on." + p : ""), { onclick: () => save({ new_devices: p, safety_hosts: $("#sh").value }) }, POLICY[p])))];
      }
      if (name === "Review") {
        return [h("h2", "Check before applying"),
          W.note ? h("p.notice", W.note) : null,
          h("dl.review",
            W.first ? [h("dt", "Admin"), h("dd", W.user)] : null,
            h("dt", "WAN"), h("dd", W.wan), h("dt", "LAN"), h("dd", W.lan.join(", ")),
            h("dt", "Placement"), h("dd", (W.placement === "internet_switch") ? "Between Internet And Switch" : "Between Router And Switch"),
            h("dt", "Mode"), h("dd", "Bridge"),
            h("dt", "Settings page"), h("dd", "https://" + I.name + ":" + W.admin_port + ", or the address your router gives the gateway, port " + W.admin_port),
            h("dt", "Safety"), h("dd", W.safety ? "on, always allowed: " + W.safety_hosts : "off"),
            h("dt", "New devices"), h("dd", POLICY[W.new_devices || "normal"])),
          h("p", "Applying loads the rules and joins the ports into one bridge. The network drops for a few seconds while that happens. Then this page has to reach the gateway again; if it can't within a few minutes, the bridge comes apart and the ports go back the way they were."),
          moveNote("When you press Apply, "),
          W.safety ? null : h("p.notice", "Safety is off. A bad rule could lock you out.")];
      }
      if (done) {
        return [h("h2", "Done"), h("p.notice.ok", "The bridge stays. " + done.wan + " goes to your router, " + done.lan.join(", ") + " to your devices."),
          h("p", "The temporary setup addresses are gone" + (done.kept_setup_addr ? ", except the one this browser is using, so this page keeps working" : "") + ". Find the gateway at https://" + I.name + ":" + W.admin_port + " or the address your router lists for it. SSH works from both sides."),
          h("p", "Remote Desktop from outside (port 3389) stays blocked by default. Devices on your home network can still use it; FortNox blocks that too. Open it for one device on Ports only if you need it."),
          h("p", "You start in Audit. When you leave Audit, FoilGateway applies the Normal protection level. ", h("a", { href: "/firewall/coach" }, "Best Practices"), " can walk you through the rest."),
          h("p", h("a.btn", { href: W.first ? "/login" : "/" }, W.first ? "Sign in" : "Open the dashboard"))];
      }
      const a = W.applied || {};
      return [h("h2", "Waiting for this page to check in"), h("p", { id: "applying" }, "The bridge is up. It's kept once this page reaches the gateway through it. If that doesn't happen in ", h("b", { id: "left" }, String(a.left || 0)), " seconds, it comes apart again."),
        moveNote("Now ")];
    }

    function draw() {
      if (!I || !W) return;
      const list = steps();
      const name = done ? "Apply" : W.applied ? "Apply" : list.includes(W.step) ? W.step : list[0];
      const at = list.indexOf(name);
      const next = list[at + 1], prev = list[at - 1];
      const fields = () => {
        if (name === "Admin") {
          const user = $("#su").value.trim();
          if (!W.has_password || F.password) {
            if (F.password.length < 10) return "The password needs at least 10 characters.";
            if (F.password !== F.password2) return "The two passwords aren't the same.";
          }
          return { user, password: F.password };
        }
        if (name === "Ports" && (!W.wan || !W.lan.length)) return "Pick one WAN port and at least one LAN port.";
        if (name === "Settings port") return { admin_port: Number($("#sp").value) };
        if (name === "Safety") {
          if (W.safety && !$("#sh").value.trim()) return "Add at least one computer, or turn safety off.";
          return { safety_hosts: $("#sh").value };
        }
        return {};
      };
      const onNext = async () => {
        const f = fields();
        if (typeof f === "string") { err = f; draw(); return; }
        if (name === "Review") { apply(); return; }
        await go(next, f);
        if (!err) { F.password = ""; F.password2 = ""; }
      };
      const nav = name === "Apply" ? null : h("div.nav-btns", prev ? h("button.quiet", { onclick: () => go(prev) }, "Back") : h("span"),
        h("button", { onclick: onNext }, name === "Review" ? "Apply" : name === "Welcome" ? "Start" : "Next"));
      root.replaceChildren(h("div.wizard",
        h("div.brand", h("img", { src: "/s/icon.svg", alt: "" }), h("div", h("b", "FoilGateway"), h("small", "Network edition · " + (W.first ? "first setup" : "setup")))),
        h("div.steps", list.map((x, k) => h("span" + (k === at ? ".on" : k < at ? ".done" : ""), x))),
        h("section.panel", stepBody(name), h("div.err", err), nav),
        done ? null : h("p.foot", "During setup the gateway answers on every port, also at https://" + I.name + ":" + I.port + " where your computer supports .local names. If your network has no router handing out addresses, connect to https://" + I.fallback_addr + ":" + I.port + ".")));
    }

    async function blink(port) {
      // A port that can't blink says why in its own row.
      try { await api("/api/setup/blink", { port }); } catch (e) { /* shown on the port */ }
      tick();
    }

    async function apply() {
      err = "";
      try {
        await api("/api/setup", {});
        await tick();
      } catch (e) { if (e.message !== "redirect") { err = e.message; draw(); } }
    }

    async function confirm() {
      if (confirming) return;
      confirming = true;
      try {
        const r = await timed("/api/setup/confirm", { method: "POST", headers: { "X-FG": "1" }, credentials: "same-origin" }, 4000);
        const d = await r.json().catch(() => ({}));
        if (r.ok && d.kept) { done = { wan: W.wan, lan: W.lan, here: d.here, kept_setup_addr: d.kept_setup_addr }; draw(); }
        else if (r.ok && !d.applied && d.wizard) { W = d.wizard; draw(); }
      } catch (e) { /* the heartbeat notices */ }
      confirming = false;
    }

    // ---- losing the gateway and finding it again ----
    function others() {
      const port = I ? I.port : location.port;
      const list = [location.origin, "https://" + (I ? I.name : "foilgateway.local") + ":" + port, "https://" + (I ? I.fallback_addr : "192.168.30.1") + ":" + port,
        "https://" + (I ? I.last_try : "169.254.42.1") + ":" + port];
      return list.filter((x, k) => list.indexOf(x) === k).map((o, k, all) => ({ o, quiet: k === all.length - 1 && o.includes("169.254.") }));
    }
    async function reachable(origin) {
      try {
        const same = origin === location.origin;
        const r = await timed(origin + "/api/ping", { mode: same ? "same-origin" : "no-cors" }, 2500);
        return same ? r.ok : true;
      } catch (e) { return false; }
    }
    async function reconnect() {
      const tries = others().map((t) => Object.assign(t, { state: "trying" }));
      const draw2 = () => root.replaceChildren(h("div.wizard",
        h("div.brand", h("img", { src: "/s/icon.svg", alt: "" }), h("div", h("b", "FoilGateway"), h("small", "Network edition · setup"))),
        h("section.panel.lost",
          h("h2", "Lost the gateway, looking for it"),
          h("p", "That's expected after a cable moves or the gateway restarts. Setup is saved on the gateway; you'll be back on the same step (" + (W ? W.step : "") + ")."),
          h("ul.tries", tries.filter((t) => !t.quiet).map((t) => h("li", h("span.dot." + (t.state === "found" ? "ok" : "warn"), ""), h("a", { href: t.o + "/setup" }, t.o), h("span.mute", " " + (t.state === "found" ? "found" : "not answering yet"))))),
          W && W.applied ? h("p", "While the bridge comes up the gateway's address can change. It's usually back within a minute.") : null,
          h("p.hint", "If a link doesn't open by itself, click it. The browser may warn about the certificate once for a new address."))));
      draw2();
      for (;;) {
        for (const t of tries) {
          if (await reachable(t.o)) {
            t.state = "found"; draw2();
            if (t.o === location.origin) { lost = 0; seen = ""; await tick(); return; }
            location.href = t.o + "/setup"; return;
          }
        }
        await sleep(1500);
      }
    }

    async function tick() {
      let d;
      try { d = await info(); } catch (e) { d = undefined; }
      if (d === null) return;
      if (d === undefined) {
        if (++lost >= 2 && !done) await reconnect();
        return;
      }
      lost = 0;
      const firstLoad = !I;
      I = d; W = d.wizard;
      // Fill in empty choices once: the router side as WAN, this port as LAN.
      if (firstLoad && W.step === "Ports" && !W.wan && !W.lan.length) prefill();
      const key = JSON.stringify([I.ports, I.here, W.step, W.applied && W.applied.left, W.note]);
      const typing = ["Admin", "Settings port", "Safety"].includes(W.step) && !W.applied;
      if (key !== seen && (!typing || firstLoad)) { seen = key; draw(); }
      if (W.applied) confirm();
    }
    function prefill() {
      const sel = { wan: I.wan_guess || "", lan: [] };
      const here = I.here && I.here !== sel.wan ? I.here : (I.ports.find((p) => p.name !== sel.wan) || {}).name;
      if (here) sel.lan.push(here);
      save(sel);
    }
    const _go = go;
    // Going to Ports for the first time fills in a guess.
    go = async (step, fields) => { await _go(step, fields); if (step === "Ports" && !W.wan && !W.lan.length) prefill(); };

    (async function loop() {
      for (;;) { if (!done) await tick(); await sleep(1500); }
    })();
  }

  const pages = { dashboard, devices, firewall, ports, log, settings, login, setup };
  if (PAGE === "login" || PAGE === "setup") pages[PAGE]();
  else {
    // Learn who is signed in before drawing, so nothing they can't use shows.
    api("/api/status").then((st) => {
      ME = { admin: !!st.admin, perms: st.perms || [] };
      // Signing in opens "/". A user who can't see the Dashboard goes to
      // the first page they can open instead; other links keep Not Available.
      if (PATH === "/" && !pageOk("dashboard")) return location.replace(firstPage());
      const sub = SUBS[PAGE] && SUBS[PAGE].some(([u]) => u === navPath);
      if (pageOk(PAGE) && (!sub || subOk(navPath))) return pages[PAGE]();
      shell("Not Available");
      statusBox(st);
      render(header("Not Available", st), h("div.body.one", panel("Not Available", null, h("p", "This user can't open this page. An admin can change what this user may do in Settings, Users."))));
    }).catch(() => pages[PAGE]());
  }
})();
