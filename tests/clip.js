// Finds text the page cuts off: anything that overflows its box or the
// window, ellipsis, inputs and selects too narrow for their text or
// placeholder. Used by browser.js at several window widths.
const WIDTHS = [1440, 1024, 768, 390];

function findClipped() {
  const bad = [];
  const say = (el, why) => {
    const id = el.id ? "#" + el.id : el.className && typeof el.className === "string" ? "." + el.className.trim().split(/\s+/).join(".") : "";
    bad.push(`${el.tagName.toLowerCase()}${id} "${(el.value || el.placeholder || el.innerText || "").trim().slice(0, 50)}": ${why}`);
  };
  const ctx = document.createElement("canvas").getContext("2d");
  const textWidth = (el, t) => { const cs = getComputedStyle(el); ctx.font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`; return ctx.measureText(t).width; };
  const shown = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && !el.closest("[hidden]") && getComputedStyle(el).visibility !== "hidden"; };
  if (document.documentElement.scrollWidth > innerWidth + 1) bad.push(`page is ${document.documentElement.scrollWidth}px wide in a ${innerWidth}px window`);
  for (const el of document.querySelectorAll("body *")) {
    if (!shown(el) || ["CANVAS", "SVG", "svg", "IMG", "path", "OPTION", "SCRIPT", "STYLE"].includes(el.tagName)) continue;
    if (el.closest("svg")) continue;
    const cs = getComputedStyle(el);
    if (cs.textOverflow === "ellipsis" && el.scrollWidth > el.clientWidth) say(el, "ellipsis");
    if (el.tagName === "INPUT" || el.tagName === "TEXTAREA") {
      if (["checkbox", "radio", "file", "hidden"].includes(el.type)) continue;
      const room = el.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight) - (el.type === "number" ? 18 : 0);
      for (const t of [el.value, el.placeholder]) {
        if (!t || el.tagName === "TEXTAREA") continue;
        const w = textWidth(el, el.type === "password" && t === el.value ? "•".repeat(t.length) : t);
        if (w > room + 1) say(el, `text needs ${Math.ceil(w)}px, has ${Math.floor(room)}px`);
      }
      continue;
    }
    if (el.tagName === "SELECT") {
      const o = el.options[el.selectedIndex];
      const room = el.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight) - 16;
      if (o && textWidth(el, o.text) > room + 1) say(el, "selected option doesn't fit");
      continue;
    }
    // Scroll boxes that scroll (auto/scroll) are fine; overflow:hidden sideways is cut-off text.
    if (el.scrollWidth > el.clientWidth + 1 && el.clientWidth > 0 && cs.overflowX === "hidden") say(el, `overflows sideways by ${el.scrollWidth - el.clientWidth}px`);
    if (el.scrollHeight > el.clientHeight + 1 && cs.overflowY === "hidden" && el.clientHeight > 0) say(el, "cut off at the bottom");
    // Text sticking out of a box that doesn't clip it.
    const p = el.parentElement;
    if (p && el.children.length === 0 && el.innerText && el.innerText.trim()) {
      const r = el.getBoundingClientRect(), pr = p.getBoundingClientRect();
      if (r.right > pr.right + 1 && getComputedStyle(p).overflowX === "visible") say(el, `sticks out of its box by ${Math.round(r.right - pr.right)}px`);
    }
  }
  return [...new Set(bad)];
}

async function audit(page, name, problems) {
  const vp = page.viewport();
  for (const w of WIDTHS) {
    await page.setViewport({ width: w, height: 900 });
    await new Promise((r) => setTimeout(r, 250));
    const found = await page.evaluate(findClipped);
    for (const f of found) problems.push(`${name} @${w}px: ${f}`);
  }
  await page.setViewport(vp);
  await new Promise((r) => setTimeout(r, 150));
}

module.exports = { audit, WIDTHS, findClipped };
