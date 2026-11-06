#!/usr/bin/env python3
"""Regenerate assets/help FULL/bundle/index/manual.html from chapter .md files.
Meta / version_note is plain "Version <Cargo.toml version>" (never "Help for … behavior").
"""
from pathlib import Path
import re, json, html

ROOT = Path(__file__).resolve().parents[1]
help_dir = ROOT / "assets/help"

CHAPTERS = [
    ("getting-started", "Getting Started", "01-getting-started.md"),
    ("daily-use", "Daily Use", "02-daily-use.md"),
    ("protection", "Protection", "03-protection.md"),
    ("ports", "Ports", "04-ports.md"),
    ("settings", "Settings", "05-settings.md"),
    ("breaks", "If Something Breaks", "06-if-something-breaks.md"),
    ("limits", "Limits", "07-limits.md"),
    ("about", "About", "08-about.md"),
    ("glossary", "Glossary", "99-glossary.md"),
]

def cargo_version() -> str:
    for line in (ROOT / "Cargo.toml").read_text().splitlines():
        if line.startswith("version"):
            return line.split('"')[1]
    raise SystemExit("no version in Cargo.toml")

def search_text(md: str) -> str:
    s = re.sub(r"^#+\s*", "", md, flags=re.M)
    s = s.replace("**", "").replace("*", "").replace("`", "")
    return re.sub(r"\s+", " ", s).strip().lower()

def inline(s: str) -> str:
    # Links first on raw text, then escape the surrounding pieces.
    parts = []
    last = 0
    for m in re.finditer(r"\[([^\]]+)\]\(([^)]+)\)", s):
        parts.append(html.escape(s[last:m.start()]))
        label = html.escape(m.group(1))
        href = html.escape(m.group(2), quote=True)
        parts.append(f'<a href="{href}">{label}</a>')
        last = m.end()
    parts.append(html.escape(s[last:]))
    s = "".join(parts)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s

def md_to_html(md: str) -> str:
    lines = md.splitlines()
    out = []
    i = 0
    in_code = False
    code_buf = []
    list_type = None
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            if in_code:
                out.append('<pre class="help-pre"><code>' + html.escape("\n".join(code_buf)) + "</code></pre>")
                code_buf = []
                in_code = False
            else:
                if list_type:
                    out.append(f"</{list_type}>")
                    list_type = None
                in_code = True
            i += 1
            continue
        if in_code:
            code_buf.append(line)
            i += 1
            continue
        if not line.strip():
            if list_type:
                out.append(f"</{list_type}>")
                list_type = None
            i += 1
            continue
        m = re.match(r"^(#{1,3})\s+(.*)$", line)
        if m:
            if list_type:
                out.append(f"</{list_type}>")
                list_type = None
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{inline(m.group(2))}</h{lvl}>")
            i += 1
            continue
        m = re.match(r"^(\d+)\.\s+(.*)$", line)
        if m:
            if list_type != "ol":
                if list_type:
                    out.append(f"</{list_type}>")
                out.append("<ol>")
                list_type = "ol"
            out.append(f"<li>{inline(m.group(2))}</li>")
            i += 1
            continue
        m = re.match(r"^[-*]\s+(.*)$", line)
        if m:
            if list_type != "ul":
                if list_type:
                    out.append(f"</{list_type}>")
                out.append("<ul>")
                list_type = "ul"
            out.append(f"<li>{inline(m.group(1))}")
            j = i + 1
            nested = []
            while j < len(lines) and re.match(r"^  [-*]\s+", lines[j]):
                nested.append(re.match(r"^  [-*]\s+(.*)$", lines[j]).group(1))
                j += 1
            if nested:
                out.append("<ul>")
                for n in nested:
                    out.append(f"<li>{inline(n)}</li>")
                out.append("</ul>")
                i = j
            else:
                i += 1
            out.append("</li>")
            continue
        if list_type:
            out.append(f"</{list_type}>")
            list_type = None
        out.append(f"<p>{inline(line)}</p>")
        i += 1
    if list_type:
        out.append(f"</{list_type}>")
    if in_code:
        out.append('<pre class="help-pre"><code>' + html.escape("\n".join(code_buf)) + "</code></pre>")
    return "\n".join(out)

def main():
    ver = cargo_version()
    note = f"Version {ver}"
    parts = [help_dir.joinpath(f).read_text().rstrip() + "\n" for _, _, f in CHAPTERS]
    help_dir.joinpath("FULL.md").write_text("\n\n".join(parts) + "\n")
    chapters = []
    index_chapters = []
    for cid, title, fname in CHAPTERS:
        md = help_dir.joinpath(fname).read_text()
        chapters.append({"id": cid, "title": title, "file": fname, "markdown": md, "search": search_text(md)})
        index_chapters.append({"id": cid, "title": title, "file": fname})
    help_dir.joinpath("bundle.json").write_text(json.dumps({
        "product": "FoilGateway Network",
        "copyright": "Copyright (C) 2026 iBGeek",
        "version_note": note,
        "chapters": chapters,
    }, ensure_ascii=False, indent=2) + "\n")
    help_dir.joinpath("index.json").write_text(json.dumps({
        "copyright": "Copyright (C) 2026 iBGeek",
        "chapters": index_chapters,
    }, ensure_ascii=False, indent=2) + "\n")
    css = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>FoilGateway Network - Help Manual</title><style>
:root {{ --bg:#050b14; --card:#0c1826; --line:#1c3348; --text:#d5dde6; --text-2:#c4ced8; --strong:#f3f6f8; --dim:#a7b4c1; --link:#7fc4ff; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:15px/1.55 "Segoe UI", system-ui, sans-serif; }}
main {{ max-width:820px; margin:0 auto; padding:28px 20px 60px; }}
h1 {{ color:var(--strong); font-size:1.6rem; }}
h2 {{ color:var(--strong); font-size:1.2rem; margin-top:1.6em; }}
h3 {{ color:var(--strong); font-size:1.05rem; }}
p, li {{ color:var(--text-2); }}
a {{ color:var(--link); }}
code {{ background:#10243a; padding:1px 5px; border-radius:4px; font-size:.92em; }}
.help-pre {{ background:#0b1724; border:1px solid var(--line); border-radius:8px; padding:12px; overflow:auto; }}
.help-table {{ width:100%; border-collapse:collapse; margin:12px 0; display:block; overflow-x:auto; }}
.help-table th, .help-table td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }}
.help-table th {{ color:var(--strong); }}
.help-table th:first-child, .help-table td:first-child {{ white-space:nowrap; }}
.meta {{ color:var(--dim); font-size:.9rem; margin-bottom:2rem; }}
hr.chap {{ border:0; border-top:1px solid var(--line); margin:2.5rem 0; }}
</style></head><body><main><h1>FoilGateway Network - Help Manual</h1><p class="meta">Copyright (C) 2026 iBGeek · {html.escape(note)}</p>"""
    sections = []
    for cid, title, fname in CHAPTERS:
        md = help_dir.joinpath(fname).read_text()
        body_md = re.sub(r"^# .*\n+", "", md, count=1)
        sections.append(f'<section id="{cid}"><h1>{html.escape(title)}</h1>\n{md_to_html(body_md)}\n</section>')
    manual = css + '<hr class="chap">'.join(sections) + "</main></body></html>\n"
    help_dir.joinpath("manual.html").write_text(manual)
    (ROOT / "assets/manual.html").write_text(manual)
    print(f"regen-help: {note}")

if __name__ == "__main__":
    main()
