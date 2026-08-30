"""Turn an analysis into a report a person can read or a machine can parse."""
from __future__ import annotations

import json
from typing import Dict

from . import stride

_SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def to_json(result: Dict) -> str:
    return json.dumps(result, indent=2)


def to_text(result: Dict, color: bool = False) -> str:
    C = {"b": "\x1b[1m", "d": "\x1b[2m", "r": "\x1b[91m", "y": "\x1b[93m",
         "g": "\x1b[92m", "c": "\x1b[96m", "x": "\x1b[0m"} if color else {k: "" for k in "bdrygcx"}
    s = result["summary"]
    out = []
    out.append(f"\n{C['b']}Mimar threat model: {result['name']}{C['x']}")
    grade_color = C['g'] if s["grade"] in ("A", "B") else (C['y'] if s["grade"] == "C" else C['r'])
    out.append(f"  score {grade_color}{s['score']}/100  grade {s['grade']}{C['x']}")
    out.append(f"  {s['zones']} zones, {s['elements']} components "
               f"({s['entities']} entities, {s['processes']} processes, {s['stores']} stores), {s['flows']} flows")
    out.append(f"  {s['weaknesses']} architecture weaknesses, {s['threats']} STRIDE threats")

    if result["problems"]:
        out.append(f"\n{C['y']}Model problems:{C['x']}")
        for p in result["problems"]:
            out.append("  - " + p)

    out.append(f"\n{C['b']}Architecture weaknesses{C['x']}  (most serious first)")
    if not result["weaknesses"]:
        out.append("  none found")
    for f in result["weaknesses"]:
        col = C['r'] if f["severity"] in ("critical", "high") else (C['y'] if f["severity"] == "medium" else C['d'])
        out.append(f"  {col}[{_SEV_LABEL[f['severity']]}]{C['x']} {f['title']}")
        out.append(f"      {f['why']}")
        out.append(f"      {C['c']}control:{C['x']} {f['control']}")

    out.append(f"\n{C['b']}STRIDE threat counts{C['x']}")
    for cat, count in result["stride_counts"].items():
        name = stride.CATEGORIES[cat][0]
        out.append(f"  {name:<24} {count}")
    out.append("")
    return "\n".join(out)


def to_markdown(result: Dict) -> str:
    s = result["summary"]
    out = []
    out.append("# Mimar threat model: " + result["name"])
    out.append("")
    out.append("**Score " + str(s["score"]) + " of 100, grade " + s["grade"] + ".** " +
               str(s["zones"]) + " zones, " + str(s["elements"]) + " components, " +
               str(s["flows"]) + " flows, " + str(s["weaknesses"]) + " architecture weaknesses, " +
               str(s["threats"]) + " STRIDE threats.")
    out.append("")
    out.append("## Architecture weaknesses")
    out.append("")
    if not result["weaknesses"]:
        out.append("None found.")
    for f in result["weaknesses"]:
        out.append("### " + _SEV_LABEL[f["severity"]] + ": " + f["title"])
        out.append("")
        out.append(f["why"])
        out.append("")
        out.append("**Control.** " + f["control"])
        out.append("")
    out.append("## STRIDE threat register")
    out.append("")
    out.append("| Category | Component | Threat | First mitigation |")
    out.append("| --- | --- | --- | --- |")
    for t in result["threats"]:
        out.append("| " + t["category_name"] + " | " + t["target_name"] + " | " +
                   t["description"] + " | " + t["mitigation"] + " |")
    out.append("")
    return "\n".join(out)


def to_html(result: Dict) -> str:
    s = result["summary"]
    grade_class = "good" if s["grade"] in ("A", "B") else ("warn" if s["grade"] == "C" else "bad")
    rows = []
    for f in result["weaknesses"]:
        rows.append(
            '<div class="w ' + f["severity"] + '"><div class="t"><span class="sev ' + f["severity"] +
            '">' + _SEV_LABEL[f["severity"]] + '</span> ' + _esc(f["title"]) + '</div><div class="why">' +
            _esc(f["why"]) + '</div><div class="ctl">Control: ' + _esc(f["control"]) + '</div></div>')
    trows = []
    for t in result["threats"]:
        trows.append("<tr><td>" + _esc(t["category_name"]) + "</td><td>" + _esc(t["target_name"]) +
                     "</td><td>" + _esc(t["description"]) + "</td><td>" + _esc(t["mitigation"]) + "</td></tr>")
    return _HTML.replace("{{name}}", _esc(result["name"])).replace("{{score}}", str(s["score"])) \
        .replace("{{grade}}", s["grade"]).replace("{{grade_class}}", grade_class) \
        .replace("{{zones}}", str(s["zones"])).replace("{{elements}}", str(s["elements"])) \
        .replace("{{flows}}", str(s["flows"])).replace("{{weaknesses}}", str(s["weaknesses"])) \
        .replace("{{threats}}", str(s["threats"])).replace("{{wrows}}", "\n".join(rows) or "<p>None found.</p>") \
        .replace("{{trows}}", "\n".join(trows))


def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Mimar: {{name}}</title>
<style>body{font:15px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0e1320;color:#e8edf6;margin:0;padding:28px}
.wrap{max-width:900px;margin:0 auto}h1{font-size:22px}.sum{color:#94a2ba}
.grade{font-weight:700}.good{color:#46d19e}.warn{color:#ffcb61}.bad{color:#f2607a}
.w{border:1px solid #263149;border-left:4px solid #263149;border-radius:9px;padding:11px 14px;margin:9px 0;background:#141b2b}
.w.critical,.w.high{border-left-color:#f2607a}.w.medium{border-left-color:#ffcb61}.w.low{border-left-color:#5a86ff}
.t{font-weight:600}.why{color:#94a2ba;font-size:13.5px;margin-top:3px}.ctl{color:#7fe4d8;font-size:13px;margin-top:5px}
.sev{font-size:11px;font-weight:700;padding:1px 7px;border-radius:20px;margin-right:6px}
.sev.critical,.sev.high{background:rgba(242,96,122,.16);color:#f2607a}.sev.medium{background:rgba(255,203,97,.16);color:#ffcb61}
.sev.low{background:rgba(90,134,255,.16);color:#5a86ff}
table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}th,td{border:1px solid #263149;padding:7px 9px;text-align:left;vertical-align:top}
th{color:#94a2ba}</style></head><body><div class="wrap">
<h1>Mimar threat model: {{name}}</h1>
<p class="sum"><span class="grade {{grade_class}}">Score {{score}} of 100, grade {{grade}}.</span>
{{zones}} zones, {{elements}} components, {{flows}} flows, {{weaknesses}} architecture weaknesses, {{threats}} STRIDE threats.</p>
<h2>Architecture weaknesses</h2>{{wrows}}
<h2>STRIDE threat register</h2>
<table><tr><th>Category</th><th>Component</th><th>Threat</th><th>First mitigation</th></tr>{{trows}}</table>
</div></body></html>"""
