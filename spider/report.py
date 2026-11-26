import html
import json

from .scanner import SEVERITIES

DISCLAIMER = "Model-assisted review. Findings are leads to verify, not a verdict. Only use on systems you own or are authorized to test."
DROPPED = ("not_reproduced", "likely_false_positive")
STRONG = ("reproduced", "likely_real")


from .owasp import owasp_2025


def _loc(f):
    if f.get("kind") == "web":
        return f["file"]
    return f"{f['file']}:{f['line']}" + (f"-{f['end_line']}" if f["end_line"] != f["line"] else "")


def _status(f):
    return f.get("verification", {}).get("status")


def summarize(findings, meta):
    """Counts and a short 'fix first' list. Rejected findings are never recommended."""
    by_sev = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    by_owasp = {}
    for f in findings:
        by_owasp[f["owasp"]] = by_owasp.get(f["owasp"], 0) + 1
    verif = {}
    for f in findings:
        k = _status(f) or "not_verified"
        verif[k] = verif.get(k, 0) + 1
    live = [f for f in findings if _status(f) not in DROPPED]
    ranked = sorted(live, key=lambda f: (SEVERITIES.index(f["severity"]), 0 if _status(f) in STRONG else 1,
                                         {"high": 0, "medium": 1}.get(f["confidence"], 2)))
    return {"total": len(findings), "by_severity": {k: v for k, v in by_sev.items() if v},
            "by_owasp": dict(sorted(by_owasp.items())), "verification": verif,
            "fix_first": [{"title": f["title"], "severity": f["severity"], "location": _loc(f), "status": _status(f) or "not_verified"}
                          for f in ranked[:5]],
            "scope": meta.get("scope"), "requests": meta.get("requests")}


def _verif_md(f):
    v = f.get("verification")
    return [f"- Verification: {v['status']} ({v['method']})" + (f": {v['note']}" if v["note"] else "")] if v else []


def to_json(findings, meta):
    return json.dumps({"meta": meta, "summary": summarize(findings, meta), "findings": findings}, indent=2)


def _summary_lines(s, meta):
    lines = []
    if meta.get("mode") == "web":
        lines.append(f"Target: {meta.get('target')} | Scope: {meta.get('scope')} | Pages: {meta['files']} | Requests: {meta.get('requests')}")
    else:
        lines.append(f"Files scanned: {meta['files']}")
    lines.append(f"Model: {meta['model']}")
    lines.append("Severity: " + (", ".join(f"{k} {v}" for k, v in s["by_severity"].items()) or "none"))
    if any(k != "not_verified" for k in s["verification"]):
        lines.append("Verification: " + ", ".join(f"{k} {v}" for k, v in s["verification"].items()))
    return lines


def to_markdown(findings, meta):
    s = summarize(findings, meta)
    out = ["# S.P.I.D.E.R security review", "", "## Summary", ""]
    out += [f"- {l}" for l in _summary_lines(s, meta)]
    out.append("")
    if s["by_owasp"]:
        out += ["| OWASP 2021 category | Findings |", "|---|---|"] + [f"| {k} | {v} |" for k, v in s["by_owasp"].items()] + [""]
    if s["fix_first"]:
        out += ["### Fix first", ""] + [f"{i}. **[{x['severity'].upper()}]** {x['title']} (`{x['location']}`, {x['status']})"
                                          for i, x in enumerate(s["fix_first"], 1)] + [""]
    if not findings:
        out += ["No findings.", ""]
    out.append("## Findings")
    out.append("")
    for i, f in enumerate(findings, 1):
        out += [f"### {i}. [{f['severity'].upper()}] {f['title']}", "", f"- Location: `{_loc(f)}`", f"- OWASP: {f['owasp']} (2025 list: {owasp_2025(f['owasp'], f['cwe'])})"]
        if f["cwe"]:
            out.append(f"- CWE: {f['cwe']}")
        out += [f"- Confidence: {f['confidence']}"] + _verif_md(f)
        if f.get("evidence"):
            out.append(f"- Evidence: {f['evidence']}")
        out += ["", f["description"], "", f"**Fix:** {f['fix']}"]
        if f["fixed_code"]:
            out += ["", "```", f["fixed_code"], "```"]
        out.append("")
    out.append(f"_{DISCLAIMER}_")
    return "\n".join(out)


def to_text(findings, meta):
    s = summarize(findings, meta)
    if not findings:
        return "\n".join(_summary_lines(s, meta)) + "\nNo findings."
    lines = []
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {_loc(f)}  {f['title']}")
        lines.append(f"           {f['owasp']}" + (f" | {f['cwe']}" if f["cwe"] else ""))
        lines.append(f"           {f['description']}")
        if f.get("verification"):
            lines.append(f"           Verification: {f['verification']['status']} ({f['verification']['method']})")
        lines.append(f"           Fix: {f['fix']}")
        lines.append("")
    lines.append(f"{len(findings)} finding(s) in {meta['files']} file(s), model {meta['model']}.")
    lines += _summary_lines(s, meta)
    if s["fix_first"]:
        lines.append("Fix first: " + "; ".join(f"{x['title']} ({x['severity']})" for x in s["fix_first"][:3]))
    return "\n".join(lines)


def to_sarif(findings, meta):
    """SARIF 2.1.0, importable by GitHub code scanning and most IDEs."""
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules, idx, results = [], {}, []
    for f in findings:
        rid = f.get("cwe") or f["owasp"].split(" ")[0]
        key = (rid, f["title"])
        if key not in idx:
            idx[key] = len(rules)
            rules.append({"id": f"{rid}:{f['title'][:60]}", "name": f["title"][:80], "shortDescription": {"text": f["title"]},
                          "help": {"text": f["fix"] or f["description"]}, "properties": {"owasp": f["owasp"], "cwe": f["cwe"]}})
        loc = {"artifactLocation": {"uri": f["file"].replace("\\", "/")}}
        if f.get("kind") != "web":
            loc["region"] = {"startLine": f["line"], "endLine": f["end_line"]}
        results.append({"ruleId": rules[idx[key]]["id"], "ruleIndex": idx[key], "level": level[f["severity"]],
                        "message": {"text": f["description"] or f["title"]}, "locations": [{"physicalLocation": loc}],
                        "properties": {"severity": f["severity"], "confidence": f["confidence"], "owasp": f["owasp"],
                                       "verification": _status(f) or "not_verified"}})
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": "S.P.I.D.E.R", "version": meta.get("version", ""),
                                                     "informationUri": "https://github.com/Mahdy0000/SPIDER", "rules": rules}},
                                 "results": results}]}, indent=2)


def to_html(findings, meta):
    e = html.escape
    s = summarize(findings, meta)
    colors = {"critical": "#b00020", "high": "#d84315", "medium": "#ef8f00", "low": "#2e7d32", "info": "#546e7a"}
    parts = ["<!doctype html><html><head><meta charset='utf-8'><title>S.P.I.D.E.R report</title><style>",
             "body{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:2em auto;padding:0 1em;color:#222}",
             ".f{border:1px solid #ddd;border-left:6px solid #888;border-radius:6px;padding:.6em 1em;margin:1em 0}",
             "code,pre{background:#f4f4f4;padding:2px 4px;border-radius:3px}pre{padding:.6em;overflow:auto}",
             "small{color:#666}</style></head><body><h1>S.P.I.D.E.R security review</h1><ul>"]
    parts += [f"<li>{e(l)}</li>" for l in _summary_lines(s, meta)] + ["</ul>"]
    if s["fix_first"]:
        parts.append("<h2>Fix first</h2><ol>" + "".join(
            f"<li><b>{e(x['severity'].upper())}</b> {e(x['title'])} <small>{e(x['location'])}</small></li>" for x in s["fix_first"]) + "</ol>")
    parts.append("<h2>Findings</h2>")
    for f in findings:
        v = f.get("verification")
        parts.append(f"<div class='f' style='border-left-color:{colors[f['severity']]}'><h3>[{e(f['severity'].upper())}] {e(f['title'])}</h3>"
                     f"<p><code>{e(_loc(f))}</code><br><small>{e(f['owasp'])}{' | ' + e(f['cwe']) if f['cwe'] else ''} | confidence {e(f['confidence'])}"
                     f"{' | verification ' + e(v['status']) if v else ''}</small></p><p>{e(f['description'])}</p><p><b>Fix:</b> {e(f['fix'])}</p>"
                     + (f"<pre>{e(f['fixed_code'])}</pre>" if f["fixed_code"] else "") + "</div>")
    if not findings:
        parts.append("<p>No findings.</p>")
    parts.append(f"<p><small>{e(DISCLAIMER)}</small></p></body></html>")
    return "".join(parts)


RENDERERS = {"text": to_text, "json": to_json, "markdown": to_markdown, "sarif": to_sarif, "html": to_html}
