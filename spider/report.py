import json

from .scanner import SEVERITIES


def _loc(f):
    if f.get("kind") == "web":
        return f["file"]
    return f"{f['file']}:{f['line']}" + (f"-{f['end_line']}" if f["end_line"] != f["line"] else "")


def to_json(findings, meta):
    return json.dumps({"meta": meta, "findings": findings}, indent=2)


def to_markdown(findings, meta):
    out = ["# S.P.I.D.E.R security review", "",
           f"Model: `{meta['model']}` | Files scanned: {meta['files']} | Findings: {len(findings)}", ""]
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    out.append("Severity: " + ", ".join(f"{s} {n}" for s, n in counts.items() if n) if findings else "No findings.")
    out.append("")
    for i, f in enumerate(findings, 1):
        loc = _loc(f)
        out += [f"## {i}. [{f['severity'].upper()}] {f['title']}", "",
                f"- Location: `{loc}`", f"- OWASP: {f['owasp']}"]
        if f["cwe"]:
            out.append(f"- CWE: {f['cwe']}")
        out += [f"- Confidence: {f['confidence']}", "", f["description"], "", f"**Fix:** {f['fix']}"]
        if f["fixed_code"]:
            out += ["", "```", f["fixed_code"], "```"]
        out.append("")
    out.append("_LLM-generated review. Verify every finding before acting on it._")
    return "\n".join(out)


def to_text(findings, meta):
    if not findings:
        return f"No findings ({meta['files']} file(s) scanned with {meta['model']})."
    lines = []
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {_loc(f)}  {f['title']}")
        lines.append(f"           {f['owasp']}" + (f" | {f['cwe']}" if f["cwe"] else ""))
        lines.append(f"           {f['description']}")
        lines.append(f"           Fix: {f['fix']}")
        lines.append("")
    lines.append(f"{len(findings)} finding(s) in {meta['files']} file(s), model {meta['model']}.")
    return "\n".join(lines)


RENDERERS = {"text": to_text, "json": to_json, "markdown": to_markdown}
