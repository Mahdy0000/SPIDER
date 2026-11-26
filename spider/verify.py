"""Finding verification stage: re-check each finding before it is reported, to cut false positives.

This stage never produces exploits or attack steps. It only *re-examines* what was already reported:
- web findings from a deterministic check: re-fetch the page and re-run the same check ("reproduced" / "not_reproduced").
- web findings from the agent loop: an independent model pass over the evidence and a fresh copy of the page.
- code findings: an independent model pass over the cited code window, asked to trace the code path and say
  whether the flaw is really present.
Every finding gets a `verification` dict: {"status", "method", "note"}. Statuses:
  reproduced, not_reproduced        deterministic (web checks)
  likely_real, likely_false_positive, uncertain   model judgement (treat as a second opinion, not proof)
"""
import json
import os

from . import ollama
from .web import agent as web_agent
from .web import checks as web_checks
from .web.pages import Page

DROPPED = ("not_reproduced", "likely_false_positive")
WINDOW = 20

VERIFY_SYSTEM = """You are a skeptical defensive security reviewer double-checking ONE reported finding in the developer's own code.
Decide whether the flaw is really present in the code shown. Trace how the data reaches the risky operation; check for sanitization,
parameterization, validation or framework protections that already prevent the problem. Do NOT write exploits or attack payloads.
Respond with ONLY JSON: {"verdict": "real|false_positive|uncertain", "reason": "one or two sentences citing the line numbers"}"""

WEB_VERIFY_SYSTEM = """You are a skeptical defensive web security reviewer double-checking ONE reported finding on a site its owner authorized you to review.
You get the claim, the evidence the first reviewer cited, and a fresh read of the page. Say whether the page actually supports the claim.
Do NOT suggest attacks. Respond with ONLY JSON: {"verdict": "real|false_positive|uncertain", "reason": "one or two sentences"}"""


def _verdict(raw):
    d = web_agent.parse_action(raw) or {}
    v = str(d.get("verdict", "")).lower()
    status = {"real": "likely_real", "false_positive": "likely_false_positive"}.get(v, "uncertain")
    return status, str(d.get("reason", ""))[:300]


def _window(path, line, end):
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    a, b = max(line - WINDOW, 1), min(end + WINDOW, len(lines))
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(a, b + 1))


def verify_code(f, host, model, timeout=300):
    if not os.path.isfile(f["file"]):
        return {"status": "uncertain", "method": "llm-second-pass", "note": "source file not readable"}
    claim = (f"Reported finding: {f['title']} ({f['cwe'] or f['owasp']}) at lines {f['line']}-{f['end_line']}.\n"
             f"Reviewer's description: {f['description']}")
    prompt = f"File: {f['file']}\n{claim}\n\nCode (line-numbered):\n{_window(f['file'], f['line'], f['end_line'])}\n\nIs this finding really present?"
    status, reason = _verdict(ollama.chat(host, model, VERIFY_SYSTEM, prompt, timeout))
    return {"status": status, "method": "llm-second-pass", "note": reason}


def _fresh_page(client, url):
    return Page(client.get(url))


def recheck_web(f, client):
    """Deterministic re-run of the check that produced f. Returns a verification dict or None if not re-runnable."""
    cid, url = f.get("check_id", ""), f["file"]
    if cid == "agent" or not cid:
        return None
    try:
        if cid.startswith("path:"):
            again = web_checks.probe_paths(client, url)
        else:
            page = _fresh_page(client, url)
            if cid.startswith("cors:"):
                again = web_checks.check_cors(client, page)
            elif cid.startswith("reflect:"):
                again = web_checks.check_reflection(client, page)
            else:
                again = (web_checks.check_headers(page) + web_checks.check_cookies(page)
                         + web_checks.check_forms(page) + web_checks.check_content(page))
    except Exception as e:  # unreachable page, out of scope, budget: cannot confirm either way
        return {"status": "uncertain", "method": "re-fetch", "note": f"could not re-check: {e}"}
    ok = any(a["check_id"] == cid for a in again)
    return {"status": "reproduced" if ok else "not_reproduced", "method": "re-fetch and re-run the same check",
            "note": "seen again on a fresh request" if ok else "not seen on a fresh request"}


def verify_agent_web(f, client, host, model, timeout=300):
    try:
        summary = web_agent.summarize(_fresh_page(client, f["file"]))
    except Exception as e:
        return {"status": "uncertain", "method": "llm-second-pass", "note": f"could not re-fetch: {e}"}
    prompt = f"Claim: {f['title']} on {f['file']}\nCited evidence: {f.get('evidence', '')}\nDescription: {f['description']}\n\nFresh page read:\n{summary}"
    status, reason = _verdict(ollama.chat(host, model, WEB_VERIFY_SYSTEM, prompt, timeout))
    return {"status": status, "method": "llm-second-pass", "note": reason}


def verify_all(findings, client=None, host=None, model=None, timeout=300, hide_false_positives=False):
    out = []
    for f in findings:
        if f.get("kind") == "web":
            v = recheck_web(f, client) if client else None
            if v is None:
                v = verify_agent_web(f, client, host, model, timeout) if client else \
                    {"status": "uncertain", "method": "none", "note": "no client"}
        else:
            v = verify_code(f, host, model, timeout)
        f = dict(f, verification=v)
        if v["status"] in DROPPED:
            f["confidence"] = "low"
        out.append(f)
    if hide_false_positives:
        out = [f for f in out if f["verification"]["status"] not in DROPPED]
    return out


def summary_counts(findings):
    c = {}
    for f in findings:
        s = f.get("verification", {}).get("status", "not_verified")
        c[s] = c.get(s, 0) + 1
    return c
