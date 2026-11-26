"""Review agent loop (ReAct style) over a fixed, read-only tool set. The model chooses which pages to inspect;
it cannot run anything else, and every request still goes through the allowlist-checked client."""
import json
import re
from urllib.parse import urljoin, urlsplit

from .. import ollama
from ..owasp import OWASP_2021, normalize_owasp
from . import checks
from .pages import Page
from .scope import ScopeError

SYSTEM = """You are a defensive web application security reviewer working on a system its owner authorized you to review.
You can only use these read-only tools by replying with ONE JSON object per turn:
{"action": "fetch", "url": "<url>"}                    read a page (headers + a short text summary)
{"action": "reflect", "url": "<url with query>"}       send a harmless unique marker in each query parameter and report if it is echoed unescaped
{"action": "finish", "findings": [ ... ]}              end the review
Rules: defensive review only. No exploit payloads, no credential guessing, no attacks. Pages outside the allowlist are refused.
Only report weaknesses supported by something you observed in a tool result; put that observation in "evidence" and the page in "url".
Finding shape: {"title": str, "severity": "critical|high|medium|low|info", "owasp": "A01..A10", "cwe": str, "url": str,
 "evidence": str, "description": str, "fix": str, "confidence": "high|medium|low"}
OWASP categories: """ + "; ".join(f"{k} {v}" for k, v in OWASP_2021.items())


def summarize(page, limit=1500):
    r = page.response
    hdrs = {k: v for k, v in r.headers.items() if k.lower() in ("server", "content-type", "set-cookie", "content-security-policy",
                                                               "x-frame-options", "access-control-allow-origin", "location")}
    text = re.sub(r"<(script|style).*?</\1>", "", r.body, flags=re.S | re.I)
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()[:limit]
    forms = [{"action": f["action"], "method": f["method"], "fields": [x["name"] for x in f["inputs"]]} for f in page.forms[:5]]
    return json.dumps({"url": page.url, "status": r.status, "headers": hdrs, "forms": forms, "links": page.links[:15], "text": text})


def parse_action(raw):
    try:
        d = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        m = re.search(r"\{.*\}", raw or "", re.S)
        try:
            d = json.loads(m.group(0)) if m else None
        except json.JSONDecodeError:
            d = None
    return d if isinstance(d, dict) else None


def run(client, start, host, model, pages=None, max_steps=8, timeout=300):
    """Returns (findings, transcript). Findings only count if their url was actually visited (grounding)."""
    visited = {p.url: p for p in (pages or [])}
    seen_text = "Pages already crawled: " + ", ".join(list(visited)[:20])
    msgs = [f"Start: {start}\n{seen_text}\nBegin the review."]
    transcript, proposed = [], []
    for step in range(max_steps):
        raw = ollama.chat(host, model, SYSTEM, "\n\n".join(msgs[-6:]), timeout)
        act = parse_action(raw)
        transcript.append({"step": step, "model": (raw or "")[:300]})
        if not act or act.get("action") == "finish":
            proposed = (act or {}).get("findings", []) if isinstance(act, dict) else []
            break
        kind, url = act.get("action"), act.get("url")
        if kind not in ("fetch", "reflect") or not isinstance(url, str):
            msgs.append("Tool error: unknown action. Use fetch, reflect or finish.")
            continue
        url = urljoin(start, url)
        try:
            client.scope.check(url)
            if kind == "fetch":
                page = Page(client.get(url))
                visited[page.url] = page
                msgs.append("Tool result: " + summarize(page))
            else:
                page = Page(client.get(url))
                visited[page.url] = page
                hits = checks.check_reflection(client, page)
                msgs.append("Tool result: " + (json.dumps([h["title"] for h in hits]) if hits else "no unescaped reflection"))
        except ScopeError as e:
            msgs.append(f"Tool error (out of scope, refused): {e}")
        except Exception as e:  # network errors, budget
            msgs.append(f"Tool error: {e}")
            if "budget" in str(e):
                break
    out = []
    for i in proposed if isinstance(proposed, list) else []:
        if not isinstance(i, dict) or not i.get("evidence"):
            continue
        url = str(i.get("url", ""))
        if url not in visited:  # grounding rule: cannot report on pages that were never fetched
            continue
        sev = str(i.get("severity", "low")).lower()
        f = checks.finding("agent", url, str(i.get("title", "Untitled"))[:120],
                           sev if sev in ("critical", "high", "medium", "low", "info") else "low",
                           i.get("owasp"), str(i.get("cwe", "") or ""), str(i.get("description", "")), str(i.get("fix", "")),
                           str(i.get("evidence", ""))[:300], str(i.get("confidence", "low")).lower())
        f["source"] = "agent"
        out.append(f)
    return out, transcript
