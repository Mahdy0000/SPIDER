"""Local knowledge base (RAG): bundled CWE/OWASP notes, retrieved by keyword overlap with the code.
No network, no embeddings. Add entries to data/cwe.json to extend it."""
import json
import os
import re

_PATH = os.path.join(os.path.dirname(__file__), "data", "cwe.json")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{2,}")


def load(path=_PATH):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def retrieve(code, k=3, kb=None):
    kb = kb if kb is not None else load()
    tokens = {t.lower() for t in _TOKEN.findall(code)}
    scored = []
    for e in kb:
        s = sum(1 for kw in e["keywords"] if kw.lower() in tokens or kw.lower() in code.lower())
        if s:
            scored.append((s, e))
    scored.sort(key=lambda x: -x[0])
    return [e for _, e in scored[:k]]


def format_refs(entries):
    return "\n".join(f"- {e['id']} ({e['owasp']}) {e['name']}: {e['guidance']}" for e in entries)
