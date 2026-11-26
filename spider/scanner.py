import json
import os
import re

from . import ollama
from .owasp import normalize_owasp
from .prompt import SYSTEM_PROMPT, user_prompt

CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".rb", ".go", ".c", ".h",
            ".cpp", ".hpp", ".cs", ".rs", ".kt", ".swift", ".sh", ".sql", ".html", ".yml", ".yaml"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".idea"}
SEVERITIES = ["critical", "high", "medium", "low", "info"]
MAX_FILE_BYTES = 200_000
CHUNK_LINES = 300


def collect_files(target):
    if os.path.isfile(target):
        return [target]
    out = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for f in sorted(files):
            p = os.path.join(root, f)
            if os.path.splitext(f)[1].lower() in CODE_EXT and os.path.getsize(p) <= MAX_FILE_BYTES:
                out.append(p)
    return out


def chunks(lines):
    for start in range(0, max(len(lines), 1), CHUNK_LINES):
        yield start, lines[start:start + CHUNK_LINES]


def parse_findings(raw):
    """Parse model output into a list of dicts; tolerate code fences / extra text."""
    raw = raw.strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            return []
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []
    items = data.get("findings", []) if isinstance(data, dict) else data
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


def _int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def clean(item, path, total_lines):
    sev = str(item.get("severity", "medium")).lower()
    line = min(max(_int(item.get("line"), 1), 1), max(total_lines, 1))
    end = min(max(_int(item.get("end_line"), line), line), max(total_lines, 1))
    return {
        "file": path,
        "line": line,
        "end_line": end,
        "title": str(item.get("title", "Untitled finding")),
        "severity": sev if sev in SEVERITIES else "medium",
        "owasp": normalize_owasp(item.get("owasp")),
        "cwe": str(item.get("cwe", "") or ""),
        "confidence": str(item.get("confidence", "medium")).lower(),
        "description": str(item.get("description", "")),
        "fix": str(item.get("fix", "")),
        "fixed_code": str(item.get("fixed_code", "")),
    }


def scan_file(path, host, model, timeout=300):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    results = []
    for start, part in chunks(lines):
        numbered = "\n".join(f"{start + i + 1}: {l}" for i, l in enumerate(part))
        raw = ollama.chat(host, model, SYSTEM_PROMPT, user_prompt(path, numbered), timeout)
        results += [clean(i, path, len(lines)) for i in parse_findings(raw)]
    seen, uniq = set(), []
    for r in results:
        k = (r["line"], r["title"].lower())
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq


def sort_findings(findings):
    return sorted(findings, key=lambda f: (SEVERITIES.index(f["severity"]), f["file"], f["line"]))
