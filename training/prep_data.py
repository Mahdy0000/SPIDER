"""Turn dataset/ into instruction-tuning data for the SPIDER reviewer model.

    python training/prep_data.py                 # writes training/data/train.jsonl, val.jsonl, stats.json
    python training/prep_data.py --help

Reads dataset/all.jsonl, or merges the dataset/*.jsonl shards in memory when all.jsonl is absent.

Design goal: the model is trained on EXACTLY the prompts the tool sends and the JSON it parses.
System prompts, the line-numbered user prompt and the RAG "reference notes" block are built with the
real spider.prompt / spider.knowledge / spider.verify code, so training and serving cannot drift apart.

Task mix (all defensive: the targets never contain exploits or attack payloads):
  review   file -> {"findings": [...]}      the SAST prompt (main task; vulnerable code and fixed code)
  verify   finding + code window -> verdict  the --verify prompt (so the second-opinion pass keeps working)
  explain  (optional, --extra-tasks) free-text explanation of the flaw and its fix
  fix      (optional, --extra-tasks) corrected code for the flagged lines

How the dataset's quirks are handled:
  * Heuristic labels (CyberNative: OWASP assigned by keyword rules, source id prefix C): kept, but capped per
    OWASP category so they do not dominate, labelled confidence "medium" in the target, never given an invented CWE.
  * Missing CWE: the target's "cwe" field is "" (the tool's schema allows it). Nothing is guessed.
  * Rows with no OWASP Top 10 category (memory safety etc.): "owasp" is "N/A"; the tool shows it as Unmapped.
  * Juice Shop rows: the "vulnerable" side is an INCORRECT candidate fix, so its description uses the note that
    explains why it is still flawed.
  * Line numbers are not in the dataset. They are computed by diffing vulnerable_code against fixed_code (first
    changed region); the target's fixed_code is the replacement for exactly those lines, which is what
    `spider --patch` applies. Severity is a coarse prior per OWASP category (the dataset has none).
  * Noise: rows with stray CJK/Cyrillic/Arabic/Thai characters in the code (a known artefact of the generated
    CyberNative rows), duplicates, rows with no real change, and rows too long for the training window are dropped.
  * Hard negatives: a share of fixed-code samples train {"findings": []} so the model learns to stay quiet on
    code that is already fixed.
  * Leakage guard: any row whose code matches the benchmark fixture (tests/fixtures/*, benchmark/) is excluded,
    and the validation split is held out by id, never used for training.
"""
import argparse
import difflib
import glob
import hashlib
import json
import os
import random
import re
import sys
from collections import Counter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
from spider import knowledge, verify  # noqa: E402
from spider.owasp import OWASP_2021  # noqa: E402
from spider.prompt import SYSTEM_PROMPT, user_prompt  # noqa: E402

CHUNK_LINES = 300
NOISE = re.compile("[\u0400-\u04ff\u0590-\u06ff\u0e00-\u0e7f\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]")
EXT = {"python": "py", "javascript": "js", "typescript": "ts", "java": "java", "php": "php", "ruby": "rb",
       "go": "go", "c": "c", "cpp": "cpp", "c++": "cpp", "c#": "cs", "csharp": "cs", "rust": "rs", "kotlin": "kt",
       "swift": "swift", "shell": "sh", "bash": "sh", "sql": "sql", "html": "html", "yaml": "yml", "sol": "sol",
       "dockerfile": "Dockerfile", "tf": "tf", "json": "json", "xml": "xml", "text": "txt"}
BASENAMES = ["app", "server", "handlers", "utils", "auth", "db", "service", "main", "views", "api"]
SEVERITY = {"A01": "high", "A02": "medium", "A03": "high", "A04": "medium", "A05": "medium", "A06": "medium",
            "A07": "high", "A08": "medium", "A09": "low", "A10": "high"}
MEMORY_CWES = {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-126", "CWE-415", "CWE-416",
               "CWE-787", "CWE-190", "CWE-191", "CWE-134", "CWE-131", "CWE-124", "CWE-123", "CWE-362"}
CWE_NAMES = {e["id"]: e["name"] for e in knowledge.load()}
FIX_TEXT = {  # short, generic remediation per OWASP category (the dataset has no per-row fix explanation)
    "A01": "Enforce the authorization check on the server for every access to this resource.",
    "A02": "Use a current, vetted cryptographic primitive and keep keys and secrets out of the source.",
    "A03": "Keep untrusted data out of the interpreter: use parameterized APIs or context-aware encoding.",
    "A04": "Add the missing control (limits, validation, secure default) in the design of this code path.",
    "A05": "Apply the secure configuration or remove the unsafe default.",
    "A06": "Upgrade or replace the vulnerable component and pin a patched version.",
    "A07": "Strengthen authentication and credential handling: no hard-coded secrets, proper session handling.",
    "A08": "Do not trust unverified data or code: verify integrity and avoid unsafe deserialization or dynamic code.",
    "A09": "Log security-relevant events and do not expose or lose the evidence needed to detect abuse.",
    "A10": "Validate and restrict outbound request targets with an allow-list.",
}
NA_FIX = "Fix the unsafe operation (bounds, lifetime or validation) as shown in fixed_code."


# ---------------------------------------------------------------- loading
def load_records(dataset_dir):
    all_path = os.path.join(dataset_dir, "all.jsonl")
    files = [all_path] if os.path.exists(all_path) else sorted(glob.glob(os.path.join(dataset_dir, "*.jsonl")))
    seen, out = set(), []
    for f in files:
        for line in open(f, encoding="utf-8"):
            if line.strip():
                r = json.loads(line)
                if r["id"] not in seen:
                    seen.add(r["id"])
                    out.append(r)
    return out, files


def fixture_texts():
    texts = []
    for pat in ("tests/fixtures/*", "benchmark/*"):
        for p in glob.glob(os.path.join(ROOT, pat)):
            if os.path.isfile(p) and p.endswith((".py", ".js", ".java", ".php", ".c", ".go", ".ts")):
                texts.append(open(p, encoding="utf-8", errors="replace").read())
    return texts


def _norm(t):
    return re.sub(r"\s+", " ", t.replace('"', "'")).strip()


def in_fixture(code, fixtures):
    """Conservative leakage guard: drop a row if any substantial line of it appears (quote/space-normalised) in a fixture."""
    lines = [_norm(l) for l in code.splitlines() if len(l.strip()) >= 18]
    texts = [_norm(t) for t in fixtures]
    return any(l in t for l in lines for t in texts)


def owasp_code(r):
    m = re.match(r"A(\d\d):2021", r.get("owasp", ""))
    return f"A{m.group(1)}" if m and f"A{m.group(1)}" in OWASP_2021 else "N/A"


def split_of(rid, val_frac):
    h = int(hashlib.sha1(rid.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    return "val" if h < val_frac else "train"


# ---------------------------------------------------------------- diff -> line span + replacement
def change_span(vuln, fixed, max_span=12):
    """(start, end, replacement_lines) with 1-based inclusive start/end in vuln, or None."""
    a, b = vuln.splitlines(), fixed.splitlines()
    ops = [o for o in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes() if o[0] != "equal"]
    if not ops or not a:
        return None
    i1, i2, j1, j2 = ops[0][1], ops[-1][2], ops[0][3], ops[-1][4]
    if i2 - i1 > max_span:  # one big rewrite: keep only the first changed region
        i1, i2, j1, j2 = ops[0][1], ops[0][2], ops[0][3], ops[0][4]
    if i1 == i2 or j1 == j2:  # pure insert/delete: anchor on a neighbouring unchanged line
        if i2 < len(a) and j2 < len(b):
            i2, j2 = i2 + 1, j2 + 1
        elif i1 > 0 and j1 > 0:
            i1, j1 = i1 - 1, j1 - 1
        else:
            return None
    if i2 - i1 > max_span:
        i2, j2 = i1 + max_span, min(j1 + max_span, len(b))
    return i1 + 1, i2, b[j1:j2]


def cwe_title(cwe):
    return f"{cwe} {CWE_NAMES[cwe]}" if cwe in CWE_NAMES else cwe


def describe(r):
    """(title, description) cleaned per source."""
    sid, cwe, desc = r["id"][0], r.get("cwe", ""), r.get("description", "").strip()
    if sid == "J":
        m = re.search(r"challenge '([^']+)'", desc)
        title = (m.group(1) if m else "Insecure code pattern") + " (flawed code)"
        return title, (r.get("notes") or desc).strip()
    if sid == "U":
        return (f"{cwe_title(cwe)} weakness" if cwe else "Memory-safety weakness",
                f"Code with a {cwe or 'security'} weakness; the fixed variant below removes it.")
    if sid == "B":
        m = re.match(r"(CVE-[\d-]+) in (\S+)", desc)
        label = f"{m.group(1)} ({m.group(2)})" if m else "a published CVE"
        return (f"{cwe_title(cwe)} weakness" if cwe else "Vulnerable function",
                f"Function that was fixed upstream for {label}: the original code contains the flaw.")
    first = re.split(r"(?<=[.!?])\s", desc, maxsplit=1)[0]
    title = first if len(first) <= 140 else first[:140].rsplit(" ", 1)[0].rstrip(",;:") + " ..."
    return title, desc


def severity_for(r):
    code = owasp_code(r)
    if code != "N/A":
        return SEVERITY[code]
    return "high" if r.get("cwe") in MEMORY_CWES else "medium"


def confidence_for(r):
    return "medium" if r["id"][0] == "C" else "high"  # C = heuristic OWASP label


def make_finding(r, start, end, repl):
    title, desc = describe(r)
    code = owasp_code(r)
    return {"title": title, "severity": severity_for(r), "owasp": code, "cwe": r.get("cwe", "") or "",
            "line": start, "end_line": end, "confidence": confidence_for(r), "description": desc,
            "fix": FIX_TEXT.get(code, NA_FIX), "fixed_code": "\n".join(repl)}


# ---------------------------------------------------------------- prompt builders (use the real tool code)
def numbered(code, start=0):
    return "\n".join(f"{start + i + 1}: {l}" for i, l in enumerate(code.splitlines()))


def path_for(r, k=0):
    ext = EXT.get(r.get("language", "").lower(), "txt")
    base = BASENAMES[int(hashlib.sha1((r["id"] + str(k)).encode()).hexdigest()[:4], 16) % len(BASENAMES)]
    return f"src/{base}.{ext}" if ext != "Dockerfile" else "Dockerfile"


def review_prompt(path, code, rng, rag_prob):
    refs = knowledge.format_refs(knowledge.retrieve(code)) if rng.random() < rag_prob else ""
    return user_prompt(path, numbered(code), "", refs)


def msgs(system, user, assistant):
    return [{"role": "system", "content": system}, {"role": "user", "content": user},
            {"role": "assistant", "content": assistant}]


def window(code, line, end, w=verify.WINDOW):
    lines = code.splitlines()
    a, b = max(line - w, 1), min(end + w, len(lines))
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(a, b + 1))


def verify_example(path, code, f, real, rng):
    claim = (f"Reported finding: {f['title']} ({f['cwe'] or f['owasp']}) at lines {f['line']}-{f['end_line']}.\n"
             f"Reviewer's description: {f['description']}")
    user = (f"File: {path}\n{claim}\n\nCode (line-numbered):\n{window(code, f['line'], f['end_line'])}\n\n"
            "Is this finding really present?")
    if real:
        ans = {"verdict": "real", "reason": f"Lines {f['line']}-{f['end_line']} contain the flaw: {f['description']}"[:300]}
    else:
        ans = {"verdict": "false_positive",
               "reason": f"Lines {f['line']}-{f['end_line']} already apply the fix, so the reported flaw is not present."}
    return msgs(verify.VERIFY_SYSTEM, user, json.dumps(ans, ensure_ascii=False))


# ---------------------------------------------------------------- main build
def build(args):
    rng = random.Random(args.seed)
    records, files = load_records(args.dataset)
    fixtures = fixture_texts()
    drop = Counter()
    ok = []
    for r in records:
        v, fx = r.get("vulnerable_code", ""), r.get("fixed_code", "")
        if not v.strip() or not fx.strip():
            drop["no vulnerable or no fixed code"] += 1
        elif v.strip() == fx.strip():
            drop["identical vulnerable and fixed"] += 1
        elif NOISE.search(v + fx):
            drop["stray non-Latin characters (generation noise)"] += 1
        elif len(v) > args.max_chars or len(fx) > args.max_chars:
            drop[f"longer than {args.max_chars} chars"] += 1
        elif len(v.splitlines()) > CHUNK_LINES:
            drop["more than one scanner chunk"] += 1
        elif in_fixture(v, fixtures) or in_fixture(fx, fixtures):
            drop["matches benchmark fixture"] += 1
        elif change_span(v, fx) is None:
            drop["no usable changed line range"] += 1
        else:
            ok.append(r)
    # cap per (source, OWASP) so heuristic CyberNative labels and Juliet templates do not dominate
    caps = {"C": args.max_cybernative_per_category, "U": args.max_juliet}
    rng.shuffle(ok)
    counts, kept = Counter(), []
    for r in ok:
        s = r["id"][0]
        key = (s, owasp_code(r)) if s == "C" else (s, "all")
        if s in caps and counts[key] >= caps[s]:
            drop["capped (heuristic/templated source)"] += 1
            continue
        counts[key] += 1
        kept.append(r)

    out = {"train": [], "val": []}
    by_split_short = {"train": {}, "val": {}}
    for r in kept:
        split = split_of(r["id"], args.val_frac)
        v, fx = r["vulnerable_code"], r["fixed_code"]
        s, e, repl = change_span(v, fx)
        short = len(v) < 500 and r["id"][0] in "OC" and not args.no_compose
        if short and rng.random() < args.compose_frac:
            by_split_short[split].setdefault(r.get("language", "").lower(), []).append(r)
            continue
        f = make_finding(r, s, e, repl)
        path = path_for(r)
        add = out[split].append
        add({"messages": msgs(SYSTEM_PROMPT, review_prompt(path, v, rng, args.rag_prob),
                              json.dumps({"findings": [f]}, ensure_ascii=False)),
             "meta": {"id": r["id"], "kind": "review", "source": r["id"][0]}})
        if rng.random() < args.negative_frac:
            add({"messages": msgs(SYSTEM_PROMPT, review_prompt(path, fx, rng, args.rag_prob),
                                  json.dumps({"findings": []})),
                 "meta": {"id": r["id"], "kind": "review_clean", "source": r["id"][0]}})
        if rng.random() < args.verify_frac:
            add({"messages": verify_example(path, v, f, True, rng), "meta": {"id": r["id"], "kind": "verify_real", "source": r["id"][0]}})
            add({"messages": verify_example(path, fx, f, False, rng), "meta": {"id": r["id"], "kind": "verify_fp", "source": r["id"][0]}})
        if args.extra_tasks and rng.random() < 0.5:
            u = f"Explain the security flaw in this {r.get('language', 'code')} code and how to fix it. Defensive review only.\n\n{v}"
            a = f"{f['title']}. {f['description']}\n\nFix: {f['fix']}"
            add({"messages": msgs("You are a defensive application-security code reviewer.", u, a),
                 "meta": {"id": r["id"], "kind": "explain", "source": r["id"][0]}})
            u = f"Rewrite this {r.get('language', 'code')} code so it is not vulnerable. Return only the corrected code.\n\n{v}"
            add({"messages": msgs("You are a defensive application-security code reviewer.", u, fx),
                 "meta": {"id": r["id"], "kind": "fix", "source": r["id"][0]}})

    # composite files: several short same-language snippets in one file, several findings (closer to real files)
    for split, langs in by_split_short.items():
        for lang, rows in langs.items():
            i = 0
            while i < len(rows):
                group = rows[i:i + rng.randint(2, 4)]
                i += len(group)
                parts, findings, off = [], [], 0
                for r in group:
                    s, e, repl = change_span(r["vulnerable_code"], r["fixed_code"])
                    f = make_finding(r, s + off, e + off, repl)
                    findings.append(f)
                    parts.append(r["vulnerable_code"].rstrip("\n"))
                    off += len(parts[-1].splitlines()) + 2
                code = "\n\n\n".join(parts)
                findings.sort(key=lambda x: x["line"])
                out[split].append({"messages": msgs(SYSTEM_PROMPT, review_prompt(path_for(group[0], 9), code, rng, args.rag_prob),
                                                    json.dumps({"findings": findings}, ensure_ascii=False)),
                                   "meta": {"id": "+".join(g["id"] for g in group), "kind": "review_multi", "source": "mixed"}})
    for k in out:
        rng.shuffle(out[k])
    return out, drop, files, len(records)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dataset", default=os.path.join(ROOT, "dataset"))
    p.add_argument("--out", default=os.path.join(ROOT, "training", "data"))
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--val-frac", type=float, default=0.1, help="share of ids held out for validation/eval")
    p.add_argument("--max-chars", type=int, default=6000, help="skip rows whose code is longer (T4 fits ~2k tokens)")
    p.add_argument("--max-cybernative-per-category", type=int, default=60)
    p.add_argument("--max-juliet", type=int, default=30)
    p.add_argument("--negative-frac", type=float, default=0.3, help="share of rows that also add a fixed-code, no-findings example")
    p.add_argument("--verify-frac", type=float, default=0.2, help="share of rows that also add --verify style examples")
    p.add_argument("--compose-frac", type=float, default=0.5, help="share of short snippets merged into multi-finding files")
    p.add_argument("--no-compose", action="store_true")
    p.add_argument("--rag-prob", type=float, default=0.7, help="how often the prompt carries the tool's CWE reference notes")
    p.add_argument("--extra-tasks", action="store_true", help="also add free-text explain and fix tasks")
    a = p.parse_args()

    out, drop, files, total = build(a)
    os.makedirs(a.out, exist_ok=True)
    stats = {"input_records": total, "input_files": [os.path.basename(f) for f in files], "dropped": dict(drop)}
    for split, rows in out.items():
        with open(os.path.join(a.out, f"{split}.jsonl"), "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        stats[split] = {"examples": len(rows), "by_kind": dict(Counter(r["meta"]["kind"] for r in rows)),
                        "by_source": dict(Counter(r["meta"]["source"] for r in rows))}
    with open(os.path.join(a.out, "stats.json"), "w") as fh:
        json.dump(stats, fh, indent=2)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
