"""Before/after evaluation against a running Ollama. Run it once per model, then compare.

    python training/prep_data.py                                   # makes training/data/val.jsonl (held out, never trained on)
    python training/evaluate.py --model dolphinlabs/llama3.2-3b-uncensored --label before
    python training/evaluate.py --model spider-reviewer --label after
    python training/evaluate.py --compare before after

Two measurements are written to training/results/<label>.json:
  benchmark  benchmark/cases.json, the same score as benchmark/run.py (recall/precision, line tolerance 2).
             It is tiny: ONE file with 4 expected findings. One more or fewer hit moves recall by 25 points.
  heldout    the validation split from prep_data.py (about 100 review prompts, same format the tool sends):
             recall      share of vulnerable samples where a finding has the right OWASP category and a line within --tolerance
             precision   share of reported findings that match a labelled one
             clean_alarm share of already-fixed samples where the model still reports something (lower is better)
             json_ok     share of answers that parse as the findings JSON
           Caveat: the held-out rows come from the same sources as the training rows (about 40% are CyberNative rows with
           heuristic labels), so this measures fit to the dataset's style, not real-world recall. Line spans come from a diff.
Nothing here proves performance on your own code. Treat the numbers as a sanity check.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "benchmark"))
from spider import ollama, scanner  # noqa: E402
import run as bench  # noqa: E402  (benchmark/run.py)


def run_benchmark(host, model, tol):
    cases = json.load(open(os.path.join(ROOT, "benchmark", "cases.json")))
    out, rs, ps = [], [], []
    for c in cases:
        fs = scanner.scan_file(os.path.join(ROOT, c["file"]), host, model)
        r, p = bench.score(fs, c["expected"], tol)
        out.append({"file": c["file"], "recall": r, "precision": p, "findings": len(fs)})
        rs.append(r)
        ps.append(p)
    return {"cases": out, "recall": sum(rs) / len(rs), "precision": sum(ps) / len(ps),
            "expected_findings_total": sum(len(c["expected"]) for c in cases)}


def run_heldout(host, model, tol, limit, timeout):
    rows = [json.loads(l) for l in open(os.path.join(HERE, "data", "val.jsonl")) if l.strip()]
    rows = [r for r in rows if r["meta"]["kind"] in ("review", "review_multi", "review_clean")][:limit]
    exp_total = hit_total = found_total = matched_total = 0
    clean = clean_alarm = ok = errors = 0
    for r in rows:
        sysm, user, gold = (m["content"] for m in r["messages"])
        expected = json.loads(gold)["findings"]
        try:
            raw = ollama.chat(host, model, sysm, user, timeout)
        except ollama.OllamaError as e:
            errors += 1
            print("error:", e, file=sys.stderr)
            continue
        try:
            json.loads(raw)
            ok += 1
        except ValueError:
            pass
        found = scanner.parse_findings(raw)
        if not expected:
            clean += 1
            clean_alarm += 1 if found else 0
            continue
        hit = set()
        for f in found:
            try:
                line = int(f.get("line", -99))
            except (TypeError, ValueError):
                continue
            for i, e in enumerate(expected):
                if str(f.get("owasp", ""))[:3].upper() == e["owasp"][:3] and abs(line - e["line"]) <= tol:
                    hit.add(i)
                    matched_total += 1
                    break
        exp_total += len(expected)
        hit_total += len(hit)
        found_total += len(found)
    n = len(rows) - errors
    return {"prompts": len(rows), "errors": errors, "vulnerable_prompts": n - clean, "clean_prompts": clean,
            "recall": hit_total / exp_total if exp_total else None,
            "precision": matched_total / found_total if found_total else None,
            "clean_alarm": clean_alarm / clean if clean else None, "json_ok": ok / n if n else None}


def pct(x):
    return "n/a" if x is None else f"{x:.0%}"


def compare(a, b):
    ra, rb = (json.load(open(os.path.join(HERE, "results", f"{x}.json"))) for x in (a, b))
    print(f"{'metric':28}{a:>14}{b:>14}   models: {ra['model']} -> {rb['model']}")
    for part, keys in (("benchmark", ("recall", "precision")), ("heldout", ("recall", "precision", "clean_alarm", "json_ok"))):
        for k in keys:
            va, vb = ra[part][k], rb[part][k]
            d = "" if va is None or vb is None else f"   ({(vb - va) * 100:+.0f} pts)"
            print(f"{part + ' ' + k:28}{pct(va):>14}{pct(vb):>14}{d}")
    print(f"benchmark has only {rb['benchmark']['expected_findings_total']} expected findings; heldout has "
          f"{rb['heldout']['vulnerable_prompts']} vulnerable + {rb['heldout']['clean_prompts']} clean prompts. Small samples: differences of a few points are noise.")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model")
    p.add_argument("--label")
    p.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    p.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    p.add_argument("--tolerance", type=int, default=2)
    p.add_argument("--heldout-tolerance", type=int, default=3)
    p.add_argument("--limit", type=int, default=120, help="max held-out prompts")
    p.add_argument("--timeout", type=int, default=300)
    a = p.parse_args()
    if a.compare:
        return compare(*a.compare)
    if not (a.model and a.label):
        p.error("need --model and --label (or --compare BEFORE AFTER)")
    res = {"model": a.model, "label": a.label, "benchmark": run_benchmark(a.host, a.model, a.tolerance),
           "heldout": run_heldout(a.host, a.model, a.heldout_tolerance, a.limit, a.timeout)}
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    path = os.path.join(HERE, "results", f"{a.label}.json")
    json.dump(res, open(path, "w"), indent=2)
    print(json.dumps(res, indent=2))
    print("saved", path)


if __name__ == "__main__":
    main()
