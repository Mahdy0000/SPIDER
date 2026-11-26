"""Measure a model on known-vulnerable files: python benchmark/run.py [--model M] [--tolerance 2]

A finding matches an expected one when OWASP code agrees and the line is within the tolerance.
Reports recall (expected found) and precision (findings that matched). Needs a running Ollama."""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from spider import scanner  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


def score(findings, expected, tol):
    hit = set()
    matched = 0
    for f in findings:
        for i, e in enumerate(expected):
            if f["owasp"][:3] == e["owasp"] and abs(f["line"] - e["line"]) <= tol:
                hit.add(i)
                matched += 1
                break
    recall = len(hit) / len(expected) if expected else 1.0
    precision = matched / len(findings) if findings else 0.0
    return recall, precision


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", default=os.environ.get("SPIDER_MODEL", "dolphinlabs/llama3.2-3b-uncensored"))
    p.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    p.add_argument("--tolerance", type=int, default=2)
    a = p.parse_args()
    cases = json.load(open(os.path.join(ROOT, "benchmark", "cases.json")))
    for c in cases:
        path = os.path.join(ROOT, c["file"])
        fs = scanner.scan_file(path, a.host, a.model)
        r, pr = score(fs, c["expected"], a.tolerance)
        print(f"{c['file']}: recall {r:.0%} precision {pr:.0%} ({len(fs)} findings, model {a.model})")


if __name__ == "__main__":
    main()
