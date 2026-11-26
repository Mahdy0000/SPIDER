import argparse
import os
import sys

from . import __version__, report, scanner
from .ollama import OllamaError


def main(argv=None):
    p = argparse.ArgumentParser(prog="spider",
                                description="S.P.I.D.E.R phase 1: local-LLM SAST. Reviews YOUR OWN code for security flaws.")
    p.add_argument("target", help="file or folder to review")
    p.add_argument("--model", default=os.environ.get("SPIDER_MODEL", "qwen2.5-coder:7b"),
                   help="Ollama model (default: qwen2.5-coder:7b, env SPIDER_MODEL)")
    p.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    p.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    p.add_argument("-o", "--output", help="write report to this file")
    p.add_argument("--timeout", type=int, default=300, help="per-request timeout seconds")
    p.add_argument("--fail-on", choices=scanner.SEVERITIES, help="exit 2 if a finding at/above this severity exists")
    p.add_argument("--version", action="version", version=__version__)
    a = p.parse_args(argv)

    if not os.path.exists(a.target):
        print(f"error: {a.target} not found", file=sys.stderr)
        return 1
    if not a.host.startswith("http"):
        a.host = "http://" + a.host
    files = scanner.collect_files(a.target)
    if not files:
        print("error: no supported source files found", file=sys.stderr)
        return 1

    findings = []
    try:
        for n, f in enumerate(files, 1):
            print(f"[{n}/{len(files)}] reviewing {f}", file=sys.stderr)
            findings += scanner.scan_file(f, a.host, a.model, a.timeout)
    except OllamaError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    findings = scanner.sort_findings(findings)
    meta = {"model": a.model, "files": len(files), "tool": "spider", "version": __version__}
    render = {"text": report.to_text, "json": report.to_json, "markdown": report.to_markdown}[a.format]
    out = render(findings, meta)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"report written to {a.output}", file=sys.stderr)
    else:
        print(out)
    if a.fail_on:
        limit = scanner.SEVERITIES.index(a.fail_on)
        if any(scanner.SEVERITIES.index(f["severity"]) <= limit for f in findings):
            return 2
    return 0
