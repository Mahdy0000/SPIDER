import argparse
import os
import sys

from . import __version__, patch, report, scanner
from .ollama import OllamaError


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == "web":
        from . import webcli
        return webcli.main(argv[1:])
    return code_main(argv)


def code_main(argv):
    p = argparse.ArgumentParser(prog="spider",
                                epilog="Web review of a running app: spider web URL --help",
                                description="S.P.I.D.E.R phase 1: local-LLM SAST. Reviews YOUR OWN code for security flaws.")
    p.add_argument("target", help="file or folder to review")
    p.add_argument("--model", default=os.environ.get("SPIDER_MODEL", "dolphinlabs/llama3.2-3b-uncensored"),
                   help="Ollama model (default: dolphinlabs/llama3.2-3b-uncensored, env SPIDER_MODEL)")
    p.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    p.add_argument("--format", choices=list(report.RENDERERS), default="text")
    p.add_argument("-o", "--output", help="write report to this file")
    p.add_argument("--timeout", type=int, default=300, help="per-request timeout seconds")
    p.add_argument("--fail-on", choices=scanner.SEVERITIES, help="exit 2 if a finding at/above this severity exists")
    p.add_argument("--patch", metavar="FILE", help="also write a unified diff of suggested fixes (never edits your files)")
    p.add_argument("--verify", action="store_true", help="second-opinion pass on each finding (extra model call per finding)")
    p.add_argument("--hide-false-positives", action="store_true", help="with --verify: drop findings the second pass rejects")
    p.add_argument("--no-rag", action="store_true", help="disable the local CWE/OWASP knowledge hints")
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
            findings += scanner.scan_file(f, a.host, a.model, a.timeout, project_files=files,
                                         root=a.target if os.path.isdir(a.target) else None, use_rag=not a.no_rag)
    except OllamaError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if a.verify:
        from . import verify
        try:
            findings = verify.verify_all(findings, host=a.host, model=a.model, timeout=a.timeout,
                                         hide_false_positives=a.hide_false_positives)
        except OllamaError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    findings = scanner.sort_findings(findings)
    meta = {"model": a.model, "files": len(files), "tool": "spider", "version": __version__}
    render = report.RENDERERS[a.format]
    out = render(findings, meta)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"report written to {a.output}", file=sys.stderr)
    else:
        print(out)
    if a.patch:
        diff = patch.build_patch(findings)
        with open(a.patch, "w", encoding="utf-8") as fh:
            fh.write(diff)
        print(f"patch written to {a.patch} ({'empty' if not diff else 'review, then: git apply ' + a.patch})", file=sys.stderr)
    if a.fail_on:
        limit = scanner.SEVERITIES.index(a.fail_on)
        if any(scanner.SEVERITIES.index(f["severity"]) <= limit for f in findings):
            return 2
    return 0
