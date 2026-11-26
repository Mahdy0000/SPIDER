import argparse
import os
import sys

from . import __version__, ollama, report, scanner
from .ollama import OllamaError
from .web import agent, checks, pages
from .web.client import ScopedClient
from .web.scope import Scope, ScopeError


def build_parser():
    p = argparse.ArgumentParser(prog="spider web", description="S.P.I.D.E.R web review. Read-only checks, only against hosts on YOUR allowlist.")
    p.add_argument("url", help="start URL (must be localhost or a host you pass with --allow)")
    p.add_argument("--allow", action="append", default=[], metavar="HOST",
                   help="host you own or are authorized to test (repeatable; also env SPIDER_ALLOW=a.com,b.com). localhost is always allowed")
    p.add_argument("--allow-file", metavar="FILE", help="file with one allowed host per line")
    p.add_argument("--max-pages", type=int, default=25)
    p.add_argument("--max-depth", type=int, default=2)
    p.add_argument("--max-requests", type=int, default=200, help="hard cap on HTTP requests")
    p.add_argument("--delay", type=float, default=0.2, help="seconds between requests")
    p.add_argument("--no-probe", action="store_true", help="passive only: skip reflection, sensitive-path and CORS probes")
    p.add_argument("--agent", action="store_true", help="also run the LLM review agent loop (needs Ollama)")
    p.add_argument("--agent-steps", type=int, default=8)
    p.add_argument("--model", default=None, help="Ollama model (default: SPIDER_MODEL, else spider-reviewer if installed, else dolphinlabs/llama3.2-3b-uncensored)")
    p.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--verify", action="store_true", help="re-check each finding on a fresh request before reporting")
    p.add_argument("--hide-false-positives", action="store_true", help="with --verify: drop findings that did not reproduce")
    p.add_argument("--format", choices=list(report.RENDERERS), default="text")
    p.add_argument("-o", "--output")
    p.add_argument("--fail-on", choices=scanner.SEVERITIES)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        scope = Scope.from_sources(a.allow, a.allow_file)
        scope.check(a.url)
    except ScopeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not a.host.startswith("http"):
        a.host = "http://" + a.host
    a.model = a.model or ollama.default_model(a.host)
    client = ScopedClient(scope, max_requests=a.max_requests, delay=a.delay)
    print(f"scope: {scope.describe()}", file=sys.stderr)
    try:
        crawled, errs = pages.crawl(client, a.url, a.max_pages, a.max_depth)
    except ScopeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    for e in errs:
        print(f"warning: {e}", file=sys.stderr)
    if not crawled:
        print("error: could not fetch the start URL", file=sys.stderr)
        return 1
    print(f"crawled {len(crawled)} page(s)", file=sys.stderr)
    findings = checks.run_all(client, crawled, probe=not a.no_probe)
    try:
        if a.agent:
            extra, _ = agent.run(client, a.url, a.host, a.model, crawled, a.agent_steps, a.timeout)
            findings += extra
        if a.verify:
            from . import verify
            findings = verify.verify_all(findings, client=client, host=a.host, model=a.model, timeout=a.timeout,
                                         hide_false_positives=a.hide_false_positives)
    except OllamaError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    findings = scanner.sort_findings(findings)
    meta = {"model": a.model if a.agent else "none (deterministic checks)", "files": len(crawled), "tool": "spider", "version": __version__,
            "mode": "web", "target": a.url, "scope": scope.describe(), "requests": client.count}
    out = report.RENDERERS[a.format](findings, meta)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"report written to {a.output}", file=sys.stderr)
    else:
        print(out)
    if a.fail_on:
        lim = scanner.SEVERITIES.index(a.fail_on)
        if any(scanner.SEVERITIES.index(f["severity"]) <= lim for f in findings):
            return 2
    return 0
