"""`spider start`: one-command setup (model pull + local RAG index, with live progress), then an interactive review loop.

Everything runs on this machine. Setup downloads only: the Ollama chat model and the Ollama embedding model
(both via `ollama pull`), plus about 3 MB of dataset shards if you did not clone the repo. The last step ASKS whether to start local fine-tuning (`spider train`);
the Colab notebook training/spider_finetune_colab.ipynb is the fallback.
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from . import cli, ollama, rag, ragcli, trainctl, webcli

COLAB_NOTEBOOK = "training/spider_finetune_colab.ipynb"
EXIT_WORDS = {"exit", "quit", "q", ":q"}


def build_parser():
    p = argparse.ArgumentParser(prog="spider start", description="One-command setup, then an interactive review loop. Defensive: review only code and apps you own or are authorized to test.")
    p.add_argument("--model", default=None, help="chat model to pull and use (default: env SPIDER_MODEL, else " + ollama.FALLBACK_MODEL + ")")
    p.add_argument("--embed-model", default=os.environ.get("SPIDER_EMBED_MODEL", rag.DEFAULT_EMBED_MODEL))
    p.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    p.add_argument("--reports-dir", default=None, help="where reports are saved (default: ./spider-reports)")
    p.add_argument("--lexical", action="store_true", help="keyword-only RAG index: skip the embedding model download")
    p.add_argument("--skip-setup", action="store_true", help="go straight to the interactive loop")
    p.add_argument("--setup-only", action="store_true", help="do the setup, then exit without the loop")
    p.add_argument("--no-train", action="store_true", help="do not offer local fine-tuning at the end of setup")
    p.add_argument("--yes", action="store_true", help="do not ask before testing a web target (only for hosts you own)")
    return p


def server_up(host, timeout=2):
    try:
        with urllib.request.urlopen(host.rstrip("/") + "/api/tags", timeout=timeout):
            return True
    except (urllib.error.URLError, OSError, ValueError):
        return False


def installed_models(host):
    try:
        with urllib.request.urlopen(host.rstrip("/") + "/api/tags", timeout=5) as r:
            return [m.get("name", "") for m in json.loads(r.read()).get("models", [])]
    except (urllib.error.URLError, OSError, ValueError):
        return []


def has_model(names, model):
    return any(n == model or n.split(":")[0] == model or n == model + ":latest" for n in names)


def start_server(host, which=shutil.which, popen=subprocess.Popen, wait=30, up=server_up):
    """Return (ok, message). Starts `ollama serve` in the background if the binary exists and nothing is listening."""
    if up(host):
        return True, "Ollama is running"
    exe = which("ollama")
    if not exe:
        return False, ("Ollama is not installed. Windows: `winget install Ollama.Ollama` (or https://ollama.com/download), "
                       "then run `spider start` again.")
    popen([exe, "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    for _ in range(wait):
        if up(host):
            return True, "started `ollama serve`"
        time.sleep(1)
    return False, "started `ollama serve` but it did not answer; start it yourself and re-run"


def pull(model, run=subprocess.call, which=shutil.which):
    """`ollama pull` with its own live progress bar on screen. Returns True on success."""
    exe = which("ollama")
    if not exe:
        return False
    return run([exe, "pull", model]) == 0


def offer_training(a, out=print, ask=input, hw=None, missing=None, trainer=None):
    """Last setup step: show what the hardware allows and ASK whether to start local fine-tuning. Default is no unless the hardware is fine."""
    out("")
    out("== Optional: local fine-tuning on the SPIDER dataset ==")
    hw = hw or trainctl.detect_hardware()
    trainctl.describe(hw, out)
    miss = trainctl.missing_packages() if missing is None else missing
    verdict = trainctl.assess(hw, miss)
    out(f"Verdict for the 3B model: {verdict['level'].upper()}")
    for r in verdict["reasons"]:
        out("  - " + r)
    default_yes = verdict["level"] == "ok" and not miss
    try:
        ans = ask(f"Start local training now? It takes hours. [{'Y/n' if default_yes else 'y/N'}] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = ""
    yes = ans in ("y", "yes") or (ans == "" and default_yes)
    if not yes:
        out("Skipping. Later: `spider train` (local, WSL2) or " + COLAB_NOTEBOOK + " on Colab.")
        return False
    (trainer or trainctl.main)([])
    return True


def setup(a, out=print):
    """Steps 1-3 of the one-command flow. Returns (ok, model)."""
    model = a.model or os.environ.get("SPIDER_MODEL") or ollama.FALLBACK_MODEL
    out("== [1/4] Ollama ==")
    ok, msg = start_server(a.host)
    out(("OK: " if ok else "ERROR: ") + msg)
    if not ok:
        return False, model
    names = installed_models(a.host)
    out(f"== [2/4] Chat model: {model} ==")
    if has_model(names, model):
        out("already installed, skipping download")
    else:
        out("downloading (one time; this is the big one)...")
        if not pull(model):
            out(f"ERROR: `ollama pull {model}` failed. Check your connection and re-run `spider start`.")
            return False, model
    out(f"== [3/4] Embedding model: {a.embed_model} ==")
    embed_flag = []
    if a.lexical:
        out("skipped (--lexical): keyword-only index")
        embed_flag = ["--lexical"]
    elif has_model(names, a.embed_model):
        out("already installed, skipping download")
    else:
        out("downloading (about 274 MB, one time)...")
        if not pull(a.embed_model):
            out("WARNING: embedding model download failed; falling back to a keyword-only index.")
            embed_flag = ["--lexical"]
    out("== [4/4] Building the local RAG index (dataset + OWASP/CWE references) ==")
    rc = ragcli.main(["index", "--host", a.host, "--embed-model", a.embed_model] + embed_flag)
    if rc != 0:
        out("WARNING: index build failed; reviews still work, just without retrieval hints.")
    out("")
    out("Setup done. Everything above ran locally; nothing is uploaded anywhere.")
    if not getattr(a, "no_train", False):
        offer_training(a, out)
    else:
        out(f"Local fine-tuning: `spider train`. Colab alternative: {COLAB_NOTEBOOK}.")
    return True, model


def parse_target(line):
    """Classify a pasted line. Returns (kind, value) with kind in url|path|empty|exit|bad."""
    s = line.strip().strip('"').strip("'")
    if not s:
        return "empty", ""
    if s.lower() in EXIT_WORDS:
        return "exit", ""
    if re.match(r"^https?://", s, re.I):
        u = urllib.parse.urlparse(s)
        return ("url", s) if u.hostname else ("bad", s)
    if re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        return "bad", s
    if os.path.exists(os.path.expanduser(s)):
        return "path", os.path.expanduser(s)
    if re.match(r"^(localhost|[\w-]+(\.[\w-]+)+)(:\d+)?(/.*)?$", s):
        return "url", "http://" + s if s.startswith("localhost") else "https://" + s
    return "bad", s


def report_path(reports_dir, target, now=None):
    now = now or datetime.datetime.now()
    slug = re.sub(r"[^A-Za-z0-9]+", "-", target.split("://")[-1]).strip("-")[:40] or "target"
    return os.path.abspath(os.path.join(reports_dir, f"spider-{now:%Y%m%d-%H%M%S}-{slug}.md"))


def build_argv(kind, value, a, model, out_path):
    common = ["--model", model, "--host", a.host, "--format", "markdown", "-o", out_path]
    if kind == "path":
        return ["spider-code", value] + common
    host = urllib.parse.urlparse(value).hostname
    return ["spider-web", value, "--allow", host, "--agent"] + common


def run_target(kind, value, a, model, runner=None):
    """Run one review. Returns (exit_code, report_path or None)."""
    os.makedirs(a.reports_dir, exist_ok=True)
    out_path = report_path(a.reports_dir, value)
    argv = build_argv(kind, value, a, model, out_path)
    if runner:
        rc = runner(argv)
    else:
        rc = webcli.main(argv[1:]) if argv[0] == "spider-web" else cli.code_main(argv[1:])
    return rc, (out_path if os.path.exists(out_path) else None)


def loop(a, model, ask=input, out=print, runner=None):
    out("")
    out("Paste a target to review: a folder/file path, or a URL of an app YOU OWN (localhost or your own domain).")
    out("Type `exit` to quit. Ctrl+C asks before quitting.")
    while True:
        try:
            line = ask("\nspider> target: ")
        except EOFError:
            out("")
            return 0
        except KeyboardInterrupt:
            out("")
            try:
                if ask("Quit SPIDER? [y/N] ").strip().lower() in ("y", "yes"):
                    return 0
            except (KeyboardInterrupt, EOFError):
                return 0
            continue
        kind, value = parse_target(line)
        if kind == "empty":
            continue
        if kind == "exit":
            return 0
        if kind == "bad":
            out(f"Not a path that exists or an http(s) URL: {value!r}. Try again.")
            continue
        if kind == "url" and not a.yes:
            host = urllib.parse.urlparse(value).hostname
            if host not in ("localhost", "127.0.0.1", "::1"):
                try:
                    okay = ask(f"Do you own {host} or have written permission to test it? [y/N] ").strip().lower() in ("y", "yes")
                except (KeyboardInterrupt, EOFError):
                    okay = False
                if not okay:
                    out("Skipped. SPIDER only reviews targets you are authorized to test.")
                    continue
        out(f"Reviewing {value} with {model} ...")
        try:
            rc, path = run_target(kind, value, a, model, runner)
        except KeyboardInterrupt:
            out("\nReview interrupted. Back to the prompt.")
            continue
        except SystemExit as e:
            rc, path = (e.code if isinstance(e.code, int) else 1), None
        except Exception as e:  # keep the session alive on any single-target failure
            out(f"Review failed: {e}")
            continue
        if path:
            out(f"\nReport saved to: {path}")
        else:
            out(f"\nNo report was written (exit code {rc}). See the messages above.")
        out("Paste the next target, or `exit`.")


def main(argv=None):
    a = build_parser().parse_args(argv)
    if not a.host.startswith("http"):
        a.host = "http://" + a.host
    a.reports_dir = a.reports_dir or os.path.join(os.getcwd(), "spider-reports")
    model = a.model or os.environ.get("SPIDER_MODEL") or ollama.FALLBACK_MODEL
    if not a.skip_setup:
        ok, model = setup(a)
        if not ok:
            return 1
    else:
        model = a.model or ollama.default_model(a.host)
    if a.setup_only:
        return 0
    return loop(a, model)
