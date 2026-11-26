"""`spider train`: check this machine, then run the repo's QLoRA fine-tune (training/train_qlora.py) on the dataset, live on screen.

It does NOT reimplement training. It detects the hardware, picks 4 GB-friendly settings (4-bit NF4, batch 1, gradient accumulation,
gradient checkpointing, short sequence length), prepares the data with training/prep_data.py if needed, then runs
training/train_qlora.py with its progress bar (step, loss, ETA) inherited on your terminal.

Note: the repo's trainer is Hugging Face transformers + peft + bitsandbytes QLoRA. Unsloth is not used.
Run it inside WSL2 (Ubuntu) with the NVIDIA driver on Windows; native Windows is not supported here.
"""
import argparse
import os
import platform
import re
import shutil
import subprocess
import sys

BASE_3B = "chuanli11/Llama-3.2-3B-Instruct-uncensored"   # the base the pipeline already uses
BASE_1B = "unsloth/Llama-3.2-1B-Instruct"                # ungated mirror of Llama 3.2 1B Instruct
COLAB = "training/spider_finetune_colab.ipynb"
REPO_URL = "https://github.com/Mahdy0000/SPIDER.git"
REQUIRED_PKGS = ["torch", "transformers", "peft", "bitsandbytes", "accelerate"]
PIP_LINE = "pip install torch transformers peft bitsandbytes accelerate sentencepiece"

# VRAM thresholds in MiB (for 4-bit QLoRA with gradient checkpointing, batch 1). Estimates, not measurements on a T1200.
VRAM_3B_OK = 8000
VRAM_3B_TIGHT = 3800
VRAM_1B_MIN = 2800


def detect_hardware(run=subprocess.run, system=platform.system, meminfo="/proc/meminfo", which=shutil.which):
    """Return dict: os, wsl, gpu, vram_mib, ram_gb, cuda (nvidia-smi sees a GPU)."""
    hw = {"os": system(), "wsl": False, "gpu": None, "vram_mib": 0, "ram_gb": None, "cuda": False}
    try:
        hw["wsl"] = "microsoft" in platform.release().lower() or bool(os.environ.get("WSL_DISTRO_NAME"))
    except Exception:  # noqa: BLE001
        pass
    exe = which("nvidia-smi")
    if exe:
        try:
            r = run([exe, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=15)
            line = (r.stdout or "").strip().splitlines()[0] if r.returncode == 0 and (r.stdout or "").strip() else ""
            m = re.match(r"(.+?),\s*(\d+)", line)
            if m:
                hw["gpu"], hw["vram_mib"], hw["cuda"] = m.group(1).strip(), int(m.group(2)), True
        except (OSError, subprocess.SubprocessError, IndexError):
            pass
    try:
        for ln in open(meminfo):
            if ln.startswith("MemTotal:"):
                hw["ram_gb"] = round(int(ln.split()[1]) / 1048576, 1)
                break
    except OSError:
        pass
    return hw


def missing_packages(find_spec=None):
    import importlib.util
    find_spec = find_spec or importlib.util.find_spec
    return [p for p in REQUIRED_PKGS if find_spec(p) is None]


def assess(hw, missing=()):
    """Decide what can run. Returns dict(level, plan, reasons, fallbacks).
    level: ok | tight | insufficient. plan: settings for the 3B (or None)."""
    reasons = []
    if hw["os"] == "Windows":
        return {"level": "insufficient", "plan": None, "fallbacks": ["wsl", "colab"],
                "reasons": ["native Windows: run `spider train` inside WSL2 (Ubuntu) where CUDA + bitsandbytes work"]}
    if not hw["cuda"]:
        return {"level": "insufficient", "plan": None, "fallbacks": ["colab"],
                "reasons": ["no NVIDIA GPU visible (nvidia-smi missing or failed). In WSL2 you need the NVIDIA Windows driver; see the README"]}
    v = hw["vram_mib"]
    if hw["ram_gb"] is not None and hw["ram_gb"] < 12:
        reasons.append(f"only {hw['ram_gb']} GB RAM visible (loading the model needs about 8 GB free)")
    if v >= VRAM_3B_OK:
        level, plan = "ok", {"base": BASE_3B, "max_seq": 2048, "lora_r": 16, "grad_accum": 16}
    elif v >= VRAM_3B_TIGHT:
        level, plan = "tight", {"base": BASE_3B, "max_seq": 1024, "lora_r": 8, "grad_accum": 16}
        reasons.append(f"{v} MiB VRAM is tight for the 3B model even in 4-bit: it may run out of memory, and it will be slow. "
                       "Settings are cut to max_seq 1024 and LoRA r 8; longer examples are skipped")
    else:
        level, plan = "insufficient", None
        reasons.append(f"{v} MiB VRAM is not enough for the 3B model")
    fb = []
    if level != "ok":
        if v >= VRAM_1B_MIN:
            fb.append("1b")
        fb.append("colab")
    if missing:
        reasons.append("missing Python packages: " + ", ".join(missing))
    return {"level": level, "plan": plan, "reasons": reasons, "fallbacks": fb}


def plan_1b():
    return {"base": BASE_1B, "max_seq": 1536, "lora_r": 16, "grad_accum": 16}


def describe(hw, out=print):
    out("Hardware found:")
    out(f"  OS: {hw['os']}{' (WSL2)' if hw['wsl'] else ''}")
    out(f"  GPU: {hw['gpu'] or 'none detected'}" + (f", {hw['vram_mib']} MiB VRAM" if hw["cuda"] else ""))
    out(f"  RAM: {hw['ram_gb'] if hw['ram_gb'] is not None else 'unknown'} GB")


def find_training_dir(env=os.environ, exists=os.path.isdir):
    """The training/ folder: the repo checkout next to the package, or a clone in ~/.spider/SPIDER."""
    here = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    for base in (env.get("SPIDER_REPO"), here, os.path.join(os.path.expanduser("~"), ".spider", "SPIDER")):
        if base and exists(os.path.join(base, "training")) and os.path.exists(os.path.join(base, "training", "train_qlora.py")):
            return os.path.join(base, "training")
    return None


def clone_repo(dest=None, run=subprocess.call):
    dest = dest or os.path.join(os.path.expanduser("~"), ".spider", "SPIDER")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if run(["git", "clone", "--depth", "1", REPO_URL, dest]) != 0:
        return None
    return os.path.join(dest, "training")


def build_commands(tdir, plan, epochs=3, out_dir=None, python=None):
    """Return [prep_cmd or None, train_cmd, merge_cmd, convert_cmd(str)]."""
    python = python or sys.executable
    out_dir = out_dir or os.path.join(tdir, "out", "adapter")
    prep = None if os.path.exists(os.path.join(tdir, "data", "train.jsonl")) else [python, os.path.join(tdir, "prep_data.py")]
    train = [python, os.path.join(tdir, "train_qlora.py"), "--base", plan["base"], "--out", out_dir,
             "--batch", "1", "--grad-accum", str(plan["grad_accum"]), "--max-seq", str(plan["max_seq"]),
             "--lora-r", str(plan["lora_r"]), "--lora-alpha", str(plan["lora_r"] * 2), "--epochs", str(epochs)]
    merged = os.path.join(tdir, "out", "merged")
    merge = [python, os.path.join(tdir, "merge_export.py"), "--adapter", out_dir, "--out", merged]
    convert = f"bash {os.path.join(tdir, 'convert_to_ollama.sh')} {merged}"
    return [prep, train, merge, convert], out_dir, merged


def finish_message(out_dir, merge_cmd, convert_cmd):
    return "\n".join([
        "", "Training finished.",
        f"LoRA adapter saved to: {out_dir}",
        "Load it into Ollama (about 10 min, needs git + cmake + a C++ compiler for the quantizer):",
        "  1) " + " ".join(merge_cmd),
        "  2) " + convert_cmd + "      # creates the Ollama model `spider-reviewer`, which SPIDER then uses by default",
        "Then compare before/after: python training/evaluate.py --help",
    ])


def choose(a, hw, verdict, ask=input, out=print):
    """Return a plan dict or None. Prints the reason plainly; never silently falls back."""
    lvl = verdict["level"]
    for r in verdict["reasons"]:
        out(("WARNING: " if lvl != "ok" else "note: ") + r)
    if lvl == "ok":
        return verdict["plan"]
    if a.model_size == "1b":
        return plan_1b() if "1b" in verdict["fallbacks"] or lvl == "tight" else None
    out("")
    out("Options:")
    n = 1
    opts = {}
    if lvl == "tight" and not a.yes:
        opts[str(n)] = ("try 3B anyway with the reduced settings (may crash with out-of-memory)", verdict["plan"]); n += 1
    if "1b" in verdict["fallbacks"]:
        opts[str(n)] = ("train the 1B variant (Llama 3.2 1B Instruct, fits 4 GB comfortably, weaker than 3B)", plan_1b()); n += 1
    opts[str(n)] = (f"stop here and use Colab: {COLAB}", None)
    for k, (t, _) in opts.items():
        out(f"  {k}) {t}")
    if len(opts) == 1:
        return None
    if a.yes and lvl == "tight":
        return verdict["plan"]
    try:
        ans = ask(f"Choose [1-{len(opts)}] (default {len(opts)}): ").strip() or str(len(opts))
    except (EOFError, KeyboardInterrupt):
        return None
    return opts.get(ans, opts[str(len(opts))])[1]


def build_parser():
    p = argparse.ArgumentParser(prog="spider train", description="Fine-tune the reviewer model locally (QLoRA, 4-bit) on the SPIDER dataset. Defensive reviewer data only. Run in WSL2 with an NVIDIA GPU.")
    p.add_argument("--model-size", choices=["3b", "1b"], default="3b", help="3b = the default base; 1b = Llama 3.2 1B Instruct (fits 4 GB)")
    p.add_argument("--epochs", type=float, default=3)
    p.add_argument("--out", help="adapter output folder (default training/out/adapter)")
    p.add_argument("--check", action="store_true", help="only detect hardware and print the verdict")
    p.add_argument("--yes", action="store_true", help="no questions: go with the 3B plan if it is ok or tight")
    p.add_argument("--install-deps", action="store_true", help="run pip to install the missing training packages first")
    return p


def run_training(a, ask=input, out=print, run=subprocess.call, hw=None, missing=None, tdir=None):
    hw = hw or detect_hardware()
    describe(hw, out)
    miss = missing_packages() if missing is None else missing
    verdict = assess(hw, miss)
    out(f"Verdict for the 3B model: {verdict['level'].upper()}")
    if a.check:
        for r in verdict["reasons"]:
            out("  - " + r)
        return 0 if verdict["level"] != "insufficient" else 1
    plan = choose(a, hw, verdict, ask, out)
    if plan is None:
        out(f"\nNot training locally. For a free GPU, open {COLAB} on Colab (T4), run all cells, then follow training/README.md.")
        return 1
    if miss:
        cmd = [sys.executable, "-m"] + PIP_LINE.split()
        if a.install_deps:
            out("Installing: " + PIP_LINE)
            if run(cmd) != 0:
                out("pip failed; fix that and re-run.")
                return 1
        else:
            out(f"\nMissing packages: {', '.join(miss)}.\nInstall them (inside WSL2, in your venv): {PIP_LINE}\nor re-run with --install-deps.")
            return 1
    tdir = tdir or find_training_dir()
    if not tdir:
        out("The training/ folder is not part of the pip package. Fetching the repo (about 3 MB) into ~/.spider/SPIDER ...")
        tdir = clone_repo()
        if not tdir:
            out("git clone failed. Clone https://github.com/Mahdy0000/SPIDER yourself and run `spider train` inside it.")
            return 1
    cmds, out_dir, merged = build_commands(tdir, plan, a.epochs, a.out)
    prep, train, merge, convert = cmds
    out(f"\nBase model: {plan['base']}  (first run downloads it from Hugging Face: {'about 6 GB' if '3B' in plan['base'] else 'about 2.5 GB'} of weights, then it is cached)")
    out(f"Settings: 4-bit NF4, batch 1, grad-accum {plan['grad_accum']}, max_seq {plan['max_seq']}, LoRA r {plan['lora_r']}, {a.epochs:g} epochs, gradient checkpointing")
    out("Progress below: step, loss and ETA are printed by the trainer. Ctrl+C stops it; nothing is saved until the end.\n")
    try:
        if prep:
            out("Preparing training data (training/prep_data.py) ...")
            if run(prep) != 0:
                out("Data preparation failed.")
                return 1
        rc = run(train)
    except KeyboardInterrupt:
        out("\nTraining stopped by you. Nothing was saved.")
        return 130
    if rc != 0:
        out("\nTraining failed (exit code %s). If it says CUDA out of memory: re-run with `spider train --model-size 1b`, or use %s." % (rc, COLAB))
        return rc
    out(finish_message(out_dir, merge, convert))
    return 0


def main(argv=None):
    return run_training(build_parser().parse_args(argv))
