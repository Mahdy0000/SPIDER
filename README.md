# S.P.I.D.E.R

**S**ystem for **P**enetration, **I**nspection, and **D**ynamic **E**xploit **R**esearch

A privacy-first AI security agent that runs on local LLMs (Ollama). The goal: find security flaws in your own code and apps, explain them, and propose fixes, without sending your source to a cloud service.

**Scope: defensive only.** Use it on code and systems you own or are authorized to test.

## Install (one command)

**Windows 11 (PowerShell), the way to install:**

```powershell
irm https://raw.githubusercontent.com/Mahdy0000/SPIDER/main/install.ps1 | iex
```

**WSL2 / Linux / macOS:**

```bash
curl -fsSL https://raw.githubusercontent.com/Mahdy0000/SPIDER/main/install.sh | bash
```

What it does, with live output on screen: installs Python, Git and Ollama if missing (winget on Windows), installs SPIDER into its own venv (`~/.spider/venv`, no third-party packages), then runs `spider start`, which:

1. starts Ollama if it is not running;
2. pulls the default model `dolphinlabs/llama3.2-3b-uncensored` (one time, about 2 GB) and the embedding model `nomic-embed-text` (about 274 MB), skipping what is already installed;
3. builds the local RAG index with a progress counter (the 1542 dataset samples and the OWASP/CWE references; downloads about 3 MB of dataset files if you did not clone the repo);
4. it prints your hardware and **asks** whether to start local fine-tuning now (default no unless the GPU is clearly big enough; see "Local training"). Skip the question with `--no-train`.
5. opens an interactive prompt: paste a folder/file path, or the URL of an app you own. It runs the review, saves a Markdown report in `./spider-reports/` and prints the exact path, then waits for the next target. `exit` quits, Ctrl+C asks before quitting. Web targets other than localhost ask you to confirm you own them first.

Later runs: `spider start` (add `--skip-setup` to go straight to the prompt, `--lexical` to skip the embedding model). If you already cloned the repo: `pip install -e . && spider start`.


Training needs Linux with CUDA: on your laptop that means **WSL2**. In PowerShell the one command installs and runs reviews, and `spider start` will tell you plainly that training must run in WSL2. For everything including training, run the second command (WSL2) once; see "Local training".

Honest status: `spider start`'s logic (argument parsing, setup checks, target parsing, the loop, Ctrl+C and bad-input handling) is unit-tested, and setup plus the loop were run on Linux against a real Ollama (embedding model pulled, 1632-document index built, a failing review did not end the session). **Not run:** `install.ps1` on Windows (no Windows machine here), `install.sh` end to end, and a full review with the default 3B model through the loop. If the installer fails on your machine, the manual steps under "Try it" still work.

## Status

| Phase | What | Status |
|---|---|---|
| II | Static code analysis (SAST) with a local LLM | **Works now (MVP, v0.1)** |
| IV | Remediation reporting (OWASP-mapped findings + fix per finding) | **Works (v0.5)**: text/JSON/Markdown/HTML/SARIF reports with summary and fix-first list, plus `--patch` unified diff |
| - | Local RAG hints (bundled CWE/OWASP notes) | **Works** (keyword retrieval, 14 entries) |
| - | Local RAG engine over the dataset + OWASP/CWE references (`spider rag`, hybrid BM25 + local embeddings) | **Works**, see "Local RAG" |
| I | Web application review (scope-enforced crawler, passive checks, LLM agent loop) | **Works (v0.3)**, see "Web review" |
| III | Finding verification to cut false positives (`--verify`) | **Works (v0.4)**, re-check only, no exploit/PoC generation |
| - | RAG knowledge base of vulnerability data, tool calling, ReAct loop | Planned |

Phases follow the project concept doc; SAST is built first.

## What works now (v0.1)

`spider <file-or-folder>` reads your source, sends it in line-numbered chunks to a local Ollama model with a security-review prompt, and prints findings with:

- file and line reference
- severity and confidence
- OWASP Top 10 (2021) category (+ CWE when the model gives one)
- description and a suggested fix (with a fixed code snippet when available)

Output: `text` (default), `json`, `markdown`, `html` (self-contained, no scripts), `sarif` (SARIF 2.1.0 for GitHub code scanning and IDEs). `--fail-on <severity>` exits 2 for CI use.

## Web review (v0.3)

```bash
# your own app or a local practice lab (DVWA, Juice Shop on localhost) is allowed by default
python -m spider web http://localhost:3000
# anything else must be named by you; there is no "allow all"
python -m spider web https://staging.myapp.com --allow staging.myapp.com
python -m spider web http://localhost:3000 --agent --model dolphin3     # + LLM review agent loop
python -m spider web http://localhost:3000 --no-probe                   # passive only, no extra probe requests
```

- **Scope is enforced in code.** Only loopback (`localhost`, `127.0.0.1`, `::1`, `*.localhost`) plus hosts you name with `--allow`, `SPIDER_ALLOW` or `--allow-file` are ever contacted. Every request and every redirect hop is checked first; anything else stops with a clear error (exit code 3). Overly broad entries such as `*` or `*.com` are rejected. Only use it on systems you own or are authorized to test.
- **Read-only.** GET requests only, with a request cap (`--max-requests`) and delay (`--delay`).
- **Crawler:** same-host breadth-first crawl (`--max-pages`, `--max-depth`), extracting links, forms, scripts and comments.
- **Checks** (each maps to OWASP 2021 and CWE): missing CSP/clickjacking/nosniff/Referrer-Policy/HSTS headers, version disclosure, cookie flags, forms (password over GET or HTTP, POST without CSRF-looking token), verbose error pages, directory listing, sensitive HTML comments, mixed content, a short fixed list of well-known exposed files (`/.git/HEAD`, `/.env`, ...), CORS misconfiguration, and unescaped reflection of a harmless marker in existing query parameters.
- **Agent loop (`--agent`):** a ReAct-style loop in which the local model picks pages to `fetch` or `reflect` (the only two tools; both go through the allowlist), then proposes findings. A finding is dropped unless it cites evidence and a page the agent actually fetched.



- Findings are LLM output. They can be wrong or miss real bugs. Treat them as leads to verify, not a verdict.
- Quality depends on the model. Small models (0.5B-3B) run anywhere but give weaker results (wrong line numbers, vague findings). For better reviews try a bigger model, e.g. `--model dolphin3` (Llama 3.1 8B) or a 7B+ coder model. The default is an uncensored Llama 3.2 3B community build, or your fine-tuned `spider-reviewer` when it is installed in Ollama; it is only a model choice, the tool still only does defensive review.
- Files are split into 300-line chunks. Cross-file context is only an outline (defined names + imports of the other files), not real data-flow analysis.
- `--patch` replaces the reported lines with the model's `fixed_code`. It can be wrong or not apply cleanly; it never edits your files, review before `git apply`.
- Web review is read-only and passive-leaning (GET only, harmless markers). It does not exploit anything, send attack payloads, guess credentials or fuzz. No exploitation or PoC generation anywhere; the prompts forbid exploit output.

## Try it

Requirements: Python 3.9+, [Ollama](https://ollama.com).

```bash
git clone https://github.com/Mahdy0000/SPIDER.git
cd SPIDER
ollama pull dolphinlabs/llama3.2-3b-uncensored        # or any model you prefer
ollama serve                        # if not already running

python -m spider tests/fixtures/vulnerable_app.py
python -m spider ./your_project --format markdown -o report.md
python -m spider ./your_project --patch fixes.diff     # suggested fixes as a diff; review, then git apply
python benchmark/run.py                                  # recall/precision of your model on the known-vulnerable fixture
python -m spider ./your_project --model dolphin3 --fail-on high

# optional: install the `spider` command
pip install -e .
```

Env vars: `SPIDER_MODEL` (default model), `OLLAMA_HOST` (default `http://localhost:11434`).

## Tests

```bash
python -m unittest discover -s tests -t .
```

The unit tests use a fake Ollama server and a local test web server on 127.0.0.1 (no model, no internet needed). They check parsing, OWASP mapping, line clamping, CLI and exit codes, not model quality.

## Tested so far

- Unit tests (fake Ollama server, local test web server): 36 pass. SAST: parsing, OWASP mapping, RAG retrieval, outline, patch diff, CLI flags. Web: allowlist (loopback, named hosts, too-broad entries, redirect to an out-of-scope host, request budget), crawler staying in scope, each check on a deliberately weak local server, agent grounding, CLI exit codes. Verification: reproduced / not reproduced, hiding, model verdict parsing, garbage output, CLI flags. Reports: summary and fix-first ranking, SARIF structure, HTML escaping, all formats render.
- Smoke test: `spider web` with `--verify` against a local `python -m http.server` produced a Markdown and a SARIF report, and an `example.com` target was refused with exit 3.
- The web checks, agent loop and `--verify` have not been run against DVWA/Juice Shop or a real model yet, so how well the model second opinion filters false positives is unmeasured.
- v0.2 features (RAG, outline, `--patch`, benchmark) were only tested with the fake server, not yet with a real model. `benchmark/run.py` has not been run against a real model.
- Real run: CLI against a real Ollama 0.40.18 with `qwen2.5-coder:0.5b` on a 1-CPU Linux box. It ran end to end and returned OWASP-mapped findings, but with that tiny model the results were low quality (generic, some wrong lines). Not yet tested with the default model (`dolphinlabs/llama3.2-3b-uncensored`) or any 7B+ model.

## Dataset

`dataset/` holds 1542 labeled samples (105 original, 89 OWASP Juice Shop, 100 Big-Vul, 60 NIST Juliet, 1188 CyberNative with heuristic labels; `python dataset/merge.py` writes them all into one `dataset/all.jsonl`) with per-source licenses, plus a script to pull more (OWASP Benchmark, CodeXGLUE/Devign, DiverseVul, Draper). Used to fine-tune the reviewer model (see "Fine-tuning") and as the retrieval corpus for "Local RAG". Counts, format, licenses: `dataset/README.md`. Findings also get an OWASP Top 10:2025 label and CWE Top 25 years (`spider/data/taxonomy.json`; `merge.py` adds them to the dataset).

## Local RAG

`spider rag index` builds a local SQLite index (`~/.spider/rag/index.db`, override with `SPIDER_RAG_DIR`) over the 1542 dataset samples and 90 reference entries (CWE notes, OWASP Top 10 2021/2025, OWASP API Security Top 10 2023, OWASP Top 10 for LLM Applications 2025, CWE Top 25). Search is hybrid: BM25 keywords plus vector similarity, fused by rank. During a review, the top similar vulnerable/fixed samples and matching references are added to the model prompt (disable with `--no-rag`). No hosted service, no pip dependency.

```bash
spider rag index              # hybrid index; falls back to keyword-only if the embedding model is missing
spider rag index --lexical    # keyword-only, downloads nothing
spider rag search "building an SQL query from user input"
spider rag status
```

What downloads on first run: (1) the embedding model, `ollama pull nomic-embed-text` (about 274 MB, runs on CPU, fine for 4 GB VRAM); (2) about 3 MB of dataset files from this repo, only if there is no local `dataset/` folder (a plain `pip install`). After that it works offline. `spider start` does all of this for you.

Honest status: tested with unit tests, a fake embedder, a real `nomic-embed-text` run on a 130-document subset (hybrid search returned sensible CWE-327 hits for "weak password hashing"), and the full 1632-document keyword index. The full hybrid index was not timed here (the 130-document subset took about 20 s on a small CPU box). **Not measured:** whether retrieval improves review quality with a real model; no before/after benchmark yet. The CyberNative-derived samples carry heuristic labels and no CWE. The OWASP API and LLM lists are in the index and in `taxonomy.json`, but not mapped onto the dataset rows (the official pages give almost no CWE links, so we did not invent a mapping).

## Local training (`spider train`)

Fine-tunes the reviewer model on this machine with the repo's own pipeline (`training/prep_data.py` then `training/train_qlora.py`; nothing is forked). `spider train` first detects your hardware (GPU, VRAM, RAM, WSL2) and prints it, then picks 4 GB-friendly settings: 4-bit NF4 loading, batch size 1, gradient accumulation 16, gradient checkpointing, a short sequence length. The trainer's own progress bar (step, loss, ETA) stays on your screen.

```bash
# inside WSL2 (Ubuntu) with the NVIDIA driver installed on Windows
spider train --check             # hardware verdict only
pip install torch transformers peft bitsandbytes accelerate sentencepiece   # or: spider train --install-deps
spider train                     # asks before doing anything risky
spider train --model-size 1b     # Llama 3.2 1B Instruct: fits 4 GB comfortably, weaker than 3B
```

Verdicts: **OK** (8 GB VRAM or more): 3B, 2048 tokens. **TIGHT** (about 4 to 8 GB, your T1200 has 4 GB): 3B with `max_seq 1024` and LoRA r 8, may run out of memory, and examples longer than the window are skipped; it offers the 1B model or Colab instead of just trying. **INSUFFICIENT** (no GPU, under 4 GB, or native Windows): it says why and points to `training/spider_finetune_colab.ipynb`. It never starts a run it expects to crash silently, and a failed run prints how to retry with the 1B model.

First run downloads the base model from Hugging Face (about 6 GB for 3B, about 2.5 GB for 1B). When it finishes it prints where the LoRA adapter was saved and the two commands that merge it and load it into Ollama as `spider-reviewer` (`training/merge_export.py`, `training/convert_to_ollama.sh`), which SPIDER then uses by default.

The trainer is Hugging Face transformers + peft + bitsandbytes QLoRA, **not Unsloth** (Unsloth is not wired in). `spider train` needs the repo's `training/` folder: if you installed with pip it clones the repo (about 3 MB) into `~/.spider/SPIDER`.

Honest status: the hardware parsing, verdicts, option menu, command building, the setup question and the failure paths are unit-tested with mocks. **Not run:** a real training run through `spider train` (this Linux box has no GPU), anything on a T1200 or in WSL2, and the 1B base end to end. Whether the 3B fits in 4 GB is an estimate, not a measurement. The underlying `train_qlora.py` was run only on a tiny CPU model.

## Fine-tuning (train the model on the dataset)

`training/` turns `dataset/` into instruction-tuning data in the tool's own prompt/JSON format, fine-tunes the Llama 3.2 3B base with QLoRA on a free Colab T4 (`training/spider_finetune_colab.ipynb`), converts it to GGUF (Q4_K_M) and an Ollama model named `spider-reviewer`, which the tool then uses by default (`--model` and `SPIDER_MODEL` still override). `training/evaluate.py` records recall/precision before and after.

```bash
python training/prep_data.py                      # data, CPU, seconds
# train on Colab: open training/spider_finetune_colab.ipynb (T4 GPU), run all cells, download the .gguf + Modelfile
ollama create spider-reviewer -f Modelfile        # on your PC, next to the .gguf
python training/evaluate.py --model dolphinlabs/llama3.2-3b-uncensored --label before
python training/evaluate.py --model spider-reviewer --label after
python training/evaluate.py --compare before after
```

Honest status: the data prep, training loop (on a tiny model), merge, tokenisation and GGUF conversion are tested; the real 3B training run, the quantised model quality and the before/after numbers are not yet measured. The benchmark has one file and 4 expected findings, so treat deltas as a sanity check. Details, caveats, local-GPU needs: `training/README.md`.

## Roadmap

1. Better SAST: cross-file outline context and a recall/precision benchmark (`benchmark/`): **done (v0.2)**. Still open: running the benchmark across bigger models.
2. Patch output (unified diffs): **done (v0.2)**.
3. RAG over CWE/OWASP data: **done (v0.2)** keyword hints; **extended**: local hybrid RAG over the dataset and taxonomy (`spider rag`), one-command install and interactive loop (`spider start`). Retrieval quality not benchmarked yet.
4. Web review: crawler, passive checks and agent loop with an enforced allowlist: **done (v0.3)**. Tested against a local test server and a fake model only.
5. Verification stage: **done (v0.4)** as re-check plus model second opinion; no PoC execution by design. Tested with a local test server and a fake model only.
6. Report improvements: **done (v0.5)**: summary by severity/OWASP/verification, a fix-first list (rejected findings are never recommended), HTML and SARIF output.

## License

MIT
