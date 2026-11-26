# S.P.I.D.E.R

**S**ystem for **P**enetration, **I**nspection, and **D**ynamic **E**xploit **R**esearch

A privacy-first AI security agent that runs on local LLMs (Ollama). The goal: find security flaws in your own code and apps, explain them, and propose fixes, without sending your source to a cloud service.

**Scope: defensive only.** Use it on code and systems you own or are authorized to test.

## Status

| Phase | What | Status |
|---|---|---|
| II | Static code analysis (SAST) with a local LLM | **Works now (MVP, v0.1)** |
| IV | Remediation reporting (OWASP-mapped findings + fix per finding) | **Works**: text/JSON/Markdown reports, plus `--patch` unified diff |
| - | Local RAG hints (bundled CWE/OWASP notes) | **Works** (keyword retrieval, 14 entries) |
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

Output: `text` (default), `json`, `markdown`. `--fail-on <severity>` exits 2 for CI use.

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
- Quality depends on the model. Small models (0.5B-3B) run anywhere but give weaker results (wrong line numbers, vague findings). For better reviews try a bigger model, e.g. `--model dolphin3` (Llama 3.1 8B) or a 7B+ coder model. The default is an uncensored Llama 3.2 3B community build; it is only a model choice, the tool still only does defensive review.
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

- Unit tests (fake Ollama server, local test web server): 30 pass. SAST: parsing, OWASP mapping, RAG retrieval, outline, patch diff, CLI flags. Web: allowlist (loopback, named hosts, too-broad entries, redirect to an out-of-scope host, request budget), crawler staying in scope, each check on a deliberately weak local server, agent grounding, CLI exit codes. Verification: reproduced / not reproduced, hiding, model verdict parsing, garbage output, CLI flags.
- The web checks, agent loop and `--verify` have not been run against DVWA/Juice Shop or a real model yet, so how well the model second opinion filters false positives is unmeasured.
- v0.2 features (RAG, outline, `--patch`, benchmark) were only tested with the fake server, not yet with a real model. `benchmark/run.py` has not been run against a real model.
- Real run: CLI against a real Ollama 0.40.18 with `qwen2.5-coder:0.5b` on a 1-CPU Linux box. It ran end to end and returned OWASP-mapped findings, but with that tiny model the results were low quality (generic, some wrong lines). Not yet tested with the default model (`dolphinlabs/llama3.2-3b-uncensored`) or any 7B+ model.

## Dataset

`dataset/` holds 1542 labeled samples (105 original, 89 OWASP Juice Shop, 100 Big-Vul, 60 NIST Juliet, 1188 CyberNative with heuristic labels; `python dataset/merge.py` writes them all into one `dataset/all.jsonl`) with per-source licenses, plus a script to pull more (OWASP Benchmark, CodeXGLUE/Devign, DiverseVul, Draper). Prepared for retrieval later; not used by the tool yet. Counts, format, licenses: `dataset/README.md`.

## Roadmap

1. Better SAST: cross-file outline context and a recall/precision benchmark (`benchmark/`): **done (v0.2)**. Still open: running the benchmark across bigger models.
2. Patch output (unified diffs): **done (v0.2)**.
3. RAG over CWE/OWASP data: **done (v0.2)**, simple keyword retrieval, no embeddings yet.
4. Web review: crawler, passive checks and agent loop with an enforced allowlist: **done (v0.3)**. Tested against a local test server and a fake model only.
5. Verification stage: **done (v0.4)** as re-check plus model second opinion; no PoC execution by design. Tested with a local test server and a fake model only.
6. Report improvements: planned (v0.5).

## License

MIT
