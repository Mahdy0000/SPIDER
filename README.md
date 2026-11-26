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
| I | Dynamic web testing (DAST) | Planned |
| III | Proof-of-concept verification to cut false positives | Planned |
| - | RAG knowledge base of vulnerability data, tool calling, ReAct loop | Planned |

Phases follow the project concept doc; SAST is built first.

## What works now (v0.1)

`spider <file-or-folder>` reads your source, sends it in line-numbered chunks to a local Ollama model with a security-review prompt, and prints findings with:

- file and line reference
- severity and confidence
- OWASP Top 10 (2021) category (+ CWE when the model gives one)
- description and a suggested fix (with a fixed code snippet when available)

Output: `text` (default), `json`, `markdown`. `--fail-on <severity>` exits 2 for CI use.

## Limitations (read this)

- Findings are LLM output. They can be wrong or miss real bugs. Treat them as leads to verify, not a verdict.
- Quality depends on the model. Small models (0.5B-3B) run anywhere but give weaker results (wrong line numbers, vague findings). For better reviews try a bigger model, e.g. `--model dolphin3` (Llama 3.1 8B) or a 7B+ coder model. The default is an uncensored Llama 3.2 3B community build; it is only a model choice, the tool still only does defensive review.
- Files are split into 300-line chunks. Cross-file context is only an outline (defined names + imports of the other files), not real data-flow analysis.
- `--patch` replaces the reported lines with the model's `fixed_code`. It can be wrong or not apply cleanly; it never edits your files, review before `git apply`.
- No RAG, no DAST, no exploitation or PoC generation. The prompt forbids exploit output.

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

The unit tests use a fake Ollama server (no model needed). They check parsing, OWASP mapping, line clamping, CLI and exit codes, not model quality.

## Tested so far

- Unit tests (fake Ollama server): 7 pass (parsing, OWASP mapping, RAG retrieval, outline, patch diff, CLI flags).
- v0.2 features (RAG, outline, `--patch`, benchmark) were only tested with the fake server, not yet with a real model. `benchmark/run.py` has not been run against a real model.
- Real run: CLI against a real Ollama 0.40.18 with `qwen2.5-coder:0.5b` on a 1-CPU Linux box. It ran end to end and returned OWASP-mapped findings, but with that tiny model the results were low quality (generic, some wrong lines). Not yet tested with the default model (`dolphinlabs/llama3.2-3b-uncensored`) or any 7B+ model.

## Dataset

`dataset/` holds 194 labeled vulnerable/fixed pairs (105 original, 89 from OWASP Juice Shop, MIT) covering all 10 OWASP categories, prepared for retrieval later (not used by the tool yet). Counts, format and licenses: `dataset/README.md`.

## Roadmap

1. Better SAST: cross-file outline context and a recall/precision benchmark (`benchmark/`): **done (v0.2)**. Still open: running the benchmark across bigger models.
2. Patch output (unified diffs): **done (v0.2)**.
3. RAG over CWE/OWASP data: **done (v0.2)**, simple keyword retrieval, no embeddings yet.
4. DAST crawler + ReAct loop: **not started, on hold** (this repo is scoped to reviewing your own source code for now).
5. Verification stage: **not started, on hold**.

## License

MIT
