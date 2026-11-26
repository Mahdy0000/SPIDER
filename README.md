# S.P.I.D.E.R

**S**ystem for **P**enetration, **I**nspection, and **D**ynamic **E**xploit **R**esearch

A privacy-first AI security agent that runs on local LLMs (Ollama). The goal: find security flaws in your own code and apps, explain them, and propose fixes, without sending your source to a cloud service.

**Scope: defensive only.** Use it on code and systems you own or are authorized to test.

## Status

| Phase | What | Status |
|---|---|---|
| II | Static code analysis (SAST) with a local LLM | **Works now (MVP, v0.1)** |
| IV | Remediation reporting (OWASP-mapped findings + fix per finding) | **Partly works**: text/JSON/Markdown reports with fixes |
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
- Quality depends on the model. A 0.5B model runs anywhere but gives weak results (wrong line numbers, vague findings). Use a 7B+ coder model for real reviews.
- Files are split into 300-line chunks; cross-file data flow is not analysed yet.
- No RAG, no DAST, no exploitation or PoC generation. The prompt forbids exploit output.

## Try it

Requirements: Python 3.9+, [Ollama](https://ollama.com).

```bash
git clone https://github.com/Mahdy0000/SPIDER.git
cd SPIDER
ollama pull qwen2.5-coder:7b        # or any model you prefer
ollama serve                        # if not already running

python -m spider tests/fixtures/vulnerable_app.py
python -m spider ./your_project --format markdown -o report.md
python -m spider ./your_project --model qwen2.5-coder:14b --fail-on high

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

- Unit tests (fake Ollama server): pass.
- Real run: CLI against a real Ollama 0.40.18 with `qwen2.5-coder:0.5b` on a 1-CPU Linux box. It ran end to end and returned OWASP-mapped findings, but with that tiny model the results were low quality (generic, some wrong lines). Not yet tested with 7B+ models.

## Roadmap

1. Better SAST: bigger-model evaluation, cross-file context, benchmark on known-vulnerable apps.
2. Patch output (unified diffs).
3. RAG over CWE/OWASP data.
4. DAST crawler + ReAct loop, restricted to targets you explicitly authorize.
5. Verification stage and full reports.

## License

MIT
