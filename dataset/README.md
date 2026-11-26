# Dataset

Labeled vulnerable/fixed code pairs, kept here so a retrieval step (RAG) can use them later. Not wired into the tool yet; `spider/data/cwe.json` is what retrieval uses today.

## Format

`samples.jsonl`, one JSON object per line:

| field | meaning |
|---|---|
| id | `S001`... |
| owasp | OWASP Top 10 (2021) category |
| cwe | CWE id |
| language | python, javascript, text |
| description | what is wrong |
| vulnerable_code | short snippet with the flaw |
| fixed_code | the corrected snippet |
| source, license | provenance |

## Provenance

All 16 samples are original, small, written for this project (MIT, same as the repo). Nothing is copied from third-party suites. Coverage: all 10 OWASP categories, 1 to 2 samples each.

This is a seed set, too small to train or evaluate a model. To grow it, add samples adapted from public suites such as OWASP Benchmark, Juliet, or CVE-fix commits, and record each one's source and license in the `source` / `license` fields. Check the license before copying.
