# Dataset

Labeled vulnerable/fixed code pairs, collected so a retrieval step (RAG) can use them later. **Not wired into the tool yet**; today retrieval uses only `spider/data/cwe.json`.

## Contents (194 pairs)

| OWASP Top 10 (2021) | original | Juice Shop | total |
|---|---|---|---|
| A01:2021 - Broken Access Control | 14 | 18 | 32 |
| A02:2021 - Cryptographic Failures | 16 | 10 | 26 |
| A03:2021 - Injection | 20 | 36 | 56 |
| A04:2021 - Insecure Design | 7 | 3 | 10 |
| A05:2021 - Security Misconfiguration | 9 | 2 | 11 |
| A06:2021 - Vulnerable and Outdated Components | 5 | 2 | 7 |
| A07:2021 - Identification and Authentication Failures | 9 | 13 | 22 |
| A08:2021 - Software and Data Integrity Failures | 10 | 0 | 10 |
| A09:2021 - Security Logging and Monitoring Failures | 9 | 5 | 14 |
| A10:2021 - Server-Side Request Forgery | 6 | 0 | 6 |
| **total** | **105** | **89** | **194** |

Languages: typescript 69, python 37, javascript 29, java 15, yaml 13, php 10, sol 6, go 5, dockerfile 2, text 2, tf 2, json 1, xml 1, shell 1, html 1.

Every OWASP Top 10 (2021) category has at least 5 pairs. Categories A08 and A10 come only from the original set; Juice Shop has no usable snippets for them.

## Files

- `samples.jsonl`: original samples written for this project (MIT). Regenerate with `python dataset/build_originals.py`.
- `juiceshop.jsonl`: pairs derived from OWASP Juice Shop coding challenges. Regenerate with `dataset/build_juiceshop.py` (instructions in its docstring).

## Format

JSONL, one object per line:

| field | meaning |
|---|---|
| id | `O0001` (original) or `J0001` (Juice Shop) |
| owasp | OWASP Top 10 (2021) category |
| cwe | CWE id (empty for Juice Shop pairs, which do not carry one) |
| language | language/format of the snippet |
| description | what is wrong |
| vulnerable_code | snippet with the flaw |
| fixed_code | corrected snippet |
| notes | optional, Juice Shop only: why this candidate fix is wrong |
| source, license | provenance of that record |

## Provenance and licenses

- **Original samples**: written for this project, MIT. Short idiomatic snippets, not copied from anywhere.
- **OWASP Juice Shop** (https://github.com/juice-shop/juice-shop), MIT license, Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors. Each challenge ships several candidate fixes of one vulnerable file; exactly one is correct. We pair each incorrect candidate (still vulnerable or only cosmetically changed) with the correct one, so `vulnerable_code` can be the original code with a small non-fix edit. The Juice Shop category to OWASP 2021 mapping is ours (Injection, XSS, Improper Input Validation -> A03; Sensitive Data Exposure -> A02; XXE -> A05; etc.), and Juice Shop's "Miscellaneous" challenges are skipped. Full MIT notice: https://github.com/juice-shop/juice-shop/blob/master/LICENSE
- **Not included**: OWASP Benchmark (GPLv2, which would conflict with this repo's MIT license) and NIST Juliet (mostly C/C++/Java test cases keyed to CWE, not OWASP categories, and very large). Both are worth adding later as separate, clearly licensed files if wanted.

## Limits

Small for training a model, fine as a retrieval corpus and test seed. Labels were assigned by script and by hand, not independently audited; the original samples are short and idealised, real code is messier. Juice Shop snippets are TypeScript/YAML/Solidity/Terraform from one app.
