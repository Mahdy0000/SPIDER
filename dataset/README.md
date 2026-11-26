# Dataset

Labeled vulnerable code samples, collected so a retrieval step (RAG) can use them later. **Not wired into the tool yet**; today retrieval uses only `spider/data/cwe.json`.

## Contents: 354 samples in this repo

| Category | original | Juice Shop | Big-Vul | Juliet | total |
|---|---|---|---|---|---|
| A01:2021 Broken Access Control | 14 | 18 | 13 | 2 | 47 |
| A02:2021 Cryptographic Failures | 16 | 10 | 2 | 0 | 28 |
| A03:2021 Injection | 20 | 36 | 11 | 4 | 71 |
| A04:2021 Insecure Design | 7 | 3 | 0 | 0 | 10 |
| A05:2021 Security Misconfiguration | 9 | 2 | 0 | 1 | 12 |
| A06:2021 Vulnerable and Outdated Components | 5 | 2 | 0 | 0 | 7 |
| A07:2021 Identification and Authentication Failures | 9 | 13 | 1 | 0 | 23 |
| A08:2021 Software and Data Integrity Failures | 10 | 0 | 1 | 0 | 11 |
| A09:2021 Security Logging and Monitoring Failures | 9 | 5 | 0 | 0 | 14 |
| A10:2021 Server-Side Request Forgery | 6 | 0 | 0 | 0 | 6 |
| N/A No OWASP Top 10 category (memory safety / other CWE) | 0 | 0 | 72 | 53 | 125 |
| **total** | **105** | **89** | **100** | **60** | **354** |

Languages: c 126, typescript 69, python 37, cpp 34, javascript 29, java 15, yaml 13, php 10, sol 6, go 5, dockerfile 2, text 2, tf 2, json 1, xml 1, shell 1, html 1.

Web-app OWASP categories (A01 to A10) come mostly from the original and Juice Shop sets. Big-Vul and Juliet are C/C++ and are dominated by memory-safety CWEs (buffer overflows, use-after-free, integer overflow), which the OWASP Top 10 does not list, so they land in the N/A row. Their CWE ids are kept in the `cwe` field. Mapping of CWE to OWASP 2021 is ours (`owasp_for` in `fetch.py`, based on the official per-category CWE lists, partial).

## Files and sources

| file | source | what | license |
|---|---|---|---|
| `samples.jsonl` | original, written for this project | short idiomatic vulnerable/fixed pairs, 9 languages | MIT |
| `juiceshop_1.jsonl`, `juiceshop_2.jsonl` | [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) coding challenges | each incorrect candidate fix paired with the correct fix | MIT, (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors |
| `bigvul.jsonl` | [Big-Vul](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset) (Fan et al., MSR 2020), via https://huggingface.co/datasets/bstee615/bigvul | CVE-fixing commits: function before (vulnerable) and after (fixed), CWE labels, C/C++ | MIT, (c) 2020 ZeoVan |
| `juliet.jsonl` | [NIST Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112) via https://huggingface.co/datasets/LorenzH/juliet_test_suite_c_1_3 | synthetic test cases: bad and good variant, CWE from file name | CC0-1.0 per the mirror card; NIST test suite for public use |

Big-Vul sample: at most a few functions per CWE, functions up to 1800 chars. Juliet sample: at most 3 per CWE, files up to 2200 chars. Both are samples, not the full sets.

## Public sets NOT redistributed here, with the command to pull them

These are normalized by `fetch.py` into the same format, but their licenses do not fit redistribution inside an MIT repo, or could not be confirmed. Run it yourself and check the license first:

```bash
python dataset/fetch.py benchmark  --n 200 --out dataset/benchmark.jsonl   # OWASP Benchmark for Java, GPL-2.0
python dataset/fetch.py codexglue  --n 200 --out dataset/codexglue.jsonl   # CodeXGLUE defect detection = Devign, C-UDA data license
python dataset/fetch.py diversevul --n 200 --out dataset/diversevul.jsonl  # DiverseVul (Chen et al.), license not confirmed by us
python dataset/fetch.py draper     --n 200 --out dataset/draper.jsonl      # Draper VDISC (Russell et al.), license not confirmed by us
```

Each was test-run with a small sample (benchmark, codexglue, diversevul, draper all produced records), so the script works. Only the first rows are pulled via the Hugging Face datasets-server API (rate limited, no login), so raise `--n` for more, or download the full upstream sets: Devign/CodeXGLUE https://github.com/microsoft/CodeXGLUE, DiverseVul https://github.com/wagner-group/diversevul, Draper VDISC https://github.com/rjust/vdisc, Juliet and others https://samate.nist.gov/SARD/, Big-Vul full https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset. CodeXGLUE and Draper have no fixed version and no (or weak) CWE labels.

## Format

JSONL, one object per line:

| field | meaning |
|---|---|
| id | prefix + number: `O` original, `J` Juice Shop, `B` Big-Vul, `U` Juliet, `D` DiverseVul, `R` Draper, `X` CodeXGLUE, `W` Benchmark |
| owasp | OWASP Top 10 (2021) category, or `N/A - ...` when the CWE has none |
| cwe | CWE id; empty when the source has none |
| language | language of the snippet |
| description | what is wrong |
| vulnerable_code | the flawed code |
| fixed_code | corrected code; empty when the source has no fix |
| notes | optional extra (Juice Shop: why a candidate fix is wrong; Draper: label caveat) |
| source, license | provenance of that record |

Regenerate: `build_originals.py` (originals), `build_juiceshop.py` (needs a Juice Shop clone, see its docstring), `fetch.py` (the rest).

## Limits

- Hundreds of samples, not a training-scale corpus. Fine for retrieval and as a test seed.
- Labels are the sources' own plus our CWE-to-OWASP mapping; not independently audited. Big-Vul labels come from commits and are known to be noisy; Juliet is synthetic and idealised.
- Juice Shop `vulnerable_code` is the original with a small non-fix edit (a deliberately wrong candidate fix), see the `notes` field.
- Mostly C/C++ for the large sets; web languages are covered by the original and Juice Shop samples.
