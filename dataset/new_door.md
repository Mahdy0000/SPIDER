# new_door dataset

New vulnerability dataset for SPIDER, built November 27, 2026. Separate from the existing shards (`samples`, `juiceshop`, `bigvul`, `juliet`, `cybernative`): different source, different record shape, `ND` id prefix.

## What it is

Every CVE published from **2025-01-01 to 2026-11-27**, pulled from the **NVD API 2.0** (nvd.nist.gov) on 2026-11-27. **157,672 unique records**, all vulnerability types - not filtered to OWASP; web, memory-safety, firmware, cloud, everything NVD catalogs.

- 2025: 49,972 CVEs. 2026 to Nov 27: 107,700 CVEs.
- Severity (CVSS base): CRITICAL 15,126 - HIGH 58,989 - MEDIUM 63,671 - LOW 10,727 - unscored ~9,159.
- OWASP Top 10 (2021) mapping applied where the primary CWE maps (97,151 records); 60,521 records have no OWASP category, which is the point: this set covers weaknesses OWASP never lists (CWE-787, CWE-416, CWE-125, ...).
- Top primary CWEs: CWE-79 (17,626), CWE-862 (7,630), CWE-284 (5,556), CWE-89 (4,813), CWE-74 (4,583), CWE-22 (4,533), CWE-416 (4,532), CWE-125 (3,663), CWE-200 (3,441), CWE-352 (3,108).

## Format

JSONL, one object per line, sorted by published date. Sharded into `new_door_1.jsonl` ... `new_door_9.jsonl` (~20 MB each, GitHub's 100 MB file limit rules out one file).

| field | meaning |
|---|---|
| id | `ND000001` ... sequential, new_door prefix |
| cve | CVE id |
| published / last_modified | NVD dates |
| status | NVD vulnStatus (Analyzed, Awaiting Analysis, ...) |
| description | NVD English description |
| cwe | CWE ids from the CNA/NVD weakness entries |
| owasp | OWASP Top 10 (2021) category when the primary CWE maps, else N/A |
| owasp_2025 | OWASP Top 10 (2025) category code when it maps, else null |
| cwe_top25_years | MITRE CWE Top 25 editions the primary CWE appears in |
| cvss | best available base score: version, score, severity, vector (v4.0 > v3.1 > v3.0 > v2) |
| affected | up to 5 `vendor product` pairs from CPE match criteria |
| references | up to 5 reference URLs, patch/vendor-advisory/exploit first |
| source, license | NVD API 2.0; public domain (NIST/NVD, US government work) |

## Differences from the existing dataset

- The existing shards are code-level vulnerable/fixed sample pairs; new_door is a real-world CVE catalog - metadata, severity, classification, affected products, references. No code fields.
- Existing Big-Vul covers CVEs up to ~2020; new_door covers 2025-2026, so no overlap.
- Records carry both OWASP 2021 and 2025 labels plus CWE Top 25 membership, so RAG can answer by either taxonomy.

## Rebuild / update

NVD API 2.0, `pubStartDate`/`pubEndDate` windows of <=120 days, `resultsPerPage=2000`, no API key needed (rate limited). To extend: pull from 2026-11-27 forward and append with new ids.
