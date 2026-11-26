"""Pull public vulnerability datasets into the normalized JSONL format (see dataset/README.md).

  python dataset/fetch.py bigvul   --n 120 --out dataset/bigvul.jsonl      # redistributed in this repo (MIT)
  python dataset/fetch.py juliet   --n 80  --out dataset/juliet.jsonl      # redistributed in this repo (CC0)
  python dataset/fetch.py diversevul|draper|codexglue|benchmark --n 200 --out my.jsonl   # NOT redistributed, pull yourself

Uses the Hugging Face datasets-server API (no login, rate limited, stdlib only) and, for benchmark, raw GitHub.
Raise --n for a bigger sample. Sources and licenses: dataset/README.md. Check each license before redistributing."""
import argparse
import csv
import io
import json
import re
import sys
import time
import urllib.parse
import urllib.request

HF = "https://datasets-server.huggingface.co"
NAMES = {"A01": "Broken Access Control", "A02": "Cryptographic Failures", "A03": "Injection", "A04": "Insecure Design",
         "A05": "Security Misconfiguration", "A06": "Vulnerable and Outdated Components",
         "A07": "Identification and Authentication Failures", "A08": "Software and Data Integrity Failures",
         "A09": "Security Logging and Monitoring Failures", "A10": "Server-Side Request Forgery"}
# CWE -> OWASP Top 10 2021 (our mapping from the official per-category CWE lists, partial)
_CWE = {
    "A01": [22, 23, 35, 36, 200, 201, 219, 264, 275, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275],
    "A02": [259, 261, 296, 310, 311, 312, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
    "A03": [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917],
    "A04": [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173],
    "A05": [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174],
    "A06": [937, 1035, 1104],
    "A07": [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216],
    "A08": [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
    "A09": [117, 223, 532, 778],
    "A10": [918],
}
CWE2OWASP = {c: o for o, cs in _CWE.items() for c in cs}


def owasp_for(cwe):
    m = re.search(r"(\d+)", cwe or "")
    o = CWE2OWASP.get(int(m.group(1))) if m else None
    return f"{o}:2021 - {NAMES[o]}" if o else "N/A - no OWASP Top 10 2021 category (memory safety / other CWE)"


def get(url, tries=6):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "spider-dataset"}), timeout=60) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:  # rate limits / transient
            if i == tries - 1:
                raise
            time.sleep(5 * (i + 1))


def hf_rows(dataset, split="train", where=None, total=200, start=0, step=100):
    out, off = [], start
    while len(out) < total:
        if where:
            q = urllib.parse.urlencode({"dataset": dataset, "config": "default", "split": split, "where": where, "offset": off, "length": step})
            j = json.loads(get(f"{HF}/filter?{q}"))
        else:
            q = urllib.parse.urlencode({"dataset": dataset, "config": "default", "split": split, "offset": off, "length": step})
            j = json.loads(get(f"{HF}/rows?{q}"))
        rows = [r["row"] for r in j.get("rows", [])]
        if not rows:
            break
        out += rows
        off += step
        time.sleep(0.7)
    return out[:total]


def spread(rows, key, per_group):
    """Keep at most per_group rows per key value so no single CWE dominates."""
    seen, out = {}, []
    for r in rows:
        k = key(r)
        if seen.get(k, 0) < per_group:
            seen[k] = seen.get(k, 0) + 1
            out.append(r)
    return out


def rec(prefix, n, cwe, lang, desc, vuln, fixed, source, lic, notes=""):
    return {"id": f"{prefix}{n:04d}", "owasp": owasp_for(cwe), "cwe": cwe, "language": lang, "description": desc,
            "vulnerable_code": vuln, "fixed_code": fixed, "notes": notes, "source": source, "license": lic}


def bigvul(n, maxlen=1800):
    rows = hf_rows("bstee615/bigvul", where='"vul"=1', total=n * 12)
    rows = [r for r in rows if r["func_before"] and r["func_after"] and r["func_before"] != r["func_after"]
            and len(r["func_before"]) <= maxlen and len(r["func_after"]) <= maxlen]
    rows = spread(rows, lambda r: str(r["CWE ID"]), max(3, n // 25))[:n]
    return [rec("B", i, (r["CWE ID"] or "") if str(r["CWE ID"]).startswith("CWE") else "", r["lang"].lower() if r["lang"] else "c",
                f"{r['CVE ID']} in {r['project']}: vulnerable function and its fix", r["func_before"], r["func_after"],
                r["codeLink"], "MIT (c) 2020 ZeoVan, MSR_20_Code_vulnerability_CSV_Dataset") for i, r in enumerate(rows, 1)]


def juliet(n, maxlen=2200):
    rows = hf_rows("LorenzH/juliet_test_suite_c_1_3", total=n * 25, step=100)
    keep = []
    for r in rows:
        m = re.search(r"CWE(\d+)_", r["filename"])
        if m and r["bad"] and r["good"] and len(r["bad"]) <= maxlen and len(r["good"]) <= maxlen:
            r["_cwe"] = f"CWE-{m.group(1)}"
            keep.append(r)
    keep = spread(keep, lambda r: r["_cwe"], 3)[:n]
    return [rec("U", i, r["_cwe"], "cpp" if r["filename"].endswith(".cpp") else "c",
                f"NIST Juliet C/C++ 1.3 test case {r['filename'].split('/')[-1]} (bad vs good variant)", r["bad"], r["good"],
                "https://samate.nist.gov/SARD/test-suites/112 via https://huggingface.co/datasets/LorenzH/juliet_test_suite_c_1_3",
                "CC0-1.0 per the Hugging Face mirror; NIST Juliet test cases are published for public use") for i, r in enumerate(keep, 1)]


def diversevul(n, maxlen=2500):
    rows = hf_rows("bstee615/diversevul", where='"target"=1', total=n * 10)
    rows = [r for r in rows if len(r["func"]) <= maxlen]
    out = []
    for r in rows:
        cwes = re.findall(r"CWE-\d+", str(r.get("cwe")))
        out.append((cwes[0] if cwes else "", r))
    out = spread(out, lambda t: t[0], max(3, n // 25))[:n]
    return [rec("D", i, c, "c", f"DiverseVul vulnerable function from {r['project']}", r["func"], "", str(r.get("message", "")),
                "see https://github.com/wagner-group/diversevul") for i, (c, r) in enumerate(out, 1)]


def draper(n, maxlen=2500):
    rows = hf_rows("claudios/Draper", total=n * 6, step=100)
    out = []
    for r in rows:
        cs = [k for k in ("CWE-119", "CWE-120", "CWE-469", "CWE-476") if str(r.get(k)).lower() == "true"]
        if cs and len(r["functionSource"]) <= maxlen:
            out.append((cs[0], r))
    out = spread(out, lambda t: t[0], max(3, n // 4))[:n]
    return [rec("R", i, c, "c", "Draper VDISC function flagged by static analyzers (weak labels)", r["functionSource"], "",
                "https://osf.io/d45bw/", "see https://github.com/rjust/vdisc", "labels come from static analyzers, not manual audit")
            for i, (c, r) in enumerate(out, 1)]


def codexglue(n, maxlen=2500):
    rows = hf_rows("google/code_x_glue_cc_defect_detection", where='"target"=true', total=n * 3)
    rows = [r for r in rows if len(r["func"]) <= maxlen][:n]
    return [rec("X", i, "", "c", f"CodeXGLUE defect detection (Devign) vulnerable function from {r['project']}", r["func"], "",
                f"https://github.com/microsoft/CodeXGLUE (commit {r['commit_id']})", "C-UDA (Computational Use of Data Agreement)",
                "binary label only, no CWE") for i, r in enumerate(rows, 1)]


def benchmark(n):
    """OWASP Benchmark for Java (GPLv2): real-vulnerability test cases with their expected category/CWE."""
    base = "https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/master"
    rows = list(csv.reader(io.StringIO(get(base + "/expectedresults-1.2.csv"))))[1:]
    rows = [r for r in rows if len(r) >= 4 and r[2].strip().lower() == "true"]
    rows = spread(rows, lambda r: r[1], max(2, n // 11))[:n]
    out = []
    for i, r in enumerate(rows, 1):
        name = r[0].strip()
        try:
            code = get(f"{base}/src/main/java/org/owasp/benchmark/testcode/{name}.java")
        except Exception:
            continue
        out.append(rec("W", i, f"CWE-{r[3].strip()}", "java", f"OWASP Benchmark 1.2 {name} ({r[1]}): real vulnerability", code, "",
                       f"https://github.com/OWASP-Benchmark/BenchmarkJava/blob/master/src/main/java/org/owasp/benchmark/testcode/{name}.java",
                       "GPL-2.0 (OWASP Benchmark); not redistributed in the SPIDER repo"))
    return out


SOURCES = {"bigvul": bigvul, "juliet": juliet, "diversevul": diversevul, "draper": draper, "codexglue": codexglue, "benchmark": benchmark}

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("source", choices=SOURCES)
    p.add_argument("--n", type=int, default=100)
    p.add_argument("--out", required=True)
    a = p.parse_args()
    rows = SOURCES[a.source](a.n)
    with open(a.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{a.source}: wrote {len(rows)} records to {a.out}", file=sys.stderr)
