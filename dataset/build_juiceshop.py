"""Builds dataset/juiceshop.jsonl from OWASP Juice Shop's coding-challenge snippets (MIT).
Usage: git clone --depth 1 https://github.com/juice-shop/juice-shop.git /tmp/js && python dataset/build_juiceshop.py /tmp/js
Needs PyYAML (build time only).

Each challenge ships several candidate fixes of one vulnerable file; exactly one is correct. We pair every
incorrect candidate (still vulnerable or only cosmetically changed) with the correct one."""
import glob
import json
import os
import re
import sys

import yaml

NAMES = {"A01": "Broken Access Control", "A02": "Cryptographic Failures", "A03": "Injection", "A04": "Insecure Design",
         "A05": "Security Misconfiguration", "A06": "Vulnerable and Outdated Components",
         "A07": "Identification and Authentication Failures", "A08": "Software and Data Integrity Failures",
         "A09": "Security Logging and Monitoring Failures", "A10": "Server-Side Request Forgery"}
# Juice Shop category -> OWASP Top 10 2021 (our mapping, not Juice Shop's)
MAP = {"Broken Access Control": "A01", "Unvalidated Redirects": "A01", "Broken Anti Automation": "A04",
       "Broken Authentication": "A07", "Cryptographic Issues": "A02", "Sensitive Data Exposure": "A02",
       "Improper Input Validation": "A03", "Injection": "A03", "XSS": "A03", "Insecure Deserialization": "A08",
       "Observability Failures": "A09", "Security Misconfiguration": "A05", "Security through Obscurity": "A05",
       "XXE": "A05", "Vulnerable Components": "A06"}

root = sys.argv[1]
cats = {c["key"]: c for c in yaml.safe_load(open(os.path.join(root, "data/static/challenges.yml")))}
out, n = [], 0
for info in sorted(glob.glob(os.path.join(root, "data/static/codefixes/*.info.yml"))):
    key = os.path.basename(info)[:-len(".info.yml")]
    ch = cats.get(key)
    if not ch or ch["category"] not in MAP:
        continue
    expl = {f["id"]: f["explanation"] for f in yaml.safe_load(open(info)).get("fixes", [])}
    files = {}
    for p in glob.glob(os.path.join(root, f"data/static/codefixes/{key}_*")):
        m = re.match(rf"{re.escape(key)}_(\d+)(_correct)?\.(\w+)$", os.path.basename(p))
        if m:
            files[int(m.group(1))] = (open(p, encoding="utf-8").read().rstrip("\n"), bool(m.group(2)), m.group(3))
    good = [v for v in files.values() if v[1]]
    if len(good) != 1:
        continue
    fixed, _, ext = good[0]
    for i, (code, ok, _) in sorted(files.items()):
        if ok:
            continue
        n += 1
        o = MAP[ch["category"]]
        out.append({"id": f"J{n:04d}", "owasp": f"{o}:2021 - {NAMES[o]}", "cwe": "", "language": {"ts": "typescript", "yml": "yaml"}.get(ext, ext),
                    "description": f"Juice Shop challenge '{ch['name']}' ({ch['category']}), candidate fix {i} is NOT a correct fix",
                    "vulnerable_code": code, "fixed_code": fixed,
                    "notes": expl.get(i, ""),
                    "source": f"https://github.com/juice-shop/juice-shop/tree/master/data/static/codefixes ({key}_{i})",
                    "license": "MIT (c) Bjoern Kimminich & the OWASP Juice Shop contributors"})
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "juiceshop.jsonl"), "w", encoding="utf-8") as f:
    for r in out:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print(len(out), "pairs")
