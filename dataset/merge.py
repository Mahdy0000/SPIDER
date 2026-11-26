"""Merge every dataset/*.jsonl shard into one file for training or retrieval.

    python dataset/merge.py                      # writes dataset/all.jsonl
    python dataset/merge.py --out /tmp/all.jsonl
    python dataset/merge.py --no-enrich          # shard fields only

Each record keeps its id, source, license, owasp (2021 label), cwe and language fields. Merged records also get:
  owasp_2025        OWASP Top 10:2025 label. From the CWE when the 2025 category lists contain it,
                    otherwise from the official 2021 to 2025 category crosswalk.
  owasp_2025_basis  "cwe" or "category-crosswalk" (how owasp_2025 was derived)
  cwe_top25         years (2021-2025) in which the CWE is in the MITRE CWE Top 25, [] when never
Mappings come from spider/data/taxonomy.json. Duplicate ids are dropped. The shards stay under 200 KB so they
can be pushed and viewed on GitHub; this script gives you the single file.
"""
import argparse, glob, json, os, sys


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser()
    p.add_argument("--out", default=os.path.join(here, "all.jsonl"))
    p.add_argument("--no-enrich", action="store_true")
    a = p.parse_args()
    sys.path.insert(0, os.path.join(here, ".."))
    from spider.owasp import cwe_top25_years, owasp_2025
    seen, n = set(), 0
    out = os.path.abspath(a.out)
    with open(a.out + ".tmp", "w", encoding="utf-8") as o:
        for f in sorted(glob.glob(os.path.join(here, "*.jsonl"))):
            if os.path.abspath(f) == out:
                continue
            for line in open(f, encoding="utf-8"):
                if not line.strip():
                    continue
                r = json.loads(line)
                if r["id"] in seen:
                    continue
                seen.add(r["id"])
                if not a.no_enrich:
                    by_cwe = owasp_2025("", r["cwe"])
                    r["owasp_2025"] = by_cwe if by_cwe != "Unmapped" else owasp_2025(r["owasp"], "")
                    if r["owasp_2025"] == "Unmapped":
                        r["owasp_2025"] = "N/A - no OWASP Top 10 2025 category (memory safety / other CWE)"
                    r["owasp_2025_basis"] = "cwe" if by_cwe != "Unmapped" else "category-crosswalk"
                    r["cwe_top25"] = cwe_top25_years(r["cwe"])
                o.write(json.dumps(r, ensure_ascii=False) + "\n")
                n += 1
    os.replace(a.out + ".tmp", a.out)
    print(f"wrote {n} records to {a.out}")


if __name__ == "__main__":
    main()
