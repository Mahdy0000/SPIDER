"""Merge every dataset/*.jsonl shard into one file for training or retrieval.

    python dataset/merge.py                      # writes dataset/all.jsonl
    python dataset/merge.py --out /tmp/all.jsonl

Each record keeps its id, source, license, owasp, cwe and language fields.
Duplicate ids are dropped. The shards stay under 200 KB so they can be pushed and
viewed on GitHub; this script gives you the single file.
"""
import argparse, glob, json, os

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser()
    p.add_argument("--out", default=os.path.join(here, "all.jsonl"))
    a = p.parse_args()
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
                o.write(json.dumps(r, ensure_ascii=False) + "\n")
                n += 1
    os.replace(a.out + ".tmp", a.out)
    print(f"wrote {n} records to {a.out}")

if __name__ == "__main__":
    main()
