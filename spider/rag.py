"""Local RAG engine: hybrid retrieval over the labeled dataset and the OWASP/CWE taxonomy.

Everything runs on this machine. The index is one SQLite file (default ~/.spider/rag/index.db, override with
$SPIDER_RAG_DIR). Retrieval is BM25 keyword search (pure Python, nothing to download) fused with dense vectors
when the index was built with an Ollama embedding model. Vectors are stored as float32 blobs and scored with a
plain cosine loop, so there is no vector-database service and no extra Python package.

    spider rag index              # build it (see `spider rag index --help` for what is downloaded)
    spider rag search "sql string concatenation in a query"
    spider rag status

`spider PATH` uses the index automatically when it exists (disable with --no-rag). Reference notes are hints for
the review model: known vulnerable/fixed patterns and the matching OWASP/CWE entries. They never replace the code
under review.
"""
import array
import glob
import json
import math
import os
import re
import sqlite3
import urllib.error
import urllib.request

from . import knowledge
from .owasp import owasp_2025

DEFAULT_EMBED_MODEL = "nomic-embed-text"  # about 274 MB in Ollama, 768 dimensions
GITHUB_DATASET_API = "https://api.github.com/repos/Mahdy0000/SPIDER/contents/dataset"
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}|CWE-\d+")
_STOP = frozenset("the a an of to in is it and or for on with this that be as by at from are was not no if else return def class self none true false".split())


def index_dir():
    return os.environ.get("SPIDER_RAG_DIR") or os.path.join(os.path.expanduser("~"), ".spider", "rag")


def index_path():
    return os.path.join(index_dir(), "index.db")


def tokenize(text):
    out = []
    for t in _TOKEN.findall(text or ""):
        t = t.lower()
        out.append(t)
        if "_" in t:  # snake_case: also index the parts
            out += [p for p in t.split("_") if len(p) > 1]
        parts = re.findall(r"[a-z]+|\d+", t)
        if len(parts) > 1 and "_" not in t:
            out += [p for p in parts if len(p) > 1]
    return [t for t in out if t not in _STOP]


# ---------------------------------------------------------------- corpus

def _clip(s, n):
    s = (s or "").strip("\n")
    return s if len(s) <= n else s[:n].rstrip() + "\n..."


def dataset_docs(dataset_dir):
    """One doc per labeled sample. Uses the shards, or all.jsonl when there are no shards."""
    files = sorted(f for f in glob.glob(os.path.join(dataset_dir, "*.jsonl")) if os.path.basename(f) != "all.jsonl")
    files = files or glob.glob(os.path.join(dataset_dir, "all.jsonl"))
    docs, seen = [], set()
    for f in files:
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                r = json.loads(line)
                if r["id"] in seen:
                    continue
                seen.add(r["id"])
                o25 = r.get("owasp_2025") or owasp_2025(r.get("owasp", ""), r.get("cwe", ""))
                text = " ".join([r.get("description", ""), r.get("cwe", ""), r.get("owasp", ""), r.get("language", ""),
                                 _clip(r.get("vulnerable_code", ""), 700)])
                docs.append({"id": r["id"], "kind": "example", "title": f"{r.get('cwe') or 'no CWE'} {r.get('language', '')}".strip(),
                             "text": text, "payload": {
                                 "owasp": r.get("owasp", ""), "owasp_2025": o25, "cwe": r.get("cwe", ""), "language": r.get("language", ""),
                                 "description": _clip(r.get("description", ""), 300), "vulnerable": _clip(r.get("vulnerable_code", ""), 400),
                                 "fixed": _clip(r.get("fixed_code", ""), 400), "source": r.get("source", ""), "license": r.get("license", "")}})
    return docs


def taxonomy_docs():
    """Reference docs from spider/data: bundled CWE notes, OWASP 2021/2025, API and LLM lists, CWE Top 25."""
    docs = []
    for e in knowledge.load():
        docs.append({"id": f"kb:{e['id']}", "kind": "reference", "title": f"{e['id']} {e['name']}",
                     "text": f"{e['id']} {e['name']} {e['owasp']} {e['guidance']} {' '.join(e.get('keywords', []))}",
                     "payload": {"line": f"{e['id']} ({e['owasp']}) {e['name']}: {e['guidance']}"}})
    with open(os.path.join(os.path.dirname(__file__), "data", "taxonomy.json"), encoding="utf-8") as f:
        tax = json.load(f)
    for ver in ("owasp_2021", "owasp_2025"):
        for code, name in tax[ver]["names"].items():
            cwes = tax[ver]["cwes"][code]
            year = ver[-4:]
            docs.append({"id": f"{ver}:{code}", "kind": "reference", "title": f"{code}:{year} {name}",
                         "text": f"OWASP Top 10 {year} {code} {name} " + " ".join(f"CWE-{c}" for c in cwes),
                         "payload": {"line": f"{code}:{year} {name} (OWASP Top 10 {year}); mapped CWEs include "
                                             + ", ".join(f"CWE-{c}" for c in cwes[:8]) + ("..." if len(cwes) > 8 else "")}})
    for key, label in (("owasp_api_2023", "OWASP API Security Top 10 2023"), ("owasp_llm_2025", "OWASP Top 10 for LLM Applications 2025")):
        for c in tax.get(key, {}).get("categories", []):
            docs.append({"id": f"{key}:{c['id']}", "kind": "reference", "title": f"{c['id']} {c['name']}",
                         "text": f"{label} {c['id']} {c['name']} {c['description']} {' '.join(c.get('cwes', []))}",
                         "payload": {"line": f"{c['id']} {c['name']} ({label}): {c['description']}"}})
    seen = {}
    for year, ed in tax["cwe_top25"]["editions"].items():
        for r in ed["top25"]:
            seen.setdefault(r["cwe"], {"name": r["name"], "ranks": {}})["ranks"][year] = r["rank"]
    for cwe, v in sorted(seen.items(), key=lambda kv: int(kv[0][4:])):
        ranks = ", ".join(f"{y}: #{r}" for y, r in sorted(v["ranks"].items()))
        docs.append({"id": f"top25:{cwe}", "kind": "reference", "title": f"{cwe} {v['name']}",
                     "text": f"MITRE CWE Top 25 {cwe} {v['name']}",
                     "payload": {"line": f"{cwe} {v['name']}: in the MITRE CWE Top 25 ({ranks})"}})
    return docs


def fetch_dataset(dest, opener=urllib.request.urlopen):
    """One-time download of the dataset shards from the project's GitHub repo into dest. Returns the file names."""
    os.makedirs(dest, exist_ok=True)
    with opener(GITHUB_DATASET_API, timeout=30) as r:
        listing = json.loads(r.read())
    names = []
    for item in listing:
        n = item.get("name", "")
        if n.endswith(".jsonl") and n != "all.jsonl" and item.get("download_url"):
            with opener(item["download_url"], timeout=60) as r, open(os.path.join(dest, n), "wb") as out:
                out.write(r.read())
            names.append(n)
    return names


def find_dataset_dir():
    """The repo's dataset/ folder when running from a clone (or an editable install), else None."""
    d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dataset")
    return d if glob.glob(os.path.join(d, "*.jsonl")) else None


# ---------------------------------------------------------------- embeddings

class EmbedError(RuntimeError):
    pass


def ollama_embedder(host, model=DEFAULT_EMBED_MODEL, timeout=120):
    """Returns embed(list[str]) -> list[list[float]] using Ollama's local /api/embed."""
    def embed(texts):
        out = []
        for i in range(0, len(texts), 16):
            body = json.dumps({"model": model, "input": texts[i:i + 16]}).encode()
            req = urllib.request.Request(host.rstrip("/") + "/api/embed", data=body, headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    out += json.loads(r.read())["embeddings"]
            except urllib.error.HTTPError as e:
                raise EmbedError(f"Ollama embeddings HTTP {e.code}: {e.read().decode(errors='replace')[:200]} (try: ollama pull {model})")
            except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
                raise EmbedError(f"embedding request to {host} failed: {e}")
        return out
    return embed


def _norm(v):
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


# ---------------------------------------------------------------- store

def build_index(docs, path=None, embed=None, embed_model="", progress=None):
    """Write the SQLite index. With embed, each doc also gets a normalized float32 vector."""
    path = path or index_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    vecs = [None] * len(docs)
    if embed:
        for i in range(0, len(docs), 64):
            for j, v in enumerate(embed([d["text"][:2000] for d in docs[i:i + 64]])):
                vecs[i + j] = array.array("f", _norm(v)).tobytes()
            if progress:
                progress(min(i + 64, len(docs)), len(docs))
    con = sqlite3.connect(tmp)
    con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    con.execute("CREATE TABLE docs (id TEXT PRIMARY KEY, kind TEXT, title TEXT, text TEXT, payload TEXT, vec BLOB)")
    con.executemany("INSERT INTO docs VALUES (?,?,?,?,?,?)",
                    [(d["id"], d["kind"], d["title"], d["text"], json.dumps(d["payload"]), vecs[i]) for i, d in enumerate(docs)])
    con.executemany("INSERT INTO meta VALUES (?,?)", [("embed_model", embed_model if embed else ""), ("count", str(len(docs)))])
    con.commit()
    con.close()
    os.replace(tmp, path)
    return path


class Index:
    def __init__(self, path=None):
        self.path = path or index_path()
        con = sqlite3.connect(self.path)
        self.meta = dict(con.execute("SELECT key, value FROM meta"))
        self.docs = [(i, k, t, tx, json.loads(p), v) for i, k, t, tx, p, v in
                     con.execute("SELECT id, kind, title, text, payload, vec FROM docs")]
        con.close()
        self.embed_model = self.meta.get("embed_model", "")
        self._tok = [tokenize(d[3]) for d in self.docs]
        n = len(self._tok)
        df = {}
        for toks in self._tok:
            for t in set(toks):
                df[t] = df.get(t, 0) + 1
        self._idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}
        self._avg = sum(len(t) for t in self._tok) / max(n, 1)

    def __len__(self):
        return len(self.docs)

    def bm25(self, query, k1=1.5, b=0.75):
        q = set(tokenize(query))
        scores = []
        for toks in self._tok:
            tf = {}
            for t in toks:
                if t in q:
                    tf[t] = tf.get(t, 0) + 1
            s = 0.0
            for t, f in tf.items():
                s += self._idf[t] * f * (k1 + 1) / (f + k1 * (1 - b + b * len(toks) / (self._avg or 1)))
            scores.append(s)
        return scores

    def dense(self, qvec):
        q = _norm(qvec)
        scores = []
        for d in self.docs:
            if d[5] is None:
                scores.append(0.0)
                continue
            v = array.array("f")
            v.frombytes(d[5])
            scores.append(sum(a * b for a, b in zip(q, v)))
        return scores

    def search(self, query, k=5, kinds=None, embed=None):
        """Top-k docs as (score, doc dict). Fuses BM25 and dense ranks (reciprocal rank fusion) when vectors exist and
        embed is given; falls back to BM25 alone if the embedding call fails."""
        lists = [self.bm25(query)]
        mode = "bm25"
        if embed and self.embed_model:
            try:
                lists.append(self.dense(embed([query[:2000]])[0]))
                mode = "hybrid"
            except EmbedError:
                pass
        fused = [0.0] * len(self.docs)
        for sc in lists:
            order = sorted((i for i in range(len(sc)) if sc[i] > 0), key=lambda i: -sc[i])
            for rank, i in enumerate(order[:200]):
                fused[i] += 1.0 / (60 + rank)
        ranked = sorted((i for i in range(len(fused)) if fused[i] > 0 and (not kinds or self.docs[i][1] in kinds)), key=lambda i: -fused[i])
        out = []
        for i in ranked[:k]:
            d = self.docs[i]
            out.append((fused[i], {"id": d[0], "kind": d[1], "title": d[2], "payload": d[4], "mode": mode}))
        return out


# ---------------------------------------------------------------- review integration

_CACHE = {}


def load_index(path=None):
    p = path or index_path()
    if not os.path.exists(p):
        return None
    m = os.path.getmtime(p)
    if _CACHE.get("p") != (p, m):
        try:
            _CACHE["idx"] = Index(p)
        except sqlite3.Error:
            _CACHE["idx"] = None
        _CACHE["p"] = (p, m)
    return _CACHE["idx"]


def format_notes(hits):
    lines = []
    for _, d in hits:
        p = d["payload"]
        if d["kind"] == "example":
            lines.append(f"- Known pattern {d['id']} ({p['owasp']} / 2025: {p['owasp_2025']}, {p['cwe'] or 'no CWE'}, {p['language']}): "
                         f"{p['description']}\n  vulnerable form:\n{_indent(p['vulnerable'])}\n  safer form:\n{_indent(p['fixed'])}")
        else:
            lines.append(f"- {p['line']}")
    return "\n".join(lines)


def _indent(s):
    return "\n".join("    " + l for l in (s or "(none)").splitlines()[:8])


def notes_for(code, host=None, k_examples=2, k_refs=2, path=None):
    """Reference notes for the review prompt: similar known vulnerable/fixed samples and matching OWASP/CWE entries.
    Returns "" when there is no index. Never raises: retrieval is a hint, not a requirement."""
    try:
        idx = load_index(path)
        if idx is None:
            return ""
        embed = ollama_embedder(host, idx.embed_model, timeout=30) if (host and idx.embed_model) else None
        query = code[:3000]
        hits = idx.search(query, k_examples, kinds={"example"}, embed=embed) + idx.search(query, k_refs, kinds={"reference"}, embed=embed)
        return format_notes(hits)
    except Exception:  # noqa: BLE001 - hint only
        return ""
