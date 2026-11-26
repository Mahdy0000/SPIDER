"""`spider rag ...`: build and query the local RAG index (see spider/rag.py)."""
import argparse
import os
import sys
import tempfile

from . import rag


def main(argv):
    p = argparse.ArgumentParser(prog="spider rag", description="Local RAG index over the labeled dataset and the OWASP/CWE taxonomy. Nothing leaves this machine except the one-time downloads listed in `spider rag index --help`.")
    sub = p.add_subparsers(dest="cmd", required=True)
    ix = sub.add_parser("index", help="build or rebuild the index",
                        description="Build the index. What gets downloaded: (1) the dataset shards (about 3 MB, from github.com/Mahdy0000/SPIDER) ONLY if there is no local dataset/ folder, i.e. a plain pip install; "
                                    "(2) with embeddings, the Ollama model `nomic-embed-text` (about 274 MB) which you pull yourself with `ollama pull nomic-embed-text`. "
                                    "With --lexical nothing is embedded and nothing is pulled. After that everything runs offline.")
    ix.add_argument("--dataset", help="folder with the *.jsonl shards (default: the repo's dataset/ if present, else downloaded once)")
    ix.add_argument("--lexical", action="store_true", help="keyword (BM25) index only, no embedding model needed")
    ix.add_argument("--embed-model", default=os.environ.get("SPIDER_EMBED_MODEL", rag.DEFAULT_EMBED_MODEL))
    ix.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    ix.add_argument("--index", help=f"index file (default {rag.index_path()})")
    se = sub.add_parser("search", help="query the index")
    se.add_argument("query")
    se.add_argument("-k", type=int, default=5)
    se.add_argument("--index")
    se.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    st = sub.add_parser("status", help="show the index")
    st.add_argument("--index")
    a = p.parse_args(argv)

    if a.cmd == "index":
        d = a.dataset or rag.find_dataset_dir()
        if not d:
            d = os.path.join(rag.index_dir(), "dataset")
            print(f"No local dataset folder found. Downloading the dataset shards (about 3 MB) from GitHub into {d} ...")
            try:
                names = rag.fetch_dataset(d)
            except OSError as e:
                print(f"Download failed: {e}. Clone the repo, or pass --dataset PATH.", file=sys.stderr)
                return 1
            print(f"Downloaded {len(names)} files.")
        docs = rag.dataset_docs(d) + rag.taxonomy_docs()
        embed = None
        if not a.lexical:
            embed = rag.ollama_embedder(a.host, a.embed_model)
            try:
                embed(["test"])
            except rag.EmbedError as e:
                print(f"{e}\nBuilding a keyword-only index instead (use --lexical to silence this, or `ollama pull {a.embed_model}` and re-run).", file=sys.stderr)
                embed = None
        def _progress(done, total):
            print(f"\r  embedding {done}/{total} ({100 * done // total}%)", end="", flush=True)
            if done == total:
                print()
        path = rag.build_index(docs, a.index, embed, a.embed_model, progress=_progress)
        print(f"Indexed {len(docs)} documents ({sum(1 for x in docs if x['kind'] == 'example')} dataset samples, "
              f"{sum(1 for x in docs if x['kind'] == 'reference')} reference entries) into {path}; mode: {'hybrid (BM25 + ' + a.embed_model + ')' if embed else 'keyword only (BM25)'}")
        return 0

    path = a.index or rag.index_path()
    if not os.path.exists(path):
        print(f"No index at {path}. Build it first: spider rag index", file=sys.stderr)
        return 1
    idx = rag.Index(path)
    if a.cmd == "status":
        kinds = {}
        for d in idx.docs:
            kinds[d[1]] = kinds.get(d[1], 0) + 1
        print(f"{path}\n{len(idx)} documents {kinds}\nembedding model: {idx.embed_model or 'none (keyword only)'}")
        return 0
    embed = rag.ollama_embedder(a.host, idx.embed_model, timeout=30) if idx.embed_model else None
    hits = idx.search(a.query, a.k, embed=embed)
    if not hits:
        print("No matches.")
        return 0
    print(f"mode: {hits[0][1]['mode']}")
    for score, d in hits:
        print(f"\n[{d['kind']}] {d['id']}  {d['title']}  (score {score:.4f})")
        print(rag.format_notes([(score, d)]))
    return 0
