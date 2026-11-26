import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from spider import rag, ragcli, scanner

TAX = os.path.join(os.path.dirname(__file__), "..", "spider", "data", "taxonomy.json")


def fake_embed(texts):
    # tiny deterministic bag-of-keywords vectors
    keys = ["sql", "hash", "xss", "path", "password"]
    return [[float(t.lower().count(k)) + 0.01 for k in keys] for t in texts]


def EX(cwe):
    return {"owasp": "A03", "owasp_2025": "A05", "cwe": cwe, "language": "python", "description": "d", "vulnerable": "bad()", "fixed": "good()"}


def docs():
    return [
        {"id": "a", "kind": "example", "title": "CWE-89 python", "text": "sql query built by string concatenation with user input", "payload": EX("CWE-89")},
        {"id": "b", "kind": "example", "title": "CWE-327 php", "text": "md5 hash used for password storage", "payload": EX("CWE-327")},
        {"id": "c", "kind": "reference", "title": "CWE-79", "text": "reflected xss from unescaped output", "payload": {"line": "CWE-79 reflected xss: escape output"}},
    ]


class TaxonomyTests(unittest.TestCase):
    def test_api_and_llm_lists(self):
        t = json.load(open(TAX, encoding="utf-8"))
        for key, n in (("owasp_api_2023", "API"), ("owasp_llm_2025", "LLM")):
            cats = t[key]["categories"]
            self.assertEqual(len(cats), 10)
            for c in cats:
                self.assertTrue(c["id"].startswith(n))
                self.assertTrue(c["name"] and c["description"] and c["source"].startswith("https://"))
                self.assertIn("cwes", c)


class RagTests(unittest.TestCase):
    def test_tokenize(self):
        self.assertIn("sql", rag.tokenize("SQL-Injection in query()"))

    def test_lexical_search(self):
        with tempfile.TemporaryDirectory() as d:
            p = rag.build_index(docs(), os.path.join(d, "i.db"))
            hits = rag.Index(p).search("password hash md5", 2)
            self.assertEqual(hits[0][1]["id"], "b")
            self.assertEqual(hits[0][1]["mode"], "bm25")

    def test_hybrid_search_and_progress(self):
        calls = []
        with tempfile.TemporaryDirectory() as d:
            p = rag.build_index(docs(), os.path.join(d, "i.db"), fake_embed, "fake", progress=lambda a, b: calls.append((a, b)))
            idx = rag.Index(p)
            self.assertEqual(idx.embed_model, "fake")
            hits = idx.search("xss output", 1, embed=fake_embed)
            self.assertEqual(hits[0][1]["id"], "c")
            self.assertEqual(hits[0][1]["mode"], "hybrid")
        self.assertEqual(calls[-1], (3, 3))

    def test_embed_failure_falls_back(self):
        def boom(_):
            raise rag.EmbedError("down")
        with tempfile.TemporaryDirectory() as d:
            p = rag.build_index(docs(), os.path.join(d, "i.db"), fake_embed, "fake")
            hits = rag.Index(p).search("sql concatenation", 1, embed=boom)
            self.assertEqual(hits[0][1]["id"], "a")
            self.assertEqual(hits[0][1]["mode"], "bm25")

    def test_taxonomy_docs_cover_all_lists(self):
        ids = " ".join(d["id"] for d in rag.taxonomy_docs())
        for needle in ("API1", "LLM01"):
            self.assertIn(needle, ids)

    def test_notes_for_without_index_is_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(rag.notes_for("x = 1", path=os.path.join(d, "none.db")), "")

    def test_fetch_dataset_with_fake_opener(self):
        listing = json.dumps([{"name": "a.jsonl", "download_url": "http://x/a"}, {"name": "README.md", "download_url": "http://x/r"}]).encode()

        class R(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def opener(req, timeout=None):
            url = req if isinstance(req, str) else req.full_url
            return R(b'{"x":1}\n' if url.endswith("/a") else listing)
        with tempfile.TemporaryDirectory() as d:
            names = rag.fetch_dataset(d, opener=opener)
            self.assertEqual(names, ["a.jsonl"])
            self.assertTrue(os.path.exists(os.path.join(d, "a.jsonl")))

    def test_cli_index_search_status(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as ds:
            with open(os.path.join(ds, "s.jsonl"), "w") as f:
                f.write(json.dumps({"id": "S1", "language": "python", "cwe": "CWE-89", "vulnerable_code": "q = 'select ' + x", "fixed_code": "q = ('select ?', (x,))", "explanation": "sql injection"}) + "\n")
            ix = os.path.join(d, "i.db")
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(ragcli.main(["index", "--lexical", "--dataset", ds, "--index", ix]), 0)
                self.assertEqual(ragcli.main(["status", "--index", ix]), 0)
                self.assertEqual(ragcli.main(["search", "sql injection", "--index", ix]), 0)
            self.assertIn("keyword only", buf.getvalue())
            with redirect_stderr(io.StringIO()):
                self.assertEqual(ragcli.main(["status", "--index", os.path.join(d, "missing.db")]), 1)

    def test_scanner_uses_index_via_env(self):
        with tempfile.TemporaryDirectory() as d:
            rag.build_index(docs(), os.path.join(d, "index.db"))
            old = os.environ.get("SPIDER_RAG_DIR")
            os.environ["SPIDER_RAG_DIR"] = d
            try:
                self.assertIn("Known pattern", rag.notes_for("query = 'select * from t where id=' + user_input  # sql concatenation"))
            finally:
                if old is None:
                    del os.environ["SPIDER_RAG_DIR"]
                else:
                    os.environ["SPIDER_RAG_DIR"] = old


if __name__ == "__main__":
    unittest.main()
