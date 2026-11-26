import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "training"))
from spider import ollama, scanner  # noqa: E402
import prep_data  # noqa: E402
import train_qlora  # noqa: E402


class Tags(BaseHTTPRequestHandler):
    names = []

    def do_GET(self):
        body = json.dumps({"models": [{"name": n} for n in Tags.names]}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class DefaultModel(unittest.TestCase):
    def setUp(self):
        self.srv = HTTPServer(("127.0.0.1", 0), Tags)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.host = f"http://127.0.0.1:{self.srv.server_port}"

    def tearDown(self):
        self.srv.shutdown()

    def test_env_wins(self):
        Tags.names = ["spider-reviewer:latest"]
        self.assertEqual(ollama.default_model(self.host, {"SPIDER_MODEL": "x"}), "x")

    def test_tuned_model_used_when_installed(self):
        Tags.names = ["other:latest", "spider-reviewer:latest"]
        self.assertEqual(ollama.default_model(self.host, {}), "spider-reviewer")

    def test_fallback_when_missing_or_unreachable(self):
        Tags.names = ["other:latest"]
        self.assertEqual(ollama.default_model(self.host, {}), ollama.FALLBACK_MODEL)
        self.assertEqual(ollama.default_model("http://127.0.0.1:1", {}), ollama.FALLBACK_MODEL)


class PrepData(unittest.TestCase):
    def test_change_span_replacement_matches_patch_semantics(self):
        vuln = "a = 1\nq = 'SELECT ' + x\nreturn q"
        fixed = "a = 1\nq = ('SELECT ?', (x,))\nreturn q"
        s, e, repl = prep_data.change_span(vuln, fixed)
        self.assertEqual((s, e, repl), (2, 2, ["q = ('SELECT ?', (x,))"]))
        old = vuln.splitlines()
        old[s - 1:e] = repl
        self.assertEqual("\n".join(old), fixed)

    def test_pure_insert_anchors_on_neighbour(self):
        s, e, repl = prep_data.change_span("x = 1\nuse(x)", "x = 1\ncheck(x)\nuse(x)")
        old = "x = 1\nuse(x)".splitlines()
        old[s - 1:e] = repl
        self.assertEqual("\n".join(old), "x = 1\ncheck(x)\nuse(x)")

    def test_build_outputs_tool_schema(self):
        class A:
            dataset = os.path.join(ROOT, "dataset"); seed = 7; val_frac = 0.1; max_chars = 6000
            max_cybernative_per_category = 5; max_juliet = 3; negative_frac = 0.5; verify_frac = 0.5
            compose_frac = 0.5; no_compose = False; rag_prob = 0.7; extra_tasks = True
        out, drop, files, total = prep_data.build(A)
        self.assertGreater(len(out["train"]), 50)
        train_ids = {i for r in out["train"] for i in r["meta"]["id"].split("+")}
        val_ids = {i for r in out["val"] for i in r["meta"]["id"].split("+")}
        self.assertFalse(train_ids & val_ids)
        kinds = set()
        for r in out["train"]:
            kinds.add(r["meta"]["kind"])
            ans = r["messages"][2]["content"]
            if r["meta"]["kind"].startswith("review"):
                items = scanner.parse_findings(ans)
                self.assertEqual(json.loads(ans).keys(), {"findings"})
                for f in items:
                    self.assertIn(f["severity"], scanner.SEVERITIES)
                    self.assertLessEqual(f["line"], f["end_line"])
                    self.assertTrue(f["cwe"] == "" or f["cwe"].startswith("CWE-"))
            if r["meta"]["kind"].startswith("verify"):
                self.assertIn(json.loads(ans)["verdict"], ("real", "false_positive"))
        self.assertTrue({"review", "review_clean", "verify_real", "verify_fp"} <= kinds)
        # no benchmark fixture code in training data
        for r in out["train"] + out["val"]:
            self.assertNotIn("sk-live-1234567890abcdef", r["messages"][1]["content"])


class Render(unittest.TestCase):
    def test_render_masks_only_answer(self):
        prompt, answer = train_qlora.render([{"role": "system", "content": "S"}, {"role": "user", "content": "U"},
                                             {"role": "assistant", "content": "A"}])
        self.assertTrue(prompt.endswith("<|start_header_id|>assistant<|end_header_id|>\n\n"))
        self.assertEqual(answer, "A<|eot_id|>")


if __name__ == "__main__":
    unittest.main()
