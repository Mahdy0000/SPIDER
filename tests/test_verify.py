"""Verification stage tests: deterministic web re-check and model second pass (fake Ollama)."""
import json
import os
import unittest
from http.server import HTTPServer
import threading

from spider import cli, scanner, verify
from spider.web import checks, pages
from spider.web.client import ScopedClient
from spider.web.scope import Scope
from tests.test_web import App, FakeOllama

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable_app.py")


class VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = HTTPServer(("127.0.0.1", 0), App)
        cls.llm = HTTPServer(("127.0.0.1", 0), FakeOllama)
        for s in (cls.app, cls.llm):
            threading.Thread(target=s.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.app.server_port}"
        cls.host = f"http://127.0.0.1:{cls.llm.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.app.shutdown()
        cls.llm.shutdown()

    def test_web_reproduced_and_not_reproduced(self):
        c = ScopedClient(Scope())
        ps, _ = pages.crawl(c, self.base + "/", max_pages=1)
        real = [f for f in checks.run_all(c, ps) if f["check_id"] == "hdr:content-security-policy"][0]
        ghost = checks.finding("cookie:ghost", self.base + "/", "Cookie 'ghost' lacks Secure", "low", "A05", "CWE-614", "d", "f")
        env = [f for f in checks.run_all(c, ps) if f["check_id"] == "path:/.env"][0]
        out = {f["check_id"]: f for f in verify.verify_all([real, ghost, env], client=c)}
        self.assertEqual(out["hdr:content-security-policy"]["verification"]["status"], "reproduced")
        self.assertEqual(out["cookie:ghost"]["verification"]["status"], "not_reproduced")
        self.assertEqual(out["cookie:ghost"]["confidence"], "low")
        self.assertEqual(out["path:/.env"]["verification"]["status"], "reproduced")

    def test_hide_false_positives(self):
        c = ScopedClient(Scope())
        ghost = checks.finding("cookie:ghost", self.base + "/", "t", "low", "A05", "", "d", "f")
        self.assertEqual(verify.verify_all([ghost], client=c, hide_false_positives=True), [])

    def test_code_second_pass(self):
        fs = [scanner.clean({"title": "SQL injection", "line": 11, "severity": "high", "owasp": "A03", "description": "d"}, FIX, 20),
              scanner.clean({"title": "Maybe", "line": 7, "severity": "low", "owasp": "A02", "description": "d"}, FIX, 20)]
        FakeOllama.script = [json.dumps({"verdict": "real", "reason": "line 11 concatenates input"}),
                             json.dumps({"verdict": "false_positive", "reason": "constant"})]
        out = verify.verify_all(fs, host=self.host, model="x")
        self.assertEqual([f["verification"]["status"] for f in out], ["likely_real", "likely_false_positive"])
        self.assertEqual(verify.summary_counts(out), {"likely_real": 1, "likely_false_positive": 1})

    def test_garbage_model_output_is_uncertain(self):
        f = scanner.clean({"title": "x", "line": 3}, FIX, 20)
        FakeOllama.script = ["not json at all"]
        self.assertEqual(verify.verify_all([f], host=self.host, model="x")[0]["verification"]["status"], "uncertain")

    def test_missing_file_is_uncertain(self):
        f = scanner.clean({"title": "x", "line": 3}, "/nonexistent/file.py", 20)
        self.assertEqual(verify.verify_all([f], host=self.host, model="x")[0]["verification"]["status"], "uncertain")

    def test_cli_verify_code(self):
        FakeOllama.script = [json.dumps({"findings": [{"title": "SQLi", "line": 11, "severity": "high", "owasp": "A03", "description": "d"}]}),
                             json.dumps({"verdict": "false_positive", "reason": "r"})]
        rc = cli.main([FIX, "--host", self.host, "--verify", "--hide-false-positives", "--format", "json", "-o", "/tmp/_v.json"])
        self.assertEqual(rc, 0)
        with open("/tmp/_v.json") as fh:
            self.assertEqual(json.load(fh)["findings"], [])

    def test_cli_verify_web(self):
        rc = cli.main(["web", self.base + "/", "--delay", "0", "--verify", "--hide-false-positives", "--format", "markdown", "-o", "/tmp/_vw.md"])
        self.assertEqual(rc, 0)
        with open("/tmp/_vw.md") as fh:
            self.assertIn("Verification: reproduced", fh.read())


if __name__ == "__main__":
    unittest.main()
