"""Offline tests: a fake Ollama HTTP server returns canned findings, so no GPU/model is needed."""
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from spider import cli, scanner

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable_app.py")
CANNED = {"findings": [
    {"title": "SQL injection", "severity": "high", "owasp": "a03", "cwe": "CWE-89", "line": 11,
     "description": "String concatenation in query.", "fix": "Use parameters.",
     "fixed_code": "cur.execute('SELECT * FROM users WHERE name = ?', (name,))"},
    {"title": "Hardcoded secret", "severity": "critical", "owasp": "A02:2021", "line": 7,
     "description": "API key in source.", "fix": "Load from env.", "fixed_code": "API_KEY = os.environ['API_KEY']"},
    {"title": "Out of range line", "severity": "bogus", "owasp": "zzz", "line": 9999},
]}


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        body = json.dumps({"message": {"content": "```json\n" + json.dumps(CANNED) + "\n```"}}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.host = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_scan(self):
        f = scanner.sort_findings(scanner.scan_file(FIX, self.host, "x"))
        self.assertEqual(f[0]["severity"], "critical")
        self.assertEqual(f[0]["owasp"], "A02:2021 - Cryptographic Failures")
        self.assertEqual(f[1]["owasp"], "A03:2021 - Injection")
        self.assertEqual(f[-1]["owasp"], "Unmapped")
        self.assertLessEqual(f[-1]["line"], 20)

    def test_cli_json_failon(self):
        rc = cli.main([FIX, "--host", self.host, "--format", "json", "-o", "/tmp/_r.json", "--fail-on", "high"])
        self.assertEqual(rc, 2)
        self.assertEqual(len(json.load(open("/tmp/_r.json"))["findings"]), 3)

    def test_unreachable(self):
        self.assertEqual(cli.main([FIX, "--host", "http://127.0.0.1:1"]), 1)


if __name__ == "__main__":
    unittest.main()
