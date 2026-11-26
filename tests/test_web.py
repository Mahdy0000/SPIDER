"""Web review tests against a local vulnerable-by-design test server (127.0.0.1) and a fake Ollama."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from spider import cli
from spider.web import agent, checks, pages
from spider.web.client import BudgetExceeded, ScopedClient
from spider.web.scope import Scope, ScopeError

INDEX = """<html><head><title>t</title></head><body><!-- TODO remove admin password --><a href="/search?q=a">s</a>
<a href="/out">out</a><a href="http://example.org/x">ext</a>
<form method="post" action="/login"><input name="user"><input type="password" name="pw"></form></body></html>"""


class App(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlsplit(self.path)
        if u.path == "/":
            self._send(INDEX, {"Server": "Apache/2.4.1", "Set-Cookie": "sessionid=abc; Path=/"})
        elif u.path == "/search":
            q = parse_qs(u.query).get("q", [""])[0]
            self._send(f"<html><body>Results for {q}</body></html>")  # deliberately unescaped (test target)
        elif u.path == "/.env":
            self._send("SECRET_KEY=abc", ctype="text/plain")
        elif u.path == "/out":
            self.send_response(302)
            self.send_header("Location", "http://example.org/evil")
            self.end_headers()
        else:
            self._send("nope", status=404)

    def _send(self, body, headers=None, status=200, ctype="text/html"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


class FakeOllama(BaseHTTPRequestHandler):
    script = []

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        content = FakeOllama.script.pop(0) if FakeOllama.script else json.dumps({"action": "finish", "findings": []})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"message": {"content": content}}).encode())

    def log_message(self, *a):
        pass


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = HTTPServer(("127.0.0.1", 0), App)
        cls.llm = HTTPServer(("127.0.0.1", 0), FakeOllama)
        for s in (cls.app, cls.llm):
            threading.Thread(target=s.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.app.server_port}"
        cls.llm_host = f"http://127.0.0.1:{cls.llm.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.app.shutdown()
        cls.llm.shutdown()

    # --- scope (the safety property) ---
    def test_scope_loopback_always_allowed(self):
        s = Scope()
        for u in ("http://localhost:3000/", "http://127.0.0.1/", "http://[::1]:8080/", "http://dvwa.localhost/"):
            s.check(u)

    def test_scope_blocks_everything_else(self):
        s = Scope()
        for u in ("https://example.com/", "http://192.168.1.5/", "http://10.0.0.1/", "http://localhost.evil.com/", "ftp://localhost/", "file:///etc/passwd"):
            with self.assertRaises(ScopeError):
                s.check(u)

    def test_scope_named_hosts(self):
        s = Scope(["app.example.com", "*.lab.example.org", "https://x.test:8443/path"])
        s.check("https://app.example.com/a")
        s.check("https://a.lab.example.org/")
        s.check("https://x.test/")
        with self.assertRaises(ScopeError):
            s.check("https://example.com/")
        with self.assertRaises(ScopeError):
            s.check("https://evilapp.example.com.attacker.io/")

    def test_scope_rejects_too_broad(self):
        for bad in ("*", "*.com", "*.org"):
            with self.assertRaises(ScopeError):
                Scope([bad])

    def test_scope_env_and_file(self):
        s = Scope.from_sources([], env="a.test, b.test")
        s.check("http://a.test/")
        s.check("http://b.test/")

    def test_client_blocks_out_of_scope_without_sending(self):
        c = ScopedClient(Scope())
        with self.assertRaises(ScopeError):
            c.get("http://example.org/")
        self.assertEqual(c.count, 0)

    def test_redirect_out_of_scope_refused(self):
        c = ScopedClient(Scope())
        with self.assertRaises(ScopeError):
            c.get(self.base + "/out")
        self.assertEqual([u for u, _ in c.log], [self.base + "/out"])  # only the in-scope hop was requested

    def test_budget(self):
        c = ScopedClient(Scope(), max_requests=1)
        c.get(self.base + "/")
        with self.assertRaises(BudgetExceeded):
            c.get(self.base + "/")

    # --- crawler and checks ---
    def test_crawl_stays_in_scope(self):
        c = ScopedClient(Scope())
        ps, _ = pages.crawl(c, self.base + "/")
        urls = {p.url for p in ps}
        self.assertIn(self.base + "/search?q=a", urls)
        self.assertFalse(any("example.org" in u for u in urls))

    def test_checks_find_expected_issues(self):
        c = ScopedClient(Scope())
        ps, _ = pages.crawl(c, self.base + "/")
        ids = {f["check_id"] for f in checks.run_all(c, ps)}
        for want in ("hdr:content-security-policy", "hdr:framing", "hdr:version:server", "cookie:sessionid", "content:comment",
                     "reflect:q", "path:/.env"):
            self.assertIn(want, ids)
        self.assertTrue(any(i.startswith("form:csrf") for i in ids))

    def test_no_probe_is_passive(self):
        c = ScopedClient(Scope())
        ps, _ = pages.crawl(c, self.base + "/", max_pages=1)
        before = c.count
        ids = {f["check_id"] for f in checks.run_all(c, ps, probe=False)}
        self.assertEqual(c.count, before)
        self.assertNotIn("path:/.env", ids)

    # --- agent ---
    def test_agent_loop_grounded(self):
        c = ScopedClient(Scope())
        good = {"title": "Reflected input", "severity": "medium", "owasp": "A03", "url": self.base + "/search?q=a",
                "evidence": "Results for echoes q", "description": "d", "fix": "f", "confidence": "medium"}
        ungrounded = dict(good, url="https://never-visited.test/", title="Made up")
        FakeOllama.script = [json.dumps({"action": "fetch", "url": "/search?q=a"}),
                             json.dumps({"action": "fetch", "url": "http://example.org/"}),
                             json.dumps({"action": "finish", "findings": [good, ungrounded]})]
        fs, tr = agent.run(c, self.base + "/", self.llm_host, "x")
        self.assertEqual([f["title"] for f in fs], ["Reflected input"])
        self.assertFalse(any("example.org" in u for u, _ in c.log))

    # --- cli ---
    def test_cli_refuses_out_of_scope(self):
        self.assertEqual(cli.main(["web", "https://example.com/"]), 3)

    def test_cli_allow_flag(self):
        rc = cli.main(["web", self.base + "/", "--delay", "0", "--format", "json", "-o", "/tmp/_web.json", "--fail-on", "high"])
        self.assertEqual(rc, 2)  # exposed .env is critical
        d = json.load(open("/tmp/_web.json"))
        self.assertEqual(d["meta"]["mode"], "web")

    def test_cli_agent(self):
        FakeOllama.script = [json.dumps({"action": "finish", "findings": []})]
        rc = cli.main(["web", self.base + "/", "--delay", "0", "--no-probe", "--agent", "--host", self.llm_host, "-o", "/tmp/_web2.txt"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
