"""Report tests: summary, fix-first ranking, SARIF structure, HTML escaping."""
import json
import unittest

from spider import report, scanner
from spider.web import checks

META = {"model": "m", "files": 2, "tool": "spider", "version": "0.5.0"}


def mk(title, sev, line=3, status=None, **kw):
    f = scanner.clean({"title": title, "severity": sev, "line": line, "owasp": "A03", "cwe": "CWE-89", "description": "d", "fix": "f"}, "a.py", 50)
    if status:
        f["verification"] = {"status": status, "method": "t", "note": ""}
    f.update(kw)
    return f


class ReportTests(unittest.TestCase):
    def test_summary_counts_and_fix_first(self):
        fs = scanner.sort_findings([mk("rejected", "critical", status="likely_false_positive"), mk("real", "high", status="likely_real"),
                                    mk("unverified", "high"), mk("low one", "low")])
        s = report.summarize(fs, META)
        self.assertEqual(s["total"], 4)
        self.assertEqual(s["by_severity"], {"critical": 1, "high": 2, "low": 1})
        titles = [x["title"] for x in s["fix_first"]]
        self.assertNotIn("rejected", titles)          # a rejected finding is never recommended
        self.assertEqual(titles[0], "real")           # verified outranks unverified at equal severity
        self.assertEqual(s["verification"]["likely_false_positive"], 1)

    def test_all_formats_render(self):
        fs = [mk("SQLi", "high", status="likely_real"),
              checks.finding("hdr:csp", "http://localhost:3000/", "Missing CSP", "medium", "A05", "CWE-693", "d", "f", "no header")]
        for name, fn in report.RENDERERS.items():
            self.assertTrue(fn(fs, dict(META, mode="web", target="http://localhost:3000/", scope="localhost/loopback", requests=5)), name)
            self.assertTrue(fn([], META), name)

    def test_sarif_shape(self):
        fs = [mk("SQLi", "high"), checks.finding("hdr:csp", "http://localhost/", "Missing CSP", "medium", "A05", "CWE-693", "d", "f")]
        d = json.loads(report.to_sarif(fs, META))
        self.assertEqual(d["version"], "2.1.0")
        r = d["runs"][0]["results"]
        self.assertEqual(r[0]["level"], "error")
        self.assertEqual(r[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 3)
        self.assertNotIn("region", r[1]["locations"][0]["physicalLocation"])  # web finding has a URL, no line
        self.assertEqual(len(d["runs"][0]["tool"]["driver"]["rules"]), 2)

    def test_html_escapes(self):
        out = report.to_html([mk("<script>alert(1)</script>", "high", description="<img src=x onerror=1>")], META)
        self.assertNotIn("<script>alert", out)
        self.assertNotIn("<img", out)
        self.assertIn("&lt;script&gt;", out)

    def test_json_has_summary(self):
        d = json.loads(report.to_json([mk("x", "low")], META))
        self.assertIn("summary", d)
        self.assertEqual(len(d["findings"]), 1)

    def test_cli_sarif_and_html(self):
        from spider import cli
        import os
        fix = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable_app.py")
        # unreachable model -> exit 1, but format choices must be accepted by the parser
        for fmt in ("sarif", "html"):
            self.assertEqual(cli.main([fix, "--host", "http://127.0.0.1:1", "--format", fmt]), 1)


if __name__ == "__main__":
    unittest.main()
