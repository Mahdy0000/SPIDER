import os
import tempfile
import unittest
from types import SimpleNamespace

from spider import cli, start


def args(**kw):
    d = dict(model=None, embed_model="nomic-embed-text", host="http://localhost:11434", reports_dir=None, lexical=False, skip_setup=False, setup_only=False, yes=False, no_train=True)
    d.update(kw)
    return SimpleNamespace(**d)


class ScriptedAsk:
    def __init__(self, items):
        self.items = list(items)
        self.prompts = []

    def __call__(self, prompt=""):
        self.prompts.append(prompt)
        v = self.items.pop(0)
        if isinstance(v, BaseException):
            raise v
        return v


class StartTests(unittest.TestCase):
    def test_parser_defaults(self):
        a = start.build_parser().parse_args([])
        self.assertFalse(a.skip_setup)
        self.assertFalse(a.yes)
        self.assertEqual(a.embed_model, "nomic-embed-text")


    def test_parse_target(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(start.parse_target("  ")[0], "empty")
            self.assertEqual(start.parse_target("EXIT")[0], "exit")
            self.assertEqual(start.parse_target(d), ("path", d))
            self.assertEqual(start.parse_target('"https://example.com/a"'), ("url", "https://example.com/a"))
            self.assertEqual(start.parse_target("localhost:3000"), ("url", "http://localhost:3000"))
            self.assertEqual(start.parse_target("example.com")[1], "https://example.com")
            self.assertEqual(start.parse_target("ftp://x.com")[0], "bad")
            self.assertEqual(start.parse_target("no such thing")[0], "bad")

    def test_has_model(self):
        self.assertTrue(start.has_model(["nomic-embed-text:latest"], "nomic-embed-text"))
        self.assertTrue(start.has_model(["a/b:latest"], "a/b"))
        self.assertFalse(start.has_model(["x"], "y"))

    def test_start_server_missing_binary(self):
        ok, msg = start.start_server("http://h", which=lambda _: None, up=lambda h: False)
        self.assertFalse(ok)
        self.assertIn("winget", msg)

    def test_start_server_already_up(self):
        self.assertTrue(start.start_server("http://h", up=lambda h: True)[0])

    def test_report_path_and_argv(self):
        p = start.report_path("/tmp/r", "https://Example.com/x?y=1", now=__import__("datetime").datetime(2026, 1, 2, 3, 4, 5))
        self.assertTrue(p.endswith("spider-20260102-030405-Example-com-x-y-1.md"))
        a = args(host="http://h")
        w = start.build_argv("url", "https://my.site/a", a, "m", "/o.md")
        self.assertEqual(w[:2], ["spider-web", "https://my.site/a"])
        self.assertIn("my.site", w)
        c = start.build_argv("path", "/code", a, "m", "/o.md")
        self.assertEqual(c[:2], ["spider-code", "/code"])

    def test_loop_flow(self):
        with tempfile.TemporaryDirectory() as d:
            a = args(reports_dir=d)
            seen = []

            def runner(argv):
                seen.append(argv)
                open(argv[argv.index("-o") + 1], "w").write("# r")
                return 0
            out = []
            ask = ScriptedAsk(["", "garbage input", d, KeyboardInterrupt(), "n", "https://evil.example", "n", KeyboardInterrupt(), "y"])
            rc = start.loop(a, "m", ask=ask, out=out.append, runner=runner)
            self.assertEqual(rc, 0)
            self.assertEqual(len(seen), 1)  # only the path ran; the unconfirmed URL was skipped
            text = "\n".join(out)
            self.assertIn("Report saved to:", text)
            self.assertIn("Not a path", text)
            self.assertIn("authorized", text)

    def test_loop_survives_failure_and_eof(self):
        with tempfile.TemporaryDirectory() as d:
            a = args(reports_dir=d)

            def runner(argv):
                raise RuntimeError("boom")
            out = []
            rc = start.loop(a, "m", ask=ScriptedAsk([d, EOFError()]), out=out.append, runner=runner)
            self.assertEqual(rc, 0)
            self.assertIn("Review failed: boom", "\n".join(out))

    def test_setup_skips_when_models_present(self):
        orig = (start.start_server, start.installed_models, start.pull, start.ragcli.main)
        pulled = []
        try:
            start.start_server = lambda host: (True, "ok")
            start.installed_models = lambda host: ["dolphinlabs/llama3.2-3b-uncensored:latest", "nomic-embed-text:latest"]
            start.pull = lambda m: pulled.append(m) or True
            start.ragcli.main = lambda argv: 0
            out = []
            ok, model = start.setup(args(), out=out.append)
            self.assertTrue(ok)
            self.assertEqual(pulled, [])
            self.assertTrue(any("spider_finetune_colab" in x for x in out))
            start.installed_models = lambda host: []
            ok, _ = start.setup(args(lexical=True), out=out.append)
            self.assertEqual(pulled, ["dolphinlabs/llama3.2-3b-uncensored"])
        finally:
            start.start_server, start.installed_models, start.pull, start.ragcli.main = orig

    def test_setup_fails_without_ollama(self):
        orig = start.start_server
        try:
            start.start_server = lambda host: (False, "no ollama")
            self.assertFalse(start.setup(args(), out=lambda x: None)[0])
        finally:
            start.start_server = orig

    def test_offer_training_default_no_on_small_gpu(self):
        hw = {"os": "Linux", "wsl": True, "gpu": "T1200", "vram_mib": 4096, "ram_gb": 32.0, "cuda": True}
        called = []
        out = []
        r = start.offer_training(args(), out.append, ask=lambda p: "", hw=hw, missing=[], trainer=lambda argv: called.append(argv))
        self.assertFalse(r)
        self.assertEqual(called, [])
        self.assertIn("TIGHT", "\n".join(out))
        r = start.offer_training(args(), out.append, ask=lambda p: "y", hw=hw, missing=[], trainer=lambda argv: called.append(argv))
        self.assertTrue(r)
        self.assertEqual(called, [[]])

    def test_offer_training_default_yes_on_big_gpu(self):
        hw = {"os": "Linux", "wsl": False, "gpu": "RTX", "vram_mib": 24000, "ram_gb": 64.0, "cuda": True}
        called = []
        self.assertTrue(start.offer_training(args(), lambda x: None, ask=lambda p: "", hw=hw, missing=[], trainer=lambda a_: called.append(a_)))
        called.clear()
        self.assertFalse(start.offer_training(args(), lambda x: None, ask=lambda p: "", hw=hw, missing=["peft"], trainer=lambda a_: called.append(a_)))


if __name__ == "__main__":
    unittest.main()
