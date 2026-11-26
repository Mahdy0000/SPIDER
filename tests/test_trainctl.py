import os
import tempfile
import unittest
from types import SimpleNamespace

from spider import trainctl as t


def hw(vram=4096, ram=32.0, cuda=True, os_="Linux"):
    return {"os": os_, "wsl": True, "gpu": "GPU" if cuda else None, "vram_mib": vram if cuda else 0, "ram_gb": ram, "cuda": cuda}


def A(**kw):
    d = dict(model_size="3b", epochs=3, out=None, check=False, yes=False, install_deps=False)
    d.update(kw)
    return SimpleNamespace(**d)


class Proc:
    def __init__(self, rc, out):
        self.returncode, self.stdout = rc, out


class HardwareTests(unittest.TestCase):
    def test_detect_parses_nvidia_smi_and_meminfo(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("MemTotal:       33554432 kB\n")
        try:
            h = t.detect_hardware(run=lambda *a, **k: Proc(0, "NVIDIA T1200 Laptop GPU, 4096\\n".replace("\\\\n", "\\n")), system=lambda: "Linux", meminfo=f.name, which=lambda n: "/usr/bin/nvidia-smi")
        finally:
            os.unlink(f.name)
        self.assertTrue(h["cuda"])
        self.assertEqual(h["vram_mib"], 4096)
        self.assertEqual(h["gpu"], "NVIDIA T1200 Laptop GPU")
        self.assertEqual(h["ram_gb"], 32.0)

    def test_detect_without_gpu(self):
        h = t.detect_hardware(run=None, system=lambda: "Linux", meminfo="/nonexistent", which=lambda n: None)
        self.assertFalse(h["cuda"])
        self.assertIsNone(h["ram_gb"])

    def test_assess_levels(self):
        self.assertEqual(t.assess(hw(24000))["level"], "ok")
        v = t.assess(hw(4096))
        self.assertEqual(v["level"], "tight")
        self.assertEqual(v["plan"]["max_seq"], 1024)
        self.assertEqual(v["fallbacks"], ["1b", "colab"])
        v = t.assess(hw(3000))
        self.assertEqual((v["level"], v["fallbacks"]), ("insufficient", ["1b", "colab"]))
        v = t.assess(hw(2000))
        self.assertEqual(v["fallbacks"], ["colab"])
        self.assertEqual(t.assess(hw(cuda=False))["level"], "insufficient")
        self.assertIn("WSL2", t.assess(hw(os_="Windows"))["reasons"][0])
        self.assertTrue(any("peft" in r for r in t.assess(hw(24000), ["peft"])["reasons"]))

    def test_missing_packages(self):
        self.assertEqual(t.missing_packages(lambda n: None if n == "peft" else object()), ["peft"])


class PlanTests(unittest.TestCase):
    def test_commands(self):
        with tempfile.TemporaryDirectory() as d:
            cmds, out_dir, merged = t.build_commands(d, t.plan_1b(), 2, python="py")
            prep, train, merge, convert = cmds
            self.assertEqual(prep[:2], ["py", os.path.join(d, "prep_data.py")])
            self.assertIn("unsloth/Llama-3.2-1B-Instruct", train)
            self.assertEqual(train[train.index("--batch") + 1], "1")
            self.assertEqual(train[train.index("--epochs") + 1], "2")
            self.assertIn("convert_to_ollama.sh", convert)
            os.makedirs(os.path.join(d, "data"))
            open(os.path.join(d, "data", "train.jsonl"), "w").close()
            self.assertIsNone(t.build_commands(d, t.plan_1b(), python="py")[0][0])

    def test_finish_message(self):
        m = t.finish_message("/o", ["merge"], "bash conv /m")
        self.assertIn("/o", m)
        self.assertIn("spider-reviewer", m)

    def test_find_training_dir(self):
        self.assertTrue(t.find_training_dir().endswith("training"))
        self.assertIsNone(t.find_training_dir(env={"SPIDER_REPO": "/nope"}, exists=lambda p: False))


class RunTests(unittest.TestCase):
    def run_it(self, a, hw_, asks=(), rc=0, missing=()):
        out, calls, asks = [], [], list(asks)
        r = t.run_training(a, ask=lambda p: asks.pop(0), out=out.append, run=lambda c: calls.append(c) or (rc if any('train_qlora' in x for x in c) else 0), hw=hw_, missing=list(missing), tdir="/tr")
        return r, "\n".join(out), calls

    def test_check_only(self):
        r, out, calls = self.run_it(A(check=True), hw(4096))
        self.assertEqual(r, 0)
        self.assertIn("TIGHT", out)
        self.assertEqual(calls, [])

    def test_no_gpu_points_to_colab_and_runs_nothing(self):
        r, out, calls = self.run_it(A(), hw(cuda=False))
        self.assertEqual(r, 1)
        self.assertIn("spider_finetune_colab", out)
        self.assertEqual(calls, [])

    def test_tight_default_is_colab(self):
        r, out, calls = self.run_it(A(), hw(4096), asks=[""])
        self.assertEqual(r, 1)
        self.assertEqual(calls, [])

    def test_tight_choose_1b(self):
        r, out, calls = self.run_it(A(), hw(4096), asks=["2"])
        self.assertEqual(r, 0)
        self.assertTrue(any("unsloth/Llama-3.2-1B-Instruct" in c for c in calls[-1]))
        self.assertIn("Training finished", out)

    def test_ok_runs_3b(self):
        r, out, calls = self.run_it(A(), hw(24000))
        self.assertEqual(r, 0)
        self.assertIn(t.BASE_3B, calls[-1])

    def test_missing_packages_stop(self):
        r, out, calls = self.run_it(A(), hw(24000), missing=["peft"])
        self.assertEqual(r, 1)
        self.assertEqual(calls, [])
        self.assertIn("pip install", out)

    def test_failure_message(self):
        r, out, calls = self.run_it(A(), hw(24000), rc=1)
        self.assertEqual(r, 1)
        self.assertIn("--model-size 1b", out)


if __name__ == "__main__":
    unittest.main()
