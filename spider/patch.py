"""Turn findings into a unified diff. Never edits your files: it only prints a patch you review and apply."""
import difflib
import os


def build_patch(findings, root=None):
    by_file = {}
    for f in findings:
        if f.get("fixed_code", "").strip():
            by_file.setdefault(f["file"], []).append(f)
    out = []
    for path, fs in by_file.items():
        with open(path, encoding="utf-8", errors="replace") as fh:
            old = fh.read().splitlines()
        new = list(old)
        used_until = len(old) + 1
        # apply bottom-up so earlier line numbers stay valid; skip overlapping findings
        for f in sorted(fs, key=lambda x: x["line"], reverse=True):
            if f["end_line"] >= used_until:
                continue
            orig = old[f["line"] - 1]
            indent = orig[:len(orig) - len(orig.lstrip())]
            repl = f["fixed_code"].splitlines()
            if repl and not repl[0].startswith((" ", "\t")) and indent:
                repl = [indent + r for r in repl]
            new[f["line"] - 1:f["end_line"]] = repl
            used_until = f["line"]
        rel = os.path.relpath(path, root or os.getcwd())
        out += list(difflib.unified_diff(old, new, f"a/{rel}", f"b/{rel}", lineterm=""))
    return "\n".join(out) + ("\n" if out else "")
