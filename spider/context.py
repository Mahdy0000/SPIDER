"""Cheap cross-file context: a short outline of the other files in the project."""
import os
import re

_DEF = re.compile(r"^\s*(?:async\s+def|def|class|function|func|public\s+\w+|export\s+(?:default\s+)?(?:function|class))\s+(\w+)")
_IMP = re.compile(r"^\s*(?:from\s+(\S+)\s+import|import\s+(\S+)|const\s+\w+\s*=\s*require\(['\"]([^'\"]+))")


def outline(path, max_items=25):
    names, imports = [], []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = _DEF.match(line)
                if m:
                    names.append(m.group(1))
                m = _IMP.match(line)
                if m:
                    imports.append(next(g for g in m.groups() if g))
    except OSError:
        pass
    return names[:max_items], sorted(set(imports))[:max_items]


def project_outline(files, current, root=None, limit=40):
    """One line per other file: defined names + imports. Lets the model see how files relate."""
    lines = []
    for p in files:
        if p == current:
            continue
        names, imports = outline(p)
        if not names and not imports:
            continue
        rel = os.path.relpath(p, root) if root else p
        lines.append(f"{rel}: defines [{', '.join(names)}] imports [{', '.join(imports)}]")
        if len(lines) >= limit:
            break
    return "\n".join(lines)
