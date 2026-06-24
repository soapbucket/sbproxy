#!/usr/bin/env python3
"""Insert each example's cassette GIF into its README.

For every examples/<name>/ that has both a README.md and a rendered
docs/assets/<name>.gif, insert an image reference just below the
`*Last modified:*` line (or below the H1 title if absent), unless one is
already present. Idempotent.

Usage: scripts/wire-example-gifs.py [--check]
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")
ASSETS = os.path.join(ROOT, "docs", "assets")


def title_of(lines):
    for ln in lines:
        if ln.startswith("# "):
            return ln[2:].strip()
    return "example"


def main():
    check = "--check" in sys.argv
    wired, skipped = [], []
    for name in sorted(os.listdir(EXAMPLES)):
        d = os.path.join(EXAMPLES, name)
        readme = os.path.join(d, "README.md")
        gif = os.path.join(ASSETS, f"{name}.gif")
        if not (os.path.isfile(readme) and os.path.isfile(gif)):
            continue
        text = open(readme).read()
        rel = f"../../docs/assets/{name}.gif"
        if rel in text:
            skipped.append(name)
            continue
        lines = text.split("\n")
        img = f"![{title_of(lines)}]({rel})"
        # Find insertion point: after the *Last modified:* line, else after H1.
        idx = None
        for i, ln in enumerate(lines):
            if ln.strip().startswith("*Last modified:"):
                idx = i + 1
                break
        if idx is None:
            for i, ln in enumerate(lines):
                if ln.startswith("# "):
                    idx = i + 1
                    break
        if idx is None:
            skipped.append(name + " (no title)")
            continue
        new = lines[:idx] + ["", img] + lines[idx:]
        if not check:
            with open(readme, "w") as f:
                f.write("\n".join(new))
        wired.append(name)

    print(f"wired: {len(wired)}")
    print(f"already-wired/skipped: {len(skipped)}")
    if check:
        print("(--check: no files written)")


if __name__ == "__main__":
    main()
