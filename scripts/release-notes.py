#!/usr/bin/env python3
"""Extract complete tagged notes and a GitHub release body within its limit."""

import argparse
import pathlib
import re
from urllib.parse import quote


# GitHub caps a release body at 125k characters. A slightly smaller UTF-8
# byte limit also accommodates multibyte text conservatively.
MAX_BODY_BYTES = 120000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--changelog", type=pathlib.Path, default=pathlib.Path("CHANGELOG.md"))
    parser.add_argument("--notes-file", type=pathlib.Path, required=True)
    parser.add_argument("--full-notes-file", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", args.version):
        parser.error("version must be a bare semantic version")

    lines = args.changelog.read_text(encoding="utf-8").splitlines(keepends=True)
    heading = re.compile(r"^## \[" + re.escape(args.version) + r"\](?:\s|$)")
    starts = [index for index, line in enumerate(lines) if heading.match(line)]
    if len(starts) != 1:
        parser.error(f"expected exactly one CHANGELOG section for {args.version}, found {len(starts)}")
    start = starts[0]
    end = next((index for index in range(start + 1, len(lines))
                if lines[index].startswith("## [")), len(lines))
    full = "".join(lines[start:end]).rstrip() + "\n"
    if not "".join(lines[start + 1:end]).strip():
        parser.error("the requested CHANGELOG section is empty")

    body = full
    if len(full.encode("utf-8")) > MAX_BODY_BYTES:
        base = "https://github.com/soapbucket/sbproxy"
        tag = "v" + args.version
        asset = quote(args.full_notes_file.name)
        upgrade = "This release includes breaking changes. " if re.search(r"^### Breaking\b", full, re.M) else ""
        body = (
            lines[start].rstrip() + "\n\n"
            + upgrade + "Read the full release notes before upgrading.\n\n"
            + "The complete notes exceed GitHub's release-body limit and are preserved in full:\n\n"
            + f"- [Full release notes]({base}/releases/download/{tag}/{asset})\n"
            + f"- [Changelog at this release]({base}/blob/{tag}/CHANGELOG.md)\n"
        )
    args.full_notes_file.write_text(full, encoding="utf-8")
    args.notes_file.write_text(body, encoding="utf-8")


if __name__ == "__main__":
    main()
