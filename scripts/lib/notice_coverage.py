#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Find Apache-2.0-only crates that NOTICE does not name (WOR-2449).

Apache 2.0 section 4(d) requires a copyright notice and the URL of the
project's source for dependencies licensed only under Apache-2.0 (not
dual MIT/Apache-2.0). `dead_code` cannot see this; neither can
cargo-deny. This scan is the same rule the CLAUDE.md / AGENTS.md
snippet used to describe by hand.

Matching is the crate name as a case-insensitive substring of NOTICE,
which is how grouped stanzas (Pingora, swc) still cover every crate:
each name has to appear in the file.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

LICENSE_SPLIT = re.compile(r"\s+(?:OR|/)\s+")


def is_apache_only(license_expr: str) -> bool:
    """True when Apache 2.0 is the only license that applies.

    Dual MIT/Apache-2.0, Apache-2.0 WITH LLVM-exception, BSL-1.0, and
    CC0-1.0 are excluded so the check matches the documented snippet
    and does not demand a stanza for crates NOTICE already groups
    under a different license story (wasmtime, cranelift).
    """
    lic = (license_expr or "").strip()
    if not lic:
        return False
    parts = [x.strip() for x in LICENSE_SPLIT.split(lic.replace("/", " OR "))]
    return (
        "Apache-2.0" in parts
        and "MIT" not in parts
        and not any(x.startswith("Apache-2.0 WITH") for x in parts)
        and "BSL-1.0" not in parts
        and "CC0-1.0" not in parts
    )


def missing_from_notice(
    packages: list[dict[str, Any]],
    workspace_member_ids: set[str],
    notice_text: str,
) -> list[tuple[str, str, str]]:
    """Return (name, version, license) for Apache-only crates NOTICE omits."""
    notice = notice_text.lower()
    missing: list[tuple[str, str, str]] = []
    for package in packages:
        if package.get("id") in workspace_member_ids:
            continue
        name = package.get("name") or ""
        license_expr = (package.get("license") or "").strip()
        if is_apache_only(license_expr) and name.lower() not in notice:
            missing.append((name, package.get("version") or "", license_expr))
    return missing


def scan_metadata(metadata: dict[str, Any], notice_text: str) -> list[tuple[str, str, str]]:
    workspace = set(metadata.get("workspace_members") or [])
    packages = metadata.get("packages") or []
    return missing_from_notice(packages, workspace, notice_text)


def _self_test() -> None:
    assert is_apache_only("Apache-2.0")
    assert not is_apache_only("MIT OR Apache-2.0")
    assert not is_apache_only("MIT/Apache-2.0")
    assert not is_apache_only("Apache-2.0 WITH LLVM-exception")
    assert not is_apache_only("BSL-1.0")
    assert not is_apache_only("CC0-1.0")
    assert not is_apache_only("MIT OR Apache-2.0 OR LGPL-2.1-or-later")
    assert not is_apache_only("")
    notice = "swc_ecma_ast and pingora-core\n"
    missing = missing_from_notice(
        [
            {"id": "ws", "name": "sbproxy", "version": "1", "license": "Apache-2.0"},
            {
                "id": "ext",
                "name": "swc_ecma_parser",
                "version": "43.0.0",
                "license": "Apache-2.0",
            },
            {
                "id": "ok",
                "name": "swc_ecma_ast",
                "version": "27.0.0",
                "license": "Apache-2.0",
            },
            {
                "id": "dual",
                "name": "serde",
                "version": "1",
                "license": "MIT OR Apache-2.0",
            },
        ],
        {"ws"},
        notice,
    )
    assert missing == [("swc_ecma_parser", "43.0.0", "Apache-2.0")], missing
    print("PASS notice_coverage self-test")


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        _self_test()
        return 0
    notice_path = "NOTICE"
    rest = argv[1:]
    if rest[:1] == ["--notice"] and len(rest) >= 2:
        notice_path = rest[1]
        rest = rest[2:]
    if rest:
        print(
            "usage: notice_coverage.py --self-test | [--notice NOTICE] < cargo-metadata.json",
            file=sys.stderr,
        )
        return 2
    metadata = json.load(sys.stdin)
    with open(notice_path, encoding="utf-8") as handle:
        notice_text = handle.read()
    missing = scan_metadata(metadata, notice_text)
    if not missing:
        return 0
    print(
        "NOTICE is missing Apache-2.0-only attribution (WOR-2449):",
        file=sys.stderr,
    )
    for name, version, license_expr in missing:
        print(f"  {name:<40} {version:<14} {license_expr}", file=sys.stderr)
    print(
        "Add a stanza to NOTICE naming each crate, its copyright, and the "
        "URL of the project's source. Apache 2.0 section 4(d) requires it.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
