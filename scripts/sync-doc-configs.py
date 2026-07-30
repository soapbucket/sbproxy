#!/usr/bin/env python3
"""Sync runnable documentation configs from canonical examples.

Strict blocks use this shape:

    <!-- sbproxy-config: examples/basic-proxy/sb.yml -->
    ```yaml
    ...
    ```

The referenced example exposes the complete body with
`# sbproxy-docs:begin` and `# sbproxy-docs:end`. An intentionally partial
block uses `<!-- sbproxy-config-excerpt -->` instead and is left untouched.

Run without arguments to refresh strict blocks. Use `--check` in CI to report
drift without writing files.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
import sys


STRICT_MARKER = re.compile(
    r"^[ \t]*<!--[ \t]*sbproxy-config:[ \t]*(?P<source>[^ \t>]+)[ \t]*-->[ \t]*$"
)
EXCERPT_MARKER = re.compile(
    r"^[ \t]*<!--[ \t]*sbproxy-config-excerpt[ \t]*-->[ \t]*$"
)
YAML_FENCE = re.compile(r"^(?P<fence>`{3,}|~{3,})yaml[ \t]*$")
SOURCE_BEGIN = "# sbproxy-docs:begin"
SOURCE_END = "# sbproxy-docs:end"
VALIDATED_EXTRA_CONFIGS = {
    PurePosixPath("examples/enterprise-ai-gateway/api.yml"),
    PurePosixPath("examples/enterprise-ai-gateway/mcp.yml"),
    PurePosixPath("examples/enterprise-ai-gateway/upstream.yml"),
}


@dataclass
class DocumentResult:
    rendered: str
    strict_blocks: int = 0
    excerpts: int = 0
    changed: bool = False


class GuardError(ValueError):
    """A user-actionable documentation config marker error."""


def canonical_region(root: Path, source_name: str) -> str:
    source = PurePosixPath(source_name)
    if source.is_absolute() or ".." in source.parts or not source.parts:
        raise GuardError(f"unsafe canonical source path: {source_name}")
    if source.parts[0] != "examples":
        raise GuardError(f"canonical source must be under examples/: {source_name}")
    swept_sb_yml = len(source.parts) == 3 and source.parts[2] == "sb.yml"
    if not swept_sb_yml and source not in VALIDATED_EXTRA_CONFIGS:
        raise GuardError(
            f"canonical source is outside the validate_examples compiler sweep: "
            f"{source_name}"
        )

    source_path = root.joinpath(*source.parts)
    examples_root = (root / "examples").resolve()
    try:
        resolved = source_path.resolve(strict=True)
    except FileNotFoundError as error:
        raise GuardError(f"canonical source does not exist: {source_name}") from error
    if not resolved.is_relative_to(examples_root) or not resolved.is_file():
        raise GuardError(f"canonical source must be a file under examples/: {source_name}")

    lines = resolved.read_text(encoding="utf-8").splitlines(keepends=True)
    begins = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == SOURCE_BEGIN]
    ends = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == SOURCE_END]
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise GuardError(
            f"{source_name} must contain exactly one ordered "
            f"{SOURCE_BEGIN} / {SOURCE_END} pair"
        )

    region = "".join(lines[begins[0] + 1 : ends[0]])
    if not region.strip():
        raise GuardError(f"canonical documentation region is empty: {source_name}")
    if not region.endswith(("\n", "\r")):
        raise GuardError(f"canonical documentation region needs a trailing newline: {source_name}")
    return region


def fenced_body(lines: list[str], marker_index: int, document: Path) -> tuple[int, int]:
    fence_index = marker_index + 1
    line_number = marker_index + 1
    if fence_index >= len(lines):
        raise GuardError(f"{document}:{line_number}: marker is not followed by a YAML fence")

    opening = lines[fence_index].rstrip("\r\n")
    match = YAML_FENCE.fullmatch(opening)
    if match is None:
        raise GuardError(
            f"{document}:{line_number}: marker must immediately precede a ```yaml fence"
        )

    fence = match.group("fence")
    closing = re.compile(rf"^{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$")
    for index in range(fence_index + 1, len(lines)):
        if closing.fullmatch(lines[index].rstrip("\r\n")):
            return fence_index + 1, index
    raise GuardError(f"{document}:{line_number}: marked YAML fence is not closed")


def render_document(root: Path, document: Path, *, check: bool) -> DocumentResult:
    original = document.read_text(encoding="utf-8")
    lines = original.splitlines(keepends=True)
    rendered: list[str] = []
    strict_blocks = 0
    excerpts = 0
    index = 0

    while index < len(lines):
        marker_text = lines[index].rstrip("\r\n")
        strict = STRICT_MARKER.fullmatch(marker_text)
        excerpt = EXCERPT_MARKER.fullmatch(marker_text)
        if strict is None and excerpt is None:
            if "<!-- sbproxy-config" in marker_text:
                raise GuardError(f"{document}:{index + 1}: malformed sbproxy config marker")
            rendered.append(lines[index])
            index += 1
            continue

        body_start, body_end = fenced_body(lines, index, document)
        rendered.extend(lines[index:body_start])
        existing = "".join(lines[body_start:body_end])

        if excerpt is not None:
            excerpts += 1
            rendered.extend(lines[body_start : body_end + 1])
            index = body_end + 1
            continue

        strict_blocks += 1
        source_name = strict.group("source")
        canonical = canonical_region(root, source_name)
        if check and existing != canonical:
            relative = document.relative_to(root)
            raise GuardError(
                f"{relative}:{index + 1}: strict config drift from {source_name}; "
                "run scripts/sync-doc-configs.py"
            )
        rendered.extend(canonical.splitlines(keepends=True))
        rendered.append(lines[body_end])
        index = body_end + 1

    output = "".join(rendered)
    return DocumentResult(
        rendered=output,
        strict_blocks=strict_blocks,
        excerpts=excerpts,
        changed=output != original,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (default: parent of scripts/)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift without rewriting documentation",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    docs = root / "docs"
    if not docs.is_dir():
        print(f"doc-configs: documentation directory not found: {docs}", file=sys.stderr)
        return 2

    results: list[tuple[Path, DocumentResult]] = []
    errors: list[str] = []
    for document in sorted(docs.rglob("*.md")):
        try:
            results.append(
                (document, render_document(root, document, check=args.check))
            )
        except (GuardError, OSError, UnicodeError) as error:
            errors.append(str(error))

    if errors:
        for error in errors:
            print(f"doc-configs: {error}", file=sys.stderr)
        return 1

    if not args.check:
        for document, result in results:
            if result.changed:
                document.write_text(result.rendered, encoding="utf-8")

    strict_blocks = sum(result.strict_blocks for _, result in results)
    excerpts = sum(result.excerpts for _, result in results)
    changed = sum(result.changed for _, result in results)
    state = "drift-free" if args.check else f"updated {changed} document(s)"
    print(
        f"doc-configs: {strict_blocks} strict block(s), "
        f"{excerpts} excerpt(s); {state}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
