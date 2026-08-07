#!/usr/bin/env python3
"""Refuse a hand-rolled secret parser, or a guardless literal passthrough.

# Why this exists

WOR-2282 converges every secret-bearing config field onto one resolver,
`SecretResolver::resolve` in `crates/sbproxy-vault/src/resolver.rs`, reached
through `sbproxy_vault::process_resolver()`. WOR-2285 moved every ad-hoc
`env:` / `file:` parser that predated the resolver over to delegate to it.
Neither ticket stops a *new* one from being written tomorrow: nothing short
of a reviewer's memory previously stood between a fresh call site and a
hand-rolled `reference.strip_prefix("env:")` copied from wherever the author
last saw the pattern. This script is that guardrail, run on every commit
instead of relied upon from memory.

It looks for two distinct defect shapes.

## Shape 1: ad-hoc secret parsing outside the shared resolver

A `strip_prefix("env:")`, `strip_prefix("file:")`, `starts_with("vault://")`,
or similar hand-rolled match against one of the resolver's own reference
schemes, anywhere under `crates/*/src/**/*.rs` except inside
`crates/sbproxy-vault/src/` (the resolver's own implementation) is a
new private reimplementation of parsing logic that already has one home.
Fixing it means routing the call site through
`sbproxy_vault::process_resolver()` / `SecretResolver::resolve` (or, when no
resolver is installed and a documented direct-read fallback is genuinely
needed, through the two existing shape guards,
`sbproxy_vault::looks_like_secret_reference_uri` and
`sbproxy_config`'s `is_secret_reference`) instead of re-parsing the scheme
by hand.

Scoped to a curated list of the resolver's own reference literals
(`env:`, `file:`, and its provider-URI schemes) rather than every string
`strip_prefix`/`starts_with` call in the tree: this codebase's non-secret
code has plenty of legitimate scheme checks of its own (`http://`,
`redis://`, `grpc://`, ...) and matching all of them would drown the
signal this check exists to carry. A further filter requires the enclosing
function's name or parameter list to mention `secret`, `credential`,
`key`, or `material`; without it, this check also flagged
`sbproxy-model-host`'s unrelated `hf:` / `file:` model-artifact-source
parsing, which has nothing to do with credentials.

## Shape 2: a guardless literal passthrough on the fallback path

The higher-value half of this check, and the one with a security
consequence: a function whose name or a parameter name mentions `secret`,
`credential`, `key`, or `material`, that has a fallback path returning
`reference.as_bytes()`, `reference.to_string()`, `reference.clone()`, or
similarly the input handed back unchanged, without first calling one of
the two shape guards named above anywhere in its body. This is the exact
bug class WOR-2283 fixed: an unresolvable provider-URI reference (a typo,
or a scheme this build has no backend for) silently became the literal
"secret" material at two call sites, rather than failing loudly. A
config value like `key_management.crypto.pepper: awssm://prod/pepper`
became a 22-byte ASCII pepper, identical on every deployment that pasted
the same doc example, because nothing checked whether the string still
looked like a reference before it was treated as the secret itself.

Both shapes are source-text heuristics, not a data-flow analysis: this is
the narrow, high-signal version the WOR-2287 ticket asked for first, not
a claim that every possible shape of either bug is caught. In particular,
shape 2 only inspects a function's own body text for a guard *call*
appearing anywhere in it; it does not verify the guard actually dominates
the passthrough on every path. Widen it if that ever proves not to be
enough.

# Exemptions

A hit that is a real, already-reviewed call site (the resolver's own
public entry point, or a documented fallback for when no resolver is
installed) is not a bug and should not require a code change. Record it
in `scripts/secret-resolver-drift-exemptions.json` instead, one entry per
`<file>::<function>::<shape>`, each with a one-line reason -- the same
"recorded verdict with a reason" shape `scripts/pub-item-verdicts.json`
uses for `scan-pub-item-usage.py`. An exemption naming a function or shape
that is no longer a finding is stale and fails this check on its own, the
same way a stale pub-item verdict fails that scan: the file must not
become an accumulating list of excuses for findings that were already
fixed.

# Usage

    python3 scripts/check-secret-resolver-drift.py
    python3 scripts/check-secret-resolver-drift.py --root /path/to/tree
    python3 scripts/check-secret-resolver-drift.py --root /path/to/tree \
        --exemptions /path/to/empty-or-alternate-exemptions.json

`--root` points the scan at a different workspace root; it exists so this
script's own behavior can be exercised against a small synthetic tree
without touching the real one. `--exemptions` defaults to this script's
own `secret-resolver-drift-exemptions.json` regardless of `--root`, so a
synthetic-tree run against the real default normally reports every one of
the real tree's exemptions as stale (they name findings the synthetic
tree does not contain); pass a second, throwaway `--exemptions` path
(even one that does not exist, which loads as empty) to scan a synthetic
tree cleanly.

Exit codes: 0 clean, 1 one or more live findings, 2 malformed exemptions
file or an exemption that no longer matches a finding.
"""

from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import sys
from dataclasses import dataclass, field

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
EXEMPTIONS_PATH = os.path.join(SCRIPT_DIR, "secret-resolver-drift-exemptions.json")

PRUNE_DIRS = {".git", "target", "node_modules", "__pycache__"}

# The resolver's own reference vocabulary (crates/sbproxy-vault/src/vault_ref.rs
# and resolver.rs): the two non-URI forms, plus every provider-URI scheme
# `VaultProviderType::from_scheme` recognizes, including the deprecated
# `secret://` alias. Deliberately not "every `scheme://` literal in the
# tree" -- see the module docstring for why that would be too noisy.
SECRET_SCHEME_LITERALS = [
    "env:",
    "file:",
    "vault://",
    "awssm://",
    "gcpsm://",
    "azurekv://",
    "k8ssecret://",
    "secretfile://",
    "localsecret://",
    "secret://",
]

SCHEME_MATCH_RE = re.compile(
    r'\.(strip_prefix|starts_with)\(\s*"('
    + "|".join(re.escape(s) for s in SECRET_SCHEME_LITERALS)
    + r')"\s*\)'
)

# The two real, already-reviewed shape guards this check expects call
# sites to prefer over hand-rolled scheme matching. Grepped from the tree
# at the time this check was written:
#   sbproxy_vault::looks_like_secret_reference_uri (crates/sbproxy-vault/src/vault_ref.rs)
#   sbproxy_config's is_secret_reference (crates/sbproxy-config/src/types.rs, pub(crate))
GUARD_CALL_RE = re.compile(r"\b(looks_like_secret_reference_uri|is_secret_reference)\s*\(")

SECRET_TERM_RE = re.compile(r"(?i)(secret|credential|key|material)")

FN_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")

PASSTHROUGH_CALL = r"(?:as_bytes\(\)(?:\.to_vec\(\))?|to_string\(\)|clone\(\))"


@dataclass
class FuncSpan:
    name: str
    params_text: str
    body_start: int  # char offset of the opening '{'
    body_end: int  # char offset of the matching closing '}'
    header_start: int  # char offset of the `fn` keyword, for cfg(test) filtering

    @property
    def size(self) -> int:
        return self.body_end - self.body_start

    def has_secret_term(self) -> bool:
        return bool(SECRET_TERM_RE.search(self.name) or SECRET_TERM_RE.search(self.params_text))

    def param_names(self) -> list[str]:
        names = []
        for part in split_top_level_commas(self.params_text):
            part = part.strip()
            if not part or part in ("self", "&self", "&mut self"):
                continue
            m = re.match(r"^(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:", part)
            if m:
                names.append(m.group(1))
        return names


def split_top_level_commas(text: str) -> list[str]:
    """Split a parameter list on commas that are not nested inside <>/()/[]."""
    parts = []
    depth = 0
    current = []
    for ch in text:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


# Matches the start of a raw (byte) string: an optional `b`, then `r`, then
# zero or more `#`, then the opening `"`. The closing delimiter is `"`
# followed by the same number of `#`.
RAW_STRING_START_RE = re.compile(r'b?r(?P<hashes>#*)"')

# A char or byte-char literal: `'x'`, `'\''`, `'\\'`, `'\u{1F600}'`,
# `b'x'`. Deliberately requires a closing `'` right after one escaped or
# bare character, so a lifetime (`'a`, `'de`, ...) -- which has no
# closing quote at all -- never matches and is left as ordinary code.
CHAR_LIT_RE = re.compile(r"b?'(\\u\{[0-9a-fA-F]+\}|\\.|[^'\\\n])'")


def mask_non_code(text: str) -> str:
    """A same-length copy of `text` with comments, string literals, and
    char literals blanked out to a filler character.

    Brace-matching below is a plain character count, and this codebase's
    string literals routinely contain unmatched brace characters that
    would otherwise desync it: `value.starts_with("${")`,
    `format!("${{{name}}}")`, JSON example text in error messages, and so
    on. Counting `mask_non_code(text)` instead of `text` itself keeps
    every structural search (matching parens, angle brackets, and braces;
    finding the next top-level `{`/`;`) blind to literal content while
    leaving `text` itself untouched for the content-sensitive regexes
    (`SCHEME_MATCH_RE` and friends), which still need to see the real
    string literal `"env:"` etc.

    Not a full lexer: raw strings, byte strings, block comments (nested),
    line comments, and the char-vs-lifetime ambiguity are handled; a
    handful of exotic forms (nested raw-string hash counts beyond what
    two greedy scans agree on, doc-comment edge cases) are not, in
    keeping with this script's textual-heuristic scope throughout.
    """
    n = len(text)
    out = list(text)
    i = 0
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            start = i
            while i < n and text[i] != "\n":
                i += 1
            for j in range(start, i):
                out[j] = "."
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            start = i
            depth = 1
            i += 2
            while i < n and depth > 0:
                if text[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                elif text[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            for j in range(start, i):
                out[j] = "."
            continue
        raw_match = RAW_STRING_START_RE.match(text, i)
        if raw_match:
            start = i
            hashes = raw_match.group("hashes")
            closing = '"' + hashes
            end = text.find(closing, raw_match.end())
            i = n if end == -1 else end + len(closing)
            for j in range(start, i):
                out[j] = "."
            continue
        if c == '"' or (c == "b" and i + 1 < n and text[i + 1] == '"'):
            start = i
            i += 1 if c == '"' else 2
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            for j in range(start, i):
                out[j] = "."
            continue
        char_match = CHAR_LIT_RE.match(text, i)
        if char_match:
            start, end = char_match.span()
            for j in range(start, end):
                out[j] = "."
            i = end
            continue
        i += 1
    return "".join(out)


def find_matching(mask: str, open_idx: int, open_ch: str, close_ch: str) -> int | None:
    """Index of the char closing the bracket opened at `open_idx`, or None.

    `mask` must be a code/comment-blanked string of the same length as the
    real source text (see `mask_non_code`), so a brace or paren character
    inside a string or char literal is never mistaken for a structural
    one.
    """
    depth = 0
    for i in range(open_idx, len(mask)):
        if mask[i] == open_ch:
            depth += 1
        elif mask[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return None


def split_top_level_statements(text: str, mask: str) -> list[str]:
    """Split `text` into statements at `;` occurring at bracket depth 0, and
    also right after a `}` that closes back to depth 0.

    `mask` (see `mask_non_code`) must be the same length as `text` and is
    what depth is actually tracked against, so a `;` or bracket character
    sitting inside a string or comment cannot desync the split. The last
    element is whatever follows the final such boundary -- the tail
    expression, or an empty string when the text ends right at one (an
    implicit-unit / no-tail-expression body).

    The `}`-boundary rule exists because a block used as a standalone
    Rust statement (`if cond { ... }`, `match x { ... }`, a bare
    `unsafe { ... }`) needs no trailing `;` at all; `decode_secret` in
    `sbproxy-middleware` is exactly two such `if let ... { return ...; }`
    statements followed by a tail expression with nothing to its left but
    those closing braces, and splitting on `;` alone left the whole
    function body as one "statement", hiding its real tail from the
    passthrough check below. This can misfire the other way on a brace
    delimited *expression* that is itself the tail (a `match` whose value
    is used, rather than a block statement) by inserting a spurious
    boundary inside it; the cost is a missed finding in that shape, not a
    false one, which is the direction this heuristic is meant to err in.
    """
    depth = 0
    start = 0
    parts = []
    for i, ch in enumerate(mask):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
            if ch == "}" and depth == 0:
                parts.append(text[start : i + 1])
                start = i + 1
                continue
        if ch == ";" and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts


def strip_trailing_comment(text: str) -> str:
    """Drop a trailing `// ...` line comment, then trailing whitespace."""
    text = text.rstrip()
    last_newline = text.rfind("\n")
    last_line = text[last_newline + 1 :]
    if "//" in last_line:
        text = text[: last_newline + 1] + last_line[: last_line.index("//")]
        text = text.rstrip()
    return text


def parse_function_spans(text: str, mask: str) -> list[FuncSpan]:
    """A structural (not full-parser) pass finding every `fn` item's name,
    parameter text, and body character range.

    Good enough for this check's purpose: it is used only to look up "what
    function contains this match" and "does this function's signature
    mention a secret-shaped term", not to typecheck or evaluate anything.
    Trait method declarations with no body (ending in `;`) are skipped;
    there is nothing to scan inside them.
    """
    spans: list[FuncSpan] = []
    for m in FN_RE.finditer(mask):
        header_start = m.start()
        idx = m.end()
        # Skip an optional `<...>` generic-parameter list before the `(`.
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx < len(text) and text[idx] == "<":
            close = find_matching(mask, idx, "<", ">")
            if close is None:
                continue
            idx = close + 1
            while idx < len(text) and text[idx].isspace():
                idx += 1
        if idx >= len(text) or text[idx] != "(":
            continue
        paren_close = find_matching(mask, idx, "(", ")")
        if paren_close is None:
            continue
        params_text = text[idx + 1 : paren_close]
        # First `{` or `;` after the parameter list, whichever comes
        # first. A return type or where-clause can contain `<...>` but
        # not a bare top-level `{`/`;` of its own in this codebase.
        rest_idx = paren_close + 1
        brace_pos = mask.find("{", rest_idx)
        semi_pos = mask.find(";", rest_idx)
        if brace_pos == -1:
            continue
        if semi_pos != -1 and semi_pos < brace_pos:
            continue  # a body-less trait/decl item
        body_close = find_matching(mask, brace_pos, "{", "}")
        if body_close is None:
            continue
        spans.append(
            FuncSpan(
                name=m.group(1),
                params_text=params_text,
                body_start=brace_pos,
                body_end=body_close,
                header_start=header_start,
            )
        )
    return spans


def enclosing_function(spans: list[FuncSpan], offset: int) -> FuncSpan | None:
    """The innermost span whose body contains `offset`, if any."""
    containing = [s for s in spans if s.body_start <= offset <= s.body_end]
    if not containing:
        return None
    return min(containing, key=lambda s: s.size)


def cfg_test_char_ranges(text: str, mask: str) -> list[tuple[int, int]]:
    """Char ranges (inclusive) covered by a `#[cfg(test)]` item.

    A test double that records or echoes back whatever it was given (a
    `RecordingTier` fake, a stub credential provider) is not this check's
    business; it exists to be inspected by an assertion, not served to a
    request. Same rationale, and the same brace-counted approach in place
    of a real parse, as `scan-pub-item-usage.py`'s `cfg_test_line_ranges`.
    """
    ranges: list[tuple[int, int]] = []
    search_from = 0
    while True:
        idx = text.find("#[cfg(test)]", search_from)
        if idx == -1:
            break
        rest = idx + len("#[cfg(test)]")
        brace_pos = mask.find("{", rest)
        semi_pos = mask.find(";", rest)
        if brace_pos != -1 and (semi_pos == -1 or brace_pos < semi_pos):
            end = find_matching(mask, brace_pos, "{", "}")
            end = end if end is not None else len(text) - 1
            ranges.append((idx, end))
            search_from = end + 1
        elif semi_pos != -1:
            ranges.append((idx, semi_pos))
            search_from = semi_pos + 1
        else:
            ranges.append((idx, len(text) - 1))
            break
    return ranges


def in_any_range(offset: int, ranges: list[tuple[int, int]]) -> bool:
    return any(lo <= offset <= hi for lo, hi in ranges)


def line_of(newline_offsets: list[int], offset: int) -> int:
    return bisect.bisect_right(newline_offsets, offset) + 1


def rust_files(root: str) -> list[str]:
    crates_dir = os.path.join(root, "crates")
    found = []
    if not os.path.isdir(crates_dir):
        return found
    for entry in sorted(os.listdir(crates_dir)):
        src_dir = os.path.join(crates_dir, entry, "src")
        if not os.path.isdir(src_dir):
            continue
        # Shape 1's own scope excludes the resolver's own crate; shape 2 is
        # scoped the same way, since this check exists to police call
        # sites this repository does not already trust to touch the wire
        # format directly, and the vault crate is that trusted core.
        if entry == "sbproxy-vault":
            continue
        for dirpath, dirnames, filenames in os.walk(src_dir):
            dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
            for name in filenames:
                if name.endswith(".rs"):
                    found.append(os.path.join(dirpath, name))
    return sorted(found)


def repo_relative(path: str, root: str) -> str:
    return os.path.relpath(path, root)


@dataclass
class Finding:
    file: str
    function: str
    shape: str  # "adhoc-parse" | "passthrough-fallback"
    lines: list[int] = field(default_factory=list)
    detail: str = ""

    @property
    def key(self) -> str:
        return f"{self.file}::{self.function}::{self.shape}"


def passthrough_fullmatch(candidate: str, param_alt: str) -> bool:
    """Whether `candidate`, stripped, IS a passthrough expression (not
    merely contains one as a sub-expression of something larger, like a
    struct literal field or a tuple)."""
    candidate = strip_trailing_comment(candidate).strip()
    if candidate.endswith(";"):
        candidate = candidate[:-1].rstrip()
    pattern = r"(?:Ok\(\s*)?(?:" + param_alt + r")\." + PASSTHROUGH_CALL + r"\s*\)?"
    return re.fullmatch(pattern, candidate) is not None


def scan_file(path: str, root: str) -> list[Finding]:
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    newline_offsets = [i for i, ch in enumerate(text) if ch == "\n"]
    mask = mask_non_code(text)
    spans = parse_function_spans(text, mask)
    test_ranges = cfg_test_char_ranges(text, mask)
    spans = [s for s in spans if not in_any_range(s.header_start, test_ranges)]
    rel = repo_relative(path, root)
    findings: dict[tuple[str, str], Finding] = {}

    # Shape 1: hand-rolled scheme matching inside a secret-shaped function.
    for m in SCHEME_MATCH_RE.finditer(text):
        span = enclosing_function(spans, m.start())
        if span is None or not span.has_secret_term():
            continue
        key = (span.name, "adhoc-parse")
        finding = findings.setdefault(
            key, Finding(file=rel, function=span.name, shape="adhoc-parse")
        )
        finding.lines.append(line_of(newline_offsets, m.start()))

    # Shape 2: a secret-shaped function with no shape-guard call anywhere
    # in its body, whose fallback hands a parameter back unchanged.
    for span in spans:
        if not span.has_secret_term():
            continue
        body_text = text[span.body_start : span.body_end + 1]
        if GUARD_CALL_RE.search(body_text):
            continue
        params = span.param_names()
        if not params:
            continue
        param_alt = "|".join(re.escape(p) for p in params)

        # Only an expression that IS (not merely contains) a bare
        # passthrough counts: `Ok(RedeemResult { token_id:
        # result.redemption_id.unwrap_or_else(|| request_id.to_string()),
        # ... })` mentions a parameter's `.to_string()` deep inside a much
        # larger literal that is not, itself, the input handed back
        # unchanged, and must not match here. Likewise an intermediate
        # `let normalized = reference.to_string();` feeding further
        # resolution (see config_source::resolve_secret_reference) is not
        # a passthrough of unvalidated input as material. Only two shapes
        # count: an explicit `return <passthrough>;` and the function's
        # actual final tail expression, i.e. exactly what a fallback
        # branch returning material unchecked looks like.
        body_mask = mask[span.body_start : span.body_end + 1]
        offset = None

        for rm in re.finditer(r"\breturn\b", body_mask):
            after = rm.end()
            semi_rel = None
            depth = 0
            for i in range(after, len(body_mask)):
                ch = body_mask[i]
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth = max(0, depth - 1)
                elif ch == ";" and depth == 0:
                    semi_rel = i
                    break
            if semi_rel is None:
                continue
            expr = body_text[after:semi_rel]
            if passthrough_fullmatch(expr, param_alt):
                offset = span.body_start + rm.start()
                break

        if offset is None:
            inner_text = body_text[1:-1]
            inner_mask = body_mask[1:-1]
            statements = split_top_level_statements(inner_text, inner_mask)
            tail = statements[-1] if statements else ""
            if tail.strip() and passthrough_fullmatch(tail, param_alt):
                offset = span.body_end - len(tail)

        if offset is None:
            continue
        offset = max(span.body_start, min(offset, span.body_end))

        key = (span.name, "passthrough-fallback")
        finding = findings.setdefault(
            key,
            Finding(
                file=rel,
                function=span.name,
                shape="passthrough-fallback",
                detail="returns a parameter unchanged with no shape-guard call in the function",
            ),
        )
        finding.lines.append(line_of(newline_offsets, offset))

    return list(findings.values())


def load_exemptions(path: str) -> dict:
    """The recorded exemptions at `path`, each required to carry a
    non-empty `reason`.

    Not a bare allowlist of paths: `ValueError` here (caught by the
    caller as a malformed-exemptions-file exit 2, same as invalid JSON)
    is deliberate, not a nicety, because an entry with an empty or
    missing reason is functionally an unexplained skip-list bypassing
    the whole point of recording verdicts instead of hardcoding an
    allowlist in the script.
    """
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    exemptions = data.get("exemptions", {})
    for key, entry in exemptions.items():
        if not isinstance(entry, dict) or not str(entry.get("reason", "")).strip():
            raise ValueError(f"exemption {key!r} has no non-empty 'reason'")
    return exemptions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        default=REPO_ROOT,
        help="workspace root to scan (default: this script's own repo)",
    )
    parser.add_argument(
        "--exemptions",
        default=EXEMPTIONS_PATH,
        help=(
            "exemptions JSON file (default: this script's own "
            "secret-resolver-drift-exemptions.json, NOT relative to --root, "
            "so a synthetic --root run starts with zero exemptions unless "
            "this is also overridden)"
        ),
    )
    args = parser.parse_args()
    root = os.path.abspath(args.root)

    try:
        exemptions = load_exemptions(args.exemptions)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"malformed exemptions file {args.exemptions}: {error}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    for path in rust_files(root):
        findings.extend(scan_file(path, root))
    findings.sort(key=lambda f: (f.file, f.function, f.shape))

    live = []
    exempted_keys_seen = set()
    for finding in findings:
        if finding.key in exemptions:
            exempted_keys_seen.add(finding.key)
            continue
        live.append(finding)

    stale = sorted(set(exemptions) - exempted_keys_seen)
    if stale:
        print(
            f"{args.exemptions} exempts a finding that no longer exists; "
            "remove the stale entry so this file cannot become a list of "
            "excuses for already-fixed code:",
            file=sys.stderr,
        )
        for key in stale:
            print(f"  {key}", file=sys.stderr)
        return 2

    if live:
        for finding in live:
            lines = ", ".join(str(n) for n in sorted(set(finding.lines)))
            if finding.shape == "adhoc-parse":
                print(
                    f"{finding.file}:{lines}  fn {finding.function}: hand-rolled secret-scheme "
                    "match outside the shared resolver",
                    file=sys.stderr,
                )
            else:
                print(
                    f"{finding.file}:{lines}  fn {finding.function}: {finding.detail}",
                    file=sys.stderr,
                )
        print(
            "\n"
            f"{len(live)} finding(s). Every secret-bearing reference should resolve\n"
            "through sbproxy_vault::process_resolver() / SecretResolver::resolve\n"
            "(crates/sbproxy-vault/src/resolver.rs), the single entry point WOR-2282\n"
            "converged the tree onto. Either:\n"
            "\n"
            "  * Route the call site through the resolver instead of hand-parsing\n"
            "    env:/file:/a provider-URI scheme, or\n"
            "  * For a passthrough-fallback finding, call\n"
            "    sbproxy_vault::looks_like_secret_reference_uri (or sbproxy_config's\n"
            "    is_secret_reference) before the fallback returns, so an\n"
            "    unresolvable reference fails loudly instead of becoming the literal\n"
            "    'secret' material -- the WOR-2283 bug class this half of the check\n"
            "    exists to catch, or\n"
            "  * If this is a real, already-reviewed exception (the resolver's own\n"
            "    entry point, or a documented no-resolver-installed fallback), add\n"
            "    an entry to scripts/secret-resolver-drift-exemptions.json:\n"
            "\n"
            '        "'
            + (live[0].key if live else "<file>::<function>::<shape>")
            + '": {\n'
            '          "reason": "one line explaining why this call site is trusted"\n'
            "        }\n",
            file=sys.stderr,
        )
        return 1

    print(
        f"secret-resolver drift check: ok ({len(findings)} finding(s), "
        f"{len(exempted_keys_seen)} exempted, 0 live)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
