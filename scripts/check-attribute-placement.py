#!/usr/bin/env python3
"""Refuse an attribute that cannot mean anything where it sits.

`#[test]` above a `static`, a `const`, a `use`, or a function that takes
arguments is always wrong. So is `#[should_panic]` or `#[ignore]` on a
function that is not a test: those two are read by the test harness and by
nothing else, so on an ordinary function they are decoration that looks
like a guarantee.

Why this exists next to the compiler
------------------------------------

rustc does refuse most of these, and it is worth being exact about which,
because a guard whose claim is wider than what it can see is worse than
none.

    #[test] static X: u32 = 5;      rustc: error, under --test
    #[test] const C: u32 = 1;       rustc: error, under --test
    #[test] use std::io::Write;     rustc: error, under --test
    #[test] fn f(x: u32) {}         rustc: error, under --test
    #[should_panic] fn f() {}       rustc: silent
    #[ignore] fn f() {}             rustc: silent

"under --test" is the whole gap, and it is not small.

* A `#[test]` behind a feature or a target the lane never enables is never
  compiled with `--test` and never seen. `gpu-apple` compiles on Apple
  Silicon only, `gpu-nvidia` needs a device, and the payment features run
  in one extra lane. This reads every file in the tree exactly once,
  whatever cfg it sits behind.
* The lanes that pass `--test` are gated on `changes.outputs.code` and
  cost around forty minutes. This runs in the `guards` lane, on every pull
  request including a docs-only one, in fifteen to twenty-five seconds.
* The last two rows are silent everywhere, in every configuration. The
  only thing that has ever reported them is this script.

How it decides
--------------

It parses. Comments, string literals, raw strings, byte strings and char
literals are masked out first, so the `#[test]` inside a raw-string
fixture and the `///` inside a block comment are not attributes; then
attribute blocks are bracket-matched and the item head under each is read
token by token, through `pub(crate)`, `async`, `unsafe`, `extern "C"` and
a generic parameter list. Grepping for the attribute cannot answer "what
item does this attach to", which is the only question here.

What it cannot see
------------------

* `#[test]` on an associated function inside an `impl`. rustc refuses that
  one under `--test` ("may only be used on a free function"); deciding it
  here needs block nesting this parser does not track.
* An attribute inside a brace-delimited macro invocation. It reads
  source, not expanded source, so the body of `macro_rules! m { ... }` or
  `proptest! { ... }` is skipped: those tokens are arguments to a macro
  that rewrites them. `proptest!` is why, since it accepts exactly the
  `#[test] fn f(a in 0..9)` shape this refuses everywhere else.
* Whether a `#[test]` function's body actually asserts anything. That is
  the reviewer's job.

Modes
-----

``--check``
    The gate. Scans every tracked `.rs` file and exits 1 on a finding.
    Reads the tree, so it works on a shallow checkout, in a detached
    worktree, and with no remote configured. There is no base to resolve
    and so no way for it to skip.

``--self-test``
    Fixtures for the masking lexer and for the item-head parser, including
    the six rows in the table above. A detector that has quietly stopped
    detecting reads exactly like a clean tree, so the fixtures run
    wherever the gate runs.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

# Attributes that mark a function as a test. A path ending in `::test` is
# one of these by convention (`tokio::test`, `async_std::test`), and the
# repository uses two of them.
TEST_ATTRS = {"test", "bench"}


def is_test_attr(path: str) -> bool:
    return path in TEST_ATTRS or path.endswith("::test") or path.endswith("::bench")


def takes_no_arguments(path: str) -> bool:
    """Whether this attribute's function is required to have no parameters.

    `#[test]` is. `#[bench]` is not: the signature libtest requires is
    `fn(&mut Bencher)`, so applying the no-arguments rule to it would
    refuse the only correct spelling. There is no `#[bench]` in the tree
    today, which is why this was latent rather than red.
    """
    return not (path == "bench" or path.endswith("::bench"))


# Read only with the harness. `#[ignore]` and `#[should_panic]` do nothing
# at all on a function libtest never collects.
HARNESS_ONLY_ATTRS = {"ignore", "should_panic"}

# Item keywords, in the order a head can carry them.
MODIFIERS = {"async", "unsafe", "default", "const", "extern", "auto"}
ITEM_KEYWORDS = {
    "fn",
    "struct",
    "enum",
    "union",
    "trait",
    "impl",
    "mod",
    "type",
    "use",
    "static",
    "const",
    "let",
    "macro",
    "macro_rules",
    "extern",
}

OPEN = {"(": ")", "[": "]", "{": "}"}

# Compiled and matched with an offset rather than against `source[i:]`.
# Slicing at every character turns the mask into an O(n^2) walk, and this
# repository has 24,000-line source files.
RAW_STRING = re.compile(r"(?:b|c)?r(#*)\"")
CHAR_LITERAL = re.compile(r"'(\\u\{[0-9a-fA-F_]+\}|\\x[0-9a-fA-F]{2}|\\.|[^\\'\n])'")


# --- The masking lexer -------------------------------------------------


def mask(source: str) -> str:
    """Replace every comment and literal with spaces, keeping offsets.

    Offsets are preserved so a position in the masked text is the same
    position in the original, which is what lets the report name a line.
    Block comments nest, raw strings carry any number of hashes, and a
    `'` is a char literal only when it closes on the same token; otherwise
    it is a lifetime and means nothing here.
    """
    out = list(source)
    i = 0
    n = len(source)

    def blank(start: int, end: int) -> None:
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        ch = source[i]

        if source.startswith("//", i):
            end = source.find("\n", i)
            end = n if end == -1 else end
            blank(i, end)
            i = end
            continue

        if source.startswith("/*", i):
            depth = 1
            j = i + 2
            while j < n and depth:
                if source.startswith("/*", j):
                    depth += 1
                    j += 2
                elif source.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue

        raw = RAW_STRING.match(source, i)
        if raw and not (i > 0 and (source[i - 1].isalnum() or source[i - 1] == "_")):
            closer = '"' + "#" * len(raw.group(1))
            j = source.find(closer, raw.end())
            j = n if j == -1 else j + len(closer)
            blank(i, j)
            i = j
            continue

        if ch == '"' or (ch == "b" and source.startswith('b"', i)):
            j = i + (2 if ch == "b" else 1)
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue

        if ch == "'":
            char = CHAR_LITERAL.match(source, i)
            if char:
                blank(i, char.end())
                i = char.end()
                continue
            i += 1
            continue

        i += 1

    return "".join(out)


def match_bracket(text: str, start: int) -> int:
    """Index just past the bracket group opening at `start`."""
    stack = [OPEN[text[start]]]
    i = start + 1
    while i < len(text) and stack:
        ch = text[i]
        if ch in OPEN:
            stack.append(OPEN[ch])
        elif ch == stack[-1]:
            stack.pop()
        i += 1
    return i


def match_generics(text: str, start: int) -> int:
    """Index just past the `<...>` group opening at `start`.

    `->` and `=>` carry a `>` that closes nothing, and a generic argument
    can hold a nested bracket group (`T: Fn(u32) -> u32`), so both are
    handled rather than counted naively.
    """
    depth = 0
    i = start
    while i < len(text):
        if text.startswith("->", i) or text.startswith("=>", i):
            i += 2
            continue
        ch = text[i]
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
            if depth == 0:
                return i + 1
        elif ch in OPEN:
            i = match_bracket(text, i)
            continue
        i += 1
    return i


# --- The item-head parser ----------------------------------------------


class Item:
    def __init__(self, kind: str, name: str, params: str | None) -> None:
        self.kind = kind  # `fn`, `static`, `use`, ..., or `?` when unread
        self.name = name
        self.params = params  # the parameter list of a `fn`, masked

    def describe(self) -> str:
        if self.kind == "?":
            return f"`{self.name}`, which is not an item this parser recognizes"
        if self.kind == "fn":
            return f"`fn {self.name}`"
        return f"a `{self.kind}` item"


WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def read_item(text: str, start: int) -> Item:
    """The item head at or after `start`, in masked text."""
    i = start
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break

        word = WORD.match(text, i)
        if not word:
            # A `#` here is another attribute, which the caller has
            # already consumed; anything else is punctuation that no item
            # head starts with.
            return Item("?", text[i : i + 40].split("\n")[0].strip(), None)

        token = word.group(0)
        end = word.end()

        if token == "pub":
            j = end
            while j < n and text[j].isspace():
                j += 1
            if j < n and text[j] == "(":
                end = match_bracket(text, j)
            i = end
            continue

        if token == "macro_rules":
            return Item("macro_rules", "", None)

        if token in ITEM_KEYWORDS and token != "fn":
            if token in MODIFIERS and token in ("const", "extern"):
                # `const fn`, `const unsafe fn`, `extern "C" fn` are
                # modifiers; a bare `const NAME` or `extern crate` is an
                # item. Look ahead for the difference.
                rest = text[end:]
                if re.match(r'\s*(unsafe\s+)?(fn\b|"[^"]*"\s*(unsafe\s+)?fn\b)', rest):
                    i = end
                    continue
            name = WORD.match(text, _skip_space(text, end))
            return Item(token, name.group(0) if name else "", None)

        if token == "fn":
            j = _skip_space(text, end)
            name = WORD.match(text, j)
            fn_name = name.group(0) if name else ""
            j = _skip_space(text, name.end() if name else j)
            if j < n and text[j] == "<":
                j = _skip_space(text, match_generics(text, j))
            if j < n and text[j] == "(":
                close = match_bracket(text, j)
                return Item("fn", fn_name, text[j + 1 : close - 1])
            return Item("fn", fn_name, None)

        if token in MODIFIERS:
            if token == "extern":
                i = _skip_space(text, end)
                if i < n and text[i] == '"':
                    # The literal was masked, so skip to the item word.
                    i = _skip_space(text, i + 1)
                continue
            i = end
            continue

        # A word that is neither a modifier nor an item keyword: a macro
        # invocation, a struct field, a match arm, an expression.
        return Item("?", token, None)

    return Item("?", "<end of file>", None)


def _skip_space(text: str, i: int) -> int:
    while i < len(text) and text[i].isspace():
        i += 1
    return i


# --- The scan ----------------------------------------------------------


class Finding:
    def __init__(self, path: str, line: int, attr: str, problem: str) -> None:
        self.path = path
        self.line = line
        self.attr = attr
        self.problem = problem

    def render(self) -> str:
        return f"{self.path}:{self.line}: `#[{self.attr}]` {self.problem}"


# A brace-delimited macro invocation: `proptest! {`, `macro_rules! m {`,
# `quote! {`. Only braces, because that is the only delimiter an item can
# appear inside, and matching every `assert!(` in the tree would cost more
# than the scan.
#
# The `!` has to touch the name. Allowing space between them made this
# match `if !flag {`, `while !done {` and `match !x {`, and every one of
# those skipped a whole block the scan is supposed to read. rustfmt
# always writes an invocation as `name!`, so requiring the adjacency
# costs nothing and closes the hole.
MACRO_BRACE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?:\s*::\s*[A-Za-z_][A-Za-z0-9_]*)*!\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*)?\{")


def macro_body_spans(text: str) -> list[tuple[int, int]]:
    """The `{...}` body of every brace-delimited macro invocation.

    An attribute in there is an argument to the macro, not an attribute on
    the item under it. `proptest! { #[test] fn f(a in 0..9) {} }` is the
    case in this repository: proptest rewrites that function, so the
    parameter list `#[test]` normally forbids is correct there.

    This is the parser's honest boundary. It reads source, not expanded
    source, so it says nothing about tokens a macro will rearrange.
    """
    spans: list[tuple[int, int]] = []
    end_of_last = -1
    for match in MACRO_BRACE.finditer(text):
        if match.start() < end_of_last:
            continue  # already inside a span this loop produced
        brace = text.index("{", match.end() - 1)
        end = match_bracket(text, brace)
        spans.append((match.start(), end))
        end_of_last = end
    return spans


def scan(path: str, source: str) -> list[Finding]:
    text = mask(source)
    skip = macro_body_spans(text)
    findings: list[Finding] = []

    i = 0
    n = len(text)
    while i < n:
        if not text.startswith("#[", i):
            i += 1
            continue
        if any(lo <= i < hi for lo, hi in skip):
            i += 2
            continue

        # Collect the whole block of consecutive outer attributes, then
        # read the one item under all of them.
        block: list[tuple[str, int]] = []
        j = i
        while j < n and text.startswith("#[", j):
            close = match_bracket(text, j + 1)
            body = text[j + 2 : close - 1]
            name = re.match(r"\s*([A-Za-z_][A-Za-z0-9_:]*)", body)
            block.append((name.group(1) if name else "", j))
            j = _skip_space(text, close)
        item = read_item(text, j)

        names = {name for name, _ in block}
        has_test = any(is_test_attr(name) for name in names)

        for name, offset in block:
            line = source.count("\n", 0, offset) + 1
            if is_test_attr(name):
                if item.kind != "fn":
                    findings.append(
                        Finding(
                            path,
                            line,
                            name,
                            f"marks a function as a test, and sits above {item.describe()}",
                        )
                    )
                elif (
                    takes_no_arguments(name)
                    and item.params is not None
                    and item.params.strip()
                ):
                    findings.append(
                        Finding(
                            path,
                            line,
                            name,
                            f"is on `fn {item.name}`, which takes arguments; "
                            "a test function takes none",
                        )
                    )
            elif name in HARNESS_ONLY_ATTRS and not has_test:
                if item.kind == "fn":
                    findings.append(
                        Finding(
                            path,
                            line,
                            name,
                            f"is read by the test harness, and `fn {item.name}` "
                            "carries no test attribute",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            path,
                            line,
                            name,
                            f"is read by the test harness, and sits above {item.describe()}",
                        )
                    )

        i = j if j > i else i + 2

    return findings


def tracked_rust_files() -> list[str]:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "*.rs"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if listed.returncode == 0 and listed.stdout:
        return [name for name in listed.stdout.split("\0") if name]
    # Not a work tree, or git is absent. Walk instead of skipping.
    return sorted(
        str(p.relative_to(ROOT))
        for p in ROOT.rglob("*.rs")
        if "target" not in p.parts and ".worktrees" not in p.parts
    )


def check() -> int:
    files = tracked_rust_files()
    if not files:
        print(
            "check-attribute-placement: found no .rs files to scan, which cannot\n"
            "be right in this repository. Refusing rather than reporting a clean\n"
            "tree it never read.",
            file=sys.stderr,
        )
        return 1

    findings: list[Finding] = []
    for name in files:
        path = ROOT / name
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"check-attribute-placement: cannot read {name}: {exc}", file=sys.stderr)
            return 1
        findings.extend(scan(name, source))

    if not findings:
        print(f"no misplaced attributes ({len(files)} Rust files)")
        return 0

    for finding in findings:
        print(finding.render(), file=sys.stderr)
    print(
        "\nAn attribute binds to the item under it. One that cannot apply to\n"
        "that item is usually a sign the item below it was inserted later:\n"
        "see scripts/check-attribute-theft.py.",
        file=sys.stderr,
    )
    return 1


# --- Self-test ---------------------------------------------------------

FIXTURES: list[tuple[str, str, int]] = [
    # The four rustc catches, which this catches without compiling.
    ("#[test] above a static", "#[test]\nstatic X: u32 = 5;\n", 1),
    ("#[test] above a const", "#[test]\nconst C: u32 = 1;\n", 1),
    ("#[test] above a use", "#[test]\nuse std::io::Write;\n", 1),
    ("#[test] on a fn with an argument", "#[test]\nfn f(x: u32) { let _ = x; }\n", 1),
    # The two nothing catches.
    ("#[should_panic] on a plain fn", "#[should_panic]\nfn f() {}\n", 1),
    ("#[ignore] on a plain fn", "#[ignore]\nfn f() {}\n", 1),
    # Behind a cfg no lane compiles, which is the whole point of not
    # relying on rustc for the first four.
    (
        "#[test] above a const behind gpu-apple",
        '#[cfg(feature = "gpu-apple")]\nmod probe {\n    #[test]\n    const C: u32 = 1;\n}\n',
        1,
    ),
    ("#[test] above a mod", "#[test]\nmod inner {}\n", 1),
    ("#[test] above a struct", "#[test]\nstruct S;\n", 1),
    ("#[test] above a macro invocation", "#[test]\nproptest! { fn f() {} }\n", 1),
    ("#[tokio::test] above a static", "#[tokio::test]\nstatic X: u32 = 5;\n", 1),
    # --- Accepted. -----------------------------------------------------
    ("a plain test", "#[test]\nfn f() {}\n", 0),
    ("an async test", "#[tokio::test]\nasync fn f() {}\n", 0),
    ("an async_std test", "#[async_std::test]\nasync fn f() {}\n", 0),
    ("a public test", "#[test]\npub fn f() {}\n", 0),
    ("a crate-visible test", "#[test]\npub(crate) fn f() {}\n", 0),
    ("an ignored test", '#[test]\n#[ignore = "slow"]\nfn f() {}\n', 0),
    ("a should_panic test", '#[test]\n#[should_panic(expected = "x")]\nfn f() {}\n', 0),
    ("attributes in either order", "#[ignore]\n#[test]\nfn f() {}\n", 0),
    ("a test with a cfg and a doc", '/// doc\n#[cfg(unix)]\n#[test]\nfn f() {}\n', 0),
    (
        "a test with a generic parameter list holding a paren",
        "#[test]\nfn f<T: Fn() -> u32>() {}\n",
        0,
    ),
    ("a const fn with a test above it", "#[test]\nfn f() {}\nconst fn g() -> u32 { 1 }\n", 0),
    ("an unsafe test", "#[test]\nunsafe fn f() {}\n", 0),
    ("a derive on a struct", "#[derive(Debug)]\nstruct S;\n", 0),
    ("a serde attribute on a field", "struct S {\n    #[serde(default)]\n    a: u32,\n}\n", 0),
    ("an inner attribute", "#![allow(dead_code)]\nuse std::io;\n", 0),
    (
        "a #[bench] on the only signature libtest accepts",
        "#[bench]\nfn bench_x(b: &mut test::Bencher) { let _ = b; }\n",
        0,
    ),
    (
        "a #[bench] above a const is still wrong",
        "#[bench]\nconst C: u32 = 1;\n",
        1,
    ),
    (
        "a raw string holding a bare quote and an attribute",
        'const S: &str = r#"a" b #[test]"#;\nstatic X: u32 = 5;\n',
        0,
    ),
    (
        "an attribute inside a nested block comment",
        "/* outer /* inner */ #[test] */\nstatic X: u32 = 5;\n",
        0,
    ),
    (
        "a #[test] inside a raw string fixture",
        'const SRC: &str = r#"\n#[test]\nstatic X: u32 = 5;\n"#;\n',
        0,
    ),
    (
        "a #[test] inside a nested block comment",
        "/* /* #[test]\nstatic X: u32 = 5; */ */\nfn f() {}\n",
        0,
    ),
    (
        "a proptest case, which takes arguments on purpose",
        "proptest! {\n    #[test]\n    fn f(a in 0..9u32) { let _ = a; }\n}\n",
        0,
    ),
    (
        "a misplaced attribute inside an `if !flag {` block",
        "fn outer() {\n    if !flag {\n        #[test]\n        const C: u32 = 1;\n    }\n}\n",
        1,
    ),
    (
        "a misplaced attribute inside a `while !done {` block",
        "fn outer() {\n    while !done {\n        #[test]\n        static X: u32 = 1;\n    }\n}\n",
        1,
    ),
    (
        "a #[test] inside a macro_rules body",
        "macro_rules! cases {\n    ($n:ident) => {\n        #[test]\n        fn $n() {}\n    };\n}\n",
        0,
    ),
    (
        "a lifetime that is not a char literal",
        "#[test]\nfn f() { let _: &'static str = \"x\"; }\n",
        0,
    ),
]


def self_test() -> int:
    failures: list[str] = []

    for name, source, expected in FIXTURES:
        found = scan("fixture.rs", source)
        if len(found) != expected:
            failures.append(
                f"{name}: expected {expected} finding(s), got {len(found)}"
                + ("".join(f"\n    {f.render()}" for f in found) if found else "")
            )

    # The masking lexer keeps offsets, or every reported line is wrong.
    for _, source, _ in FIXTURES:
        masked = mask(source)
        if len(masked) != len(source):
            failures.append("the mask changed the length of a fixture")
        if masked.count("\n") != source.count("\n"):
            failures.append("the mask changed the line count of a fixture")

    # A line number is reported from the attribute, not from the item.
    found = scan("fixture.rs", "fn a() {}\n\n#[test]\nstatic X: u32 = 5;\n")
    if not found or found[0].line != 3:
        failures.append(f"wrong line reported: {[f.line for f in found]}")

    # The item-head parser, directly.
    for source, kind in [
        ("pub(crate) async unsafe fn f() {}", "fn"),
        ('pub extern "C" fn f() {}', "fn"),
        ("const fn f() -> u32 { 1 }", "fn"),
        ("const C: u32 = 1;", "const"),
        ("pub(in crate::a) static X: u32 = 1;", "static"),
        ("macro_rules! m { () => {}; }", "macro_rules"),
        ("impl Foo for Bar {}", "impl"),
        ("extern crate alloc;", "extern"),
    ]:
        item = read_item(mask(source), 0)
        if item.kind != kind:
            failures.append(f"read_item({source!r}) said {item.kind!r}, expected {kind!r}")

    if read_item(mask("fn f(x: u32) {}"), 0).params.strip() != "x: u32":
        failures.append("read_item did not read a parameter list")
    if read_item(mask("fn f() {}"), 0).params.strip() != "":
        failures.append("read_item invented a parameter list")

    for failure in failures:
        print(f"self-test: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"check-attribute-placement self-test: all {len(FIXTURES)} fixtures pass")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="the gate; writes nothing")
    mode.add_argument("--self-test", action="store_true", help="run the fixtures")
    args = parser.parse_args()
    return self_test() if args.self_test else check()


if __name__ == "__main__":
    sys.exit(main())
