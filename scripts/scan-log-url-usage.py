#!/usr/bin/env python3
"""Count operator URLs that reach a log line unredacted (WOR-2629/WOR-2640).

Two things get counted, because they are two different mistakes with the
same consequence.

# raw-url

A `tracing` field whose name reads as a URL, interpolated with `%` or `?`
from something that is not the shared redactor. An operator URL carries a
credential twice over: `scheme://user:password@host` puts it in the
authority, and a Slack, Teams, or PagerDuty webhook puts the whole secret
in the path. Both end up in shared observability systems the moment the
connection breaks, which is exactly when the line fires.

The redacted form is `sbproxy_security::url_redact::redacted_url`, and it
is the only one accepted on a general URL field. Its sibling
`redacted_url_with_path` keeps the path, which for a Slack, Teams, or
PagerDuty webhook is the secret itself, so the scanner accepts it only on
a DSN-shaped field name (`*_dsn`, `redis*`) where the path is the database
index and nothing more. That is the rule the helper's own rustdoc states;
the scanner enforces it rather than leaving it to prose.

A value hoisted out of a loop counts as redacted when its binding is named
`*_origin` **and** that binding is assigned from a redactor call somewhere
in the same file:

    let feed_origin = redacted_url(&url);
    loop {
        tracing::warn!(url = %feed_origin, "feed poll failed");
    }

The suffix on its own is not enough. `let webhook_origin = url.clone()`
followed by `url = %webhook_origin` is a one-word rename that would
otherwise defeat the whole rule, so the assignment is resolved rather than
trusted. A binding hoisted from `redacted_url_with_path` carries the
with-path restriction to its log sites too.

# raw-request-error

An `error`/`err` field interpolated from a plain binding at a log site
that sits just below an outbound `reqwest` call. `reqwest::Error`'s
`Display` ends with `" for url ({url})"`, so `error = %e` writes the full
request URL, path and query included, with no `url` field in sight. That
one is worse than the first because nothing at the call site looks wrong.

The fix is `sbproxy_httpkit::request_error_summary`, which renders the
failure class and the wrapped error's own message and no URL at all.

Its baseline is zero and stays zero: the population it can see was
converted to the summary in full, so a hit is new rather than inherited.
Read the rest of this section before trusting that sentence further than
it goes.

# What the raw-request-error detector can and cannot see

It is a proximity heuristic, and the honest statement of its reach is:

Seen. A log site with `error = %e` (or `%err`, `%error`) whose preceding
15 lines contain, in the same file, one of `.send().await`,
`.bytes().await`, `.text().await`, `.json::<`, `.bytes_stream()`,
`.execute(`, or the literal `reqwest::Error`. Also seen: the same log site
where those 15 lines instead call a **function defined in the same file**
whose own body reaches one of those, transitively. That second rule is
what makes `send_sink_post` visible from the three `warn!` lines that log
its `String` error, which the window alone could not do.

Not seen, by construction:

  * A helper in a **different file or crate** that returns a
    reqwest-derived `String`, `anyhow::Error`, or custom error. Nothing
    here resolves an import.
  * A binding that travelled further than 15 lines, through a channel, or
    into a struct field before it was logged.
  * `error = %e` where `e` is an `anyhow::Error` whose source chain ends
    in a `reqwest::Error` with no context of its own, unless one of the
    call shapes above is inside the window.
  * Any error rendered somewhere other than a `tracing` field: a
    `format!`, a `Display` impl, a returned error string, or a cause
    handed to another error type whose own `Display` prints it.

So a zero on this count means "no site of the shape above", not "no
reqwest URL reaches a log". Widening it further would take type
information this script does not have; the type-level answer is to make
`request_error_summary` the only way the workspace renders a
`reqwest::Error`, and this count is the ratchet that holds the line while
that stays a convention.

A false positive is possible in the seen set and costs little: the summary
is the right thing to log for a `reqwest::Error`, and a binding named for
the error it holds (`Err(parse_error)`) is the right thing when it is not
one.

# What is scanned

Production code under `crates/*/src` only, with `#[cfg(test)]` items,
test-only module files, comments, and string-literal interiors removed
first. That machinery is shared with `scan-unwrap-usage.py` rather than
copied.

# Usage

    scripts/scan-log-url-usage.py                       # listing
    scripts/scan-log-url-usage.py --count raw-url       # one integer
    scripts/scan-log-url-usage.py --count raw-request-error
    scripts/scan-log-url-usage.py --by-file
    scripts/scan-log-url-usage.py --self-test           # fixtures
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from collections import Counter
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent


def _load_shared():
    """Import `scan-unwrap-usage.py`, whose name is not an identifier."""
    target = SCRIPTS / "scan-unwrap-usage.py"
    spec = importlib.util.spec_from_file_location("scan_unwrap_usage", target)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {target}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SHARED = _load_shared()

# A `tracing` emission macro, with or without the `tracing::` prefix. The
# span constructors are included because a span field is emitted too.
LOG_MACRO = re.compile(
    r"\b(?:tracing\s*::\s*)?"
    r"(?:trace|debug|info|warn|error)(?:_span)?\s*!\s*\(|"
    r"\b(?:tracing\s*::\s*)?(?:event|span)\s*!\s*\("
)

# `name = %value` or `name = ?value` inside a macro argument list. The
# name may be dotted (`self.url`); the value runs to the end of its line,
# which is where every one of these sits in this workspace.
FIELD = re.compile(
    r"(?<![A-Za-z0-9_.])([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*([%?])[ \t]*([^,\n]*)"
)

# Field names that mean "this value is a URL".
URL_FIELD = re.compile(r"(?:^|_)(url|uri|endpoint|dsn|webhook)$")

# Field names where the path is a structural selector rather than a
# secret, which in this workspace means a Redis DSN and its database
# index. Only these accept `redacted_url_with_path`; everywhere else the
# path is where Slack, Teams, and PagerDuty keep the whole webhook
# secret, and the helper's own rustdoc says so.
DSN_FIELD = re.compile(r"(?:^|_)dsn$|^redis[A-Za-z0-9_]*$")

# The origin form, which is safe on any URL field.
REDACTED_ORIGIN_CALL = re.compile(r"\bredacted_url\s*\(")

# The with-path form, restricted to `DSN_FIELD`.
REDACTED_PATH_CALL = re.compile(r"\bredacted_url_with_path\s*\(")

# A `*_origin` binding appearing in a value expression. The suffix alone
# proves nothing; `binding_redactors` below resolves what it was assigned
# from, and a name with no resolvable redactor assignment is not accepted.
ORIGIN_BINDING = re.compile(r"\b([A-Za-z0-9_]*_origin)\b")

# `let x_origin = ..redacted_url(..)` in one statement, which is the
# hoisting convention the log sites read against. The optional type
# ascription and the `mut` are both shapes this tree uses.
ORIGIN_ASSIGNMENT = re.compile(
    r"\blet\s+(?:mut\s+)?([A-Za-z0-9_]*_origin)\s*(?::[^=;]*)?=[^;]*?"
    r"\bredacted_url(_with_path)?\s*\("
)

# Field names carrying an error, and the shape that is an anonymous
# binding: `%e`, `%err`, `%error`. Two other shapes are deliberately not
# matched, because both are someone having made a decision. A call
# (`%request_error_summary(&e)`) is the fix. A binding named for the
# error it holds (`%parse_error`) says the author knew which error type
# was in hand, which is the whole question this rule asks near an
# outbound request.
ERROR_FIELD = re.compile(r"^(?:error|err)$")
PLAIN_BINDING = re.compile(r"^&?(?:e|err|error)[0-9]?$")

# An outbound reqwest call whose error is the one that carries a URL.
#
# `.execute(req` is here because `reqwest::Client::execute` is the
# primitive both governed-send helpers in this tree are built on
# (`send_governed`, `send_sink_post`), and its absence hid three live
# leaks from an earlier revision of this scanner. It is spelled with the
# argument rather than as a bare `.execute(` for the reason
# `crates/sbproxy-observe/tests/outbound_trace_drift.rs` already
# documents for its own marker list: the SQLite stores, the Redis client,
# and all four scripting engines call `.execute(` on things that never
# touch a socket. `request` and `req` are the only two spellings any real
# `reqwest::Client::execute` call site in this workspace uses.
REQWEST_CALL = re.compile(
    r"\.send\(\)\s*\.await|\.bytes\(\)\s*\.await|\.text\(\)\s*\.await"
    r"|\.json::<|\.bytes_stream\(\)|\.execute\(req(?:uest)?\b|\breqwest::Error\b"
)

# A function definition, used to extend `REQWEST_CALL` one file at a time
# (see `reqwest_helpers`). The name is what a call site writes.
FN_DEFINITION = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]")

# How many lines above a log site are searched for that call. Fifteen
# covers the `match req.send().await { Ok(..) => .., Err(e) => .. }`
# shape, including the arms in between, without reaching the previous
# statement block.
REQWEST_WINDOW_LINES = 15

CATEGORIES = ("raw-url", "raw-request-error")


def read_parenthesized(text: str, open_paren: int) -> tuple[str, int]:
    """Return the text inside the parens at `open_paren`, and the index past it."""
    depth = 0
    index = open_paren
    while index < len(text):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : index], index + 1
        index += 1
    return text[open_paren + 1 :], len(text)


def read_braced(text: str, open_brace: int) -> int:
    """Return the index just past the `}` closing the brace at `open_brace`."""
    depth = 0
    index = open_brace
    while index < len(text):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(text)


def binding_redactors(code: str) -> dict[str, str]:
    """Map each `*_origin` binding in this file to the redactor it came from.

    `"origin"` for `redacted_url`, `"path"` for `redacted_url_with_path`.
    A name that is never assigned from either is absent, which is what
    stops `let webhook_origin = cfg.webhook_url.clone()` from reading as
    redacted on the strength of its suffix alone.
    """
    resolved: dict[str, str] = {}
    for match in ORIGIN_ASSIGNMENT.finditer(code):
        name, with_path = match.group(1), match.group(2)
        kind = "path" if with_path else "origin"
        # A name assigned from both forms in one file takes the stricter
        # reading, so the with-path restriction cannot be shaken off by
        # adding a second, safer assignment elsewhere.
        if resolved.get(name) != "path":
            resolved[name] = kind
    return resolved


def reqwest_helpers(code: str) -> re.Pattern | None:
    """Match a call to a same-file function that sends an outbound request.

    The window heuristic sees `client.execute(request)` but not
    `send_sink_post(..).await`, and the second is where three live leaks
    hid: the helper renders the `reqwest::Error` into a `String` and every
    caller logs that string, so nothing inside the window looks like a
    request at all. Each function whose own body contains a
    `REQWEST_CALL` therefore becomes a call shape of its own, and a call
    to it counts as an outbound request at the caller's log site.

    Two limits, both deliberate and both stated in this module's header.
    One file only: nothing here resolves an import. One hop only: a
    function that merely calls such a helper is not itself one, because
    the transitive form pulls in whole call graphs (`record`, `new`,
    `run`) and turns the count into noise the next reader would learn to
    ignore.
    """
    reaching: set[str] = set()
    for match in FN_DEFINITION.finditer(code):
        if match.group(1) in reaching:
            continue
        brace = code.find("{", match.end() - 1)
        semicolon = code.find(";", match.end() - 1)
        if brace < 0 or (0 <= semicolon < brace):
            # A trait method declaration or an `fn` pointer type, no body.
            continue
        if REQWEST_CALL.search(code[brace : read_braced(code, brace)]):
            reaching.add(match.group(1))

    if not reaching:
        return None
    # `(?<!fn\s)` so the helper's own definition is not read as a call to
    # itself, which would put every log line in its body inside the
    # window whether or not the request is above them.
    return re.compile(r"(?<!fn\s)\b(?:" + "|".join(sorted(reaching)) + r")\s*\(")


def redacted_for_field(value: str, leaf: str, bindings: dict[str, str]) -> bool:
    """Whether `value` is a redacted rendering that this field may carry."""
    dsn_field = bool(DSN_FIELD.search(leaf))
    if REDACTED_PATH_CALL.search(value):
        # The path-bearing form. Safe only where the path is a database
        # index; on an `http(s)` webhook it is the credential.
        return dsn_field
    if REDACTED_ORIGIN_CALL.search(value):
        return True
    for match in ORIGIN_BINDING.finditer(value):
        kind = bindings.get(match.group(1))
        if kind == "origin" or (kind == "path" and dsn_field):
            return True
    return False


def scan_source(code: str, spans: list[tuple[int, int]] | None = None):
    """Yield `(category, line, field, value)` for one blanked source file."""
    spans = spans or []
    line_starts = [0]
    for index, char in enumerate(code):
        if char == "\n":
            line_starts.append(index + 1)

    def line_of(offset: int) -> int:
        return code.count("\n", 0, offset) + 1

    bindings = binding_redactors(code)
    helper_call = reqwest_helpers(code)

    for macro in LOG_MACRO.finditer(code):
        start = macro.start()
        if any(begin <= start < end for begin, end in spans):
            continue
        args, _ = read_parenthesized(code, macro.end() - 1)
        base = macro.end()
        for field in FIELD.finditer(args):
            name, _sigil, value = field.group(1), field.group(2), field.group(3).strip()
            leaf = name.rsplit(".", 1)[-1]
            offset = base + field.start()
            if URL_FIELD.search(leaf) and not redacted_for_field(value, leaf, bindings):
                yield ("raw-url", line_of(offset), name, value)
            elif ERROR_FIELD.match(leaf) and PLAIN_BINDING.match(value):
                line = line_of(offset)
                first = max(1, line - REQWEST_WINDOW_LINES)
                window = code[line_starts[first - 1] : offset]
                if REQWEST_CALL.search(window) or (helper_call and helper_call.search(window)):
                    yield ("raw-request-error", line, name, value)


def collect(repo: Path):
    kept, excluded = SHARED.production_code(repo)
    hits = []
    for path, code, spans in kept:
        for category, line, name, value in scan_source(code, spans):
            hits.append((category, path.relative_to(repo), line, name, value))
    hits.sort(key=lambda hit: (str(hit[1]), hit[2]))
    return hits, excluded


# --- Self-test -------------------------------------------------------
#
# Every refusal below is paired with a loosening of the scanner that has
# to break a fixture. A guard whose detector has quietly stopped
# detecting reads exactly like a clean tree, which is the one failure a
# ratchet cannot self-report.

REFUSED = [
    (
        "a bare url field",
        'tracing::warn!(url = %url, "feed poll failed");',
        "raw-url",
    ),
    (
        "a dotted url field",
        'warn!(url = %self.config.url, "boom");',
        "raw-url",
    ),
    (
        "a suffixed url field",
        'warn!(feed_url = %feed, "boom");',
        "raw-url",
    ),
    (
        "an endpoint field",
        'info!(otlp_endpoint = %endpoint, "exporting");',
        "raw-url",
    ),
    (
        "a dsn field",
        'error!(redis_dsn = %dsn, "connect failed");',
        "raw-url",
    ),
    (
        "debug interpolation, not just display",
        'warn!(url = ?url, "boom");',
        "raw-url",
    ),
    (
        "a url field on a span",
        'let _s = info_span!("deliver", url = %url);',
        "raw-url",
    ),
    (
        "a bare reqwest error below a send",
        "match req.send().await {\n"
        "    Ok(r) => r,\n"
        '    Err(e) => warn!(error = %e, "delivery failed"),\n'
        "}",
        "raw-request-error",
    ),
    (
        "a bare reqwest error below a body read",
        "let bytes = resp.bytes().await;\n"
        'if let Err(err) = bytes { warn!(err = %err, "read failed"); }',
        "raw-request-error",
    ),
    (
        "a bare reqwest error below an execute",
        "match client.execute(request).await {\n"
        "    Ok(r) => r,\n"
        '    Err(e) => warn!(error = %e, "delivery failed"),\n'
        "}",
        "raw-request-error",
    ),
    (
        # The `send_sink_post` shape. The request lives in a helper, the
        # helper renders the error into a `String`, and the caller logs
        # the string, so nothing inside the window looks like a request.
        # The filler is load bearing: it puts the helper's own
        # `.execute(` further than `REQWEST_WINDOW_LINES` above the log
        # site, so only the same-file resolution can find it.
        "a reqwest error laundered through a same-file helper",
        "async fn send_sink_post(client: &Client, req: Request) -> Result<Response, String> {\n"
        "    client.execute(req).await.map_err(|error| error.to_string())\n"
        "}\n" + "// filler\n" * 20 + "async fn deliver(client: &Client, req: Request) {\n"
        "    if let Err(e) = send_sink_post(client, req).await {\n"
        '        warn!(error = %e, "usage sink: webhook POST failed");\n'
        "    }\n"
        "}",
        "raw-request-error",
    ),
    (
        # The path-bearing redactor on a field that is not a DSN. Slack,
        # Teams, and PagerDuty all keep the whole webhook secret in the
        # path, which is what the helper's rustdoc says and what nothing
        # enforced before.
        "the with-path redactor on a webhook url",
        'warn!(url = %redacted_url_with_path(&slack_webhook), "delivery failed");',
        "raw-url",
    ),
    (
        # A one-word rename that used to defeat the whole rule.
        "an origin-suffixed binding that never saw a redactor",
        "let webhook_origin = cfg.webhook_url.clone();\n"
        'warn!(url = %webhook_origin, "delivery failed");',
        "raw-url",
    ),
    (
        "a with-path binding hoisted onto a webhook field",
        "let webhook_origin = redacted_url_with_path(&cfg.webhook_url);\n"
        'warn!(url = %webhook_origin, "delivery failed");',
        "raw-url",
    ),
]

ACCEPTED = [
    (
        "the inline redactor",
        'tracing::warn!(url = %redacted_url(&url), "feed poll failed");',
    ),
    (
        "the with-path redactor on a dsn field",
        'warn!(redis_dsn = %redacted_url_with_path(&dsn), "connect failed");',
    ),
    (
        "the fully qualified redactor",
        'warn!(url = %sbproxy_security::url_redact::redacted_url(&url), "boom");',
    ),
    (
        "a hoisted origin binding",
        "let feed_origin = redacted_url(&url);\n"
        'warn!(url = %feed_origin, "feed poll failed");',
    ),
    (
        "a hoisted origin binding through the full path",
        "let store_origin = sbproxy_security::url_redact::redacted_url(&path);\n"
        'warn!(url = %store_origin, "open failed");',
    ),
    (
        "a with-path binding hoisted onto a dsn field",
        "let redis_origin = redacted_url_with_path(&url);\n"
        'warn!(redis_url = %redis_origin, "reconnecting");',
    ),
    (
        "a field that is not a url",
        'warn!(provider = %provider.name, "cascade failed");',
    ),
    (
        "a url in the message rather than a field",
        'warn!("could not reach the url");',
    ),
    (
        "the reqwest summary",
        "match req.send().await {\n"
        '    Err(e) => warn!(error = %request_error_summary(&e), "failed"),\n'
        "}",
    ),
    (
        "a hoisted summary binding",
        "match req.send().await {\n"
        "    Err(e) => {\n"
        "        let summary = request_error_summary(&e);\n"
        '        warn!(error = %summary, "failed");\n'
        "    }\n"
        "}",
    ),
    (
        "an error named for what it is, next to a request",
        "let body = resp.text().await?;\n"
        "match parse(&body) {\n"
        '    Err(parse_error) => warn!(error = %parse_error, "parse failed"),\n'
        "    Ok(v) => v,\n"
        "}",
    ),
    (
        "an error far from any request",
        "let parsed = serde_json::from_str(&raw);\n"
        "let a = 1;\nlet b = 2;\nlet c = 3;\nlet d = 4;\nlet e2 = 5;\n"
        "let f = 6;\nlet g = 7;\nlet h = 8;\nlet i = 9;\nlet j = 10;\n"
        "let k = 11;\nlet l = 12;\nlet m = 13;\nlet n = 14;\nlet o = 15;\n"
        'if let Err(e) = parsed { warn!(error = %e, "parse failed"); }',
    ),
    (
        "a url inside a comment",
        '// warn!(url = %url, "this is prose about the rule");',
    ),
    (
        "a url inside a string literal",
        'let sample = "warn!(url = %url)";',
    ),
]

# Each entry loosens the scanner in a way that would make it stop
# refusing something. If a mutation leaves every fixture passing, the
# fixture set has a hole.
MUTATIONS = [
    ("URL_FIELD drops the suffix form", "URL_FIELD", re.compile(r"^(url|uri|endpoint|dsn)$")),
    ("URL_FIELD drops endpoint and dsn", "URL_FIELD", re.compile(r"(?:^|_)(url|uri)$")),
    ("FIELD stops accepting `?`", "FIELD", re.compile(r"(?<![A-Za-z0-9_.])([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(%)[ \t]*([^,\n]*)")),
    ("LOG_MACRO drops the span forms", "LOG_MACRO", re.compile(r"\b(?:tracing\s*::\s*)?(?:trace|debug|info|warn|error)\s*!\s*\(")),
    ("REQWEST_CALL drops the body reads", "REQWEST_CALL", re.compile(r"\.send\(\)\s*\.await")),
    (
        "REQWEST_CALL drops `.execute(`",
        "REQWEST_CALL",
        re.compile(
            r"\.send\(\)\s*\.await|\.bytes\(\)\s*\.await|\.text\(\)\s*\.await"
            r"|\.json::<|\.bytes_stream\(\)|\breqwest::Error\b"
        ),
    ),
    ("PLAIN_BINDING stops matching `err`", "PLAIN_BINDING", re.compile(r"^&?e[0-9]?$")),
    (
        # Without a function definition to find, `reqwest_helpers` has
        # nothing to extend the window with, and a request laundered
        # through a same-file helper goes back to being invisible.
        "FN_DEFINITION finds no functions",
        "FN_DEFINITION",
        re.compile(r"(?!x)x"),
    ),
    (
        # The pre-enforcement reading: either redactor on any field.
        "DSN_FIELD accepts every field name",
        "DSN_FIELD",
        re.compile(r""),
    ),
    (
        # The pre-enforcement reading of the hoisting convention: the
        # `*_origin` suffix taken on trust, with no assignment resolved.
        "ORIGIN_ASSIGNMENT trusts the suffix alone",
        "ORIGIN_ASSIGNMENT",
        re.compile(r"\blet\s+(?:mut\s+)?([A-Za-z0-9_]*_origin)\s*(?::[^=;]*)?=()"),
    ),
]


def _categories(source: str) -> list[str]:
    blanked = SHARED.blank_noncode(source)
    return [hit[0] for hit in scan_source(blanked)]


def _self_test() -> int:
    failures: list[str] = []

    for label, source, expected in REFUSED:
        found = _categories(source)
        if expected not in found:
            failures.append(f"not refused: {label} (found {found or 'nothing'})")

    for label, source in ACCEPTED:
        found = _categories(source)
        if found:
            failures.append(f"wrongly refused: {label} (found {found})")

    # The mutation battery. Each loosening has to break at least one
    # refusal fixture, otherwise nothing in the set is holding that rule.
    globals_ = globals()
    for label, name, replacement in MUTATIONS:
        original = globals_[name]
        globals_[name] = replacement
        try:
            broke = any(
                expected not in _categories(source) for _label, source, expected in REFUSED
            )
        finally:
            globals_[name] = original
        if not broke:
            failures.append(f"no fixture covers: {label}")

    if failures:
        for failure in failures:
            print(f"self-test: {failure}", file=sys.stderr)
        return 1

    print(
        f"scan-log-url-usage self-test: {len(REFUSED)} refusals, "
        f"{len(ACCEPTED)} acceptances, {len(MUTATIONS)} mutations, all pass"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=None, help="workspace root (default: this script's repo)")
    parser.add_argument("--count", choices=CATEGORIES, help="print one integer and nothing else")
    parser.add_argument("--by-file", action="store_true", help="per-file totals instead of sites")
    parser.add_argument("--self-test", action="store_true", help="run the scanner fixtures")
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    repo = Path(args.repo).resolve() if args.repo else SCRIPTS.parent
    hits, excluded = collect(repo)

    if args.count:
        print(sum(1 for category, *_ in hits if category == args.count))
        return 0

    if args.by_file:
        per_file: dict[str, Counter] = {}
        for category, path, _line, _name, _value in hits:
            per_file.setdefault(str(path), Counter())[category] += 1
        for name in sorted(per_file, key=lambda key: -sum(per_file[key].values())):
            counts = per_file[name]
            print(
                f"{sum(counts.values()):4d}  raw-url={counts['raw-url']:<4d} "
                f"raw-request-error={counts['raw-request-error']:<3d}  {name}"
            )
    else:
        for category, path, line, name, value in hits:
            print(f"{path}:{line}: {category}: {name} = {value}")

    totals = Counter(category for category, *_ in hits)
    print(
        f"\nraw-url={totals['raw-url']} "
        f"raw-request-error={totals['raw-request-error']} "
        f"(test-only files skipped: {len(excluded)})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
