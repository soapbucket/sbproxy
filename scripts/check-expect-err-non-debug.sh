#!/usr/bin/env bash
# Reject `expect_err` / `unwrap_err` on the two Ok types that have no
# Debug (WOR-2193).
#
# # Why this exists
#
# `Result::expect_err` and `Result::unwrap_err` require `T: Debug`,
# because both print the `Ok` value when the result was not an error.
# `CompiledConfig` and `CompiledPipeline` deliberately have no `Debug`:
# they carry compiled credentials, resolved secrets and key material,
# and a blanket derive added to satisfy one test would put all of it
# into whatever the panic message lands in.
#
# Nothing in production calls either method on those types, so
# `cargo build --workspace` is green and only the test-profile compile
# fails. That is the worst place for it: it is a natural thing to write,
# nothing warns at authoring time, and the error arrives behind a build.
# It cost four gate cycles in one session on 2026-08-02 (WOR-2162,
# WOR-2183, WOR-2166), every time with the same one-line fix. Agents hit
# it especially reliably, because they cannot compile before they write.
#
# The rule this script enforces: a statement that builds one of those
# two types and then asks for its error goes through `.err().expect()`,
# which needs no `Debug` on the `Ok` side.
#
# # The two forms are not interchangeable
#
# `.err().expect()` is correct HERE and wrong nearly everywhere else.
# Where the `Ok` type does implement `Debug`, clippy's `err_expect`
# fires on `.err().expect()` and sends you back to `expect_err`. The
# two forms are mutually exclusive, which is why this check names the
# constructors it covers instead of banning a method outright: outside
# that list, `expect_err` is the right call and clippy enforces it.
#
# # What a grep cannot see
#
# This matches a statement that names one of the constructors below and
# then calls `expect_err` / `unwrap_err` on the same statement. It does
# not resolve types, so it cannot see a test helper that wraps one of
# those constructors and returns the same `Result` under a local name.
# Such a helper still fails to compile, just without this check's
# message in front of it. Widening the constructor list is part of
# adding a constructor, not a follow-up.
#
# # Usage
#
#   scripts/check-expect-err-non-debug.sh              # exit 1 on any violation
#   scripts/check-expect-err-non-debug.sh --self-test  # prove the detector detects

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The constructors whose `Ok` type is one of the two non-Debug types,
# as an awk ERE. Longest alternative first: not every awk implements
# POSIX leftmost-longest alternation, and `compile_config` is a prefix
# of `compile_config_from_source_blocking`.
#
#   compile_config, compile_config_from_source_blocking
#       -> anyhow::Result<CompiledConfig>   (sbproxy-config)
#   CompiledPipeline::from_config and its from_config_* siblings
#       -> anyhow::Result<CompiledPipeline> (sbproxy-core)
#
# The leading `(^|[^A-Za-z0-9_])` is the word boundary awk's ERE has no
# escape for, and the trailing paren is the other half of it. Together
# they keep out the test function
# `upstream_plus_publish_fails_validation_through_compile_config()` and
# the helper `compile_config_with_variables()`: one has an identifier
# character where the pattern wants a boundary, the other has one where
# it wants a paren. `from_config` alone is deliberately not listed, and
# cannot be: `WafPolicy`, `AiHandlerConfig`, `McpAction` and two dozen
# others carry a `from_config` whose Ok type does implement Debug, and
# `expect_err` is the correct call on every one of them.
#
# The trailing `\\(` is doubled on purpose. awk resolves string escapes
# in a `-v` assignment before the value is ever used as a regex, so a
# single backslash arrives as a bare `(`, which opens a group that
# never closes: BWK awk calls that "illegal primary in regular
# expression" and exits 2, which a self-test that only checks for exit
# 1 would have read as a passing detector.
CONSTRUCTORS='(^|[^A-Za-z0-9_])(compile_config_from_source_blocking|compile_config|CompiledPipeline::from_config[A-Za-z0-9_]*)[[:space:]]*\\('

# The two types this check exists for, as `<file>:<struct>` pairs. Rule
# B reads the derive above each one: the day either gains `Debug` the
# advice above inverts, and this script has to be corrected rather than
# quietly kept.
GUARDED_TYPES=(
  "crates/sbproxy-config/src/snapshot.rs:CompiledConfig"
  "crates/sbproxy-core/src/pipeline.rs:CompiledPipeline"
)

# Files permitted to pair a listed constructor with expect_err /
# unwrap_err in one statement, with the reason each earns it. Empty
# today: every call site in the tree already uses `.err().expect()`,
# because the alternative does not compile. An entry here should say
# why the statement is fine (a different receiver later in the same
# statement, say), not that the fix was inconvenient.
ALLOWED=()

is_allowed() {
  local file="$1" allowed
  for allowed in ${ALLOWED[@]+"${ALLOWED[@]}"}; do
    if [ "$file" = "$allowed" ]; then
      return 0
    fi
  done
  return 1
}

# Rule A. Scan the named files. Prints `<file>:<line>: <statement>` for
# each statement that names a listed constructor and then calls
# expect_err or unwrap_err on it. Exit 1 when anything printed.
#
# Statements are accumulated across lines and flushed at `;`, because
# rustfmt breaks exactly the chain this looks for:
#
#     let err = compile_config(yaml)
#         .expect_err("must be refused");
#
# A line-oriented grep sees two lines and neither one is a violation.
# Ordering is checked rather than assumed: the expect_err has to fall
# after the constructor in the statement.
#
# Only whole-line comments are dropped, the way check-env-mutation.sh
# drops them. Stripping from an inline `//` to end of line would cut
# `compile_config("http://host").expect_err(..)` in half at the URL and
# lose the violation, and the prose this repository writes next to a
# corrected call site names the methods without calling them.
scan_files() {
  awk -v ctors="$CONSTRUCTORS" '
    function flush(   rest) {
      if (buf != "" && match(buf, ctors)) {
        rest = substr(buf, RSTART + RLENGTH)
        if (match(rest, /\.[[:space:]]*(expect_err|unwrap_err)[[:space:]]*\(/)) {
          gsub(/[[:space:]]+/, " ", buf)
          sub(/^ /, "", buf)
          printf "%s:%d: %s\n", bufile, start, buf
          hits++
        }
      }
      buf = ""
      start = 0
      bufile = ""
    }
    FNR == 1 { flush() }
    {
      line = $0
      if (line ~ /^[[:space:]]*\/\//) { next }
      if (line ~ /^[[:space:]]*$/) {
        if (buf != "") { flush() }
        next
      }
      if (buf == "") { start = FNR; bufile = FILENAME }
      buf = buf " " line
      if (line ~ /;/) { flush() }
    }
    END {
      flush()
      exit(hits > 0 ? 1 : 0)
    }
  ' "$@"
}

# Rule B. Neither guarded type may derive Debug. Fails closed: a struct
# this cannot find is a rename that moved the type out from under the
# check, not a pass.
scan_guarded_type() {
  local file="$1" name="$2" derives
  if [ ! -f "$file" ]; then
    printf 'missing %s: %s is not where this check expects it\n' "$file" "$name" >&2
    return 1
  fi
  if ! grep -qE "(^|[^A-Za-z0-9_])struct ${name}([^A-Za-z0-9_]|\$)" "$file"; then
    printf '%s: no `struct %s` found; it was renamed or moved\n' "$file" "$name" >&2
    return 1
  fi
  # The attribute block immediately above the struct. A doc comment
  # resets it, which is the order this repository writes: rustdoc, then
  # derives, then the item.
  derives="$(awk -v name="$name" '
    $0 ~ ("^[[:space:]]*(pub[^ ]* )?struct " name "([ ;{(<]|$)") { print block; exit }
    /^[[:space:]]*#\[/ { block = block "\n" $0; next }
    { block = "" }
  ' "$file")"
  if printf '%s' "$derives" | grep -qE '(^|[^A-Za-z0-9_])Debug([^A-Za-z0-9_]|$)'; then
    printf '%s: %s now derives Debug.\n' "$file" "$name" >&2
    printf 'That inverts this whole check: with Debug present, `expect_err` is\n' >&2
    printf 'the correct call and clippy::err_expect refuses `.err().expect()`.\n' >&2
    printf 'Either the derive is a secret-leak regression (scripts/check-secret-\n' >&2
    printf 'debug-registry.sh guards the same failure mode for other types), or\n' >&2
    printf 'this script and its CLAUDE.md row are now wrong and have to change.\n' >&2
    return 1
  fi
  return 0
}

run_check() {
  local root="$1" file out entry type_file type_name
  local -a files=()

  cd "$root"

  while IFS= read -r file; do
    if is_allowed "$file"; then
      continue
    fi
    files+=("$file")
  done < <(find crates e2e -name '*.rs' -type f | sort)

  if ! out="$(scan_files "${files[@]}")"; then
    printf 'expect_err / unwrap_err on a Result whose Ok type has no Debug:\n\n' >&2
    printf '%s\n' "$out" | sed 's/^/  /' >&2
    cat >&2 <<'MSG'

Both methods print the Ok value on the wrong branch, so both require
`T: Debug`. CompiledConfig and CompiledPipeline do not have it, on
purpose: they hold compiled credentials and key material. Production
never calls these methods on them, so `cargo build --workspace` stays
green and only the test-profile compile fails, minutes later.

Write this instead:

  let err = compile_config(yaml).err().expect("config must be refused");

Do not carry that form anywhere else. Where the Ok type DOES implement
Debug, clippy::err_expect refuses `.err().expect()` and sends you back
to `expect_err`. The two are mutually exclusive; this check fires only
for the constructors named in its header.
MSG
    return 1
  fi

  for entry in "${GUARDED_TYPES[@]}"; do
    type_file="${entry%%:*}"
    type_name="${entry##*:}"
    scan_guarded_type "$type_file" "$type_name" || return 1
  done

  printf 'expect_err check: %d files, no expect_err/unwrap_err on CompiledConfig or CompiledPipeline.\n' \
    "${#files[@]}"
  return 0
}

# A detector that stopped detecting reads exactly like a clean tree, so
# both rules run against fixtures that must fail.
self_test() {
  local scratch status failures=0
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-expect-err-selftest.XXXXXX")"
  trap 'rm -rf "$scratch"' RETURN

  expect() {
    local label="$1" want="$2"
    shift 2
    set +e
    "$@" >/dev/null 2>&1
    status=$?
    set -e
    if [ "$status" -ne "$want" ]; then
      echo "self-test: $label expected exit $want, got $status" >&2
      failures=1
    fi
  }

  # Rule A, the shape that cost the four gate cycles: one line.
  cat >"$scratch/oneline.rs" <<'EOF'
#[test]
fn refuses() {
    let err = compile_config(YAML).expect_err("must be refused");
    assert!(err.to_string().contains("origins"));
}
EOF
  expect "a one-line expect_err is refused" 1 scan_files "$scratch/oneline.rs"

  # The same call after rustfmt broke the chain, which is what a grep
  # over single lines cannot see.
  cat >"$scratch/wrapped.rs" <<'EOF'
#[test]
fn refuses() {
    let err = compile_config(YAML)
        .expect_err("must be refused");
}
EOF
  expect "a wrapped expect_err is refused" 1 scan_files "$scratch/wrapped.rs"

  cat >"$scratch/multiline_args.rs" <<'EOF'
#[test]
fn refuses() {
    let err = sbproxy_config::compile_config(
        r#"
origins:
  api.test.sbproxy.dev:
    upstream: http://example.test
"#,
    )
    .unwrap_err();
}
EOF
  expect "unwrap_err past a multi-line argument is refused" 1 scan_files "$scratch/multiline_args.rs"

  cat >"$scratch/url_arg.rs" <<'EOF'
#[test]
fn refuses() {
    let err = compile_config("upstream: http://host").expect_err("must be refused");
}
EOF
  expect "a URL in the argument does not hide the call" 1 scan_files "$scratch/url_arg.rs"

  cat >"$scratch/pipeline.rs" <<'EOF'
#[test]
fn refuses() {
    let err = CompiledPipeline::from_config(cfg).expect_err("must be refused");
}
EOF
  expect "CompiledPipeline::from_config is refused" 1 scan_files "$scratch/pipeline.rs"

  cat >"$scratch/pipeline_sibling.rs" <<'EOF'
#[test]
fn refuses() {
    let err = crate::pipeline::CompiledPipeline::from_config_for_validation(cfg)
        .unwrap_err();
}
EOF
  expect "a from_config_* sibling is refused" 1 scan_files "$scratch/pipeline_sibling.rs"

  cat >"$scratch/blocking.rs" <<'EOF'
#[test]
fn refuses() {
    let err = compile_config_from_source_blocking(text, &ctx).expect_err("no");
}
EOF
  expect "compile_config_from_source_blocking is refused" 1 scan_files "$scratch/blocking.rs"

  # The correct form, which is what every call site in the tree uses.
  cat >"$scratch/good.rs" <<'EOF'
#[test]
fn refuses() {
    let err = compile_config(YAML)
        .err()
        .expect("config must be refused");
    assert!(err.to_string().contains("origins"));
}
EOF
  expect "the .err().expect() form passes" 0 scan_files "$scratch/good.rs"

  # expect_err on a type that does implement Debug is the correct call
  # and has to stay silent, or this guard would push people into
  # clippy::err_expect.
  cat >"$scratch/other_type.rs" <<'EOF'
#[test]
fn refuses() {
    let err = WafPolicy::from_config(json).expect_err("must be refused");
    let other = AiHandlerConfig::from_config(json).unwrap_err();
}
EOF
  expect "expect_err on a Debug type passes" 0 scan_files "$scratch/other_type.rs"

  # Near-misses on the word boundary: a test function whose name ends
  # in the constructor's name, and a helper whose name extends it.
  cat >"$scratch/near_miss.rs" <<'EOF'
#[test]
fn upstream_plus_publish_fails_validation_through_compile_config() {
    let err = helper().expect_err("must be refused");
}

#[test]
fn helper_wrapper() {
    let err = compile_config_with_variables(YAML, &vars).expect_err("nope");
}
EOF
  expect "a name that merely ends in the constructor passes" 0 scan_files "$scratch/near_miss.rs"

  # Prose about the two methods is what this repository's comments are
  # full of, including the one next to every corrected call site.
  cat >"$scratch/comment.rs" <<'EOF'
#[test]
fn refuses() {
    // `.err().expect(..)` and not `expect_err`: the latter needs the Ok
    // type to be Debug, so compile_config(..).expect_err("x") would not build.
    let err = compile_config(YAML).err().expect("must be refused");
}
EOF
  expect "a comment naming both forms passes" 0 scan_files "$scratch/comment.rs"

  # Two separate statements must not be joined across the semicolon.
  cat >"$scratch/two_statements.rs" <<'EOF'
#[test]
fn refuses() {
    let cfg = compile_config(YAML).err().expect("must be refused");
    let other = WafPolicy::from_config(json).expect_err("must be refused");
}
EOF
  expect "an unrelated later statement passes" 0 scan_files "$scratch/two_statements.rs"

  # Rule B: the derive that would invert the advice.
  mkdir -p "$scratch/fixtures"
  cat >"$scratch/fixtures/ok.rs" <<'EOF'
/// The complete compiled config.
#[derive(Clone, Default)]
pub struct CompiledConfig {
    pub origins: Vec<String>,
}
EOF
  expect "a struct with no Debug derive passes" 0 \
    scan_guarded_type "$scratch/fixtures/ok.rs" CompiledConfig

  cat >"$scratch/fixtures/bad.rs" <<'EOF'
/// The complete compiled config.
#[derive(Debug, Clone, Default)]
pub struct CompiledConfig {
    pub origins: Vec<String>,
}
EOF
  expect "a Debug derive is refused" 1 \
    scan_guarded_type "$scratch/fixtures/bad.rs" CompiledConfig

  cat >"$scratch/fixtures/renamed.rs" <<'EOF'
#[derive(Clone, Default)]
pub struct CompiledConfigV2 {
    pub origins: Vec<String>,
}
EOF
  expect "a renamed struct fails closed" 1 \
    scan_guarded_type "$scratch/fixtures/renamed.rs" CompiledConfig

  expect "a missing file fails closed" 1 \
    scan_guarded_type "$scratch/fixtures/gone.rs" CompiledConfig

  if [ "$failures" -ne 0 ]; then
    echo "self-test failed: the detector is narrower than the enforcer" >&2
    return 1
  fi
  echo "self-test passed: 16 fixtures"
  return 0
}

case "${1:-}" in
  --self-test) self_test ;;
  "") self_test && run_check "$ROOT_DIR" ;;
  *)
    echo "usage: $0 [--self-test]" >&2
    exit 2
    ;;
esac
