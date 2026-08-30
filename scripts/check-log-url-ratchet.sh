#!/usr/bin/env bash
#
# Refuse a new operator URL at a log line (WOR-2629, WOR-2640).
#
# An operator URL is a credential carrier twice over. `scheme://user:
# password@host` puts the password in the authority, and a Slack, Teams,
# or PagerDuty webhook puts the whole secret in the path. Both reach
# shared observability systems the moment the connection breaks, which is
# exactly when something logs them. A survey of this tree found four
# private, drifted URL sanitizers and no shared one; the shared one is
# `sbproxy_security::url_redact::redacted_url`, and this is what keeps
# the next call site from writing a fifth.
#
# # Two counts, not one
#
# `raw-url` is a URL-named `tracing` field interpolated from something
# that is not the redactor. Its baseline is the inherited population,
# which is allowed to fall and never to rise, on the same grounds as the
# unwrap ratchet next door: demanding zero would mean a big-bang cleanup
# before anything else can merge.
#
# `raw-request-error` is `error = %e` at a log site just below an
# outbound reqwest call. `reqwest::Error`'s Display ends with
# `" for url ({url})"`, so that one line writes the full request URL with
# no `url` field anywhere in sight, which is why it is tracked separately
# rather than folded into a larger number it could be traded against.
#
# Its baseline is zero, and the honest reading of that zero is narrower
# than it looks. The detector is a proximity heuristic: a log site whose
# preceding fifteen lines contain an outbound call, or a call to a
# same-file function that makes one. It does not resolve imports, it does
# not follow a value more than fifteen lines, and it sees nothing outside
# a `tracing` field. So zero means "no site of that shape", not "no
# reqwest URL reaches a log anywhere". The scanner's own header sets out
# the seen and unseen sets in full; read it before treating this number
# as a proof rather than as a ratchet.
#
# # Why a script and not clippy
#
# There is no lint for this. It is not a type error to interpolate a
# `String` that happens to hold a webhook URL, and the reqwest half is a
# property of a third-party `Display` impl. `disallowed_methods` cannot
# express "not at a log site", and the workspace lint lane runs
# `-D warnings`, so there is no warn-now-fix-later level to ratchet
# against.
#
# # What to do when this fails
#
# See the new sites:
#
#   python3 scripts/scan-log-url-usage.py
#
# Then pick one:
#
#   * `url = %redacted_url(&target)` for the origin, which is what an
#     operator needs to act on the failure and what the egress inventory
#     already records for the same dial.
#   * `url = %redacted_url_with_path(&dsn)` when the path is a structural
#     selector rather than a secret, which in this workspace means the
#     Redis database index and nothing else.
#   * Hoist it out of a loop as `let x_origin = redacted_url(..)`. The
#     `*_origin` suffix is the convention that lets the log site be read
#     on its own, and the scanner accepts it for that reason.
#   * For a reqwest failure, `error = %request_error_summary(&e)`. If the
#     error is not a reqwest one, name the binding for what it is
#     (`Err(parse_error)`), which says so at the call site.
#
# # Why the counts are committed
#
# Same reasoning as the unwrap and pub-item ratchets: lowering one is a
# normal part of the cleanup and a reviewer should see the number move in
# the diff. Each is its own single-line file, because a number stored
# among prose merges badly (WOR-2252): two branches editing non-adjacent
# lines look like two independent hunks, git keeps both, and the reader
# squashes them into a ceiling no real count can exceed.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCANNER="$ROOT_DIR/scripts/scan-log-url-usage.py"

cd "$ROOT_DIR"

fail=0

# Read a committed single-integer baseline, rejecting anything else.
# Taken exactly as it is: no comment stripping, no blank-line stripping,
# so a merge that kept both sides is an error rather than something this
# reader quietly reassembles. `|| [ -n "$line" ]` catches a final line
# with no trailing newline.
read_baseline() {
  local file="$1" kind="$2"
  local -a lines=()
  local line

  if [ ! -f "$file" ]; then
    echo "missing baseline file: $file" >&2
    echo "It holds the integer only. Recompute with:" >&2
    echo "  python3 scripts/scan-log-url-usage.py --count $kind" >&2
    return 1
  fi

  while IFS= read -r line || [ -n "$line" ]; do
    lines+=("$line")
  done < "$file"

  if [ "${#lines[@]}" -ne 1 ]; then
    echo "baseline count file must hold exactly one line, found ${#lines[@]}: $file" >&2
    if [ "${#lines[@]}" -gt 1 ]; then
      echo >&2
      echo "More than one line usually means a merge kept both sides. Recompute" >&2
      echo "against the merged tree rather than keeping either branch's number:" >&2
      printf '  %s\n' "${lines[@]}" >&2
      echo >&2
      echo "  python3 scripts/scan-log-url-usage.py --count $kind" >&2
    fi
    return 1
  fi

  case "${lines[0]}" in
    '' | *[!0-9]*)
      echo "baseline file does not contain a single integer: $file" >&2
      echo "  found: ${lines[0]}" >&2
      return 1
      ;;
  esac

  printf '%s' "${lines[0]}"
}

check_one() {
  local kind="$1" file="$2" label="$3"
  local baseline actual

  baseline="$(read_baseline "$file" "$kind")" || return 1

  # The status is captured rather than left to `set -e`, which does not
  # apply here: `check_one` is invoked as `check_one ... || fail=1`, and
  # that puts the whole function body in a context where a failing
  # command does not abort. A crashed scanner would otherwise leave
  # `actual` empty, both comparisons below would evaluate false with a
  # `[: : integer expected` on stderr, and the function would print the
  # success line and return 0. A detector that has stopped detecting
  # reading as a clean tree is the one failure this file exists to
  # prevent, so it cannot be the failure mode of the file itself.
  if ! actual="$(python3 "$SCANNER" --count "$kind")"; then
    echo "the scanner failed while counting $kind" >&2
    echo "Run it directly to see why:" >&2
    echo "  python3 scripts/scan-log-url-usage.py --count $kind" >&2
    return 1
  fi

  case "$actual" in
    '' | *[!0-9]*)
      echo "the scanner did not print a single integer for $kind" >&2
      echo "  found: $actual" >&2
      return 1
      ;;
  esac

  if [ "$actual" -gt "$baseline" ]; then
    echo "$label in production code: $actual (baseline $baseline)" >&2
    echo >&2
    echo "This change adds $((actual - baseline)). A URL at a log line is an" >&2
    echo "operator credential in whatever system collects those logs: the" >&2
    echo "password sits in the authority and a webhook's secret sits in the" >&2
    echo "path." >&2
    echo >&2
    echo "See the sites with:" >&2
    echo "  python3 scripts/scan-log-url-usage.py" >&2
    echo >&2
    echo "See the header of this script for the four ways to resolve it." >&2
    return 1
  fi

  if [ "$actual" -lt "$baseline" ]; then
    echo "$label in production code: $actual (baseline $baseline)" >&2
    echo >&2
    echo "Lower than the baseline, which is the good direction. Lock it in so" >&2
    echo "the ground is not given back:" >&2
    echo >&2
    echo "  printf '%s\\n' $actual > $file" >&2
    return 1
  fi

  echo "$label in production code: $actual (baseline $baseline)"
  return 0
}

# --- This script's own fixtures ---------------------------------------
#
# The scanner's `--self-test` covers the detector. It cannot cover this
# file, and this file has its own way of reading like a clean tree: the
# scanner crashing only while walking the real crates, which no in-memory
# fixture reaches. So the harness below builds a throwaway root holding a
# copy of this script, a pair of baselines, and a stub scanner, and
# asserts that a scanner which dies is a failure rather than a pass.
#
# The copy is run with `--counts-only`, which is this file's whole
# recursion guard: without it the child would run the harness again.
self_test() {
  local tmp status failures=0

  run_case() {
    local label="$1" want="$2" body="$3" baseline="${4:-0}"
    tmp="$(mktemp -d)"
    mkdir -p "$tmp/scripts"
    cp "${BASH_SOURCE[0]}" "$tmp/scripts/check-log-url-ratchet.sh"
    printf '%s\n' "$baseline" > "$tmp/scripts/log-url-ratchet-baseline.count"
    printf '%s\n' "$baseline" > "$tmp/scripts/request-error-ratchet-baseline.count"
    printf '%s\n' '#!/usr/bin/env python3' "$body" > "$tmp/scripts/scan-log-url-usage.py"

    set +e
    bash "$tmp/scripts/check-log-url-ratchet.sh" --counts-only >/dev/null 2>&1
    status=$?
    set -e
    rm -rf "$tmp"

    if [ "$want" = "pass" ] && [ "$status" -ne 0 ]; then
      echo "ratchet self-test: $label should have passed, exited $status" >&2
      failures=$((failures + 1))
    fi
    if [ "$want" = "fail" ] && [ "$status" -eq 0 ]; then
      echo "ratchet self-test: $label was reported as a pass" >&2
      failures=$((failures + 1))
    fi
  }

  # The control. Without it a harness that always reports failure would
  # look like it was holding the line.
  run_case "a scanner that counts" pass \
    'import sys
sys.exit(0) if "--self-test" in sys.argv else print(0)'

  # The finding: `check_one` runs with `set -e` suppressed, so a failed
  # command substitution used to leave `actual` empty and fall through to
  # the success line.
  run_case "a scanner that dies while walking the tree" fail \
    'import sys
if "--self-test" in sys.argv:
    sys.exit(0)
sys.stderr.write("boom\n")
sys.exit(3)'

  # Same shape, one step earlier: an exit code of zero and something
  # other than an integer on stdout.
  run_case "a scanner that prints a traceback and exits clean" fail \
    'import sys
sys.exit(0) if "--self-test" in sys.argv else print("Traceback (most recent call last)")'

  # A scanner whose own fixtures fail is a detector that has stopped
  # detecting, which the counts cannot see.
  run_case "a scanner whose fixtures fail" fail \
    'import sys
sys.exit(1) if "--self-test" in sys.argv else print(0)'

  # And the ratchet direction itself, so the harness proves it can tell a
  # rise from a hold.
  run_case "a count above the baseline" fail \
    'import sys
sys.exit(0) if "--self-test" in sys.argv else print(7)'

  [ "$failures" -eq 0 ] || return 1
  echo "check-log-url-ratchet self-test: 5 cases, all pass"
}

if [ "${1:-}" != "--counts-only" ]; then
  self_test || fail=1
fi

# The scanner's own fixtures next. A detector that has quietly stopped
# detecting reads exactly like a clean tree, and the counts below cannot
# tell the difference.
python3 "$SCANNER" --self-test || fail=1

check_one raw-url \
  "$ROOT_DIR/scripts/log-url-ratchet-baseline.count" \
  "unredacted URL log fields" || fail=1
check_one raw-request-error \
  "$ROOT_DIR/scripts/request-error-ratchet-baseline.count" \
  "raw reqwest errors at a log site" || fail=1

# What these two counts cannot see, printed rather than left in a header
# nobody opens. A guard narrower than its claim is worse than no guard,
# because the green line reads as coverage.
#
# The raw-request-error count keys on `reqwest::Error` at a log site.
# `sbproxy-vault` reaches Vault, Azure Key Vault and GCP Secret Manager
# through `ureq` instead, and `ureq`'s own `Display for Transport` ends
# with the URL it dialed, userinfo and all. Those files are counted here
# rather than listed as a literal, so a fifth client or a second test
# changes the notice instead of leaving it stale.
# Skipped under --counts-only, which is the mode the self-test runs a copy
# of this file in: that copy has no crates/ tree beside it and the notice
# is not what the self-test is checking.
if [ "$fail" -eq 0 ] && [ "${1:-}" != "--counts-only" ] &&
   [ -d "$ROOT_DIR/crates/sbproxy-vault/src" ]; then
  ureq_files=$(grep -rl 'ureq::' "$ROOT_DIR/crates/sbproxy-vault/src" 2>/dev/null | sort || true)
  ureq_count=$(printf '%s\n' "$ureq_files" | grep -c . || true)
  pinned=$(printf '%s\n' "$ureq_files" | while read -r f; do
    [ -n "$f" ] || continue
    if grep -q 'never_carries_the_address' "$f"; then basename "$f"; fi
  done | paste -sd, - )
  [ -n "$pinned" ] || pinned="none"
  printf '  not covered: %s ureq client file(s) under crates/sbproxy-vault/src.\n' "$ureq_count"
  printf '  The raw-request-error count keys on reqwest::Error, so these are\n'
  printf '  outside it. ureq Transport Display carries the dialed URL including\n'
  printf '  userinfo. Pinned by a test today: %s\n' "$pinned"
fi

exit "$fail"
