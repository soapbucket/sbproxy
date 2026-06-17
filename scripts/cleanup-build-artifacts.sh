#!/usr/bin/env bash
# Remove high-churn Cargo build artifacts that are not useful after a completed
# gate. The dependency cache remains intact; this is meant to keep repeated
# builds from ballooning target/ without throwing away every compiled crate.
#
# Pass --aggressive to also remove target/release after local release-profile
# experiments. This is intentionally opt-in because rebuilding release artifacts
# is expensive and deployment-oriented workflows should control that tradeoff.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
QUIET=false
AGGRESSIVE=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --quiet)
      QUIET=true
      ;;
    --aggressive)
      AGGRESSIVE=true
      ;;
    --ci)
      # Reserved for callers that want to document CI intent. The cleanup set is
      # intentionally the same locally and in CI so the behavior is predictable.
      ;;
    --help|-h)
      sed -n '1,40p' "$0"
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
  shift
done

case "$TARGET_DIR" in
  /*) ;;
  *) TARGET_DIR="$ROOT/$TARGET_DIR" ;;
esac

if [ ! -d "$TARGET_DIR" ]; then
  $QUIET || printf 'cleanup: no target dir at %s\n' "$TARGET_DIR"
  exit 0
fi

size_of_target() {
  du -sh "$TARGET_DIR" 2>/dev/null | awk '{print $1}' || printf 'unknown'
}

BEFORE="$(size_of_target)"

rm_if_present() {
  if [ -e "$1" ]; then
    rm -rf "$1"
  fi
}

rm_if_present "$TARGET_DIR/doc"
rm_if_present "$TARGET_DIR/nextest"
rm_if_present "$TARGET_DIR/criterion"
rm_if_present "$TARGET_DIR/tmp"
rm_if_present "$TARGET_DIR/synthetic-logs"
rm_if_present "$TARGET_DIR/chaos-logs"

if $AGGRESSIVE; then
  rm_if_present "$TARGET_DIR/release"
fi

find "$TARGET_DIR" -type d -name incremental -prune -exec rm -rf {} + 2>/dev/null || true
find "$TARGET_DIR" -type d -name '*.dSYM' -prune -exec rm -rf {} + 2>/dev/null || true

AFTER="$(size_of_target)"
$QUIET || printf 'cleanup: target %s -> %s\n' "$BEFORE" "$AFTER"
