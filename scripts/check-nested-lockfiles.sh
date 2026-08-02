#!/usr/bin/env bash
# Verify every standalone workspace lockfile still satisfies --locked.
#
# # Why this exists
#
# The repository carries lockfiles outside the root workspace: the bench
# harnesses, the synthetic bench, and the config-source test fixture are
# each their own workspace. Several of them path-depend on crates in this
# workspace, so adding one ordinary dependency here silently invalidates
# their lockfiles too.
#
# Nothing in the normal local loop notices. `cargo build`, `cargo test`,
# `cargo clippy`, and `scripts/check.sh` all operate on the root
# workspace and never open the nested locks, so a completely green local
# gate says nothing about them. The failure surfaces only in CI, as
#
#   error: cannot update the lock file .../ai_lb_strategy/Cargo.lock
#   because --locked was passed to prevent this
#
# which reads like a dependency problem and is really a stale generated
# file. Two pull requests hit it on the same day (#838 adding postcard
# and lru, #839 adding rustix), each needing a one-line regeneration per
# nested lock. This script moves that discovery back to the machine
# where the dependency was added.
#
# # Usage
#
#   scripts/check-nested-lockfiles.sh          # verify, exit 1 on drift
#   scripts/check-nested-lockfiles.sh --fix    # regenerate, then verify
#
# The nested workspaces are discovered rather than listed, so a new one
# is covered the day it lands instead of the day someone remembers to
# add it here.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

FIX=false
for arg in "$@"; do
  case "$arg" in
    --fix) FIX=true ;;
    -h | --help)
      sed -n '1,35p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

# Every Cargo.lock that is not the root one and not build output. Sorted
# so the report is stable, and -prune keeps this off target/ and the
# worktrees directory.
mapfile -t nested < <(
  find . \
    \( -name target -o -name .git -o -name .worktrees -o -name node_modules \) -prune -o \
    -name Cargo.lock -print |
    sed 's|^\./||' |
    grep -v '^Cargo.lock$' |
    sort
)

if [ "${#nested[@]}" -eq 0 ]; then
  echo "no standalone workspace lockfiles found" >&2
  exit 1
fi

stale=()
for lock in "${nested[@]}"; do
  manifest="${lock%Cargo.lock}Cargo.toml"
  if [ ! -f "$manifest" ]; then
    echo "::warning::$lock has no sibling Cargo.toml; skipping"
    continue
  fi
  if $FIX; then
    cargo update --manifest-path "$manifest" --workspace --quiet
  fi
  if cargo metadata --manifest-path "$manifest" --locked --format-version=1 >/dev/null 2>&1; then
    echo "ok: $lock"
  else
    stale+=("$lock")
  fi
done

if [ "${#stale[@]}" -ne 0 ]; then
  echo >&2
  echo "These standalone lockfiles no longer match their manifests:" >&2
  for lock in "${stale[@]}"; do
    echo "  $lock" >&2
  done
  echo >&2
  echo "A dependency change in the root workspace reaches them through a" >&2
  echo "path dependency. Regenerate and commit the result:" >&2
  echo >&2
  echo "  scripts/check-nested-lockfiles.sh --fix" >&2
  exit 1
fi

echo "all ${#nested[@]} standalone workspace lockfiles are current"
