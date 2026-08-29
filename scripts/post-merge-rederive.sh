#!/usr/bin/env bash
# Re-derive every generated file after a merge from main, and say what moved.
#
# Run this immediately after `git merge origin/main`, before the gate.
#
# A merge can leave a generated file stale without conflicting on it: two
# branches each add an example, git merges both example directories
# cleanly, and examples/README.md now lists neither correctly. Nothing in
# the merge is a conflict, so nothing asks you to look. On 2026-08-27
# every lane hand-rolled this list from memory and one of them got it
# wrong, which cost a CI round trip on a stale catalog.
#
# The rule for the ratchet baselines, and the reason they are not simply
# rewritten: A BASELINE MAY ONLY FALL. Merging two branches that each
# removed unwrap sites should lower the count. Merging two branches that
# each added one must NOT quietly raise it; this script refuses, prints
# the delta, and tells you to remove the sites instead. "Recompute" is
# not "accept whatever is there now".
#
# Usage:
#
#   bash scripts/post-merge-rederive.sh            # rewrite and report
#   bash scripts/post-merge-rederive.sh --check    # report only, exit 1 if stale
#
# The generator half needs the workspace binaries in target/debug. It
# reuses them rather than re-entering cargo with a `-p` selection, which
# would resolve a different feature union and recompile the graph. It also
# refuses a binary older than anything it is built from, which after a
# merge from main is the normal case: a stale generator reproduces
# pre-merge output, and copying that over a freshly merged file while
# printing MOVED is worse than doing nothing. Either way it names what it
# could not re-derive and exits non-zero, rather than reporting those files
# as current.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PYTHONDONTWRITEBYTECODE=1

CHECK_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

MOVED=()
FAILED=()
UNCHANGED=0

note_moved() { MOVED+=("$1"); }
note_failed() { FAILED+=("$1"); }

# The workspace binaries this script execs. `cargo run -p <crate> --bin
# <name>` would work and is what the standalone checks do, but under
# resolver = "2" a narrow -p selection recomputes the feature union and
# rebuilds the dependency graph: scripts/lib/workspace-bin.sh measured four
# such calls at about two minutes. Nine of them, immediately before a gate
# that is about to build the workspace anyway, is the wrong trade.
#
# So this reuses target/debug or reports. A generator whose binary is not
# built is counted, named, and the run exits non-zero, because printing
# "nothing moved" about a file nothing regenerated would be a lie.
NEEDS_BUILD=()

# Run a built generator that writes one file to stdout, and report whether
# the file moved. $1 label, $2 target path, $3 binary name.
rederive_generated() {
  local label="$1" target="$2" bin="$3"
  local target_dir="${CARGO_TARGET_DIR:-target}"
  local prebuilt="$target_dir/debug/$bin"

  if [ ! -x "$prebuilt" ]; then
    printf '  \033[1;33mskip\033[0m    %s (no %s in %s/debug)\n' \
      "$label" "$bin" "$target_dir"
    NEEDS_BUILD+=("$label")
    return 0
  fi

  # Existence is not freshness, and this script runs at the one moment
  # freshness is least likely: right after a merge from main, when
  # target/debug holds binaries built from the pre-merge tree.
  #
  # Both failure modes are silent without this. In write mode, main lands a
  # new metric family and its regenerated table, the stale binary
  # reproduces the pre-merge output, and the script copies a revert of
  # main's regeneration over the freshly merged file and prints MOVED. In
  # --check mode the stale binary reproduces the old content, which matches
  # the old committed file, and the line printed is `ok`, which is the
  # exact false green this script exists to prevent.
  #
  # So: if anything the generator is built from is newer than the
  # generator, the binary is not authoritative. `find -newer` is a per-inode
  # mtime comparison, so this costs milliseconds.
  #
  # Sources and manifests only, and `target` pruned. The first version of
  # this compared against everything under crates/, which meant a scratch
  # directory a test had left behind
  # (crates/sbproxy-core/target/test-cluster-control-state) held every
  # generator hostage forever: the script reported all nine as unbuilt on a
  # tree where they were current. A freshness check that is never satisfied
  # is the same defect as one that always is.
  local newer
  newer="$(
    {
      find crates -name target -prune -o \
        \( -name '*.rs' -o -name 'Cargo.toml' \) -newer "$prebuilt" -print
      find Cargo.toml Cargo.lock -newer "$prebuilt" -print
    } 2>/dev/null | head -1
  )"
  if [ -n "$newer" ]; then
    printf '  \033[1;33mskip\033[0m    %s (%s is older than %s)\n' \
      "$label" "$bin" "$newer"
    NEEDS_BUILD+=("$label")
    return 0
  fi

  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/rederive.XXXXXX")"
  if ! "$prebuilt" >"$tmp" 2>"$tmp.err"; then
    printf '  \033[1;31mFAILED\033[0m  %s\n' "$label"
    sed 's/^/      /' "$tmp.err" | head -20
    note_failed "$label"
    rm -f "$tmp" "$tmp.err"
    return 0
  fi

  if [ -e "$target" ] && cmp -s "$tmp" "$target"; then
    printf '  ok      %s\n' "$label"
    UNCHANGED=$((UNCHANGED + 1))
  else
    if [ "$CHECK_ONLY" = "1" ]; then
      printf '  \033[1;33mSTALE\033[0m   %s\n' "$label"
    else
      cp "$tmp" "$target"
      printf '  \033[1;33mMOVED\033[0m   %s\n' "$label"
    fi
    note_moved "$label"
  fi
  rm -f "$tmp" "$tmp.err"
}

# Run a generator that rewrites in place (its own --check is the probe).
# $1 label, $2 check command, $3 write command.
rederive_inplace() {
  local label="$1" check_cmd="$2" write_cmd="$3"
  if bash -c "cd '$ROOT'; $check_cmd" >/dev/null 2>&1; then
    printf '  ok      %s\n' "$label"
    UNCHANGED=$((UNCHANGED + 1))
    return 0
  fi
  if [ "$CHECK_ONLY" = "1" ]; then
    printf '  \033[1;33mSTALE\033[0m   %s\n' "$label"
    note_moved "$label"
    return 0
  fi
  if bash -c "cd '$ROOT'; $write_cmd" >/dev/null 2>&1; then
    printf '  \033[1;33mMOVED\033[0m   %s\n' "$label"
    note_moved "$label"
  else
    printf '  \033[1;31mFAILED\033[0m  %s\n' "$label"
    note_failed "$label"
  fi
}

# The seven ratchet scanners each walk the whole tree and take about
# thirty seconds. Serially that is three minutes to learn that nothing
# moved. They are independent reads, so they are launched together and
# collected below.
SCAN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rederive-scans.XXXXXX")"
trap 'rm -rf "$SCAN_DIR"' EXIT

# start_count <slot> <command...>
start_count() {
  local slot="$1"
  shift
  ( "$@" 2>/dev/null | tail -1 | tr -dc '0-9' >"$SCAN_DIR/$slot" ) &
}

# A ratchet baseline. Falls freely; a rise is refused.
# $1 label, $2 baseline file, $3 the slot start_count wrote.
rederive_ratchet() {
  local label="$1" file="$2" slot="$3"
  local actual baseline
  actual="$(cat "$SCAN_DIR/$slot" 2>/dev/null)"
  if [ -z "$actual" ]; then
    printf '  \033[1;31mFAILED\033[0m  %s (the scanner printed no count)\n' "$label"
    note_failed "$label"
    return 0
  fi
  baseline="$(tr -dc '0-9' <"$file" 2>/dev/null)"
  if [ -z "$baseline" ]; then
    printf '  \033[1;31mFAILED\033[0m  %s (no baseline at %s)\n' "$label" "$file"
    note_failed "$label"
    return 0
  fi

  if [ "$actual" -eq "$baseline" ]; then
    printf '  ok      %s (%s)\n' "$label" "$actual"
    UNCHANGED=$((UNCHANGED + 1))
  elif [ "$actual" -lt "$baseline" ]; then
    if [ "$CHECK_ONLY" = "1" ]; then
      printf '  \033[1;33mSTALE\033[0m   %s (%s -> %s, the baseline should fall)\n' \
        "$label" "$baseline" "$actual"
    else
      printf '%s\n' "$actual" >"$file"
      printf '  \033[1;33mMOVED\033[0m   %s (%s -> %s)\n' "$label" "$baseline" "$actual"
    fi
    note_moved "$label"
  else
    printf '  \033[1;31mREFUSED\033[0m %s (%s -> %s: the merge ADDED %s sites)\n' \
      "$label" "$baseline" "$actual" "$((actual - baseline))"
    printf '      A ratchet only falls. Remove the new sites; do not raise this file.\n'
    note_failed "$label (baseline would have to rise)"
  fi
}

printf '\033[1mpost-merge re-derive\033[0m'
[ "$CHECK_ONLY" = "1" ] && printf ' (--check: reporting only)'
printf '\n\n'

# --- Generated documentation and schemas -------------------------------
# These exec the workspace binaries, so a build has to exist. Without one
# the run reports every generator as failed rather than pretending the
# files are current.
printf '\033[1m  generators (need the workspace binaries)\033[0m\n'

rederive_generated "schemas/sb-config.schema.json" \
  schemas/sb-config.schema.json generate-schema
rederive_generated "schemas/ai-proxy-provider.schema.json" \
  schemas/ai-proxy-provider.schema.json generate-ai-provider-schema
rederive_generated "schemas/ai-compression.schema.json" \
  schemas/ai-compression.schema.json generate-ai-compression-schema
rederive_generated "schemas/ai-external-guardrail.schema.json" \
  schemas/ai-external-guardrail.schema.json generate-ai-external-guardrail-schema
rederive_generated "schemas/ai-rag.schema.json" \
  schemas/ai-rag.schema.json generate-ai-rag-schema
rederive_generated "schemas/ai-semantic-cache.schema.json" \
  schemas/ai-semantic-cache.schema.json generate-ai-semantic-cache-schema

rederive_generated "docs/metrics-stability.md" \
  docs/metrics-stability.md generate-metrics-stability
rederive_generated "docs/decision-records.md" \
  docs/decision-records.md generate-decision-contract
rederive_generated "docs/model-host-capabilities.md" \
  docs/model-host-capabilities.md generate-model-host-capabilities

# --- Python generators. No build needed. -------------------------------
printf '\n\033[1m  generators (tree only)\033[0m\n'

rederive_inplace "examples/README.md catalog" \
  "python3 scripts/gen-examples-catalog.py --check" \
  "python3 scripts/gen-examples-catalog.py"
rederive_inplace "docs/tapes corpus" \
  "python3 scripts/gen-example-tapes.py --check" \
  "python3 scripts/gen-example-tapes.py"
rederive_inplace "example GIF wiring" \
  "python3 scripts/wire-example-gifs.py --check" \
  "python3 scripts/wire-example-gifs.py"
rederive_inplace "documentation config blocks" \
  "python3 scripts/sync-doc-configs.py --check" \
  "python3 scripts/sync-doc-configs.py"

# docs/llms-full.txt is regenerated at release prep and is normally absent
# from a feature branch. Touch it only when the branch already carries a
# change to it, which is exactly the condition the gate checks.
printf '\n\033[1m  llms-full corpus\033[0m\n'
LLMS_BASE="$(git merge-base HEAD origin/main 2>/dev/null || true)"
if [ -z "$LLMS_BASE" ]; then
  printf '  skip    docs/llms-full.txt (no merge base with origin/main)\n'
elif git diff --quiet "$LLMS_BASE" -- docs/llms-full.txt; then
  printf '  skip    docs/llms-full.txt (this branch does not carry it)\n'
else
  rederive_inplace "docs/llms-full.txt" \
    "bash scripts/regen-llms-full.sh --check" \
    "bash scripts/regen-llms-full.sh"
fi

# --- Ratchet baselines -------------------------------------------------
printf '\n\033[1m  ratchet baselines (these only fall)\033[0m\n'

start_count unwrap  python3 scripts/scan-unwrap-usage.py --count unwrap-expect
start_count panic   python3 scripts/scan-unwrap-usage.py --count panic
start_count tests   python3 scripts/scan-pub-item-usage.py --count tests-only
start_count unref   python3 scripts/scan-pub-item-usage.py --count unreferenced
start_count metrics python3 scripts/scan-metric-visibility.py --count
start_count logurl  python3 scripts/scan-log-url-usage.py --count raw-url
start_count reqerr  python3 scripts/scan-log-url-usage.py --count raw-request-error
wait

rederive_ratchet "unwrap/expect sites" scripts/unwrap-ratchet-baseline.count unwrap
rederive_ratchet "panic! sites" scripts/panic-ratchet-baseline.count panic
rederive_ratchet "pub items consumed only by tests" scripts/pub-item-ratchet-baseline.count tests
rederive_ratchet "pub items with no consumer" scripts/pub-item-unreferenced-baseline.count unref
rederive_ratchet "stable metrics with no panel" scripts/metric-visibility-baseline.count metrics
rederive_ratchet "raw-url log sites" scripts/log-url-ratchet-baseline.count logurl
rederive_ratchet "raw request-error log sites" scripts/request-error-ratchet-baseline.count reqerr

# The stack budget has no scanner to re-derive it from: it is a decision
# about how much worker stack the request path may use, not a count of
# source sites. On a merge the correct number is the LOWER of the two
# sides. Never their maximum, and never a fresh guess: a budget that
# rises to accommodate whichever branch spent more is not a budget.
printf '  %-46s %s\n' "AI dispatch stack budget (not re-derivable)" \
  "$(cat scripts/stack-budget-baseline.count 2>/dev/null || echo missing) bytes; keep the lower side"

# --- Report ------------------------------------------------------------
printf '\n------------------------------------------------------------------------\n'
if [ "${#MOVED[@]}" -eq 0 ] && [ "${#FAILED[@]}" -eq 0 ] && [ "${#NEEDS_BUILD[@]}" -eq 0 ]; then
  printf '\033[1;32mNothing moved. %s derived artifacts are already current.\033[0m\n' "$UNCHANGED"
else
  if [ "${#MOVED[@]}" -gt 0 ]; then
    if [ "$CHECK_ONLY" = "1" ]; then
      printf '\033[1;33mStale after the merge (%s):\033[0m\n' "${#MOVED[@]}"
    else
      printf '\033[1;33mRewritten by this run (%s). Commit them with the merge:\033[0m\n' "${#MOVED[@]}"
    fi
    for item in "${MOVED[@]}"; do
      printf '  * %s\n' "$item"
    done
  fi
  if [ "${#FAILED[@]}" -gt 0 ]; then
    printf '\n\033[1;31mCould not re-derive (%s):\033[0m\n' "${#FAILED[@]}"
    for item in "${FAILED[@]}"; do
      printf '  * %s\n' "$item"
    done
  fi
fi
if [ "${#NEEDS_BUILD[@]}" -gt 0 ]; then
  printf '\n\033[1;33mNot re-derived, because the generator is not built (%s):\033[0m\n' \
    "${#NEEDS_BUILD[@]}"
  for item in "${NEEDS_BUILD[@]}"; do
    printf '  * %s\n' "$item"
  done
  printf '\nThese were NOT checked and are NOT known to be current. Build the\n'
  printf 'workspace in this worktree, which is what makes the generators match\n'
  printf 'the merged tree, and re-run:\n\n'
  printf '  cargo build --workspace --exclude sbproxy-e2e --locked\n'
fi
printf -- '------------------------------------------------------------------------\n'

printf '\nNext: bash scripts/check-fast.sh, then bash scripts/check.sh\n'

if [ "${#FAILED[@]}" -gt 0 ] || [ "${#NEEDS_BUILD[@]}" -gt 0 ]; then
  exit 1
fi
if [ "$CHECK_ONLY" = "1" ] && [ "${#MOVED[@]}" -gt 0 ]; then
  exit 1
fi
exit 0
