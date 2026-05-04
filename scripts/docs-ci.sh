#!/usr/bin/env bash
# Wave 1 / Q1.10 - Doc CI runner.
#
# Runs two checks over the rust + enterprise docs trees:
#   1. lychee link checker (offline; external links live in .lycheeignore).
#   2. Code-block syntax check: `rust` blocks go through `rust-script`,
#      `bash` blocks go through `bash -n`. Blocks tagged `no_run` (rust)
#      or `skip` (bash) are skipped.
#
# Exits non-zero on the first failure. The companion workflow at
# `.github/workflows/docs-ci.yml` (B1.10) wraps this script.
#
# Usage:
#   scripts/docs-ci.sh                     # both trees, both checks
#   scripts/docs-ci.sh --links             # link check only
#   scripts/docs-ci.sh --code              # code-block check only
#   scripts/docs-ci.sh --tree rust         # one tree only
#
# Env knobs:
#   LYCHEE_BIN     path to lychee (default: lychee on PATH)
#   RUST_SCRIPT    path to rust-script (default: rust-script on PATH)
#   DOCS_CI_QUIET  set to 1 to suppress per-block progress

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENTERPRISE_ROOT="${ENTERPRISE_ROOT:-$RUST_ROOT/../sbproxy-enterprise}"

LYCHEE_BIN="${LYCHEE_BIN:-lychee}"
RUST_SCRIPT="${RUST_SCRIPT:-rust-script}"

# --- Argument parsing -------------------------------------------------

DO_LINKS=1
DO_CODE=1
TREE_FILTER=""

while [ $# -gt 0 ]; do
  case "$1" in
    --links)  DO_CODE=0; shift ;;
    --code)   DO_LINKS=0; shift ;;
    --tree)   TREE_FILTER="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,30p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- Tree resolution --------------------------------------------------

declare -a TREES=()
if [ -z "$TREE_FILTER" ] || [ "$TREE_FILTER" = "rust" ]; then
  TREES+=("$RUST_ROOT/docs")
fi
if [ -z "$TREE_FILTER" ] || [ "$TREE_FILTER" = "enterprise" ]; then
  if [ -d "$ENTERPRISE_ROOT/docs" ]; then
    TREES+=("$ENTERPRISE_ROOT/docs")
  fi
fi

if [ ${#TREES[@]} -eq 0 ]; then
  echo "no doc trees found; tried $RUST_ROOT/docs and $ENTERPRISE_ROOT/docs" >&2
  exit 2
fi

# --- Lychee link check ------------------------------------------------

run_links() {
  if ! command -v "$LYCHEE_BIN" >/dev/null 2>&1; then
    echo "lychee not found at $LYCHEE_BIN; install with 'cargo install lychee' or set LYCHEE_BIN" >&2
    return 127
  fi

  local rc=0
  for tree in "${TREES[@]}"; do
    echo "[docs-ci] lychee --offline --no-progress $tree/**/*.md"
    # --offline blocks all network; we explicitly want CI to be
    # hermetic. External links that need real fetch are excluded via
    # the per-tree `.lycheeignore`. localhost links are always excluded.
    local ignore_file="$tree/.lycheeignore"
    local args=(
      --offline
      --no-progress
      --include-fragments
      --exclude-loopback
      --exclude '^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)'
    )
    if [ -f "$ignore_file" ]; then
      args+=(--exclude-path "$ignore_file")
    fi
    if ! "$LYCHEE_BIN" "${args[@]}" "$tree" >&2; then
      rc=1
    fi
  done
  return $rc
}

# --- Code-block check -------------------------------------------------
#
# Block extraction lives in `extract_blocks_to_dir`. It walks the
# markdown file as a stream and tracks two pieces of state: whether
# we're inside a fenced block, and (if so) what the fence info string
# was. Blank lines INSIDE a block are content; the awk-based extractor
# this replaced treated them as block separators, which mis-split
# multi-line code blocks and surfaced false-positive failures. See
# `scripts/test-fixtures/docs-ci/multi-line-blocks.md` for a regression.
#
# Each extracted block becomes one file under $out_dir named
# `<lang>.<index>` and one peer file `<lang>.<index>.info` carrying
# the original fence info string. The caller iterates by `ls`.

extract_blocks_to_dir() {
  local file="$1"
  local lang="$2"
  local out_dir="$3"

  python3 - "$file" "$lang" "$out_dir" <<'PY'
import os
import sys

src_path, lang, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(out_dir, exist_ok=True)

# Fenced-block state machine. We track:
#   in_block   - True while inside a fenced block whose info[0] == lang.
#   skipping   - True while inside a fenced block whose info[0] != lang.
#                (We still need to know when the block ends.)
#   info       - The full info string (e.g. "rust,no_run") of the
#                current block, captured at the opening fence.
#   buf        - List of body lines for the current block.
in_block = False
skipping = False
info = ""
buf = []
index = 0

with open(src_path, "r", encoding="utf-8") as f:
    for raw in f:
        line = raw.rstrip("\n")
        # Fence line check. We accept both ``` and ~~~ as fence
        # markers; each must appear at column 0 (markdown spec
        # actually allows up to 3 leading spaces, but every doc in
        # this repo follows the column-0 form).
        is_fence = line.startswith("```") or line.startswith("~~~")
        if is_fence:
            if in_block:
                # Closing fence for a tracked block. Emit it.
                out_path = os.path.join(out_dir, f"{lang}.{index}")
                with open(out_path, "w", encoding="utf-8") as g:
                    g.write("\n".join(buf))
                    if buf:
                        g.write("\n")
                with open(out_path + ".info", "w", encoding="utf-8") as g:
                    g.write(info)
                index += 1
                in_block = False
                info = ""
                buf = []
                continue
            if skipping:
                skipping = False
                continue
            # Opening fence. Parse the info string.
            fence = "```" if line.startswith("```") else "~~~"
            info_str = line[len(fence):].strip()
            first_tag = info_str.split(",", 1)[0].strip()
            if first_tag == lang:
                in_block = True
                info = info_str
                buf = []
            else:
                skipping = True
            continue
        # Body line. If inside a tracked block, buffer it; if inside
        # a non-tracked block, drop it. Outside any block, also drop.
        if in_block:
            buf.append(line)
        # If neither in_block nor skipping, line is plain prose; ignore.
PY
}

# Returns 0 if the info string contains any "skip" tag.
is_skipped() {
  local info="$1" tag
  for tag in $(echo "$info" | tr ',' ' '); do
    case "$tag" in
      no_run|skip|ignore|compile_fail|edition2024) return 0 ;;
    esac
  done
  return 1
}

# Run a single language pass over a markdown file. $lang is "rust" or
# "bash"; $checker_fn is the bash function that takes a body file path
# and an info string and returns 0 if the block compiles / parses.
run_lang_pass() {
  local md="$1" lang="$2" checker_fn="$3"
  local rc_var="$4" checked_var="$5" skipped_var="$6"

  local block_dir
  block_dir=$(mktemp -d -t docs-ci-blocks-XXXXXX)

  extract_blocks_to_dir "$md" "$lang" "$block_dir"

  # Iterate every body file in lexicographic order. The peer .info
  # file carries the fence info string.
  local body
  # shellcheck disable=SC2010 # filenames are controlled (lang.N) and
  # the grep + sort pipe is the simplest portable ordering by index.
  for body in $(ls "$block_dir" 2>/dev/null | grep -E "^${lang}\\.[0-9]+\$" | sort -t. -k2 -n); do
    local body_path="$block_dir/$body"
    local info_path="$block_dir/${body}.info"
    local info=""
    [ -f "$info_path" ] && info=$(cat "$info_path")

    if is_skipped "$info"; then
      eval "$skipped_var=\$(($skipped_var + 1))"
      continue
    fi

    if "$checker_fn" "$body_path" "$info" "$md"; then
      :
    else
      eval "$rc_var=1"
    fi
    eval "$checked_var=\$(($checked_var + 1))"
  done

  rm -rf "$block_dir"
}

# Rust block checker. Tries rust-script first (full type-check via a
# scripted crate), falls back to `rustc --emit=metadata` for syntax
# only. Returns 0 on success, 1 on failure.
#
# The rustc fallback tries two shapes in order: first the block as-is
# (which works for top-level items: structs, impls, fn defs, use
# statements), then wrapped in a `fn _docs_ci_block() { ... }` (which
# rescues blocks that contain bare statements / expressions). A block
# is considered "valid" if either shape compiles. This avoids the
# false-negative pattern where a code block has a top-level `use`
# followed by a struct, which the wrapped form rejects.
check_rust_block() {
  local body_path="$1" info="$2" md="$3"

  if command -v "$RUST_SCRIPT" >/dev/null 2>&1; then
    if ! "$RUST_SCRIPT" --check "$body_path" >/dev/null 2>&1; then
      echo "  rust block FAILED in $md (info: $info)" >&2
      return 1
    fi
    return 0
  fi

  # rustc fallback. We emit metadata to a real temp dir; rustc's
  # `-o /dev/null` mode tries to write a sibling .rmeta which fails
  # on macOS / linux because /dev is unwriteable.
  local tmp_dir
  tmp_dir="$(mktemp -d -t docs-ci-rust-XXXXXX)"

  # Shape 1: as-is, top-level items (fn / struct / impl / use).
  local tmp_raw="$tmp_dir/raw.rs"
  cat "$body_path" > "$tmp_raw"
  if rustc --edition=2021 --emit=metadata --crate-type=lib \
       --out-dir "$tmp_dir/raw-out" "$tmp_raw" >/dev/null 2>&1; then
    rm -rf "$tmp_dir"
    return 0
  fi

  # Shape 2: wrap in a fn so bare statements parse.
  local tmp_wrap="$tmp_dir/wrap.rs"
  {
    echo "#[allow(dead_code)]"
    echo "fn _docs_ci_block() {"
    cat "$body_path"
    echo "}"
  } > "$tmp_wrap"
  if rustc --edition=2021 --emit=metadata --crate-type=lib \
       --out-dir "$tmp_dir/wrap-out" "$tmp_wrap" >/dev/null 2>&1; then
    rm -rf "$tmp_dir"
    return 0
  fi

  rm -rf "$tmp_dir"
  echo "  rust block FAILED in $md (info: $info)" >&2
  return 1
}

# Bash block checker. `bash -n` parses without executing.
check_bash_block() {
  local body_path="$1" info="$2" md="$3"
  if ! bash -n "$body_path" >/dev/null 2>&1; then
    echo "  bash block FAILED in $md (info: $info)" >&2
    return 1
  fi
  return 0
}

run_code() {
  local rc=0
  local checked=0
  local skipped=0

  for tree in "${TREES[@]}"; do
    while IFS= read -r -d '' md; do
      [ "${DOCS_CI_QUIET:-0}" = "1" ] || echo "[docs-ci] code blocks: $md"
      run_lang_pass "$md" rust check_rust_block rc checked skipped
      run_lang_pass "$md" bash check_bash_block rc checked skipped
    done < <(find "$tree" -type f -name '*.md' -print0)
  done

  echo "[docs-ci] code-block check: checked=$checked skipped=$skipped rc=$rc"
  return $rc
}

# --- Driver -----------------------------------------------------------

overall=0

if [ "$DO_LINKS" = "1" ]; then
  if ! run_links; then
    overall=1
  fi
fi

if [ "$DO_CODE" = "1" ]; then
  if ! run_code; then
    overall=1
  fi
fi

exit "$overall"
