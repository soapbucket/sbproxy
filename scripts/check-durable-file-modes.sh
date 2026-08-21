#!/usr/bin/env bash
# Durable sinks create their files through sbproxy-util's secure_fs,
# never through std directly (WOR-2626).
#
# # Why this exists
#
# Ten durable sinks opened their files with a bare
# `std::fs::OpenOptions` or `std::fs::File::create`. Each asks the
# kernel for `0o666` and lets the umask decide; the near-universal
# `0o022` made every one of them `0o644`, so the signed usage ledger,
# the settlement database, per-request events, session ledger records
# and the LLM usage feed were readable by every account on the host.
#
# Fixing ten call sites does not fix the eleventh. The rule this script
# enforces is that inside the four crates that own durable, sensitive
# output, production code does not reach `File::create`,
# `OpenOptions::new` or `create_dir_all` at all. It goes through
# `sbproxy_util::secure_fs`, which puts the mode in the `open(2)` call
# rather than chmod-ing afterwards.
#
# That distinction is the second half of the check. A create-then-chmod
# leaves the file world-readable between the two syscalls, which is
# long enough on a busy host for another process to open a descriptor
# and keep reading through the tightening. Nothing at runtime can prove
# that window is absent (a test that stats the file afterwards sees
# `0o600` either way), so it is proved here, structurally, by requiring
# the creation mode to be applied before the open and by refusing the
# path-based `fs::set_permissions` that a symlink can redirect.
#
# # Usage
#
#   scripts/check-durable-file-modes.sh              # exit 1 on any violation
#   scripts/check-durable-file-modes.sh --self-test  # prove the detector detects

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The crates whose `src/` trees write durable, sensitive output.
GUARDED_CRATES=(
  crates/sbproxy-observe
  crates/sbproxy-meter
  crates/sbproxy-billing
  crates/sbproxy-ai
)

# The helper every guarded site must reach instead.
HELPER="crates/sbproxy-util/src/secure_fs.rs"

# Files inside the guarded crates that still open their own files.
#
# This list is shrink-only. Every entry is a real WOR-2626 site that a
# concurrent branch held when the helper landed; converting one is a
# one-line change plus a mode assertion, and the entry comes out with
# it. Nothing may be added here without a mode of its own.
EXEMPT=(
  # Access log write, rotation, and the rotated `.gz`. Operator-facing
  # and the most likely to be read by an outside shipper, so the
  # conversion wants its own upgrade note.
  "crates/sbproxy-observe/src/access_log.rs"
  # The compiled observability sink fan-out: file target plus its
  # parent directory.
  "crates/sbproxy-observe/src/sink_dispatcher.rs"
  # The decision event file worker.
  "crates/sbproxy-observe/src/event_sink.rs"
  # Only the parent directory here. The chain file itself already goes
  # through sbproxy-meter's `UsageLedger::open`, which is converted.
  "crates/sbproxy-observe/src/audit_chain.rs"
  # The value-ledger cache directory under the serve cache dir.
  "crates/sbproxy-ai/src/handler.rs"
)

# Production code only. Everything from the first column-zero
# `#[cfg(test)]` onward is a test module, and a test that pre-creates a
# fixture at `0o644` to prove the tightening works is exactly what this
# change added.
production_region() {
  awk '/^#\[cfg\(test\)\]/ { exit } /^#\[cfg\(all\(test/ { exit } { print NR "\t" $0 }' "$1"
}

# Rule A: no direct std file or directory creation in a guarded crate.
scan_guarded_file() {
  local file="$1" found=0 line
  while IFS= read -r line; do
    printf '%s:%s\n' "$file" "${line/$'\t'/: }"
    found=1
  done < <(production_region "$file" |
    grep -E 'File::create\(|OpenOptions::new\(\)|create_dir_all\(' || true)
  return "$found"
}

# Rule B: the helper itself must set the mode in the open, and must
# never chmod by path.
scan_helper() {
  local file="$1" body found=0
  body="$(production_region "$file")"

  if ! grep -q 'options\.mode(OWNER_ONLY_FILE_MODE)' <<<"$body"; then
    echo "$file: the creation mode is never requested in the open" >&2
    found=1
  fi

  local mode_line open_line
  mode_line="$(grep -n 'apply_creation_mode(&mut options)' <<<"$body" | head -1 | cut -d: -f1)"
  open_line="$(grep -n 'options\.open(' <<<"$body" | head -1 | cut -d: -f1)"
  if [ -z "$mode_line" ] || [ -z "$open_line" ] || [ "$mode_line" -ge "$open_line" ]; then
    echo "$file: the mode is not applied before the open (create-then-chmod leaves a window)" >&2
    found=1
  fi

  if grep -q 'fs::set_permissions(' <<<"$body"; then
    echo "$file: path-based set_permissions follows symlinks; chmod the descriptor instead" >&2
    found=1
  fi

  if ! grep -q 'file\.set_permissions(' <<<"$body"; then
    echo "$file: nothing reasserts the mode, so a pre-existing loose file is inherited" >&2
    found=1
  fi

  return "$found"
}

is_exempt() {
  local candidate="$1" entry
  for entry in "${EXEMPT[@]}"; do
    [ "$entry" = "$candidate" ] && return 0
  done
  return 1
}

run_check() {
  local root="$1" failures=0 crate file relative hits

  if [ ! -f "$root/$HELPER" ]; then
    echo "$HELPER is missing; durable sinks have nothing to go through" >&2
    return 1
  fi
  scan_helper "$root/$HELPER" || failures=1

  for crate in "${GUARDED_CRATES[@]}"; do
    [ -d "$root/$crate/src" ] || continue
    while IFS= read -r file; do
      relative="${file#"$root"/}"
      is_exempt "$relative" && continue
      if ! hits="$(scan_guarded_file "$file" 2>&1)"; then
        printf '%s\n' "$hits" >&2
        failures=1
      fi
    done < <(find "$root/$crate/src" -name '*.rs' -type f | sort)
  done

  if [ "$failures" -ne 0 ]; then
    cat >&2 <<'MSG'

Durable sinks must create files through sbproxy_util::secure_fs:

  open_append_owner_only(path)     append-structured sinks
  ensure_file_owner_only(path)     a file another library will open
  create_dir_all_owner_only(path)  state directories this process creates

Each puts the mode in the open(2) call, so the file never exists at a
wider mode, and reasserts it through the descriptor, so a file that was
already there is tightened rather than inherited.
MSG
    return 1
  fi

  echo "durable sinks all go through sbproxy_util::secure_fs"
  return 0
}

# A detector that stopped detecting reads exactly like a clean tree, so
# the rules are run against fixtures that must fail.
self_test() {
  local scratch status failures=0
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-durable-modes-selftest.XXXXXX")"
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

  # Rule A: a guarded file that opens its own file must be refused, and
  # the same file with the helper call must pass.
  mkdir -p "$scratch/bad"
  cat >"$scratch/bad/sink.rs" <<'EOF'
pub fn open(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().create(true).append(true).open(path)
}
EOF
  expect "a bare OpenOptions is refused" 1 scan_guarded_file "$scratch/bad/sink.rs"

  cat >"$scratch/bad/good.rs" <<'EOF'
pub fn open(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    sbproxy_util::secure_fs::open_append_owner_only(path)
}
EOF
  expect "a converted sink passes" 0 scan_guarded_file "$scratch/bad/good.rs"

  # A test module that pre-creates a loose fixture must not trip it.
  cat >"$scratch/bad/tested.rs" <<'EOF'
pub fn open(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    sbproxy_util::secure_fs::open_append_owner_only(path)
}

#[cfg(test)]
mod tests {
    #[test]
    fn seeds_a_loose_fixture() {
        let _ = std::fs::File::create("/tmp/x");
    }
}
EOF
  expect "a test-module fixture is not a violation" 0 scan_guarded_file "$scratch/bad/tested.rs"

  # Rule B: create-then-chmod is the window this whole change is about.
  cat >"$scratch/bad/window.rs" <<'EOF'
fn open_with_mode(mut options: std::fs::OpenOptions, path: &Path) -> io::Result<File> {
    let file = options.open(path)?;
    apply_creation_mode(&mut options);
    file.set_permissions(std::fs::Permissions::from_mode(OWNER_ONLY_FILE_MODE))?;
    Ok(file)
}
fn apply_creation_mode(options: &mut std::fs::OpenOptions) {
    options.mode(OWNER_ONLY_FILE_MODE);
}
EOF
  expect "chmod after open is refused" 1 scan_helper "$scratch/bad/window.rs"

  # Rule B: a path-based chmod can be redirected through a symlink.
  cat >"$scratch/bad/bypath.rs" <<'EOF'
fn open_with_mode(mut options: std::fs::OpenOptions, path: &Path) -> io::Result<File> {
    apply_creation_mode(&mut options);
    let file = options.open(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    file.set_permissions(std::fs::Permissions::from_mode(OWNER_ONLY_FILE_MODE))?;
    Ok(file)
}
fn apply_creation_mode(options: &mut std::fs::OpenOptions) {
    options.mode(OWNER_ONLY_FILE_MODE);
}
EOF
  expect "a path-based chmod is refused" 1 scan_helper "$scratch/bad/bypath.rs"

  # Rule B: no reassertion means a pre-existing loose file is inherited.
  cat >"$scratch/bad/inherits.rs" <<'EOF'
fn open_with_mode(mut options: std::fs::OpenOptions, path: &Path) -> io::Result<File> {
    apply_creation_mode(&mut options);
    options.open(path)
}
fn apply_creation_mode(options: &mut std::fs::OpenOptions) {
    options.mode(OWNER_ONLY_FILE_MODE);
}
EOF
  expect "no reassertion is refused" 1 scan_helper "$scratch/bad/inherits.rs"

  expect "the shipped helper passes" 0 scan_helper "$ROOT_DIR/$HELPER"

  if [ "$failures" -ne 0 ]; then
    echo "self-test failed: the detector is narrower than the enforcer" >&2
    return 1
  fi
  echo "self-test passed: 7 fixtures"
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
