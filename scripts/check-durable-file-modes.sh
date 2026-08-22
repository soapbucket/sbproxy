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
  crates/sbproxy-keystore
)

# Individual files outside the guarded crates that still own durable,
# sensitive output.
#
# sbproxy-core is deliberately not guarded whole. It creates directories
# for extension bundles and writes a throwaway probe file to decide
# whether a state directory is writable, and neither is a secret; a
# blanket rule there would be mostly exemptions, and an exemption list
# longer than the rule stops being read.
#
# What that means this script cannot see: a NEW durable secret sink added
# to sbproxy-core, or to any crate not listed above, is invisible to it.
# The rule is only as wide as these two lists, and widening them is part
# of adding a sink, not a follow-up.
GUARDED_FILES=(
  # The key plane creates the directory holding the redb database of
  # encrypted upstream credentials.
  "crates/sbproxy-core/src/key_plane.rs"
)

# Embedded databases create their own files. redb's `Database::create`
# and rusqlite's `Connection::open*` both call `File::create` inside the
# library, at `0o666` masked by the umask, so Rule A cannot see them:
# the guarded crate never names a std file API at all. The only thing a
# caller can do is create the file owner-only first and let the library
# open what is already there.
DB_CONSTRUCTORS='Database::create\(|Connection::open(_with_flags)?\('

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

# Production code only. A test that pre-creates a fixture at `0o644` to
# prove the tightening works is exactly what this change added, so the
# test code has to come out before the rules run.
#
# The first version of this stopped at the first column-zero
# `#[cfg(test)]` and treated everything after it as test code. That is
# true of the trailing `mod tests`, and false of a `#[cfg(test)]`
# *helper* sitting among the production items, which several files in
# this workspace have. The cost was not theoretical: it truncated
# `value_ledger.rs` at line 90 and `key_plane.rs` at line 754, which
# put the redb `Database::create` this change exists to protect, and
# the one directory in GUARDED_FILES, outside the scanned region. Both
# read as covered and neither was; deleting either fix left the script
# green.
#
# So a `#[cfg(test)] mod` still ends the production region, because
# that is the trailing test module by convention, and any other
# `#[cfg(test)]` item is skipped by brace balance and scanning
# continues after it. Items that carry no brace (`#[cfg(test)] use
# ...;`) end at their semicolon.
production_region() {
  awk '
    /^#\[cfg\(test\)\]/ || /^#\[cfg\(all\(test/ { pending = 1; next }
    pending {
      pending = 0
      if ($0 ~ /^(pub(\([^)]*\))? )?mod /) { exit }
      skipping = 1; depth = 0; opened = 0
    }
    skipping {
      n = gsub(/\{/, "{"); m = gsub(/\}/, "}")
      if (n > 0) opened = 1
      depth += n - m
      if (opened && depth <= 0) skipping = 0
      else if (!opened && $0 ~ /;[[:space:]]*$/) skipping = 0
      next
    }
    { print NR "\t" $0 }
  ' "$1"
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

# Rule C: a path handed to an embedded database constructor must be
# pre-created owner-only, and the pre-creation must come first.
#
# The ordering is checked by line number within the production region.
# What this does NOT prove is that the two calls name the same path: a
# file that calls `ensure_file_owner_only` on one path and opens a
# database at another passes. Proving that needs dataflow this script
# does not have, so the narrower claim is the honest one.
scan_db_constructors() {
  local file="$1" body found=0 ensure_line db_line
  body="$(production_region "$file")"

  grep -qE "$DB_CONSTRUCTORS" <<<"$body" || return 0

  db_line="$(grep -nE "$DB_CONSTRUCTORS" <<<"$body" | head -1 | cut -d: -f1)"
  ensure_line="$(grep -n 'ensure_file_owner_only(' <<<"$body" | head -1 | cut -d: -f1)"

  if [ -z "$ensure_line" ]; then
    echo "$file: hands a path to an embedded database constructor without creating it owner-only first; the library calls File::create at 0o666 masked by the umask" >&2
    found=1
  elif [ "$ensure_line" -ge "$db_line" ]; then
    echo "$file: creates the database before making it owner-only, which leaves it world-readable in between" >&2
    found=1
  fi

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
      if ! hits="$(scan_db_constructors "$file" 2>&1)"; then
        printf '%s\n' "$hits" >&2
        failures=1
      fi
    done < <(find "$root/$crate/src" -name '*.rs' -type f | sort)
  done

  for relative in "${GUARDED_FILES[@]}"; do
    file="$root/$relative"
    [ -f "$file" ] || { echo "$relative is guarded but missing" >&2; failures=1; continue; }
    if ! hits="$(scan_guarded_file "$file" 2>&1)"; then
      printf '%s\n' "$hits" >&2
      failures=1
    fi
    if ! hits="$(scan_db_constructors "$file" 2>&1)"; then
      printf '%s\n' "$hits" >&2
      failures=1
    fi
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

  # A `#[cfg(test)]` helper among the production items must not end the
  # scan. Stopping there is what hid `value_ledger.rs` and
  # `key_plane.rs` from the rules that were supposed to cover them.
  cat >"$scratch/bad/helper_first.rs" <<'EOF'
#[cfg(test)]
fn seed_for_test(path: &std::path::Path) {
    let _ = std::fs::File::create(path);
}

pub fn open(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().create(true).append(true).open(path)
}
EOF
  expect "a test helper does not hide the production sink after it" 1 \
    scan_guarded_file "$scratch/bad/helper_first.rs"

  cat >"$scratch/bad/helper_first_db.rs" <<'EOF'
#[cfg(test)]
fn seed_for_test(path: &std::path::Path) {
    let _ = std::fs::File::create(path);
}

fn open(path: &Path) -> anyhow::Result<Database> {
    let database = Database::create(path)?;
    Ok(database)
}
EOF
  expect "a test helper does not hide the database after it" 1 \
    scan_db_constructors "$scratch/bad/helper_first_db.rs"

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

  # Rule C: an embedded database creates its own file, so Rule A's std
  # patterns never fire and only this rule stands between the ledger and
  # a 0o644 default.
  cat >"$scratch/bad/redb.rs" <<'EOF'
fn open(path: &Path) -> anyhow::Result<Database> {
    let database = Database::create(path)?;
    Ok(database)
}
EOF
  expect "an unprotected redb create is refused" 1 scan_db_constructors "$scratch/bad/redb.rs"

  cat >"$scratch/bad/redb_ordered.rs" <<'EOF'
fn open(path: &Path) -> anyhow::Result<Database> {
    sbproxy_util::secure_fs::ensure_file_owner_only(path)?;
    let database = Database::create(path)?;
    Ok(database)
}
EOF
  expect "a pre-created redb file passes" 0 scan_db_constructors "$scratch/bad/redb_ordered.rs"

  cat >"$scratch/bad/redb_late.rs" <<'EOF'
fn open(path: &Path) -> anyhow::Result<Database> {
    let database = Database::create(path)?;
    sbproxy_util::secure_fs::ensure_file_owner_only(path)?;
    Ok(database)
}
EOF
  expect "tightening after the create is refused" 1 scan_db_constructors "$scratch/bad/redb_late.rs"

  cat >"$scratch/bad/sqlite.rs" <<'EOF'
fn open(path: &Path) -> anyhow::Result<Connection> {
    let connection = Connection::open_with_flags(path, flags)?;
    Ok(connection)
}
EOF
  expect "an unprotected sqlite open is refused" 1 scan_db_constructors "$scratch/bad/sqlite.rs"

  cat >"$scratch/bad/nodb.rs" <<'EOF'
fn helper(path: &Path) -> anyhow::Result<()> {
    sbproxy_util::secure_fs::open_append_owner_only(path)?;
    Ok(())
}
EOF
  expect "a file with no database constructor is not judged" 0 scan_db_constructors "$scratch/bad/nodb.rs"

  if [ "$failures" -ne 0 ]; then
    echo "self-test failed: the detector is narrower than the enforcer" >&2
    return 1
  fi
  echo "self-test passed: 14 fixtures"
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
