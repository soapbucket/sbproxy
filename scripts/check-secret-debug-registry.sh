#!/usr/bin/env bash
# Types that hold a reusable credential do not derive `Debug`
# (WOR-2640).
#
# # Why this exists
#
# Sixteen types held a plaintext credential behind a derived `Debug`,
# so any `{:?}` printed it in full: an AWS secret access key, an Entra
# client secret, a Vault token, a minted virtual key. Fixing sixteen
# does not keep them fixed. Deleting one hand-written `impl Debug` and
# putting `Debug` back in the derive is a one-line change that compiles,
# passes clippy, and reads in review like tidying, and the only thing
# that notices is a test somebody has to remember to keep.
#
# So the registry is the thing that remembers. Every line in
# `scripts/secret-debug-registry.txt` names a type, and this script
# refuses a tree where that type has
#
#   1. regained `Debug` in its `#[derive(...)]`,
#   2. lost its hand-written `impl std::fmt::Debug`, or
#   3. lost the test that pushes a sentinel through it.
#
# All three, because each alone is defeatable: the derive can come back
# alongside a dead impl, the impl can be deleted while the derive stays
# absent (which does not compile, but says so late and confusingly),
# and either can be changed while a test that only asserts the type
# name still passes.
#
# # Why there are no exemptions
#
# A line here says somebody decided a `{:?}` must not print this value.
# There is no version of "except sometimes". Removing a line is
# removing a protection, and the only honest reason is that the type is
# gone, which this script reports as a missing declaration rather than
# accepting silently.
#
# # What this cannot see
#
# A *new* secret-bearing type that never gets a line. Nothing derives
# the list from the code, because "this field holds a credential" is a
# judgment about meaning rather than a pattern: `Challenge.token` and
# `max_tokens` and `tokens_per_minute` all match every field-name
# heuristic worth writing, and a guard whose output is mostly false
# positives stops being read. Adding the line is part of adding the
# type, the same way adding a metric means adding it to the metric
# registry.
#
# # Usage
#
#   scripts/check-secret-debug-registry.sh              # exit 1 on any violation
#   scripts/check-secret-debug-registry.sh --self-test  # prove the detector detects

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY="$ROOT_DIR/scripts/secret-debug-registry.txt"

# Does `file` declare `type` with a `#[derive(...)]` containing `Debug`?
#
# The derive is looked for in the contiguous attribute block directly
# above the declaration, walking back over doc comments and other
# attributes, so a `#[derive(Debug)]` on an unrelated item earlier in
# the file is not read as this type's.
derives_debug() {
  local file="$1" type="$2"
  awk -v want="$type" '
    # Remember the most recent contiguous attribute/doc block.
    /^[[:space:]]*#\[/ { block = block "\n" $0; next }
    /^[[:space:]]*\/\/\// { next }
    /^[[:space:]]*$/ { block = ""; next }
    {
      if ($0 ~ ("^(pub(\\([^)]*\\))? )?(struct|enum|union) " want "([ <({]|$)")) {
        if (block ~ /#\[derive\([^)]*\<Debug\>/) { found = 1 }
        if (block ~ /#\[derive\([^)]*Debug[,)]/) { found = 1 }
      }
      block = ""
    }
    END { exit(found ? 0 : 1) }
  ' "$file"
}

# Does `file` declare `type` at all?
declares_type() {
  local file="$1" type="$2"
  grep -qE "^(pub(\([^)]*\))? )?(struct|enum|union) $type([ <({]|\$)" "$file"
}

# Does `file` carry a hand-written Debug impl for `type`?
has_debug_impl() {
  local file="$1" type="$2"
  grep -qE "^impl (std::fmt|fmt)::Debug for $type([ <{]|\$)" "$file"
}

# Does `file` carry the named test function?
has_test() {
  local file="$1" test="$2"
  grep -qE "fn $test\(" "$file"
}

check_entry() {
  local file="$1" type="$2" test="$3" found=0

  if [ ! -f "$file" ]; then
    echo "$file: registered but missing; a registry line whose file is gone is a protection nobody is enforcing" >&2
    return 1
  fi
  if ! declares_type "$file" "$type"; then
    echo "$file: $type is registered but not declared here; delete the registry line only if the type is genuinely gone" >&2
    found=1
  fi
  if derives_debug "$file" "$type"; then
    echo "$file: $type derives Debug again, which prints its credential in every {:?}" >&2
    found=1
  fi
  if ! has_debug_impl "$file" "$type"; then
    echo "$file: $type has no hand-written 'impl std::fmt::Debug', so nothing redacts it" >&2
    found=1
  fi
  if ! has_test "$file" "$test"; then
    echo "$file: $type lost its pinning test '$test'; the redaction is now unproved" >&2
    found=1
  fi
  return "$found"
}

run_check() {
  local root="$1" registry="$2" failures=0 entries=0 line file type test

  if [ ! -f "$registry" ]; then
    echo "$registry is missing; nothing is protected" >&2
    return 1
  fi

  while IFS= read -r line; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    file="$(printf '%s' "$line" | cut -d'|' -f1 | sed 's/[[:space:]]*$//')"
    type="$(printf '%s' "$line" | cut -d'|' -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    test="$(printf '%s' "$line" | cut -d'|' -f3 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [ -z "$file" ] || [ -z "$type" ] || [ -z "$test" ]; then
      echo "$registry: malformed entry '$line'; want '<path> | <Type> | <test fn>'" >&2
      failures=1
      continue
    fi
    entries=$((entries + 1))
    check_entry "$root/$file" "$type" "$test" || failures=1
  done < "$registry"

  if [ "$entries" -eq 0 ]; then
    echo "$registry has no entries; an empty registry passes trivially and protects nothing" >&2
    return 1
  fi

  if [ "$failures" -ne 0 ]; then
    cat >&2 <<'MSG'

A type in scripts/secret-debug-registry.txt holds a reusable credential
and must not print it. Each registered type needs all three of:

  * no `Debug` in its `#[derive(...)]`
  * a hand-written `impl std::fmt::Debug` that redacts the secret and
    keeps the identifier naming what failed
  * a test that pushes a sentinel through it and asserts both halves

MSG
    return 1
  fi

  echo "secret-bearing Debug registry: $entries types, all redacted and pinned"
  return 0
}

# A detector that stopped detecting reads exactly like a clean tree.
self_test() {
  local scratch status failures=0
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-secret-debug-selftest.XXXXXX")"
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

  mkdir -p "$scratch/crates/demo/src"

  # The shape a protected type has.
  cat >"$scratch/crates/demo/src/good.rs" <<'EOF'
/// Doc comment above the derive.
#[derive(Clone, Deserialize)]
pub struct Creds {
    pub secret: String,
    pub id: String,
}

impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Creds").field("id", &self.id).finish()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn debug_never_renders_the_secret() {}
}
EOF
  printf 'crates/demo/src/good.rs | Creds | debug_never_renders_the_secret\n' \
    >"$scratch/registry.txt"
  expect "a protected type passes" 0 run_check "$scratch" "$scratch/registry.txt"

  # 1. The derive comes back.
  cat >"$scratch/crates/demo/src/derived.rs" <<'EOF'
#[derive(Debug, Clone, Deserialize)]
pub struct Creds {
    pub secret: String,
}

impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Creds").finish()
    }
}

fn debug_never_renders_the_secret() {}
EOF
  printf 'crates/demo/src/derived.rs | Creds | debug_never_renders_the_secret\n' \
    >"$scratch/registry.txt"
  expect "a restored derive is refused" 1 run_check "$scratch" "$scratch/registry.txt"

  # The derive at the end of the list, which a naive pattern misses.
  cat >"$scratch/crates/demo/src/derived_last.rs" <<'EOF'
#[derive(Clone, Deserialize, Debug)]
pub struct Creds {
    pub secret: String,
}

impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Creds").finish()
    }
}

fn debug_never_renders_the_secret() {}
EOF
  printf 'crates/demo/src/derived_last.rs | Creds | debug_never_renders_the_secret\n' \
    >"$scratch/registry.txt"
  expect "a trailing Debug in the derive is refused" 1 run_check "$scratch" "$scratch/registry.txt"

  # A `Debug` derive on an unrelated earlier item is not this type's.
  cat >"$scratch/crates/demo/src/neighbour.rs" <<'EOF'
#[derive(Debug, Clone)]
pub struct Unrelated {
    pub label: String,
}

#[derive(Clone)]
pub struct Creds {
    pub secret: String,
}

impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Creds").finish()
    }
}

fn debug_never_renders_the_secret() {}
EOF
  printf 'crates/demo/src/neighbour.rs | Creds | debug_never_renders_the_secret\n' \
    >"$scratch/registry.txt"
  expect "a neighbour's derive is not attributed" 0 run_check "$scratch" "$scratch/registry.txt"

  # 2. The impl is deleted.
  cat >"$scratch/crates/demo/src/noimpl.rs" <<'EOF'
#[derive(Clone)]
pub struct Creds {
    pub secret: String,
}

fn debug_never_renders_the_secret() {}
EOF
  printf 'crates/demo/src/noimpl.rs | Creds | debug_never_renders_the_secret\n' \
    >"$scratch/registry.txt"
  expect "a deleted impl is refused" 1 run_check "$scratch" "$scratch/registry.txt"

  # 3. The pinning test is deleted.
  cat >"$scratch/crates/demo/src/notest.rs" <<'EOF'
#[derive(Clone)]
pub struct Creds {
    pub secret: String,
}

impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Creds").finish()
    }
}
EOF
  printf 'crates/demo/src/notest.rs | Creds | debug_never_renders_the_secret\n' \
    >"$scratch/registry.txt"
  expect "a deleted test is refused" 1 run_check "$scratch" "$scratch/registry.txt"

  # The type itself is gone.
  printf 'crates/demo/src/missing.rs | Creds | debug_never_renders_the_secret\n' \
    >"$scratch/registry.txt"
  expect "a missing file is refused" 1 run_check "$scratch" "$scratch/registry.txt"

  cat >"$scratch/crates/demo/src/renamed.rs" <<'EOF'
#[derive(Clone)]
pub struct Renamed {
    pub secret: String,
}

impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Creds").finish()
    }
}

fn debug_never_renders_the_secret() {}
EOF
  printf 'crates/demo/src/renamed.rs | Creds | debug_never_renders_the_secret\n' \
    >"$scratch/registry.txt"
  expect "a renamed type is refused" 1 run_check "$scratch" "$scratch/registry.txt"

  # An empty registry must not pass trivially.
  printf '# only a comment\n' >"$scratch/registry.txt"
  expect "an empty registry is refused" 1 run_check "$scratch" "$scratch/registry.txt"

  # A malformed line is refused rather than skipped.
  printf 'crates/demo/src/good.rs | Creds\n' >"$scratch/registry.txt"
  expect "a malformed entry is refused" 1 run_check "$scratch" "$scratch/registry.txt"

  if [ "$failures" -ne 0 ]; then
    echo "self-test failed: the detector is narrower than the enforcer" >&2
    return 1
  fi
  echo "self-test passed: 10 fixtures"
  return 0
}

case "${1:-}" in
  --self-test)
    self_test
    ;;
  *)
    self_test >/dev/null
    run_check "$ROOT_DIR" "$REGISTRY"
    ;;
esac
