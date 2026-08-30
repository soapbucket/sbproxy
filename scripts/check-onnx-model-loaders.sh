#!/usr/bin/env bash
# Reject the two tract entry points that load an ONNX model without our
# external-tensor-data refusal (WOR-2694, GHSA-h668-6x6g-f8r5).
#
# # Why this exists
#
# An ONNX `TensorProto` can set `data_location: EXTERNAL` and name a file in
# its `external_data` `location` entry. `tract-onnx` resolves that value
# against the model's directory, and up to 0.21.16 it did so with
# `PathBuf::from(dir).join(location)` and no containment check of any kind.
# `Path::join` with an absolute argument discards the base, so a model
# carrying `location: "/etc/ssl/private/server.key"` reads that file and
# materializes its bytes as a tensor the graph can route to an output. That is
# an arbitrary file read, and it is reachable here: operators point sbproxy at
# ONNX files they did not author.
#
# `Framework::model_for_path` and `Framework::model_for_read` do the parse and
# the translation in one call, so there is no point between them at which a
# caller can refuse. `model_for_path` also hands tract the model's directory,
# which is the state the vulnerable resolution needs. The shape every loader
# in this workspace uses instead is three steps:
#
#   let onnx = tract_onnx::onnx();
#   let proto = onnx.proto_model_for_path(path)?;
#   sbproxy_classifiers::reject_external_tensor_data(&proto)?;   // where available
#   let model = onnx.model_for_proto_model(&proto)?;
#
# `model_for_proto_model` passes no model directory, so tract refuses external
# data on its own. That refusal is the layer every loader has, and it is the
# one this script enforces.
#
# The explicit `reject_external_tensor_data` walk is a second layer, and only
# crates that already depend on `sbproxy-classifiers` run it.
# `sbproxy-agent-detect` does not: it is a foundational crate, and depending on
# the classifier crate to share one function would pull tonic, reqwest, and the
# AI stack into it. Its loader has the translation layer alone, which is stated
# here rather than left for a reader to assume.
#
# The guard is a grep because the property is syntactic: there is no type that
# can express "this call site refused first", and a test can only cover the
# loaders that exist today. Grep covers the ones nobody has written yet, which
# is the failure this is actually guarding against.
#
# `model_for_path` and `model_for_read` are wrappers. The primitive underneath
# is `Onnx::parse` / `Onnx::parse_with_template`, both `pub` in tract 0.21.10
# (`model.rs:236`, `:239`), which take `model_dir: Option<&str>` directly, and
# `ParsingContext`, which is `pub` with a `pub model_dir` field. Any of those
# reintroduces the vector without ever naming `model_for_path`, so they are
# banned too. Nothing in the workspace calls them today; the point is the
# loader nobody has written yet.
#
# The scan runs in two tiers, because the names differ in how ambiguous they
# are.
#
# Tier 1, every source root: `model_for_path`, `model_for_read`,
# `parse_with_template`, `ParsingContext`. These are tract-specific spellings
# that mean nothing else in this workspace, so they are matched bare. No
# leading `.` is required, which catches the UFCS forms
# `Onnx::parse_with_template(...)`; and `ParsingContext` is matched as an
# identifier rather than only in its one-line struct-literal form.
#
# Tier 2, only files that name `tract_onnx` / `tract_core` / `tract_ndarray`:
# the method-call form `.parse(` and the UFCS form `Onnx::parse(`. Bare
# `parse` is far too common in Rust to ban everywhere, but inside a file that
# already reaches for tract it is worth a build failure. Measured before
# choosing: those files contain zero `.parse(` method calls today, and the two
# `parse(` calls they do contain are `SidecarDetector::parse(...)`, a UFCS
# call on a type that is not `Onnx`, so tier 2 does not match them.
#
# Tier 2 also flags the *safe* `parse(&proto, None)`. That is deliberate: this
# workspace translates with `model_for_proto_model`, so a bare `parse` call is
# a thing to look at even when its directory argument is `None` today, and one
# character turns it into the vulnerable form. Failing closed on it costs a
# build, and the message says which shape to use instead.
#
# An earlier version required a `Some` token in the argument list. That was
# wrong in both directions and is why this rewrite exists. It missed
#
#   let dir: Option<&str> = model_path.parent().and_then(|p| p.to_str());
#   let model = onnx.parse(&proto, dir)?.model;
#
# which is exactly what tract's own `model_for_path` does
# (`tract-onnx-0.21.10/src/model.rs:294-301`) and therefore the most likely
# accidental reintroduction, not the least. And it fired on any unrelated
# `.parse(x, Some(y))`. Keying on the receiver's file rather than on the
# argument shape fixes both.
#
# `proto_model_for_path` and `proto_model_for_read` are the allowed forms and
# are not matched: tier 1 requires a character that is not `_` before the
# name, and those two carry `proto_` immediately before it.
#
# # What this cannot see
#
# It is a line-oriented grep, and the limits are real rather than theoretical:
#
#   * A call reaching tract through a re-export or type alias under another
#     name, in a file that never spells `tract_*`. Tier 2 would not scan it and
#     tier 1 would not recognize the name.
#   * A `parse` invoked through a generic or a trait object, where no receiver
#     name appears at the call site.
#   * Anything generated by a macro.
#   * A model directory reaching `ParsingContext` by field assignment far from
#     any line this matches.
#
# So the guarantee is narrower than "every ONNX load is safe": it is that no
# line in the scanned roots spells one of the known directory-taking entry
# points. The tests in `crates/sbproxy-classifiers/tests/external_data_refusal.rs`
# and `crates/sbproxy-agent-detect/tests/external_data_refusal.rs` are what
# cover the loaders that exist; this covers the one nobody has written yet, in
# the shapes a grep can see. Its success message says exactly that and no more.
#
# # Usage
#
#   scripts/check-onnx-model-loaders.sh   # exit 1 on any violation

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VIOLATIONS=0

# Whole-line comments are skipped so the doc comments above can name these
# functions. A call after code on the same line, including one behind a
# trailing `//`, is still reported. That fails closed: it costs a build rather
# than missing a vector, and commenting a call out is not a reason to keep the
# line.
while IFS=: read -r file line text; do
  trimmed="${text#"${text%%[![:space:]]*}"}"
  case "$trimmed" in
    //*) continue ;;
  esac
  if [[ "$VIOLATIONS" -eq 0 ]]; then
    printf 'ONNX model loaded without the external-tensor-data refusal:\n\n' >&2
  fi
  printf '  %s:%s: %s\n' "$file" "$line" "$trimmed" >&2
  VIOLATIONS=$((VIOLATIONS + 1))
done < <(
  ROOTS=(crates/ e2e/ fuzz/ sbproxy-bench/ bench-synthetic/ examples/ test/)

  # Tier 1: tract-specific spellings, everywhere, matched bare.
  grep -rn --include='*.rs' -E \
    '[^_[:alnum:]]model_for_(path|read)[[:space:]]*\(|[^_[:alnum:]]parse_with_template[[:space:]]*\(|[^_[:alnum:]]ParsingContext[^_[:alnum:]]' \
    "${ROOTS[@]}" 2>/dev/null || true

  # Tier 2: the ambiguous `parse`, only where tract is already in scope.
  TRACT_FILES=$(grep -rl --include='*.rs' -E 'tract_onnx|tract_core|tract_ndarray' \
    "${ROOTS[@]}" 2>/dev/null || true)
  if [[ -n "$TRACT_FILES" ]]; then
    printf '%s\n' "$TRACT_FILES" \
      | xargs grep -nE '\.parse[[:space:]]*\(|Onnx::parse[[:space:]]*\(' 2>/dev/null || true
  fi
)

if [[ "$VIOLATIONS" -gt 0 ]]; then
  printf '\n%s call site(s) hand a model file straight to tract.\n' "$VIOLATIONS" >&2
  printf 'Parse the protobuf first, refuse external tensor data, then translate:\n' >&2
  printf '\n' >&2
  printf '  let onnx = tract_onnx::onnx();\n' >&2
  printf '  let proto = onnx.proto_model_for_path(path)?;\n' >&2
  printf '  sbproxy_classifiers::reject_external_tensor_data(&proto)?;  // where available\n' >&2
  printf '  let model = onnx.model_for_proto_model(&proto)?;\n' >&2
  printf '\n' >&2
  printf 'The same applies to tract Onnx::parse / parse_with_template and a\n' >&2
  printf 'hand-built ParsingContext: pass no model directory.\n' >&2
  printf '\n' >&2
  printf 'See crates/sbproxy-classifiers/src/onnx_external_data.rs and\n' >&2
  printf 'docs/model-pinning.md for the seam and GHSA-h668-6x6g-f8r5.\n' >&2
  exit 1
fi

printf 'onnx-model-loaders check: no line in the scanned roots names a\n'
printf 'directory-taking tract entry point. See the header for what a\n'
printf 'line-oriented grep cannot see.\n'
