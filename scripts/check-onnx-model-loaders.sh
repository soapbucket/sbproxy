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
# `.parse(` alone is far too common in Rust to ban, so the pattern requires a
# `Some` in the argument list, which is the only shape that supplies a
# directory. `parse(proto, None, ...)` is the safe form and is not matched.
#
# `proto_model_for_path` and `proto_model_for_read` are the allowed forms and
# are not matched: the pattern requires a character that is not `_` before the
# name, and those two carry `proto_` immediately before it.
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
done < <(grep -rn --include='*.rs' -E \
  '[^_[:alnum:]]model_for_(path|read)[[:space:]]*\(|\.parse_with_template[[:space:]]*\(|\.parse[[:space:]]*\([^)]*Some|ParsingContext[[:space:]]*\{' \
  crates/ e2e/ fuzz/ sbproxy-bench/ bench-synthetic/ examples/ test/ 2>/dev/null || true)

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

printf 'onnx-model-loaders check: no call site hands tract a model directory.\n'
