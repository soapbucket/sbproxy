#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
model_path="${SBPROXY_CENTROID_MODEL_PATH:-${HOME}/.cache/sbproxy/models/minilm/model.onnx}"
tokenizer_path="${SBPROXY_CENTROID_TOKENIZER_PATH:-${HOME}/.cache/sbproxy/models/minilm/tokenizer.json}"
artifact_path="${workspace_dir}/crates/sbproxy-classifiers/artifacts/default-safety-centroids-v1.json"
digest_path="${workspace_dir}/crates/sbproxy-classifiers/artifacts/default-safety-centroids-v1.sha256"
report_path="${workspace_dir}/docs/ai-default-centroids-evaluation.md"
training_path="${workspace_dir}/crates/sbproxy-classifiers/fixtures/default-safety-centroids-training.json"
evaluation_path="${workspace_dir}/crates/sbproxy-classifiers/fixtures/default-safety-centroids-evaluation.json"
mode="${1:---check}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
generated_artifact="${tmp_dir}/default-safety-centroids-v1.json"
generated_report="${tmp_dir}/ai-default-centroids-evaluation.md"

artifact_sha256="$(
  cd "${workspace_dir}"
  cargo run --quiet -p sbproxy-classifiers \
    --example regenerate-default-safety-centroids -- \
    "${model_path}" "${tokenizer_path}" "${training_path}" "${evaluation_path}" \
    "${generated_artifact}" "${generated_report}"
)"

case "${mode}" in
  --write)
    cp "${generated_artifact}" "${artifact_path}"
    printf '%s\n' "${artifact_sha256}" > "${digest_path}"
    cp "${generated_report}" "${report_path}"
    ;;
  --check)
    cmp "${generated_artifact}" "${artifact_path}"
    cmp <(printf '%s\n' "${artifact_sha256}") "${digest_path}"
    cmp "${generated_report}" "${report_path}"
    ;;
  *)
    printf 'usage: %s [--check|--write]\n' "$0" >&2
    exit 2
    ;;
esac
