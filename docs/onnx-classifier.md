# ONNX classifier

*Last modified: 2026-04-26*

The `sbproxy-classifiers` crate exposes a pure-Rust ONNX inference path
plus a Hugging Face tokenizer wrapper. Detectors that need a learned
model (currently the `prompt_injection_v2` `onnx` detector) embed it
behind the existing trait surface, so the policy code is unchanged.

## Why pure Rust?

The crate uses `tract-onnx`, not the C++ ONNX Runtime. Trade-offs:

- No system libraries to link. Builds clean in containers, on musl,
  and across the cross-compile matrix the rest of the workspace
  already targets.
- Inference is slower than the C++ runtime. Acceptable for the small
  classifier models used here (a few hundred BPE tokens, low-millisecond
  forward pass).
- The interpreter is permissively licensed (Apache-2.0 / MIT) and ships
  no telemetry.

## Selecting the detector

Reference the detector by name in a `prompt_injection_v2` policy:

```yaml
policies:
  - type: prompt_injection_v2
    detector: onnx
    detector_config:
      model_url: https://example.com/your-model.onnx
      tokenizer_url: https://example.com/your-tokenizer.json
      # SHA-256 pinning is strongly recommended.
      model_sha256: 8e1c...
      tokenizer_sha256: 3d20...
      cache_dir: /var/cache/sbproxy/models
      threshold: 0.5
      labels: [benign, injection]
      injection_label: injection
```

Fields:

- `model_url`, `tokenizer_url` - HTTPS URLs for the ONNX file and the
  Hugging Face `tokenizer.json`.
- `model_sha256`, `tokenizer_sha256` - hex-encoded SHA-256 hashes for
  pinning. Either set both or neither. Mixed pinning is rejected at
  load time so partial validation can never sneak in.
- `cache_dir` - where downloads land. Defaults to the platform cache
  dir (`$XDG_CACHE_HOME/sbproxy/models/` on Linux,
  `~/Library/Caches/sbproxy/models/` on macOS).
- `threshold` - score in `[0.0, 1.0]` at which the policy reports
  `Injection`. Below the threshold but at least 0.3, the policy
  reports `Suspicious`. Below 0.3 it reports `Clean`.
- `labels` - optional vocabulary indexed by softmax output. When omitted
  the model reports `class_<n>`.
- `injection_label` - which model label means "this is an injection".
  Defaults to `injection`. Comparison is case-insensitive.

## Cache + offline behaviour

`download_and_load` writes to `cache_dir` keyed by the URL hash. On
restart the cached file is reused without touching the network. When
`*_sha256` is set, the cached file is re-validated on every load; if
the hash drifts the file is removed and re-downloaded.

If model loading fails for any reason - DNS error, 404, malformed
ONNX file, hash mismatch - the policy falls back to the heuristic
detector and logs a `tracing::warn!`. The fallback contract is hard:
the proxy keeps serving traffic and the policy is still in force, just
with a weaker detector. Operators who want a hard failure on missing
models should health-check the configured URL out of band.

## Security posture

- **HTTPS only.** The download client trusts the system trust store.
  Self-signed CAs are not supported; do not work around this by
  patching the client. Host the model on a CDN with public TLS or
  serve it from a private endpoint behind your own load balancer.
- **Pin hashes.** Without `model_sha256` + `tokenizer_sha256` the
  detector accepts whatever the URL returns. Pinning is the only
  defence against a compromised mirror swapping the model.
- **Offline only after first sync.** The detector cannot bootstrap
  itself in an air-gapped environment without seed files. Operators
  with strict outbound policies should pre-stage the cache directory
  and skip the download.

## Tests + fixtures

Unit tests in `crates/sbproxy-classifiers/tests/` cover the load
failure path, SHA-256 validation, and softmax. A future fixture model
(see `crates/sbproxy-classifiers/scripts/build_fixture_model.py`) will
let us exercise the full classify path without a real model. Until
that fixture is committed, end-to-end behaviour is exercised in the
eval harness at `eval/prompt_injection/` against an operator-supplied
model.

## What's deferred

- A real classifier model file pinned in CI. The detector ships, but
  the precision / recall lift to >=0.9 on the OWASP-LLM-01 corpus is
  tracked separately and gated on a model selection / fine-tuning
  pass.
- Body-aware detection inside `ai_proxy`. The current integration
  scores prompts that arrive through the policy pipeline; richer
  request body parsing for Anthropic / OpenAI / etc. lives behind a
  follow-up card.
