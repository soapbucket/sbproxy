# ONNX classifier

*Last modified: 2026-05-08*

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
      # Optional supply-chain hardening (see "Supply-chain hardening"
      # below). All four settings are independent of the SHA pins.
      model_signature_url: https://example.com/your-model.onnx.sig
      tokenizer_signature_url: https://example.com/your-tokenizer.json.sig
      model_pubkey_path: /etc/sbproxy/classifier-signer.pub
      max_model_bytes: 209715200
      max_tokenizer_bytes: 209715200
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
- `model_signature_url`, `tokenizer_signature_url` - optional URLs of
  detached Ed25519 signatures over each artifact. Either set both or
  neither; mixed signature config is rejected at load time, the same
  way mixed hash pinning is. The signature payload is signed
  `SHA-256(artifact_bytes)`, so the verification step uses bounded
  memory regardless of model size. Signatures may be served as raw 64
  bytes, base64, or hex; whichever decodes to a 64-byte Ed25519
  signature wins.
- `model_pubkey` / `model_pubkey_path` - operator-supplied Ed25519
  verifying key. Set exactly one when the signature URL pair is set.
  `model_pubkey` accepts an inline PEM `PUBLIC KEY` block (the
  standard `openssl genpkey -algorithm Ed25519 -outform PEM -pubout`
  output) or a 64-character hex of the raw 32-byte key.
  `model_pubkey_path` reads the same content from a file. The same
  key verifies both the model and the tokenizer signature.
- `max_model_bytes`, `max_tokenizer_bytes` - hard upper bound on each
  artifact in bytes. Defaults to 200 MiB (`209715200`). A file that
  exceeds the limit is a hard error at load time, not a warning. Set
  to 0 only when you have an out-of-band reason to trust an oversized
  artifact; the budget is the cheapest line of defence against a
  hostile origin trying to exhaust the cache disk.
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

## Supply-chain hardening

Three load-time guards harden the path from "model file on a CDN" to
"model loaded into the proxy":

1. **SHA-256 pinning.** The historic story; documented above. Pinning
   is the single most important guard against a compromised mirror
   silently swapping the model.
2. **Size budget.** Every artifact is rejected at load time if it
   exceeds the configured ceiling. A runaway download stops at the
   ceiling rather than filling the cache disk and OOM-killing tract.
   The default of 200 MiB matches the budget the enterprise
   classifier ships with and is generous for the small DeBERTa-base
   class of models the OSS detector is designed for.
3. **Detached signature verification.** When configured, every
   artifact is fetched alongside a detached Ed25519 signature, and
   the signature is verified against an operator-supplied public key
   before tract or tokenizers ever sees the bytes. This catches the
   case where the operator does not yet have a SHA-256 pin (a fresh
   model) but does have a long-lived signing key on an out-of-band
   path.

The trust model is OPERATOR-trusted, not vendor-trusted: the OSS
crate ships no built-in vendor key. Operators that turn on signature
verification supply their own key, rotate it themselves, and store
it in their own secret material. See
[`adr-classifier-supply-chain-oss.md`](adr-classifier-supply-chain-oss.md)
for the full rationale and how this differs from the enterprise
vendor-key path.

### Worked example: signing a custom model

```bash
# 1. Generate a long-lived signer key. Keep the private key in your
#    secret store (Vault, Secrets Manager, etc.) and check the public
#    key in alongside the proxy config.
openssl genpkey -algorithm Ed25519 -out signer.priv
openssl pkey -in signer.priv -pubout -out signer.pub

# 2. Sign each artifact. The signature is over SHA-256 of the file,
#    so the signing step is constant-memory.
sha_then_sign() {
  openssl dgst -sha256 -binary "$1" \
    | openssl pkeyutl -sign -inkey signer.priv -rawin \
    > "$1.sig"
}
sha_then_sign model.onnx
sha_then_sign tokenizer.json

# 3. Publish model.onnx, tokenizer.json, model.onnx.sig,
#    tokenizer.json.sig, and signer.pub to wherever your fleet can
#    reach them. The .pub file is the only piece the proxy config
#    references; the .priv stays in your secret store.
```

The proxy config then references the public key with
`model_pubkey_path: /etc/sbproxy/signer.pub` and the two signature
URLs alongside the existing model URLs.

### Key management guidance

- Treat the signing key like any other long-lived signing material.
  Generate it on a host you control, never paste it into a chat or
  ticket, and rotate on a fixed cadence (annual is fine for a
  classifier signer).
- The OSS crate has no key-rotation protocol. To rotate, generate a
  new key, re-sign existing artifacts, ship the new public key
  alongside the new signatures, and update `model_pubkey_path` on
  every proxy in lockstep with the new artifact URLs.
- Hash-pin AND sign in production. The two checks defend against
  different threats: a hash pin defends against a swapped binary on a
  trusted mirror, a signature defends against an untrusted mirror.
  Both checks are cheap to keep on; there is no reason to drop one
  once the other is in place.
- The OSS crate does not ship a built-in vendor key. If you need a
  vendor-trusted (rather than operator-trusted) supply chain (cosign +
  CI verification + an SBOM emitted alongside each release tag), see
  the enterprise tier description in
  [`enterprise.md`](enterprise.md).

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
  defence against a compromised mirror swapping the model on a path
  you do otherwise trust.
- **Sign artifacts when the mirror is not trusted.** Detached Ed25519
  signatures plus an operator-held verifying key cover the case where
  the mirror itself is in scope of your threat model. Hash pinning and
  signature verification stack: keep both on in production.
- **Size budget on by default.** A 200 MiB ceiling is enforced even
  without explicit config. Operators who need a larger model raise
  `max_model_bytes` / `max_tokenizer_bytes` deliberately.
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
- Vendor signing key + cosign / SLSA + SBOM CycloneDX entry for an
  OSS-shipped model. The OSS detector ships the operator-trusted
  signature path today; the vendor-trusted path lands the day we
  publish a first-party model file, alongside CI verification of the
  signature on every release.
