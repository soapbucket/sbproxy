# ADR: OSS classifier supply chain (operator-trusted)

*Last modified: 2026-05-08*

## Status

Accepted. Implemented in WOR-146 ("land now" portion). The "land when
shipping a model" tasks (vendor signing key, SBOM CycloneDX entry,
cosign / SLSA, CI verification of the signature on every release) are
deferred until a first-party OSS classifier model ships.

## Context

`crates/sbproxy-classifiers` is the OSS path for ONNX-backed
classifiers used by detectors like `prompt_injection_v2`. It uses the
pure-Rust `tract-onnx` runtime and downloads model + tokenizer files
on first run, caching them on disk. The enterprise classifier
(WOR-35) closed its supply-chain story around vendor signing, an
SBOM entry, a 200 MB size budget, and a documented update procedure.
The OSS half stayed open: SHA-256 pinning was supported, but there
was no signature path, no enforced size budget, and no documented key
or update story.

Two things constrain the OSS design:

1. **No vendor key.** The OSS crate is source-available under BSL 1.1
   and is built by anyone who can run `cargo`. It cannot meaningfully
   carry a hard-coded vendor key the way the enterprise tier can; an
   attacker who can rebuild the crate can also overwrite the key.
2. **No first-party OSS model yet.** The detector ships, but the
   operator points it at a model URL of their choosing
   (typically a Hugging Face mirror). A vendor-trusted signature
   chain only makes sense once we publish a model under our own
   release process.

We need a guard rail today that an operator who does not trust the
mirror can use, without claiming a property (vendor trust) we cannot
deliver in OSS.

## Decision

Adopt an **operator-trusted** supply-chain model for the OSS
classifier:

- Enforce a default 200 MB size budget on both the ONNX file and the
  tokenizer file at load time. Configurable via `max_model_bytes` /
  `max_tokenizer_bytes`. Hard error, not a warning. Mirrors the
  enterprise budget so the two paths report the same shape of failure
  on a runaway artifact.
- Add an optional Ed25519 detached-signature verification path,
  activated by setting `model_signature_url` +
  `tokenizer_signature_url` and one of `model_pubkey` /
  `model_pubkey_path`. The signature is taken over `SHA-256(artifact)`
  so memory stays bounded for arbitrarily large models.
- Apply the existing all-or-nothing rule (both URLs or neither) to
  the signature URL pair, the same way the SHA-256 pin rule already
  works. Half-configured signature paths are a hard error.
- Keep the trust model operator-trusted: no built-in vendor key in
  OSS, no implicit fallback, no vendored public key bundle. The
  operator brings their own key and rotates it themselves.

### Why operator-trusted, not vendor-trusted

| Concern | OSS (today) | Enterprise |
|---|---|---|
| Trust root | Operator key, rotated by operator. | Soap Bucket signing key, rotated on a published cadence. |
| Model file | Operator-supplied URL (Hugging Face, private CDN, etc.). | Vendor-shipped artifact pinned to a release tag. |
| Signature path | Optional; SHA pin remains the default for operators that trust the mirror. | Mandatory; CI verifies the signature on every release. |
| SBOM | Not emitted today. The OSS classifier currently has no model bundled in. | CycloneDX entry covers the classifier weights. |
| Update procedure | Operator-driven; documented in `onnx-classifier.md`. | Vendor-driven; tied to release notes. |

The split is intentional: OSS gives operators a real guard rail that
matches their threat model (untrusted mirror, trusted local key
material) without overclaiming vendor trust. Enterprise lifts the
trust root from the operator to Soap Bucket and pairs that with the
release-tagged SBOM and CI verification an enterprise buyer expects.

### Why Ed25519 over SHA-256 of `SHA-256(artifact)`

- **Bounded memory.** A 200 MB artifact never lives in a buffer at
  once: the verify step streams the file through `Sha256` and then
  runs Ed25519 over the 32-byte digest. The same `dalek` API used
  elsewhere in the workspace handles it.
- **No new heavy dep.** `ed25519-dalek` is already in the workspace
  (sbproxy-middleware HTTP-message signatures, sbproxy-modules quote
  tokens, sbproxy-observe notify). Lighting it up in
  sbproxy-classifiers does not add a transitive dep; it activates an
  existing one.
- **Signing tooling is ubiquitous.** `openssl genpkey -algorithm
  Ed25519 -outform PEM -pubout` lands a usable PEM. Operators with
  Vault or AWS KMS can sign offline. The detector accepts the
  signature as raw 64 bytes, base64, or hex, which covers the three
  ways a signing pipeline typically emits it.

### Why the size budget defaults to 200 MB

The enterprise classifier (WOR-35) used 200 MB. Keeping the same
ceiling means an operator running both flavours sees the same
"too big" diagnostic across them. The DeBERTa-base int8 ONNX export
is roughly 70 MB; 200 MB has comfortable headroom for fine-tuned
variants without paving the road for a 5 GB unquantised checkpoint
that would saturate the cache disk.

### Backwards compatibility

- Omitting all four new fields preserves today's SHA-256-only
  behaviour byte-for-byte. No config edit is required to upgrade.
- The size budget is enforced even when omitted. The default of
  200 MB is generous enough that no current configured model is
  affected, and an operator who deliberately wants to point at a
  larger artifact bumps `max_model_bytes` in the same config file
  they edit when they bump the URL.

## Consequences

- The OSS detector now has a credible defence against a hostile
  mirror serving a swapped model, even when the operator has not yet
  pinned a SHA-256.
- An operator who turns on signature verification owns the key
  rotation procedure. The OSS crate has no opinion on how that key is
  stored or rotated; that is documented in `onnx-classifier.md` as
  guidance, not enforcement.
- A future first-party OSS model will need its own ADR addendum to
  add the vendor-trusted path (a built-in vendor key, an SBOM entry,
  and CI verification on every release tag). That work is tracked as
  the second half of WOR-146 and stays deferred until a model is
  ready to ship.

## Alternatives considered

- **Cosign / Sigstore from day one.** Discarded for "land now": the
  Rust cosign client pulls a non-trivial dep tree (Fulcio /
  Rekor / OIDC), and OSS operators do not all have a Sigstore
  identity story. The Ed25519 detached-signature path is strictly
  simpler and is what operators with their own KMS are already
  comfortable with. Cosign remains a candidate for the
  vendor-trusted path once we ship a first-party model.
- **Hard-coded vendor public key in OSS.** Discarded: anyone who
  rebuilds the crate can patch the constant out, so the trust
  property does not actually hold under the OSS distribution model.
- **Reuse the HTTP-message-signatures verifier.** Discarded: that
  code path is wired through Pingora request / response objects and
  expects an HTTP signing context. Verifying a single 64-byte
  detached signature against a SHA-256 digest is a few calls to
  `ed25519_dalek::VerifyingKey::verify`; pulling in the HTTP-shaped
  verifier would have created an awkward dependency cycle from
  sbproxy-classifiers back into sbproxy-middleware.
- **Skip the size budget; rely on the SHA-256 pin.** Discarded: an
  operator who has not yet pinned a hash is exactly the operator
  most exposed to a runaway artifact. The budget is the cheapest
  guard and is independent of whether a hash pin is in play.

## References

- WOR-35: enterprise classifier supply chain (closed; lives in the
  enterprise tree).
- WOR-146: OSS classifier supply chain. This ADR covers the "land
  now" portion.
- `docs/onnx-classifier.md`: operator-facing reference for the new
  config fields and the worked signing example.
- `crates/sbproxy-classifiers/src/lib.rs`: the size-budget and
  signature verification implementation.
- `crates/sbproxy-modules/src/policy/prompt_injection_v2/onnx.rs`:
  the detector config layer that enforces the all-or-nothing rule
  and wires the new fields into the load path.
