# Model pinning

*Last modified: 2026-05-09*

SBproxy ships a small registry of "known" classifier models in
`crates/sbproxy-classifiers/src/known_models.rs`. Each entry pins a
specific upstream URL plus the SHA-256 hash of the file at that URL on
the day the entry was added. Detectors reference an entry by name, so
operators do not have to copy the URL and hash into every config.

This page is the procedure note for pinning hashes on a fresh entry,
and the reasoning behind the assertion test that fails the build when
an entry is committed without a hash.

## Why hashes are pinned in source

- A model rotation is a code change with a code review attached, not a
  YAML edit any operator can land. The registry is the single source
  of truth for what "the production model" means.
- `cargo deny` and supply-chain audits pick up the registry the same
  way they pick up `Cargo.toml` pins.
- Detectors that load a known model use the SHA pair to verify the
  download out of caution against tampering or a compromised mirror.
  An empty hash flags the entry as "unpinned" and disables that
  verification, which is the same posture as supplying the URL
  directly in policy config without `model_sha256`.

## Computing the SHA on first download

Some entries land with empty `model_sha256` and `tokenizer_sha256`
values. The build sandbox has no outbound network access, so we will
not commit a hash we have not verified. The follow-up procedure to
populate those values is:

1. Run the proxy locally with the relevant detector enabled. On first
   request, the detector fetches the file and stores it under the
   classifier cache directory (`SBPROXY_CACHE_DIR` if set, otherwise
   the OS default returned by the `dirs` crate).
2. Run `sha256sum <cache-path>/model.onnx` and
   `sha256sum <cache-path>/tokenizer.json`. Use lowercase hex for the
   value you paste back.
3. Cross-check the hash against the upstream model card. Hugging Face
   exposes a "Files and versions" tab that lists the SHA for each
   blob; the values must match exactly.
4. Paste the lowercase hex strings into the matching `KnownModel`
   entry in `known_models.rs` and update `revision_pinned_at` to
   today's date in `YYYY-MM-DD` form.
5. Re-enable the assertion test by removing the `#[ignore]` attribute
   on `no_known_model_has_unpinned_sha256` in the same module.
6. Open the follow-up PR. The review must include the upstream model
   card URL and the LICENSE the model ships under.

## Assertion test

The `no_known_model_has_unpinned_sha256` test in
`crates/sbproxy-classifiers/src/known_models.rs` walks every entry in
`KNOWN_MODELS` and fails if either `model_sha256` or
`tokenizer_sha256` is:

- the empty string,
- the literal 64-character hex zero placeholder
  (`0000...`, which operators sometimes paste while shadowing local
  builds),
- or the lowercase hex form of a 32-byte zero buffer.

The test is marked `#[ignore]` while the registry still ships an
unpinned entry; the follow-up that pastes the computed hashes also
drops the `#[ignore]`, at which point any future PR that
re-introduces an empty hash trips the gate at CI time.
