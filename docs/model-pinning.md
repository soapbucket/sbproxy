# Model pinning

*Last modified: 2026-07-27*

SBproxy keeps its trusted classifier registry in
`crates/sbproxy-classifiers/src/known_models.rs`. Every merged entry
identifies an immutable upstream artifact pair and carries both SHA-256
digests. Detectors can reference an entry by name instead of repeating
the pins in every configuration.

## Trust requirements

A registry candidate must have:

- An immutable upstream revision, never a moving `resolve/main` URL.
- Clear model-weight and tokenizer provenance.
- An Apache-2.0 or MIT license (or an explicitly reviewed equivalent).
- A verified label/output contract for its intended detector.
- Measured artifact sizes within that detector's default budgets.
- SHA-256 digests computed from the exact downloadable bytes.

Empty, placeholder, or deferred digests are not allowed in
`KNOWN_MODELS`. If the review environment cannot fetch and verify a
candidate, leave it out of the trusted registry until someone can.
Local prompt-injection auto-selection likewise requires a complete pin
pair; it never trusts files merely because they are present.

## Adding or rotating an entry

1. Select the exact upstream commit or immutable revision and review
   its model card, license, tokenizer, label order, and export
   provenance.
2. Download the model and tokenizer on a connected host with redirects
   visible in the command output. Confirm the final artifact belongs to
   the reviewed immutable revision.
3. Measure both files. Do not rely on a filename or model-card estimate.
4. Compute lowercase digests:

   ```bash
   sha256sum model.onnx tokenizer.json
   ```

   On macOS, use `shasum -a 256` when `sha256sum` is unavailable.
5. Cross-check any upstream-published digest. A mismatch blocks the
   entry; do not choose whichever value makes a download pass.
6. Add the immutable URLs, both digests, SPDX license identifier, and
   current `revision_pinned_at` date to the `KnownModel` entry.
7. Run the registry assertion test and the relevant detector load test.
8. Include the model card, license, immutable revision, measured sizes,
   digests, and label verification evidence in the PR.

## Assertion gate

`no_known_model_has_unpinned_sha256` runs in the normal test suite. It
walks every `KNOWN_MODELS` entry and rejects:

- an empty digest,
- a literal 64-character all-zero placeholder,
- or the lowercase hex form of a 32-byte zero buffer.

The test is intentionally not ignored. A new model without verified
pins must fail CI instead of silently weakening artifact verification.
