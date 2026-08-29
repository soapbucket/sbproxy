# Model pinning

*Last modified: 2026-08-29*

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

## What a model file may not do

Pinning answers "are these the bytes we reviewed". It says nothing about
what those bytes are allowed to ask the process to do, and an ONNX model
is a program with a file-reading primitive in it.

An ONNX `TensorProto` may set `data_location: EXTERNAL` and name a file in
its `external_data` `location` entry, instead of carrying the tensor
inline. The runtime is then expected to open that file and use its bytes
as the tensor. `tract-onnx` up to 0.21.16 resolved the value as
`PathBuf::from(model_dir).join(location)` with no containment check at
all. `Path::join` with an absolute argument discards the base, so a model
carrying `location: "/etc/ssl/private/server.key"` read that file, and one
carrying `location: "../../../../etc/shadow"` walked out of the model
directory. The bytes then became a tensor the graph could route to an
output. That is GHSA-h668-6x6g-f8r5, and it is a read of any file the
proxy user can open.

SBproxy refuses external tensor data outright. A model this process loads
holds its own tensors, and one that does not is refused before any file is
opened:

```
Error: failed to load classifier
Caused by:
    ONNX external tensor data is unsupported for tensor "encoder.weight";
    a model this process loads must hold its own tensors
```

The refusal names the tensor and never the path it declined to read.
Echoing an attacker-chosen host path into a log or an error would turn the
refusal into the disclosure it exists to prevent.

Three things make the refusal affordable rather than a restriction anyone
will hit:

- Nothing in the trusted registry uses it. `all-MiniLM-L6-v2` at the
  revision `KNOWN_MODELS` pins carries no external reference, and neither
  does either vendored test fixture.
- The only legitimate reason to split a model is the 2 GB protobuf
  ceiling, and the default 200 MB artifact budget refuses those already.
- A confined external reference is still an unbounded read. Size budgets
  measure the `.onnx` file, so a 900-byte model naming a 40 GB sibling
  passes every one of them. Refusal is the only posture under which the
  file that was sized is the file that gets parsed.

Two mechanisms enforce it, and they do not cover the same ground, so it is
worth being exact about which loader gets which.

The layer **every** loader has is the translation step. Each one parses the
protobuf, then translates it with `model_for_proto_model`, which passes no
model directory. That is the state the ONNX spec reserves for "external data
cannot be resolved", and tract refuses there on its own. The one-shot
`model_for_path` is what hands tract a directory to resolve against, and
`scripts/check-onnx-model-loaders.sh` fails the build if any crate calls it
or its `model_for_read` sibling, including in a loader nobody has written
yet.

The second layer is `reject_external_tensor_data`, which walks every tensor
a model can reach, including subgraph bodies, node attributes, function
bodies, and both training graphs, and refuses before the runtime sees the
proto. It is wider than the runtime it guards: tract takes the external
branch off `data_location` alone, while the walk also refuses a non-empty
`external_data` list. Its refusal also names only the tensor, whereas tract's
own confinement error echoes the `location` value back.

**Only the loaders in `sbproxy-classifiers` run that second walk.**
`sbproxy-agent-detect`, which loads the JA4 CatBoost scorer, has the
translation layer alone. It is a foundational crate whose only heavy
dependency is the runtime, and taking a dependency on the classifier crate to
share one function would pull tonic, reqwest, and the AI stack into it. Its
refusal message is therefore tract's rather than ours, which is why the test
covering it asserts on tract's wording. What it is not is unprotected: a
model naming a path outside its own directory is refused there too, and the
guard script is what keeps that call site in the two-step shape.

Version floor: `tract-onnx` 0.21, held there deliberately. That is worth
stating plainly, because the advisory that motivates this section is fixed
upstream and we are not taking the fix.

The NNEF overflow is fixed from 0.21.16, and the `external_data` read from
0.21.17. **0.21.17 is the release worth wanting**: it closes both, and it
predates the Gather regression described below, so it is the only version in
reach that is strictly better than what we run.

It is blocked by exactly one character. `tract-data` 0.21.17 declares
`libm = "=0.2.11"`, an exact pin, while `wasmtime-internal-core` needs
`libm ^0.2.16` and this lockfile resolves `libm 0.2.16`. Remove the `=` and
the graph resolves. 0.22 and 0.23 already write that same requirement as a
caret, which is why they resolve where 0.21.17 cannot.

But they regress correctness, and 0.21.17 does not. 0.22 added an unchecked
block-copy fast path to the Gather op that indexes a slice directly:

```text
let input_offset = resolved_index * block_len;
output_slice[out_offset..out_offset + block_len]
    .clone_from_slice(&input_slice[input_offset..input_offset + block_len]);
```

0.21 used a checked lookup and returned `Invalid gather` as an error. An
out-of-range index is not exotic here: it is what a tokenizer and a model
whose vocabularies disagree produce, which is an ordinary operator
misconfiguration the detector stack is built to survive. On 0.22 that
panics a worker on the AI request path instead of failing cleanly, and the
prompt-injection tests that assert a typed inference failure catch it.
0.23 carries the same fast path.

So the trade on offer from 0.22 and 0.23 is an unreachable NNEF integer
overflow against a panic on a live request path, and it is refused.
`deny.toml` carries GHSA-x5mv-8wgw-29hg with an expiry and the reasoning
beside it.

The way out is not to bounds-check Gather across two major lines. It is to
ask tract for a 0.21.18 that relaxes one exact pin, which unblocks a release
that is already correct on both counts.

**The file-read advisory is not being carried.** GHSA-h668-6x6g-f8r5 is
closed by the refusal described above, which is why that refusal is written
to hold whichever tract is underneath rather than to lean on the runtime's
own containment. The mitigation was verified against 0.21.10 with the
runtime still vulnerable, which is the only configuration where its
independence can actually be observed.
