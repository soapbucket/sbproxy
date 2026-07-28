# WOR-1984 Prompt-Injection Default Design

*Last modified: 2026-07-27*

## Goal

Make `prompt_injection_v2` select verified in-process inference when an
operator has staged a complete model and tokenizer pair, while preserving a
safe zero-artifact boot path and treating the legacy AI guardrail names as
compatibility aliases for the same detector behavior.

## Product contract

- An explicit `detector` always wins.
- Explicit `heuristic-v1` does not inspect any in-process artifact.
- Explicit `inprocess` remains fail-fast when its artifact pair is absent or
  invalid.
- When `detector` is omitted, resolve one candidate pair in this order:
  1. `detector_config.model_path` and `detector_config.tokenizer_path`, when
     either field is supplied.
  2. `<default_model_cache_dir>/prompt-injection-v2/model.onnx` and
     `<default_model_cache_dir>/prompt-injection-v2/tokenizer.json`.
- A selected pair with both files absent chooses `heuristic-v1` and emits one
  clear startup log.
- Partial presence, unreadable artifacts, oversize artifacts, digest mismatch,
  signature mismatch, tokenizer parse failure, and ONNX parse failure are hard
  startup errors. None may downgrade to the heuristic.
- A present pair must have a complete SHA-256 pin pair. Optional detached
  Ed25519 signatures remain all-or-nothing and verify the SHA-256 digest of
  each artifact before parsing.
- The existing 200 MiB model and tokenizer limits remain unchanged.

## Architecture

### Detector selection

`PromptInjectionV2Policy::from_config` will deserialize `detector` as
`Option<String>` so omission remains distinguishable from an explicit
`heuristic-v1`. Explicit names keep the current direct dispatch. Omission
delegates to an in-process artifact resolver that returns either a loaded
detector or the precise both-absent state.

The resolver checks configured paths before conventional cache paths. If only
one configured path is supplied, that is a partial configuration error rather
than permission to inspect the conventional location.

### Verified local loading

`sbproxy-classifiers` will expose a local verified-load entry point next to
`load_with_options`. It will apply checks in this order:

1. File type and readability.
2. Existing size budgets.
3. Both SHA-256 pins.
4. Both detached signatures when configured.
5. Tokenizer and ONNX parsing.

This keeps security-sensitive byte validation in the classifier crate. The
policy layer only resolves configuration and enforces all-or-nothing field
groups.

The configured pair can provide its own two SHA-256 values. If they are
omitted, the resolver may use a complete pin pair from the named
`KnownModel`. A known model with missing pins is not trusted and cannot
activate in-process inference.

### One heuristic detector

The canonical case-insensitive matcher stays in `sbproxy-ai`, which is already
below `sbproxy-modules` in the dependency graph. It returns a small scored
finding with clean, suspicious, or injection confidence.

The `prompt_injection_v2` heuristic is a score-and-label adapter over that
engine. The legacy AI proxy `injection` and `prompt_injection` names retain
their existing blocking configuration, including `patterns` and
`detect_common`, but delegate matching to the same engine. This avoids the
forbidden `sbproxy-ai -> sbproxy-modules` dependency and leaves one pattern
implementation.

### Model-selection constraint

No model is promoted to the built-in default in this change unless it is all
of the following:

- Published at an immutable revision.
- Licensed under Apache-2.0 or MIT with clear artifact provenance.
- Paired with the tokenizer and verified `SAFE` / `INJECTION` label order.
- At or below the existing 200 MiB cap.
- Loadable and runnable through the pinned tract engine.

The current ProtectAI registry entry does not qualify. Its immutable ONNX file
is 738,563,188 bytes, despite older documentation describing an approximately
70 MB artifact. The other official ProtectAI ONNX candidate is 267,955,712
bytes. The official Patronus Apache-2.0 ONNX artifacts are also above the cap.
Sub-200 MiB community exports found during the audit lacked either an explicit
license for the fine-tuned weights or first-party export provenance.

Therefore this change will not pin an unsafe default, raise the cap, or claim
a request-latency number. Configured, pinned artifact pairs can still activate
the full auto-selection path. Conventional cache files remain both-absent in
a normal install and select the heuristic. If files are staged there before a
safe `KnownModel` pin exists, startup fails because they cannot verify.

## Error and logging behavior

The both-absent auto path emits one info event under
`sbproxy::prompt_injection_v2` containing the selected detector and both
resolved paths. Every other artifact failure is returned with path and check
context. Explicit detector choices emit no auto-selection fallback event.

Per-request inference failures retain the existing fail-open behavior after a
model has passed startup verification. This ticket changes startup trust and
selection, not the established request-time failure policy.

## Test design

Focused tests will prove:

- Configured, digest-pinned fixture artifacts plus omitted `detector` select
  active mode `inprocess`.
- Both absent choose `heuristic-v1` and emit exactly one fallback event.
- A configured partial pair fails even when a conventional pair exists.
- A partial conventional pair fails.
- A wrong digest, signature, unreadable path, oversize artifact, or parser
  failure cannot downgrade.
- Explicit `heuristic-v1` ignores partial or tampered artifacts.
- Explicit `inprocess` fails on absent artifacts.
- Legacy `injection` and `prompt_injection` configs still compile and block
  through the canonical heuristic engine, including custom patterns.
- The v2 heuristic and legacy adapter return consistent decisions for common
  patterns.

## Documentation and measurement

The public detector guide, configuration reference, local-inference guide, and
examples will describe one prompt-injection detector with legacy aliases.
They will document path precedence, fallback boundaries, verification fields,
and the unchanged 200 MiB cap. Generated `llms-full.txt` will be refreshed
from those source docs.

The latency section will record the local hardware and measurement method, but
will state that no valid result was produced because no eligible pinned model
was available. It will include no estimate or substituted model number.

## Approaches rejected

1. Falling back on any load error was rejected because tampering and partial
   deployment would silently weaken protection.
2. Moving the detector trait into `sbproxy-ai` was rejected because
   `sbproxy-classifiers -> sbproxy-ai` and
   `sbproxy-modules -> sbproxy-classifiers` make that placement create or
   encourage a dependency cycle.
3. Pinning the 738 MB ProtectAI model or increasing the cap was rejected
   because it violates the existing memory-safety boundary.
4. Pinning an unlicensed or third-party quantized export was rejected because
   the artifact provenance is not strong enough for an automatic security
   control.
