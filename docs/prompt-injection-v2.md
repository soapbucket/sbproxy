# prompt_injection_v2
*Last modified: 2026-04-27*

Successor to the v1 `prompt_injection` heuristic guardrail. The v2
policy splits *detection* from *enforcement*: a swappable detector
returns a numeric score plus a categorical label, and the policy maps
the score onto an action. The OSS build ships a heuristic detector by
default so the policy works out of the box; the trait is shaped so a
future ONNX classifier can plug in without touching the policy core.

## Why a v2 policy

The v1 `prompt_injection` guardrail is a substring match that returns
a boolean block. That works as a first cut but does not give operators
a way to tune sensitivity, observe near-miss prompts, or upgrade the
detector to a probabilistic model. The v2 policy preserves the v1
behaviour as the default detector while exposing a richer interface:

- Score in `[0.0, 1.0]` plus a label (`Clean`, `Suspicious`,
  `Injection`).
- Three actions: `tag` (default), `block`, `log`.
- Pluggable detector slot. Configs reference detectors by name; the
  inventory registry rejects unknown names at compile time.

The v1 policy is unchanged. Operators upgrade by switching the policy
`type` from `prompt_injection` to `prompt_injection_v2`.

## The Detector trait

```rust
pub trait Detector: Send + Sync + 'static {
    fn detect(&self, prompt: &str) -> DetectionResult;
    fn name(&self) -> &str;
}
```

`DetectionResult` carries:

- `score: f64` in `[0.0, 1.0]`. The policy fires when
  `score >= threshold` (default `0.5`).
- `label: DetectionLabel` (`Clean`, `Suspicious`, `Injection`).
- `reason: Option<String>` for human-readable context (matched
  pattern, classifier rationale, etc.).

`Detector` is intentionally synchronous: detection runs on the
request hot path. Async work or remote calls belong in a wrapper that
pre-loads state at startup, not in `detect` itself.

## Registered detectors (OSS build)

| Name | Description |
|------|-------------|
| `heuristic-v1` | Case-insensitive substring matching against the OWASP-LLM-01 vocabulary plus a small "suspicious" cue list. Default; works out of the box. |
| `onnx` | Pure-Rust ONNX inference via `tract-onnx`. Loads a Hugging Face style classifier from a configurable URL, validates SHA-256, caches on disk, and falls back to the heuristic on any load failure. See [onnx-classifier.md](onnx-classifier.md). |

## Registering a custom detector

Custom detectors register at module scope via the
`register_prompt_injection_detector!` macro. The macro wraps the
factory in an `inventory::submit!` so the registry picks it up at
link time.

```rust
use std::sync::Arc;
use sbproxy_modules::{
    register_prompt_injection_detector, DetectionLabel, DetectionResult, Detector,
};

struct MyDetector;

impl Detector for MyDetector {
    fn detect(&self, prompt: &str) -> DetectionResult {
        // ... your logic ...
        DetectionResult {
            score: 0.0,
            label: DetectionLabel::Clean,
            reason: None,
        }
    }
    fn name(&self) -> &str {
        "my-detector"
    }
}

fn factory() -> Arc<dyn Detector> {
    Arc::new(MyDetector)
}

register_prompt_injection_detector!("my-detector", factory);
```

Reference the detector by name in the policy config:

```yaml
policies:
  - type: prompt_injection_v2
    detector: my-detector
```

## Eval harness

The repo ships golden corpora at `eval/prompt_injection/`:

- `golden_injection.txt`: 33 known-injection prompts paraphrased from
  OWASP-LLM-01, PROMPTBENCH, and similar public corpora.
- `golden_clean.txt`: 35 known-clean prompts (typical user queries).
- `README.md`: source attribution and usage notes.

The integration test at `crates/sbproxy-modules/tests/prompt_injection_eval.rs`
runs the configured detector against the corpora and computes
precision and recall. The test is `#[ignore]` by default; run
explicitly with:

```bash
cargo test -p sbproxy-modules --test prompt_injection_eval -- --ignored
```

The heuristic baseline gates at precision and recall >= 0.7. These
thresholds are intentionally lower than the eventual ONNX target
(>0.9): they exist to catch regressions in the heuristic, not to
measure final detector quality. Bump the thresholds when the ONNX
classifier lands.

## OSS vs enterprise: what ships and what runs in CI

The ONNX inference code in
`crates/sbproxy-modules/src/policy/prompt_injection_v2/onnx.rs` ships
in the OSS build. Operators with their own trained model and tokenizer
files can wire them up by setting `detector: onnx` plus
`detector_config.model_url` and `detector_config.tokenizer_url` (with
optional SHA-256 pinning). The `tract-onnx` runtime is statically
linked, so no system dependency is required.

The trained model weights themselves do not ship in OSS. There is no
default model URL baked into the build, and no model artifact is
included in any release asset.

The ONNX-gated eval test at
`crates/sbproxy-modules/tests/prompt_injection_eval.rs` is
`#[ignore]`-gated and additionally guarded by the
`SBPROXY_ONNX_MODEL` and `SBPROXY_ONNX_TOKENIZER` environment
variables. When those variables are unset the test exits early with a
SKIP message, which is the case for every job in the OSS CI
pipeline. The enterprise CI pipeline has access to the trained model
and tokenizer and exercises the test on every change to the v2
detector.

The heuristic detector's quality gate (precision and recall >= 0.7
against the bundled golden corpora) runs unconditionally in the
default OSS test suite via the same test file. That gate is what
guards against regressions to the OSS-shipped detector; the ONNX gate
guards the enterprise classifier.

## What the OSS scaffold scans

The scaffold runs detection at request-filter time on the request URI
plus all non-auth headers. Tag mode stamps the score / label headers
via the existing trust-headers channel before
`upstream_request_filter` builds the upstream request, mirroring the
`exposed_credentials` and `dlp` policies. The auth-class headers
(`Authorization`, `Cookie`, `Set-Cookie`) are excluded so tokens
carried by design don't self-flag.

Body-aware detection (the prompt typically lives in the JSON body of
an `ai_proxy` request) is intentionally out of scope for the OSS
scaffold. Stamping headers from the body filter is too late: Pingora
has already called `upstream_request_filter` and built the upstream
request by then. Body-aware detection lands with the ONNX classifier
follow-up, which will run inside `ai_proxy` (where the body is parsed
into `messages` already) rather than as a generic policy.

Real-world patterns the scaffold catches today:

- Chat consoles that send the prompt as a `?q=...` query parameter.
- Webhooks and integrations that put user content in custom headers
  like `X-Prompt`, `X-User-Message`, or `X-Subject`.
- Any path that includes user-supplied free text (e.g. RPC-style URLs
  that encode the prompt in the path segment).

## Heuristic limitations

The heuristic detector is a substring matcher. It does not handle:

- **Obfuscation.** `i.gn.o.r.e p.r.e.v.i.o.u.s i.n.s.t.r.u.c.t.i.o.n.s`
  evades the patterns. Future detectors will tokenise.
- **Translation.** Patterns are English-only.
- **Indirect injection.** Prompts that smuggle the attack through a
  retrieved document (RAG poisoning) sail through; the detector only
  sees the inbound prompt.
- **Novel phrasings.** Anything outside the published OWASP-LLM-01
  vocabulary is missed unless it happens to share a substring.

These are the gaps the ONNX classifier in the Fail-4 follow-up closes.

## When to graduate to a vendor

Operators with strict compliance requirements, multilingual traffic,
or known-targeted threat models should route to a vendor (Lakera, Rebuff,
Anthropic Constitutional Classifiers, etc.) by registering a custom
detector that wraps the vendor's API. Keep `heuristic-v1` as a
fast-path pre-filter so vendor calls are reserved for ambiguous
prompts.

## Relationship to the v1 policy

| | v1 (`prompt_injection`) | v2 (`prompt_injection_v2`) |
|--|--|--|
| Where | Inside `ai_proxy` guardrails pipeline | Standalone policy on any origin |
| Output | Boolean block | Score + label |
| Detector | Hard-coded substring match | Swappable trait |
| Default action | Block | Tag |
| Status | Stable; no behaviour change | New; OSS scaffold |

The two coexist. We will collapse the heuristic implementation into
a shared helper once the v2 detector trait is stable; today the
patterns are duplicated with a `// TODO` comment in
`crates/sbproxy-modules/src/policy/prompt_injection_v2/heuristic.rs`.
