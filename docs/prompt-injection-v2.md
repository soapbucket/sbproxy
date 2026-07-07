# prompt_injection_v2
*Last modified: 2026-05-23*

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

```rust,no_run
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
| `sidecar` | Runs inference in a separate process over gRPC instead of in the proxy. The proxy holds one client; the sidecar (minimal OSS or richer enterprise) implements the shared `InferenceService`. Isolates the model runtime so a bad model cannot exhaust the proxy. Fail-open by default. See [Running detection out of process](#running-detection-out-of-process-the-sidecar-detector). |
| `inprocess` | Runs the ONNX classifier inside the proxy via the pure-Rust tract engine. No second process, but the model parse and inference share the proxy's address space, so it is gated behind an explicit opt-in plus a `max_model_bytes` size guard. Prefer `sidecar` for isolation; use `inprocess` for a single-binary deploy. See [In-process detection](#in-process-detection-the-inprocess-detector). |

### In-process detection (the `inprocess` detector)

For a single binary, run the ONNX classifier in the proxy. The original in-process detector was removed because an unsandboxed model parse could exhaust the proxy; this brings it back only behind the explicit `detector: inprocess` choice plus a hard `max_model_bytes` cap, and the operator supplies the model and tokenizer paths (OSS ships no weights).

```yaml
policies:
  - type: prompt_injection_v2
    action: block
    detector: inprocess
    threshold: 0.8
    detector_config:
      # On-disk ONNX model + tokenizer the operator provides.
      model_path: /var/lib/sbproxy/models/injection/model.onnx
      tokenizer_path: /var/lib/sbproxy/models/injection/tokenizer.json
      # Label the model emits for an injection verdict (case-insensitive).
      injection_label: INJECTION
      # Optional class labels indexed by output class; omit to report class_<n>.
      # labels: ["SAFE", "INJECTION"]
      # Hard upper bound on the model file size in bytes (default 200 MB).
      max_model_bytes: 209715200
```

The detector loads the model at config-compile time (the slow path), so a missing or oversized model fails fast at startup rather than on the first request. `detect` then runs cheap tract inference per prompt and maps the top label and score onto the v2 vocabulary using the same cutoffs as the sidecar detector: at or above `threshold` is `injection`, `[0.3, threshold)` is `suspicious`, below `0.3` is `clean`. A non-injection top label is read as confidence the prompt is benign, so its score is inverted. Inference failures fail open (clean); operators who want fail-closed should use the sidecar detector. Because the model loads eagerly, this detector cannot appear in the `examples/` validation sweep; see `docs/local-inference.md` for the full deployment recipe.

## Registering a custom detector

Custom detectors register at module scope via the
`register_prompt_injection_detector!` macro. The macro wraps the
factory in an `inventory::submit!` so the registry picks it up at
link time.

```rust,no_run
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

## In-process vs out-of-process model inference

The OSS build ships only the heuristic detector in-process. Model
inference runs out of process in the classifier sidecar, never inside
the proxy: parsing and running a model graph on the proxy's own heap
lets a malformed or oversized model exhaust proxy memory, so that path
was removed. `detector: sidecar` is the supported way to run a
learned classifier; `detector: onnx` is no longer accepted and fails at
config load with a pointer to the sidecar.

The trained model weights do not ship in OSS. There is no default model
baked into the build and no model artifact in any release asset; you
supply the ONNX file and tokenizer to the sidecar.

The heuristic detector's quality gate (precision and recall >= 0.7
against the bundled golden corpora) runs unconditionally in the default
OSS test suite via
`crates/sbproxy-modules/tests/prompt_injection_eval.rs`. That gate
guards the OSS-shipped detector against regressions.

## Running detection out of process: the sidecar detector

A learned classifier runs in a separate process, not in the proxy. The
proxy holds one gRPC client and sends the prompt to a sidecar that
implements the `InferenceService` contract; the sidecar runs the model
and returns a label and score. Because the proxy and the model runtime
do not share an address space, a bad model takes down the sidecar (which
an orchestrator restarts) rather than the proxy.

Two sidecars implement the same contract:

- The minimal OSS sidecar (`sbproxy-classifier-sidecar`) wraps the
  `tract-onnx` engine.
- The enterprise sidecar adds batching, GPU execution providers, and a
  model registry behind the identical proto.

Switching between them is a deployment change, not a config change.

### Config

```yaml
policies:
  - type: prompt_injection_v2
    action: tag
    detector: sidecar
    threshold: 0.5
    detector_config:
      # gRPC endpoint of the sidecar.
      endpoint: http://127.0.0.1:9440
      # Model id to request; empty selects the sidecar's default.
      model: prompt-injection
      # Label the model emits for an injection verdict (case-insensitive).
      injection_label: injection
      # Per-call timeout in milliseconds (covers the lazy connect).
      timeout_ms: 250
      # Fail policy when the sidecar is unreachable or slow.
      fail_closed: false
```

The client connects lazily, so the proxy starts even when the sidecar
is not up yet, and the first request after the sidecar comes online
succeeds. An invalid `endpoint` is the only error reported at config
load.

### Fail policy

A sidecar that is down, slower than `timeout_ms`, or returning an error
is handled by `fail_closed`:

- `fail_closed: false` (default) returns a clean verdict and lets the
  request through, so an inference outage never blocks traffic.
- `fail_closed: true` returns a high-confidence injection. Pair this
  with `action: block` only when a missing verdict should deny the
  request, and budget for the sidecar's availability accordingly.

### Running the OSS sidecar

The sidecar is a separate binary built from this workspace. The OSS
build does not ship model weights; supply your own ONNX file and
tokenizer (the `protectai/deberta-v3-base-prompt-injection-v2`
artifacts work well):

```bash
cargo run -p sbproxy-classifier-sidecar -- \
  --listen 127.0.0.1:9440 \
  --default-model prompt-injection \
  --model prompt-injection=/models/model.onnx:/models/tokenizer.json
```

`--model ID=MODEL:TOKENIZER` registers a model under an id the policy
references via `detector_config.model`.

### Co-locating in Kubernetes

Run the sidecar as a second container in the proxy pod and point the
policy at `http://127.0.0.1:9440`. Sharing the pod keeps the call over
loopback, so the added latency is one local gRPC round trip rather than
a network hop. Build and publish the images from this workspace; the
refs below are placeholders.

```yaml
spec:
  containers:
    - name: sbproxy
      image: REGISTRY/sbproxy:TAG
      # proxy config selects detector: sidecar, endpoint http://127.0.0.1:9440
    - name: classifier-sidecar
      image: REGISTRY/sbproxy-classifier-sidecar:TAG
      args:
        - --listen=127.0.0.1:9440
        - --default-model=prompt-injection
        - --model=prompt-injection=/models/model.onnx:/models/tokenizer.json
      volumeMounts:
        - name: models
          mountPath: /models
          readOnly: true
  volumes:
    - name: models
      # Stage model artifacts however you prefer: a baked image layer,
      # an initContainer download, or a persistent volume.
      emptyDir: {}
```

A runnable config is at
[`examples/prompt-injection-sidecar/`](../examples/prompt-injection-sidecar/).

### Unix domain socket transport (co-located only)

When the sidecar is co-located with the proxy (in-pod or on the
same host), the gateway can reach it over a Unix domain socket
instead of loopback TCP. This skips the loopback round trip and
stays bounded to the local filesystem namespace; the
authentication boundary is filesystem permissions on the socket
path rather than network reachability.

Run the sidecar with `--listen-uds` (mutually exclusive with
`--listen`):

```bash
cargo run -p sbproxy-classifier-sidecar -- \
  --listen-uds /run/sbproxy/classifier.sock \
  --default-model prompt-injection \
  --model prompt-injection=/models/model.onnx:/models/tokenizer.json
```

The sidecar removes any stale socket file at the path on bind, so
restarts after a crash do not hit `EADDRINUSE`. The parent
directory must already exist; create it via a `tmpfiles.d` entry
in systemd or a one-shot `mkdir` in an init container.

Programmatic callers reach the UDS transport via the
`ClassifierClient::connect_uds` and
`ClassifierClient::connect_uds_lazy` constructors in
`sbproxy-classifier-client`. The lazy form is the supervised-
child pattern: build the client at proxy boot from sync code,
let the supervisor (a separate follow-up) spawn the sidecar with
`--listen-uds <path>`, and the first call races the sidecar's
bind exactly once.

Exposing the UDS path as a `detector_config.uds_path` YAML field
on the `prompt_injection_v2` policy is a small follow-up; today
the transport choice is wired at the `ClassifierClient`
construction site rather than configured per-policy.

TCP stays the default for the remote / external-sidecar case;
the two transports do not coexist in the same sidecar process
(`--listen` and `--listen-uds` are mutually exclusive).

### Child supervisor (auto-spawn)

For the standalone / single-pod case, the proxy can spawn and
supervise the sidecar binary itself rather than expect the
operator to run it out of band. The `Supervisor` type in
`sbproxy_classifier_client::supervisor` owns the child's
lifecycle:

* Spawns `sbproxy-classifier-sidecar --listen-uds <path>
  --model <id=model:tokenizer> ...` per the configured
  `SupervisorConfig`.
* Restarts the child on unexpected exit with exponential
  backoff (initial 200 ms, capped at 30 s; a child that
  survives 30 s resets the backoff schedule on the next crash).
* On graceful shutdown sends SIGTERM, waits up to
  `shutdown_grace` (default 5 s), then SIGKILL.

The pattern pairs naturally with `connect_uds_lazy`: the
supervisor passes the UDS path to the child; the proxy holds a
lazy client at the same path; the first `classify` call races
the child's bind exactly once.

```rust
use std::path::PathBuf;
use std::time::Duration;
use sbproxy_classifier_client::{ClassifierClient, Supervisor, SupervisorConfig};

let uds_path = PathBuf::from("/run/sbproxy/classifier.sock");

let supervisor = Supervisor::spawn(SupervisorConfig {
    binary: PathBuf::from("/opt/sbproxy/sbproxy-classifier-sidecar"),
    uds_path: uds_path.clone(),
    models: vec!["prompt-injection=/models/model.onnx:/models/tokenizer.json".into()],
    default_model: Some("prompt-injection".into()),
    ..SupervisorConfig::default()
});

let client = ClassifierClient::connect_uds_lazy(&uds_path, Duration::from_millis(250))?;

// ... at shutdown ...
supervisor.shutdown().await;
```

`Supervisor` is `Clone`; cheap clones share lifecycle state.
The proxy's `prompt_injection_v2` policy does not surface this
in YAML yet; the wire-up is in code (the proxy holds the
supervisor next to the lazy client and drives both from the
same config block).

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
