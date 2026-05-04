# ADR: ML agent classifier serving contract

*Last modified: 2026-05-03*

## Status

Accepted. Builds on `adr-agent-class-taxonomy.md` (the `AgentClass` taxonomy and resolver chain the classifier feeds into), `adr-tls-fingerprint-pipeline.md` (TLS fingerprint features consumed by the classifier), `adr-admin-action-audit.md` (audit trail for inference results), and `adr-schema-versioning.md`.

## Context

`sbproxy-classifiers` today runs one ONNX model: the prompt-injection v2 detector. The runtime infrastructure (tract-onnx, tokenizer, `OnnxClassifier` struct, `Send + Sync` sharing via `Arc`) is already in place and documented in `crates/sbproxy-classifiers/src/lib.rs`.

This ADR adds a second model: agent classification. The model answers "what kind of agent is this client?" across four output classes: `human`, `llm-agent`, `scraper`, and `unknown`. This is distinct from the four-step resolver chain in `adr-agent-class-taxonomy.md`, which uses rule-based signals (bot-auth keyid, rDNS, UA, fallback). The ML classifier uses a learned feature vector that captures behavioral patterns the rule-based resolver cannot detect: rate anomalies, path entropy, header ordering, and TLS fingerprint combinations that indicate automation even when UA and rDNS checks pass.

Three design questions shape this ADR:

1. What is the exact feature schema, and how does it compose with existing signals?
2. How does inference latency interact with the request hot path?
3. When the classifier says `human` but the rule-based resolver said something else, who wins?

## Decision

### Input feature schema

The classifier takes a fixed-length feature vector. The feature builder lives in `sbproxy-classifiers::features::agent_classifier`. Feature schema version is tracked as `feature_schema_version: u32 = 1`; bump on any breaking change to this list. A mismatch between the configured `feature_schema_version` and the model's trained version causes the proxy to refuse to load the model at validation time, preventing silent misclassification.

Features are ordered as follows (the ONNX model is trained on this exact ordering):

**Request-shape features (8 features):**

1. `method_encoded` - one-hot over `{GET=0, POST=1, HEAD=2, PUT=3, DELETE=4, OPTIONS=5, PATCH=6, OTHER=7}`. Value is the index as f32.
2. `path_token_count` - number of `/`-delimited path segments, capped at 16, as f32.
3. `query_string_present` - 1.0 if `?` present in URL, else 0.0.
4. `header_count` - number of request headers, capped at 64, as f32.
5. `body_size_class` - one-hot over `{empty=0, small=1, medium=2, large=3}` with thresholds 0, 1 KB, 64 KB. Value is the index as f32.
6. `accept_header_entropy` - Shannon entropy of the `Accept` header value over character bytes, scaled to [0.0, 1.0]. 0.0 if absent.
7. `user_agent_length` - length of `User-Agent` value in bytes, capped at 512, divided by 512. 0.0 if absent.
8. `cookie_present` - 1.0 if `Cookie` header present, else 0.0.

**TLS fingerprint features (4 features):**

9. `ja4_prefix_byte_0` - first byte of the JA4 prefix string (ASCII code divided by 255) as f32 in [0.0, 1.0]. 0.0 if fingerprint unavailable or `trustworthy = false`.
10. `ja4_prefix_byte_1` - second byte of JA4 prefix, same treatment.
11. `ja4_trustworthy` - 1.0 if `tls_fingerprint.trustworthy == true`, else 0.0.
12. `ja4_known_headless` - 1.0 if `tls_fingerprint.ja4` matches a known headless library in the reference catalogue, else 0.0.

**Agent-class resolver hints (4 features):**

13. `resolver_source_bot_auth` - 1.0 if the resolver's `agent_id_source == "bot_auth"`, else 0.0.
14. `resolver_source_rdns` - 1.0 if `agent_id_source == "rdns"`, else 0.0.
15. `resolver_source_user_agent` - 1.0 if `agent_id_source == "user_agent"`, else 0.0.
16. `resolver_source_fallback` - 1.0 if `agent_id_source == "fallback"` or `"anonymous_bot_auth"`, else 0.0.

**Behavioral features (4 features, from rate-limit middleware counters):**

17. `ip_request_rate_60s` - requests from this IP in the last 60 seconds, divided by 600 (normalizing a 10-rps ceiling to 1.0), capped at 1.0.
18. `ip_path_entropy_60s` - Shannon entropy of the path distribution for this IP in the last 60 seconds, from the rate-limit middleware's per-IP path histogram. In [0.0, 1.0].
19. `ip_cookie_consistency` - fraction of this IP's last 60 seconds of requests that carried a `Cookie` header. In [0.0, 1.0]. Scrapers typically send no session cookies.
20. `ip_referer_consistency` - fraction of this IP's last 60 seconds of requests that carried a `Referer` header. In [0.0, 1.0]. Human browsers typically send `Referer`; scrapers typically do not.

Total: 20 features as `[f32; 20]`. The feature builder outputs this vector and passes it to the ONNX session.

The behavioral features (17-20) read from the rate-limit middleware's per-IP counter store read-only. When the store has no data for an IP (fresh proxy startup, first request), features 17-20 are 0.0.

### Output schema

The ONNX model returns a softmax probability vector over 4 classes:

| Index | Class | `MlClass` enum variant |
|---|---|---|
| 0 | `human` | `MlClass::Human` |
| 1 | `llm-agent` | `MlClass::LlmAgent` |
| 2 | `scraper` | `MlClass::Scraper` |
| 3 | `unknown` | `MlClass::Unknown` |

The serving layer extracts the argmax and the max probability:

```rust
pub enum MlClass { Human, LlmAgent, Scraper, Unknown }

pub struct MlClassification {
    pub class: MlClass,
    pub confidence: f32,             // max softmax probability, in [0.0, 1.0]
    pub model_version: &'static str,
    pub feature_schema_version: u32,
}
```

`RequestContext` gains `ml_classification: Option<MlClassification>`. The field is `None` when the `agent-classifier` cargo feature is disabled (default off) or when inference timed out.

### Model serving

The existing `OnnxClassifier` struct is reused. The agent classifier model is registered in the `ClassifierRegistry` alongside the prompt-injection v2 model. Each Pingora worker thread holds an `Arc<OnnxClassifier>` per registered model; the `Arc` is swapped atomically on hot-reload.

The serving entry point lives in `sbproxy-classifiers::agent_classifier::serve`:

```rust
pub fn classify(
    features: &[f32; 20],
    classifier: &OnnxClassifier,
) -> Result<MlClassification>
```

Feature building is the caller's responsibility; the serving layer takes an already-built vector. This separation allows testing the feature builder independently of the ONNX runtime.

### Hot-swap policy

Operators hot-reload the model without a proxy restart by sending SIGHUP (which also reloads `sb.yml`). Reload sequence:

1. Load the new `.onnx` file from disk into a new `OnnxClassifier` instance.
2. Validate by running inference on a zero-vector input (confirms input/output shape compatibility).
3. If validation passes: atomically swap the `Arc<OnnxClassifier>` in the registry. In-flight requests finish on the old model; new requests after the swap use the new model. The old model drops when the last `Arc` reference is released.
4. If validation fails: log `tracing::error!`, keep the old model, emit `sbproxy_ml_classifier_reload_failures_total`.

Model configuration in `sb.yml`:

```yaml
classifier:
  agent_classifier:
    model_path: /etc/sbproxy/models/agent_classifier.onnx
    feature_schema_version: 1
    sync_mode: false
```

### Inference latency and sync vs async mode

Target p99 inference latency: 5ms. A 20-feature MLP via `tract-onnx` runs in under 1ms on modern hardware; the 5ms budget includes feature building and ONNX session dispatch overhead.

**Async mode (default, `sync_mode: false`).** Inference runs in a `tokio::spawn_blocking` task. The proxy does not await the verdict before responding. The verdict is written into a shared `Arc<OnceLock<MlClassification>>` on `RequestContext` that response-phase pipeline stages can poll. The 402-challenge decision path uses the rule-based resolver verdict, not the ML verdict, in async mode. This is intentional: the 402 path is rule-based and synchronous; the ML classifier enhances but does not gate it in the default configuration.

**Sync mode (`sync_mode: true`).** Inference runs inline on the request path. Operators accept up to 5ms p99 latency impact. The verdict is available immediately after the classifier step. If inference times out (>5ms in sync mode, measured from feature-vector construction start), the classifier emits `MlClassification { class: MlClass::Unknown, confidence: 0.0, ... }` and the request continues. Timeout is enforced via `tokio::time::timeout` around the `spawn_blocking` call. `sbproxy_ml_classifier_timeouts_total` increments.

### Worked example: async mode with response-phase policy

An operator uses a CEL rule in the response phase to log high-confidence scraper verdicts:

```yaml
policies:
  - type: script
    engine: cel
    on_response: |
      ml = request.ml_classification;
      if ml != null && ml.class == "scraper" && ml.confidence > 0.85 {
        log("warn", "high-confidence scraper", {
          "agent_id": request.agent_id,
          "ip": request.client_ip,
          "confidence": ml.confidence
        })
      }
```

In async mode `request.ml_classification` is populated by the time the response phase runs, because inference has had the full request processing time to complete.

### Worked example: sync mode gating on 402

An operator enables sync mode and wants to deny `scraper`-classified requests at the 402 tier:

```yaml
classifier:
  agent_classifier:
    sync_mode: true
policies:
  - type: ai_crawl_control
    tiers:
      - route_pattern: /premium/*
        price: { amount_micros: 5000, currency: USD }
        agent_class_deny:
          - class: scraper
            min_ml_confidence: 0.9
```

`agent_class_deny` is a new extension to `ai_crawl_control`'s `Tier` struct. The classifier verdict is available before `ai_crawl_control` evaluates because `sync_mode: true` blocks the pipeline.

### Training data and evaluation

The training notebook is `sbproxy-classifier/notebooks/agent_classifier.ipynb` (not shipped in the binary). The vendored model artifact is `crates/sbproxy-classifiers/data/models/agent_classifier.onnx`, signed with cosign.

Evaluation harness shape:

- Input: labeled dataset of `(feature_vector, true_class)` pairs, held out from training.
- Metrics: per-class precision, recall, F1 at the default argmax threshold.
- Production acceptance gate (all must pass):
  - `human` precision >= 0.99 (false positives on real users are highly costly).
  - `human` recall >= 0.95.
  - `scraper` precision >= 0.90.
  - `llm-agent` recall >= 0.80.
  - Macro-averaged F1 >= 0.85.

A model that does not meet these gates fails the `ml-eval.yml` CI check and is not vendored.

### Drift detection

Full drift detection is deferred. For now, the proxy emits:

- `sbproxy_ml_classifier_inferences_total{class="human|llm-agent|scraper|unknown"}` - inference count by predicted class.
- `sbproxy_ml_classifier_inference_latency_seconds` - histogram of inference latency.
- `sbproxy_ml_classifier_timeouts_total` - count of inference timeouts.
- `sbproxy_ml_classifier_reload_failures_total` - count of failed model reloads.

An analyst can spot class-distribution drift by querying `sbproxy_ml_classifier_inferences_total` over time. A future anomaly pipeline will formalize this into automated alerts.

### Failure mode

Inference timeout in sync mode: `MlClassification { class: Unknown, confidence: 0.0, ... }`. Request is not blocked. `sbproxy_ml_classifier_timeouts_total` increments.

Inference error (ONNX runtime panic or input shape mismatch): caught via `std::panic::catch_unwind` in the `spawn_blocking` closure. `tracing::error!` logged. Request continues with `ml_classification = None`. `sbproxy_ml_classifier_errors_total` increments. A sustained error rate above 1% triggers the alert `SbproxyMlClassifierErrorRateHigh`.

### Interaction with the rule-based resolver: who wins when they disagree?

The rule-based resolver chain produces a rule-based `agent_id` verdict. The ML classifier produces a probabilistic class verdict. They can disagree.

**Pin: the ML verdict overrides the rule-based resolver verdict only when `ml_classification.class == Human` AND `ml_classification.confidence >= 0.9`.** In all other cases the rule-based resolver verdict is authoritative and the ML verdict is advisory.

Rationale: the most consequential error is falsely gating a real user with a 402 challenge. A confident `Human` verdict (>= 0.90) is strong evidence the rule-based resolver is wrong (e.g. the user's browser UA happens to match a bot pattern). Overriding in the `Scraper` or `LlmAgent` direction is not done because the consequence of blocking a legitimate agent is less severe than the consequence of blocking a real user, and the precision bar for agent classes is lower than for `human` per the evaluation criteria above.

When the ML `Human` verdict overrides a resolver verdict (e.g. `openai-gptbot`), the resulting `agent_id` is `"human"` and `agent_id_source` is `"ml_override"` (new closed-enum variant per `adr-schema-versioning.md` Rule 4). The override is logged at `tracing::info!` with both verdicts.

### Audit trail

One in 1000 inferences is emitted to the audit log per `adr-admin-action-audit.md` with:

- `target_kind = "MlClassification"` (new closed-enum variant; closed-enum amendment required)
- `action = "MlInference"` (new `AuditAction` variant; closed-enum amendment required)
- `after = { class, confidence, model_version, feature_schema_version }`

The full inference log goes to ClickHouse via the async ingest pipeline. The Prometheus counters provide the operational view; ClickHouse provides the analytical view for drift analysis.

## Consequences

- Classifier in async mode adds zero latency to the request hot path.
- Sync mode adds up to 5ms p99. Operators enabling sync mode should budget for this in their SLO targets.
- The `Human` override at confidence >= 0.90 is the only case where the ML verdict overrides the rule-based resolver. This is a narrow, high-confidence exception designed to protect real users from false-positive 402 challenges.
- `feature_schema_version` is the safety interlock against silent misclassification on model-feature mismatch.
- Audit sampling rate 1/1000 keeps audit volume under budget. Full coverage via ClickHouse is available for analytical purposes.
- Three new closed-enum variants require ADR amendment entries on ship: `MlClass` (4-variant closed enum), `AuditAction::MlInference`, `AgentIdSource::MlOverride`.

## Alternatives considered

**Use `ort` (Microsoft ONNX Runtime) instead of `tract-onnx`.** Rejected. `tract-onnx` is pure Rust, cross-compiles to musl and arm64 without system C++ dependencies, and inference latency for a 20-feature MLP is well within budget. This matches the rationale in `crates/sbproxy-classifiers/src/lib.rs`.

**Synchronous-only mode.** Rejected. The p99 latency impact of sync mode is unacceptable for operators who prioritize throughput over real-time gating. Async mode with response-phase decisioning covers most use cases at zero added latency.

**Per-IP persistent behavioral model (LSTM / time-series) instead of per-request MLP.** Rejected for now. A time-series model requires persistent IP-keyed state that survives proxy restarts, significantly complicating serving. The 60-second behavioral features in the per-request MLP capture sufficient temporal signal for the current model.

**Insert ML verdict at resolver step 1 (highest confidence).** Rejected. The rule-based resolver's top positions (bot-auth keyid, rDNS) are cryptographically or network-verified. ML confidence at 0.9 is not equivalent to a cryptographic proof. Inserting ML at step 1 would allow the classifier to override a verified bot-auth result.

**Automated drift detection now.** Deferred. The current ADR ships the counter label set needed to observe drift. Automated detection requires a production baseline.

## References

1. `docs/adr-agent-class-taxonomy.md` - `AgentClass` enum, `AgentIdSource`, resolver chain.
2. `docs/adr-tls-fingerprint-pipeline.md` - JA4 features 9-12 in the feature schema.
3. `docs/adr-admin-action-audit.md` - audit envelope and sampling.
4. `docs/adr-schema-versioning.md` - closed-enum amendment rules.
5. `crates/sbproxy-classifiers/src/lib.rs` - `OnnxClassifier` struct and `tract-onnx` rationale.
6. `crates/sbproxy-classifiers/src/agent_class.rs` - `AgentClass`, `AgentIdSource` types extended by this ADR.
7. FoxIO JA4 spec: `https://github.com/FoxIO-LLC/ja4` (JA4 features 9-10 source).
