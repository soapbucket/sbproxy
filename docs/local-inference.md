# Local inference (embeddings and prompt-injection classify)
*Last modified: 2026-07-26*

SBproxy can run three AI-gateway features on local ONNX models instead of paid
APIs:

- The **embedding semantic cache** vectorizes prompts to serve near-duplicate
  requests from cache.
- **Prompt-injection v2** classifies prompts for injection attempts.
- The **embedding classifier guardrail** maps prompts onto operator-defined
  classes that can feed model-routing policy.

For running a full **LLM** locally (the gateway pulls weights, fits an engine
to the GPU, and supervises it), see [model-host.md](model-host.md). This page
covers the two ONNX auxiliary features; the model host covers chat/completion
serving.

Running these locally means no per-call API cost, no prompt egress (the prompt
never leaves your network), low loopback latency, and air-gap support. Models
run on a pure-Rust engine (`tract`), so there is no Python and no native
ONNX Runtime install.

There are two ways to run local inference:

- **Sidecar (recommended).** A small co-located process holds the model. A bad
  or oversized model can only OOM the sidecar, which the proxy restarts; it
  never takes the proxy down.
- **In-process (opt-in).** The model loads inside the proxy for a true single
  binary. Simpler to deploy, but a model parse runs in the proxy's address
  space, so it is gated behind explicit config and a size guard.

## Models

| Use | Default model | License | Size |
|---|---|---|---|
| Embeddings | `all-MiniLM-L6-v2` (384-dim) | Apache-2.0 | ~90 MB |
| Prompt-injection classify | `protectai/deberta-v3-base-prompt-injection-v2` | Apache-2.0 | ~70 MB int8 |

Both are operator-supplied runtime data, not bundled with the binary. Download
them once and point the sidecar (or the in-process config) at the files.

### Download the models

```bash
mkdir -p /var/lib/sbproxy/models/minilm /var/lib/sbproxy/models/injection

# Embedding model (all-MiniLM-L6-v2)
curl -fSL -o /var/lib/sbproxy/models/minilm/model.onnx \
  https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/5641a7880f40ebf4035d05e60c5f9b7a9c272c84/onnx/model.onnx
curl -fSL -o /var/lib/sbproxy/models/minilm/tokenizer.json \
  https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/5641a7880f40ebf4035d05e60c5f9b7a9c272c84/tokenizer.json

# Prompt-injection classifier
curl -fSL -o /var/lib/sbproxy/models/injection/model.onnx \
  https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/model.onnx
curl -fSL -o /var/lib/sbproxy/models/injection/tokenizer.json \
  https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/tokenizer.json
```

Air-gapped sites: download on a connected host, verify the SHA-256 against the
upstream model card, then copy the files into place. The engine validates a
pinned hash when one is configured, and otherwise trusts the local file.

## Run the sidecar

The sidecar binary is `sbproxy-classifier-sidecar`. It serves both `Classify`
and `Embed` over gRPC (TCP or a Unix domain socket). Load whichever models you
need:

```bash
sbproxy-classifier-sidecar \
  --listen 127.0.0.1:9440 \
  --model prompt-injection=/var/lib/sbproxy/models/injection/model.onnx:/var/lib/sbproxy/models/injection/tokenizer.json \
  --embed-model all-MiniLM-L6-v2=/var/lib/sbproxy/models/minilm/model.onnx:/var/lib/sbproxy/models/minilm/tokenizer.json
```

Health and readiness are on the same host; the proxy connects lazily, so the
sidecar does not have to be up before the proxy starts. For a co-located
deployment, use `--listen-uds /run/sbproxy/classifier.sock` instead of
`--listen` to skip the loopback TCP round trip.

## Enable the local semantic cache

The semantic cache is configured on each AI origin under `action.semantic_cache`.
Point it at the sidecar with `source: sidecar`:

```yaml
origins:
  ai.example.com:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o]
      routing:
        strategy: round_robin
      semantic_cache:
        enabled: true
        threshold: 0.85        # cosine similarity for a near-duplicate hit
        ttl_secs: 3600
        max_entries: 1024
        source: sidecar
        sidecar:
          endpoint: http://127.0.0.1:9440
          model: all-MiniLM-L6-v2
          timeout_ms: 500
```

On a miss the proxy vectorizes the prompt via the sidecar, scans the cache, and
replays the closest cached response when cosine similarity meets `threshold`. If
the sidecar is unreachable, the lookup is treated as a miss and the request
proceeds to the upstream uncached. The cache never wedges a request.

The default `source` is `provider`, which calls an AI provider's `/v1/embeddings`
API. Existing configs are unchanged.

If you would rather reuse a shared embedding model elsewhere than run one on this
box, set `source: openai` to point the cache at any OpenAI-compatible
`/v1/embeddings` endpoint (another sbproxy that fronts an embedding model,
OpenRouter, or a hosted provider), decoupled from this origin's chat providers
and with its own URL and auth. That source is documented with the AI gateway's
[semantic cache configuration](./ai-gateway.md#semantic-cache); the rest of this
guide covers the on-box options.

## Enable first-class ONNX prompt-injection

Select the sidecar detector in the origin's `prompt_injection_v2` policy (the
`policies` list sits alongside `action` on the origin):

```yaml
origins:
  ai.example.com:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o]
    policies:
      - type: prompt_injection_v2
        threshold: 0.8
        action: block
        detector: sidecar
        detector_config:
          endpoint: http://127.0.0.1:9440
          model: prompt-injection
          injection_label: INJECTION
          timeout_ms: 250
          fail_closed: false     # a sidecar outage degrades to "clean" (allow)
```

The default detector is `heuristic-v1` (a zero-dependency regex pass). Choosing
`detector: sidecar` runs the ONNX classifier in the sidecar.

## In-process opt-in

For a single binary, run either feature in-process. This loads a model into the
proxy address space, so it is gated behind explicit config and a
`max_model_bytes` guard. Prefer the sidecar for isolation.

Each block sits in the same place as its sidecar form (the AI origin's
`action.semantic_cache`, and the origin's `policies`); only `source` /
`detector` and its sub-block change.

Prompt-injection in-process:

```yaml
origins:
  ai.example.com:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o]
    policies:
      - type: prompt_injection_v2
        threshold: 0.8
        action: block
        detector: inprocess
        detector_config:
          model_path: /var/lib/sbproxy/models/injection/model.onnx
          tokenizer_path: /var/lib/sbproxy/models/injection/tokenizer.json
          injection_label: INJECTION
          max_model_bytes: 209715200   # 200 MB guard
```

In-process semantic cache embeddings:

```yaml
origins:
  ai.example.com:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o]
      semantic_cache:
        enabled: true
        threshold: 0.85
        source: inprocess
        inprocess:
          model: all-MiniLM-L6-v2
          model_path: /var/lib/sbproxy/models/minilm/model.onnx
          tokenizer_path: /var/lib/sbproxy/models/minilm/tokenizer.json
          max_model_bytes: 209715200   # 200 MB guard
```

The released `sbproxy` binary is built with the `inprocess-embed` feature, so
`source: inprocess` works out of the box. If you build from source without the
default features, add `--features inprocess-embed`; without it, `source:
inprocess` returns a clear error and the cache treats lookups as misses.

## Enable classifier-backed routing

The `classifier` input guardrail uses the same `OnnxEmbedder` implementation
to build a nearest-centroid classifier from operator-provided examples. The
released binary includes `inprocess-classify`; a source build without default
features must enable it.

Multiple classifier entries share one loaded embedder when the resolved model
and tokenizer paths and digests match and each entry's model-size limit
accepts the artifact. Replacing either file at the same path invalidates reuse
on reload. The implementation lives in `sbproxy-core` behind the
`TextClassifier` trait from `sbproxy-ai`: `sbproxy-classifiers` depends on
`sbproxy-ai`, so placing the concrete ONNX implementation in `sbproxy-ai`
would introduce a crate cycle.

Classifier results are always non-enforcing routing labels; no mesh override
is required to prevent them from blocking. The complete configuration and
model download commands are in
[ai-classifier-routing](../examples/ai-classifier-routing/).

## Enable classifier-backed safety enforcement

The `toxicity`, `jailbreak`, and `content_safety` guardrails can use the same
in-process embedding backend for enforcing verdicts. Set
`mode: classifier` and nest the classifier configuration under
`classifier:`. Unlike the routing-only `type: classifier` entry, these modes
block when their configured unsafe class wins.

Classifier mode is never an automatic upgrade. Keyword mode remains the
zero-dependency default, and it is a literal substring matcher. When
classifier mode is explicit, startup and reload construct the enforcing
classifier before publishing the pipeline. An unavailable artifact or digest
mismatch rejects boot or reload with a configuration error instead of quietly
weakening the guardrail.

The three guardrails use separate closed class taxonomies but share the
process-level model cache. Multiple entries that point at the same resolved
model and tokenizer therefore load one embedder while maintaining independent
centroids, thresholds, and verdicts. `content_safety` also requires a
nonempty `blocked_categories` subset.

The safety taxonomies ship precomputed default centroids. Operator examples
are optional and extend the defaults. Those vectors are valid only for the
pinned model and tokenizer revision, so a digest mismatch fails classifier
construction. See
[the evaluation report](ai-default-centroids-evaluation.md) for the exact
pins, measured class precision and recall, and deterministic regeneration
method.

For a configuration covering input scope, output streaming behavior,
taxonomies, and metrics, see
[ai-safety-classifiers](../examples/ai-safety-classifiers/). The normative
field table is [Safety guardrail modes](configuration.md#safety-guardrail-modes).

## Metrics and usage tracking

Local inference and the semantic cache emit `sbproxy_*` metrics, attributed per
tenant where relevant (see [metrics-stability.md](./metrics-stability.md)):

| Metric | What it tells you |
|---|---|
| `sbproxy_semantic_cache_results_total{tenant,origin,source,result}` | Cache hit / miss / error rate by embedding source |
| `sbproxy_inference_requests_total{kind,backend,model,result}` | Embed and classify call counts |
| `sbproxy_inference_duration_seconds{kind,backend,model}` | Embed and classify latency |
| `sbproxy_ai_safety_guardrail_verdicts_total{guardrail,class,backend,verdict}` | Safety verdicts and whether they came from the keyword or classifier path |
| `sbproxy_ai_tokens_saved_total{tenant,origin,model,kind}` | Tokens a cache hit avoided |
| `sbproxy_ai_cost_saved_micros_total{tenant,origin,model}` | Micro-USD a cache hit avoided |

The saved-cost metric uses the same cost table as spent cost, so a dashboard can
show spend and savings side by side and they reconcile. Saved cost is the value
the cache delivered, not just its hit rate.

## Troubleshooting

- **Cache never hits.** Confirm the sidecar is up and `--embed-model` is loaded
  (`sbproxy_inference_requests_total{kind="embed"}` should increment). Lower
  `threshold` if near-duplicates are scored just under it.
- **`Embed` returns FAILED_PRECONDITION.** The sidecar has no embedding model
  loaded. Start it with `--embed-model`.
- **Classify always allows.** Check the `injection_label` matches the model's
  label set, and that `--model` is loaded on the sidecar.
- **Dimension mismatch after a model change.** The cache skips entries with a
  different vector length and logs a warning once. Clear the cache (restart) or
  let entries age out via `ttl_secs`.
- **In-process load fails fast.** The model exceeds `max_model_bytes`. Raise the
  guard or use the sidecar.
