# Local inference (embeddings and prompt-injection classify)
*Last modified: 2026-06-08*

SBproxy can run two AI-gateway features on local ONNX models instead of paid
APIs:

- The **embedding semantic cache** vectorizes prompts to serve near-duplicate
  requests from cache.
- **Prompt-injection v2** classifies prompts for injection attempts.

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
  https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx
curl -fSL -o /var/lib/sbproxy/models/minilm/tokenizer.json \
  https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/tokenizer.json

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

Point the `semantic_cache` block at the sidecar with `source: sidecar`:

```yaml
ai:
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

## Enable first-class ONNX prompt-injection

Select the sidecar detector in the `prompt_injection_v2` policy:

```yaml
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

Prompt-injection in-process:

```yaml
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

The in-process embedding source for the semantic cache (`source: inprocess`) is
parsed but not yet wired into the default build; use `source: sidecar` for now.

## Metrics and usage tracking

Local inference and the semantic cache emit `sbproxy_*` metrics, attributed per
tenant where relevant (see [metrics-stability.md](./metrics-stability.md)):

| Metric | What it tells you |
|---|---|
| `sbproxy_semantic_cache_results_total{tenant,origin,source,result}` | Cache hit / miss / error rate by embedding source |
| `sbproxy_inference_requests_total{kind,backend,model,result}` | Embed and classify call counts |
| `sbproxy_inference_duration_seconds{kind,backend,model}` | Embed and classify latency |
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
