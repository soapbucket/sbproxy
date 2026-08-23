# Local inference for gateway helper models
*Last modified: 2026-08-21*

SBproxy can run four AI-gateway features on local ONNX models instead of paid
APIs:

- The **embedding semantic cache** vectorizes prompts to serve near-duplicate
  requests from cache.
- **Prompt-injection v2** classifies prompts for injection attempts.
- The **embedding classifier guardrail** maps prompts onto operator-defined
  classes that can feed model-routing policy.
- **Context token pruning** removes lower-value source tokens from explicitly
  marked retrieval text through the classifier sidecar.

For running a full **LLM** locally (the gateway pulls weights, fits an engine
to the GPU, and supervises it), see [model-host.md](model-host.md). This page
covers the four ONNX auxiliary features; the model host covers chat/completion
serving.

Running these locally means no per-call API cost, no prompt egress (the prompt
never leaves your network), low loopback latency, and air-gap support. Models
run on a pure-Rust engine (`tract`), so there is no Python and no native
ONNX Runtime install.

There are two ways to run local inference:

- **Sidecar (recommended).** A small co-located process holds the model. A bad
  model can only crash the sidecar, which your service manager can restart; it
  never takes the proxy down.
- **In-process.** The model loads inside the proxy for a true single binary.
  Prompt-injection can select it automatically from a complete verified
  artifact pair; operators can also select it explicitly. Model parsing runs
  in the proxy address space, so size and integrity checks run first.

## Models

| Use | Default model | License | Size |
|---|---|---|---|
| Embeddings | `all-MiniLM-L6-v2` (384-dim) | Apache-2.0 | ~90 MB |
| Prompt-injection classify | No built-in default | Operator-reviewed; Apache-2.0 or MIT recommended | 200 MiB default maximum |
| Context token pruning | No built-in default | Operator-reviewed; Apache-2.0 or MIT recommended | 200 MiB default maximum |

These model files are operator-supplied runtime data, not bundled with the
binary. Download them once and point the sidecar, or the in-process config
where supported, at the files.

### Download the models

```bash
mkdir -p /var/lib/sbproxy/models/minilm /var/lib/sbproxy/models/injection

# Embedding model (all-MiniLM-L6-v2)
curl -fSL -o /var/lib/sbproxy/models/minilm/model.onnx \
  https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/5641a7880f40ebf4035d05e60c5f9b7a9c272c84/onnx/model.onnx
curl -fSL -o /var/lib/sbproxy/models/minilm/tokenizer.json \
  https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/5641a7880f40ebf4035d05e60c5f9b7a9c272c84/tokenizer.json

```

There is deliberately no copy-paste prompt-injection download URL. The model
audit found that first-party, clearly licensed candidates were larger than the
unchanged 200 MiB default, while smaller community exports lacked sufficient
artifact provenance or weight licensing. Do not stage a moving
`resolve/main` artifact for automatic security enforcement. Choose an
immutable, reviewed model/tokenizer pair, record both SHA-256 digests, confirm
its label order, and then copy it into place.

Air-gapped sites follow the same process on a connected host before transfer.
In-process prompt-injection loading always requires both SHA-256 pins (either
in config or from a complete trusted registry entry); a local file is never
trusted merely because it exists.

## Run the sidecar

The sidecar binary is `sbproxy-classifier-sidecar`. It serves `Classify`,
`Embed`, and `Compress` over gRPC on TCP or a Unix domain socket. Load whichever
models you need:

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

### Bounds on `Classify` and `Embed`

Both RPCs hand caller-supplied text to a synchronous model on the blocking
pool, so both are bounded whether or not you pass a flag. The command above
sets none of these and still runs inside them:

| Flag | Default | Hard ceiling | What it limits |
|---|---:|---:|---|
| `--inference-max-request-bytes` | 1,048,576 | 16 MiB | Exact encoded protobuf size of one `Classify` or `Embed` request |
| `--inference-max-items` | 64 | 4,096 | Texts in one `Embed` batch |
| `--inference-max-concurrent` | this host's available parallelism, held between 4 and 64 | 64 | Classifications running at once, and separately embeddings |
| `--inference-max-queued` | 8 per running slot | 1,024 | Requests waiting behind running inference |
| `--inference-timeout-ms` | 30,000 | 600,000 | One request from arrival to answer, including its wait for a running slot |

The two concurrency defaults are derived from the host rather than fixed,
because one classification is one thread until it returns and a literal
would be wrong on every machine but the one that produced it. `--help`
prints the numbers this host resolved them to. A request over any of these
bounds comes back `RESOURCE_EXHAUSTED` or `DEADLINE_EXCEEDED`, which the
proxy treats as a failed call and routes through the calling policy's
`failure_posture`. See
[classifier-sidecar.md](classifier-sidecar.md#3-request-limits-and-load-shedding)
for the status each bound returns and for the per-reason refusal counters.

### Run token pruning

Token pruning needs an operator-supplied LLMLingua-2-compatible ONNX token
classifier and its matching Hugging Face tokenizer. The runtime submits one
item at a time. The model's batch axis may therefore be a fixed `1`, a
symbolic dynamic dimension, or an unspecified dynamic dimension. Its output
must be `f32` logits with a final dimension of `2`; class index 1 is the
probability that the source token should remain. Review the artifact license
and provenance, pin its digest in your deployment manifest, and stage it
before starting the sidecar.

The tokenizer must use one of the two official LLMLingua-2 layouts:

- mBERT: cased `BertNormalizer`, `BertPreTokenizer`, and `WordPiece`.
- XLM-R: `Precompiled`, then `WhitespaceSplit` and always-prepended
  `Metaspace`, with a `Unigram` model.

Both layouts must add exactly two model special tokens for a single input.
The sidecar rejects other tokenizer layouts and non-special added tokens at
load time. This boundary-separable contract is what lets it enforce a token
target with bounded work.

```bash
sbproxy-classifier-sidecar \
  --listen 127.0.0.1:9440 \
  --token-model llmlingua-2=/var/lib/sbproxy/models/llmlingua-2/model.onnx:/var/lib/sbproxy/models/llmlingua-2/tokenizer.json:512 \
  --default-token-model llmlingua-2 \
  --token-model-max-bytes 750000000 \
  --token-max-request-bytes 1048576 \
  --token-max-request-tokens 131072 \
  --token-max-windows 256 \
  --token-max-model-window 512 \
  --token-max-concurrent 2 \
  --token-max-queued 8
```

The last value in `--token-model` is the classifier's total token window,
including two special tokens. It must be at least 3. Repeat `--token-model` to
serve more than one reviewed model. `--default-token-model` is optional when
only one token model is loaded, and an explicit `compression.levers[].model`
still selects the requested ID. Model IDs are limited to 256 UTF-8 bytes.

The standard model-file limit is 209,715,200 bytes. A typical float32 mBERT
LLMLingua-2 ONNX export is about 709 MB, so the command raises only that limit
to 750,000,000 bytes. Set the smallest value that admits your pinned artifact.
The remaining flags spell out the defaults so the `Compress` half of the
deployment's resource envelope is visible; the `Classify` and `Embed` half
is the `--inference-*` table above:

| Flag | Default | Hard ceiling | What it limits |
|---|---:|---:|---|
| `--token-model-max-bytes` | 209,715,200 | 4 GiB | Each token-model ONNX file at load time |
| `--token-max-request-bytes` | 1,048,576 | 16 MiB | Exact encoded protobuf size of one `Compress` request, including model ID, text, target, and framing |
| `--token-max-request-tokens` | 131,072 | 1,000,000 | Tokenizer output for one request |
| `--token-max-windows` | 256 | 4,096 | Model windows evaluated for one request |
| `--token-max-model-window` | 512 | 4,096 | Window declared by a `--token-model` entry |
| `--token-max-concurrent` | 2 | 64 | Token-compression inferences running at once |
| `--token-max-queued` | 8 | 1,024 | Requests waiting behind active inference |

`--token-max-queued 0` disables waiting. Requests beyond the active and queued
limits fail at this lever instead of growing sidecar memory without a bound.
The gRPC decoder is shared by every RPC and admits the larger of 4 MiB and
the biggest configured per-RPC byte budget, so raising either
`--token-max-request-bytes` or `--inference-max-request-bytes` above 4 MiB
raises the decoder envelope to match, and neither one lowers it. Decoding is
not acceptance: after the message decodes, `Compress` enforces the exact size
shown in the table and `Classify` and `Embed` enforce their own
`--inference-max-request-bytes`, which defaults to 1 MiB. A 3 MiB `Classify`
therefore decodes and is then refused with `RESOURCE_EXHAUSTED` unless you
raise that flag.

The sidecar divides longer text into punctuation-aware windows, scores
subtokens, averages their scores for each source word, and reconstructs output
from source spans. If reconstructed punctuation changes the tokenizer count,
the sidecar performs at most 24 tokenizer measurements and returns only a
result within the requested token target. The proxy sends only marked
`format="text"` chunk bodies. JSON and tabular chunks do not reach the model.
Configure the route's `token_prune` lever as shown in
[AI context compression](ai-context-compression.md#sidecar-token-pruning).
If the sidecar is unavailable or returns an invalid extractive result, that
lever fails open and the next compression lever runs.

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
          fallback:
            model_path: /var/lib/sbproxy/models/injection/model.onnx
            tokenizer_path: /var/lib/sbproxy/models/injection/tokenizer.json
            model_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
            tokenizer_sha256: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
            labels: ["SAFE", "INJECTION"]
            injection_label: INJECTION
```

An explicit `detector: sidecar` makes the sidecar primary and requires the
verified local ONNX `fallback`; every primary transport, timeout, RPC,
admission, or response-validation failure runs that fallback instead of
admitting an unscored request. If `detector` is omitted instead, SBproxy
attempts verified in-process auto-selection and uses `heuristic-v1` only when
both resolved local artifacts are absent.

## Verified in-process selection

For a single binary, run either feature in-process. This loads a model into the
proxy address space. SBproxy enforces size and integrity checks before parsing;
prefer the sidecar when process isolation matters.

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
        # Omit detector for verified auto-selection. Use
        # detector: inprocess to require this mode explicitly.
        detector_config:
          model_path: /var/lib/sbproxy/models/injection/model.onnx
          tokenizer_path: /var/lib/sbproxy/models/injection/tokenizer.json
          model_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          tokenizer_sha256: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
          labels: [SAFE, INJECTION]
          injection_label: INJECTION
          max_model_bytes: 209715200   # 200 MB guard
          max_tokenizer_bytes: 209715200
          max_concurrent: 2            # 1..=64
          max_queued: 16               # 1..=1024
          inference_timeout_ms: 500    # 1..=30000
```

Configured paths take precedence. With no paths configured, auto-selection
checks `<user-cache-dir>/sbproxy/models/prompt-injection-v2/model.onnx` and
`tokenizer.json` (falling back to
`./.sbproxy-cache/models/prompt-injection-v2/`). Both absent selects the
heuristic with one startup log. A partial pair, unreadable or oversize file,
missing/mismatched digest, incomplete signature group, or parse error stops
startup. An explicit `detector: heuristic-v1` skips artifact inspection.

The local prompt-injection runtime validates its concurrency, queue, and
deadline limits before creating Tokio primitives. Request-time admission,
deadline, worker, runtime, and inference failures remain typed unavailable.
They fail closed with a generic `503` under `action: block`, or continue as
explicitly degraded under `tag` and `log`; none is cached as a clean verdict.

Optional detached Ed25519 verification adds
`model_signature_path`, `tokenizer_signature_path`, and
`signature_public_key`; configure all three or none. See
[prompt-injection-v2.md](prompt-injection-v2.md) for the full failure contract
and latency-measurement status.

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

The model is not bundled. Before enabling classifier mode, run the pinned
[MiniLM download commands](#download-the-models), which place `model.onnx` and
`tokenizer.json` under `/var/lib/sbproxy/models/minilm/`. The runnable
[ai-safety-classifiers example](../examples/ai-safety-classifiers/) points its
`model_path` and `tokenizer_path` at those files.

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
