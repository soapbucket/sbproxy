# Local embedding semantic cache

*Last modified: 2026-07-09*

Serves near-duplicate AI prompts from cache, vectorizing prompts on-box via the
classifier sidecar instead of a paid provider embedding API. No per-call cost,
no prompt egress, low loopback latency.

## Run

Start the sidecar with an embedding model (supply your own ONNX model and
tokenizer; the OSS build ships no weights):

```bash
cargo run -p sbproxy-classifier-sidecar -- \
  --listen 127.0.0.1:9440 \
  --embed-model all-MiniLM-L6-v2=/models/minilm/model.onnx:/models/minilm/tokenizer.json
```

Then the proxy. The provider block in `sb.yml` reads `${OPENAI_API_KEY}`:

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/semantic-cache-local/sb.yml
```

Send two near-duplicate prompts; the second is served from cache (`x-semcache:
HIT`) with no second upstream call. Watch `sbproxy_semantic_cache_results_total`,
`sbproxy_inference_requests_total{kind="embed"}`, and the savings counters
`sbproxy_ai_tokens_saved_total` / `sbproxy_ai_cost_saved_micros_total`.

See [docs/local-inference.md](../../docs/local-inference.md) for the in-process
option and the full metric set.
