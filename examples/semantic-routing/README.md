# AI gateway: semantic (embedding-similarity) routing

*Last modified: 2026-08-20*

The `semantic_route` strategy routes on what a request means. Each deployment declares its specialty as a few exemplar prompts. The proxy embeds the request's final user message once, cosine-matches it against the exemplar vectors, and pins the best-scoring deployment when the score clears `min_similarity`. Anything that cannot be matched (a below-floor score, a request with no user message, an embedder outage) routes to the declared `fallback` deployment instead of erroring.

This example declares two pools: `code-pool`, serving a code model, and `chat-pool`, a general-conversation replica. Exemplar texts embed once per process on first use; after that the strategy costs one embedding call per request.

## Run

Every upstream is loopback, so this runs with no keys and no network. `fixture.py` stands in for all three: an embedding endpoint on 18091 and the two pools on 18092 and 18093.

```bash
python3 examples/semantic-routing/fixture.py
make run CONFIG=examples/semantic-routing/sb.yml LOG_LEVEL='info,sbproxy_core::server::ai_dispatch=debug'
```

Routing decisions log at `debug` because they fire once per request, which is why the log level above widens that one target. The durable per-request record is the `routing_detail` field on the admin request log, which the console's request detail renders as **Routing detail**; the counters below are the durable aggregate.

The stand-in embedder is a three-axis topic projection, not a language model, so the scores below are a property of that toy and a real embedding model gives different numbers for the same prompts. The decisions the proxy makes from those scores are the real thing. For a real deployment, point `openai.base_url` at your embedding provider, drop `allow_private_base_url`, and point the two pools at your own replicas.

## Try it

A code question. Its embedding sits close to `code-pool`'s exemplars, so the request pins that pool:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{
    "messages": [{"role": "user",
      "content": "Explain this Rust stack trace and help me fix the borrow checker error"}]
  }'
```

```json
{"id": "chatcmpl-code-pool", "object": "chat.completion", "created": 0, "model": "code-pool", "choices": [{"index": 0, "message": {"role": "assistant", "content": "answered by code-pool"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
```

The proxy logs the decision with the winning exemplar and its score. `exemplar=2` is the third exemplar `code-pool` declared, `Explain what this stack trace means and how to fix it`:

```
DEBUG sbproxy_core::server::ai_dispatch: semantic routing selected deployment event="ai.semantic_route.route" deployment=code-pool exemplar=2 score=0.9996442198753357 floor=0.75
```

A conversational request lands on the other pool the same way:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{
    "messages": [{"role": "user",
      "content": "Help me write a short, polite thank you note to a colleague"}]
  }'
```

```
DEBUG sbproxy_core::server::ai_dispatch: semantic routing selected deployment event="ai.semantic_route.route" deployment=chat-pool exemplar=1 score=0.9935280084609985 floor=0.75
```

## The below-floor fallback

A request neither pool specializes in scores under the floor and routes to `fallback` rather than to the least-bad match:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{
    "messages": [{"role": "user",
      "content": "Which are the tallest mountains in South America and what is the elevation of each?"}]
  }'
```

```
DEBUG sbproxy_core::server::ai_dispatch: no exemplar cleared the similarity floor; routing to the default event="ai.semantic_route.fallback" reason="below_floor" best_deployment=chat-pool best_score=0.21087251603603363 floor=0.75
```

The request still gets an answer, from the declared fallback:

```json
{"id": "chatcmpl-chat-pool", "object": "chat.completion", "created": 0, "model": "chat-pool", "choices": [{"index": 0, "message": {"role": "assistant", "content": "answered by chat-pool"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
```

The near-miss score and the deployment that came closest are both reported, so you can tune `min_similarity` against real traffic rather than guessing.

## When the embedder is down

Restart the stand-ins with the embedding port unbound and send the code question again:

```bash
python3 examples/semantic-routing/fixture.py --no-embedder
```

```
WARN sbproxy_core::server::ai_dispatch: semantic routing embedder unavailable (fail-open to the default) event="ai.semantic_route.fallback" reason="embed_error" failure="embedding_unavailable"
```

```json
{"id": "chatcmpl-chat-pool", "object": "chat.completion", "created": 0, "model": "chat-pool", "choices": [{"index": 0, "message": {"role": "assistant", "content": "answered by chat-pool"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
```

The request that could not be scored still routes and still answers. An embedding outage shows up as a counted fallback rather than as failed requests, which is the difference between a routing hint and a dependency.

## Metrics

`/metrics` after the four requests above:

```
sbproxy_ai_semantic_route_decisions_total{outcome="matched"} 2
sbproxy_ai_semantic_route_decisions_total{outcome="below_floor"} 1
sbproxy_ai_semantic_route_decisions_total{outcome="embed_error"} 1
sbproxy_ai_routing_fallbacks_total{reason="below_floor",strategy="semantic_route"} 1
sbproxy_ai_routing_fallbacks_total{reason="embed_error",strategy="semantic_route"} 1
sbproxy_ai_semantic_route_similarity_sum{provider="code-pool"} 0.9996442198753357
sbproxy_ai_semantic_route_similarity_count{provider="code-pool"} 1
sbproxy_ai_semantic_route_similarity_sum{provider="chat-pool"} 1.2044005244970322
sbproxy_ai_semantic_route_similarity_count{provider="chat-pool"} 2
```

`no_prompt` and `target_ineligible` are the two outcomes this walkthrough does not reach: the first is a request with no user message to embed (a transcription upload, a DELETE), the second is a match whose deployment was filtered out of that request by credential policy, model eligibility, the training opt-out, or health.

The similarity histogram is labeled by the best-scoring deployment and records matched and below-floor requests both, which is what makes it the right place to look when choosing a floor. `chat-pool`'s two observations here are the 0.9935 match and the 0.2109 near miss; the score itself is never a label.

## Notes

- The embedding source is required. A `semantic_route` block without one fails config compile with a named error rather than degrading at runtime.
- Route deployments, the `fallback`, and `embedding.provider` (for `source: provider`) must all name entries in `providers`; unknown names fail config compile the way cascade tiers do.
- Declared `centroid` vectors can stand in for exemplar texts when you precompute embeddings offline; they never trigger an embedding call.
