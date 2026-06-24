# Semantic cache (OpenAI-compatible embeddings)

*Last modified: 2026-06-24*

![sbproxy serving a reworded prompt from the semantic cache with x-semcache: HIT](../../docs/assets/semantic-cache.gif)

Serves near-duplicate AI prompts from cache. Each prompt is embedded and, on a cache hit (cosine similarity above the threshold), the stored completion is replayed instead of calling the provider, so the slow, billable completion is skipped and the response carries `x-semcache: HIT`.

This example vectorizes prompts via any OpenAI-compatible `/v1/embeddings` endpoint (`source: openai`). It defaults to OpenAI itself so it runs with just `OPENAI_API_KEY`; point `base_url` at another sbproxy that fronts an embedding model, at OpenRouter, or at any hosted provider to decouple it from this origin's chat provider.

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/semantic-cache-openai/sb.yml
```

## Try it

The first prompt is a cache miss (real provider round-trip). The second, reworded one matches on meaning and is served from cache:

```bash
# MISS - real completion
$ curl -s -D - -o /dev/null http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"What are the benefits of caching?"}]}' \
    -w 'roundtrip=%{time_total}s\n' | grep -iE 'x-semcache|roundtrip'
roundtrip=2.24s

# HIT - reworded, served from cache, no completion call
$ curl -s -D - -o /dev/null http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize the benefits of caching."}]}' \
    -w 'roundtrip=%{time_total}s\n' | grep -iE 'x-semcache|roundtrip'
x-semcache: HIT
roundtrip=0.55s
```

Watch `sbproxy_semantic_cache_results_total` (the `source` label reads `openai`) and the savings counters `sbproxy_ai_tokens_saved_total` / `sbproxy_ai_cost_saved_micros_total`.

## Auth (for non-OpenAI embedding endpoints)

Auth defaults to `Authorization: Bearer ${api_key}`. For endpoints that expect a different header (Azure `api-key`, an `x-api-key` gateway), set `auth_header` and clear `auth_prefix`:

```yaml
auth_header: api-key
auth_prefix: ""
```

Endpoints that need extra headers (such as OpenRouter's `HTTP-Referer` / `X-Title`) take a `headers` list, sent verbatim. For header-only auth, omit `api_key` and carry the credential in `headers`.

See [docs/local-inference.md](../../docs/local-inference.md) for the full recipe. For an on-box embedder with no egress, see [semantic-cache-local](../semantic-cache-local/sb.yml).
