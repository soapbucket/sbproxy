# OpenAI-compatible embedding semantic cache

Serves near-duplicate AI prompts from cache, vectorizing prompts via any
OpenAI-compatible `/v1/embeddings` endpoint (`source: openai`). Unlike `source:
provider`, the endpoint is not one of this origin's chat providers, so you can
point it at another sbproxy that fronts an embedding model, at OpenRouter, or at
any hosted provider, each with its own URL and key.

## Run

```bash
make run CONFIG=examples/semantic-cache-openai/sb.yml
```

Send two near-duplicate prompts; the second is served from cache (`x-semcache:
HIT`) with no second upstream call. Watch `sbproxy_semantic_cache_results_total`
(the `source` label reads `openai`) and the savings counters
`sbproxy_ai_tokens_saved_total` / `sbproxy_ai_cost_saved_micros_total`.

## Auth

Auth defaults to `Authorization: Bearer ${api_key}`. For endpoints that expect a
different header (Azure `api-key`, an `x-api-key` gateway), set `auth_header` and
clear `auth_prefix`:

```yaml
auth_header: api-key
auth_prefix: ""
```

Endpoints that need extra headers (such as OpenRouter's `HTTP-Referer` /
`X-Title`) take a `headers` list, sent verbatim. For header-only auth, omit
`api_key` and carry the credential in `headers`.

See [docs/local-inference.md](../../docs/local-inference.md) for the full recipe.
For an on-box embedder with no egress, see
[semantic-cache-local](../semantic-cache-local/sb.yml).
