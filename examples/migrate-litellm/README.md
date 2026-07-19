# Migrate off LiteLLM

*Last modified: 2026-07-06*

![Migrate off LiteLLM](../../docs/assets/migrate-litellm.gif)

A before-and-after pair for [docs/migration-litellm.md](../../docs/migration-litellm.md). `config.yaml` is a small LiteLLM proxy config: two models with rate caps, latency routing, caching, a budget kwarg, and a master key. `sb.yml` is what `sbproxy config import-litellm` produces from it, annotated so you can trace every field back to its LiteLLM source. A clean `max_budget` emits an action-level `budget:` block; `master_key` still warns for manual auth setup, and the comments in `sb.yml` show where that warning lands.

## Re-run the import yourself

```bash
cd examples/migrate-litellm
sbproxy config import-litellm config.yaml
```

The translated config prints to stdout and one warning prints to stderr, ending with `1 key(s) need manual attention`. The committed `sb.yml` is that stdout plus comments, nothing else. Prove it:

```bash
diff <(sbproxy config import-litellm config.yaml 2>/dev/null) \
     <(grep -vE '^[[:space:]]*(#|$)' sb.yml)
```

An empty diff means the file you are reading is exactly what the importer wrote.

## Run the migrated config

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
sbproxy sb.yml
```

Then send an OpenAI-shaped request:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Say hi."}]}'
```

Expect a 200 with a chat completion body: `choices[0].message.content` holds the answer and `usage.total_tokens` is filled in. The public name `gpt-4` reaches OpenAI's `gpt-4o-mini` through the imported `model_map`; `"model": "claude"` reaches Anthropic the same way.

## Run both proxies side by side

```bash
docker compose up
```

This starts LiteLLM (from `config.yaml`) on port 4000 and SBproxy (from `sb.yml`) on port 8080. Send the same request to both and diff the response shape:

```bash
REQ='{"model": "gpt-4", "messages": [{"role": "user", "content": "Say hi."}]}'

diff <(curl -s http://127.0.0.1:4000/v1/chat/completions \
        -H "Authorization: Bearer ${LITELLM_MASTER_KEY:-sk-1234}" \
        -H 'Content-Type: application/json' -d "$REQ" | jq 'keys') \
     <(curl -s http://127.0.0.1:8080/v1/chat/completions \
        -H 'Host: ai.local' \
        -H 'Content-Type: application/json' -d "$REQ" | jq 'keys')
```

Both sides return the OpenAI chat completion shape, so the diff of the top-level keys is empty. Note the auth difference: LiteLLM requires its master key on every request, while the imported SBproxy config accepts anonymous clients until you add `virtual_keys` or a `credentials` block (that is exactly what the importer's `master_key` warning is about).

## See also

- [docs/migration-litellm.md](../../docs/migration-litellm.md) - the full migration story this pair belongs to
- [examples/ai-virtual-keys](../ai-virtual-keys/) - per-team keys, the follow-up for `master_key`
- [examples/ai-budget](../ai-budget/) - budget enforcement shapes beyond the imported `budget:` window
