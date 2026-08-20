# Connect Codex to a governed gateway

*Last modified: 2026-08-19*

Codex CLI's config format makes it easy to point at any OpenAI-compatible endpoint. That is also exactly what a generic multi-provider proxy needs: no per-key budgets, no attribution, no guardrails on the prompt, nothing recording what got spent. This page connects Codex to SBproxy instead, so the same base-URL change also buys per-key budgets, prompt guardrails, a local-model alias under the same endpoint, and a signed usage ledger.

## What to set

Codex reads a shared config at `~/.codex/config.toml`. Two ways to point it at SBproxy, in increasing order of control:

- `openai_base_url` changes the built-in `openai` provider's base URL. Simplest, and enough if you only ever call OpenAI-shaped models through the gateway.
- A `[model_providers.sbproxy]` block defines a distinct named provider, which is the better fit here since SBproxy is not literally OpenAI: it lets a governed-model completion coexist with a direct-OpenAI provider if you keep one.

`model_providers` only takes effect in the user-level `~/.codex/config.toml`; Codex ignores it in a project-local `.codex/config.toml` and warns at startup.

```toml
# ~/.codex/config.toml
model_provider = "sbproxy"

[model_providers.sbproxy]
name = "sbproxy"
base_url = "http://localhost:8080/v1"
env_key = "SBPROXY_API_KEY"
wire_api = "chat"
```

`wire_api = "chat"` matters. SBproxy's `ai_proxy` action does serve `/v1/responses`, but only for stateless requests: Codex's Responses mode leans on OpenAI-side response storage (`previous_response_id`, `store`), which the gateway refuses with a 400 rather than silently running without the stored turns. The chat-completions wire on `POST /v1/chat/completions` resends the full conversation every turn, so it works end to end through the gateway.

## Wire format

OpenAI chat-completions (`POST /v1/chat/completions`). SBproxy's `ai_proxy` action classifies this natively and can also translate the same request to Anthropic Messages format for another origin, but Codex only needs the OpenAI wire.

## A governed gateway, not just a proxy

The `sb.yml` below is the same shape as [use-case-own-openrouter.md](use-case-own-openrouter.md) and its runnable [`examples/use-case-own-openrouter/`](../examples/use-case-own-openrouter/): one data-plane port, dynamic key management so keys are a runtime resource instead of lines in a file, and a budget plus a usage ledger. Save it and start the gateway before touching Codex.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/soapbucket/sbproxy/main/schemas/sb-config.schema.json
proxy:
  http_bind_port: 8080

  admin:
    enabled: true
    port: 9090
    username: admin
    password: admin   # demo credentials; change both before any real use

  key_management:
    enabled: true
    store:
      backend: embedded
      path: /tmp/sbproxy-codex-keys.redb
    cache:
      ttl_secs: 60
    crypto:
      pepper: demo-pepper-not-for-production
      master_key: demo-master-not-for-production
    failure_posture: closed

origins:
  "localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          default_model: gpt-4o-mini
          models:
            - gpt-4o-mini

      budget:
        on_exceed: block
        limits:
          - scope: api_key
            max_tokens: 200000
            period: daily

      usage_sinks:
        - type: ledger
          path: /tmp/sbproxy-codex-ledger.jsonl
```

Start it:

```bash
export OPENAI_API_KEY=sk-...
sbproxy serve -f sb.yml
```

## Mint a key for Codex

```bash
curl -s -u admin:admin -X POST http://127.0.0.1:9090/admin/keys \
    -H 'Content-Type: application/json' \
    -d '{"name":"codex-cli"}'
```

The response's `token` field is the plaintext credential, returned exactly once. Export it as the variable `config.toml` names in `env_key`:

```bash
export SBPROXY_API_KEY=sk-...
```

Run `codex` as usual. Its requests now carry your SBproxy key, land on `gpt-4o-mini` through your own gateway, and get counted against the `codex-cli` key's daily budget.

## The payoff

Every request Codex sends is now attributed to the `codex-cli` key by name in the usage ledger (`sbproxy ai ledger verify` proves the file has not been edited after the fact), covered by whatever guardrails you attach to the origin (PII redaction, prompt-injection classifiers, external moderation adapters), and stopped at `402` the moment the daily budget is spent rather than quietly running up a bill. Add a `serve:` block naming a local model and give it the same alias as a hosted one, and Codex switches to your own GPU with no client-side change at all: see [use-case-coding-assistant.md](use-case-coding-assistant.md) for that half.

## Next steps

- [use-case-own-openrouter.md](use-case-own-openrouter.md) - the full governed-gateway walkthrough: key lifecycle, budget behavior, and ledger verification with captured output
- [use-case-coding-assistant.md](use-case-coding-assistant.md) - point the same alias at a model running on your own GPU
- [key-management.md](key-management.md) - key lifecycle, rotation, and per-key policy
- [ai-gateway.md](ai-gateway.md) - the provider array, routing, guardrails, and budget reference
- [configuration.md](configuration.md) - the full configuration schema
