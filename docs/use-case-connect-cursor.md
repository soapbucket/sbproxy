# Connect Cursor to a governed gateway

*Last modified: 2026-08-02*

Cursor's "Override OpenAI Base URL" setting redirects its OpenAI-key traffic to any OpenAI-compatible endpoint, which is enough to reach a generic multi-provider proxy but buys nothing beyond it: no per-key budgets, no attribution, no guardrails on the prompt. This page points that same setting at SBproxy, so the base-URL change also buys per-key budgets, prompt guardrails, a local-model alias under the same endpoint, and a signed usage ledger.

## What to set

Open Cursor Settings (`Cmd+,` / `Ctrl+,`) and go to **Models**. At the top of the section:

- **Override OpenAI Base URL**: `http://localhost:8080/v1` (Cursor appends `/chat/completions` itself, so stop at `/v1`)
- **OpenAI API Key**: paste your SBproxy virtual key here. The field says "OpenAI," but whatever you enter is sent to the endpoint above, not to OpenAI.

This override applies to Cursor's AI panel (chat and agent mode). Tab autocomplete and inline edit still use Cursor's own backend regardless of this setting.

## Wire format

OpenAI chat-completions (`POST /v1/chat/completions`). SBproxy's `ai_proxy` action serves this natively.

## A governed gateway, not just a proxy

The `sb.yml` below is the same shape as [use-case-own-openrouter.md](use-case-own-openrouter.md): one data-plane port, dynamic key management, and a budget plus a usage ledger. Save it and start the gateway before touching Cursor's settings.

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
      path: /tmp/sbproxy-cursor-keys.redb
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
          path: /tmp/sbproxy-cursor-ledger.jsonl
```

Start it:

```bash
export OPENAI_API_KEY=sk-...
sbproxy serve -f sb.yml
```

## Mint a key for Cursor

```bash
curl -s -u admin:admin -X POST http://127.0.0.1:9090/admin/keys \
    -H 'Content-Type: application/json' \
    -d '{"name":"cursor-editor"}'
```

Paste the returned `token` into Cursor's "OpenAI API Key" field alongside the base URL above. Cursor's requests now carry it, land on `gpt-4o-mini` through your own gateway, and get counted against the `cursor-editor` key's daily budget.

## The payoff

Every request Cursor sends is now attributed to the `cursor-editor` key by name in the usage ledger (`sbproxy ai ledger verify` proves the file has not been edited after the fact), covered by whatever guardrails you attach to the origin, and stopped at `402` the moment the daily budget is spent. Add a `serve:` block naming a local model and give it the same alias as a hosted one, and Cursor switches to your own GPU with no further client-side change: see [use-case-coding-assistant.md](use-case-coding-assistant.md) for that half.

## Next steps

- [use-case-own-openrouter.md](use-case-own-openrouter.md) - the full governed-gateway walkthrough: key lifecycle, budget behavior, and ledger verification with captured output
- [use-case-coding-assistant.md](use-case-coding-assistant.md) - point the same alias at a model running on your own GPU
- [key-management.md](key-management.md) - key lifecycle, rotation, and per-key policy
- [ai-gateway.md](ai-gateway.md) - the provider array, routing, guardrails, and budget reference
- [configuration.md](configuration.md) - the full configuration schema
