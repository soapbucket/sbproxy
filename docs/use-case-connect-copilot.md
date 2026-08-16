# Connect GitHub Copilot to a governed gateway

*Last modified: 2026-08-16*

GitHub Copilot's bring-your-own-key (BYOK) support lets you register an OpenAI-compatible endpoint with an API key and use it in place of Copilot's own models. That is enough to reach a generic multi-provider proxy but buys nothing beyond it: no per-key budgets, no attribution, no guardrails on the prompt. This page registers SBproxy as that endpoint, so the same setup also buys per-key budgets, prompt guardrails, a local-model alias under the same endpoint, and a signed usage ledger.

BYOK configuration is per surface: VS Code Chat, the Copilot app, JetBrains, and Copilot CLI each have their own settings screen or environment variables, and where a given surface lands changes release to release. What follows is the VS Code path; the same base URL and key work anywhere else Copilot accepts a custom OpenAI-compatible provider, including Copilot CLI via environment variables.

## What to set

In VS Code, open Copilot Chat's model picker and add a custom model provider (Settings → GitHub Copilot → Model Providers, or the equivalent BYOK entry point in your installed version). Register:

- **Base URL**: `http://localhost:8080/v1`
- **API Key**: your SBproxy virtual key
- **Model**: `gpt-4o-mini` (or whatever alias your `sb.yml` names)

BYOK model usage is billed by the provider behind the endpoint, not counted against your Copilot request quota, which is exactly what SBproxy's budget and ledger exist to track instead.

## Wire format

OpenAI chat-completions (`POST /v1/chat/completions`). SBproxy's `ai_proxy` action serves this natively.

## A governed gateway, not just a proxy

The `sb.yml` below is the same shape as [use-case-own-openrouter.md](use-case-own-openrouter.md): one data-plane port, dynamic key management, and a budget plus a usage ledger. Save it and start the gateway before registering the provider in Copilot.

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
      path: /tmp/sbproxy-copilot-keys.redb
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
          path: /tmp/sbproxy-copilot-ledger.jsonl
```

Start it:

```bash
export OPENAI_API_KEY=sk-...
sbproxy serve -f sb.yml
```

## Mint a key for Copilot

```bash
curl -s -u admin:admin -X POST http://127.0.0.1:9090/admin/keys \
    -H 'Content-Type: application/json' \
    -d '{"name":"copilot-vscode"}'
```

Register the returned `token` as the BYOK provider's API key alongside the base URL and model above. Copilot's requests through that provider now carry it, land on `gpt-4o-mini` through your own gateway, and get counted against the `copilot-vscode` key's daily budget.

## The payoff

Every request Copilot sends through the BYOK provider is now attributed to the `copilot-vscode` key by name in the usage ledger (`sbproxy ai ledger verify` proves the file has not been edited after the fact), covered by whatever guardrails you attach to the origin, and stopped at `402` the moment the daily budget is spent. Add a `serve:` block naming a local model and give it the same alias as a hosted one, and the BYOK provider switches to your own GPU with no further client-side change: see [use-case-coding-assistant.md](use-case-coding-assistant.md) for that half. `serve:` is the compatibility form; [model-host.md](model-host.md) documents the canonical `proxy.model_host` form for new deployments.

## Next steps

- [use-case-own-openrouter.md](use-case-own-openrouter.md) - the full governed-gateway walkthrough: key lifecycle, budget behavior, and ledger verification with captured output
- [use-case-coding-assistant.md](use-case-coding-assistant.md) - point the same alias at a model running on your own GPU
- [key-management.md](key-management.md) - key lifecycle, rotation, and per-key policy
- [ai-gateway.md](ai-gateway.md) - the provider array, routing, guardrails, and budget reference
- [configuration.md](configuration.md) - the full configuration schema
