# Migrating from LiteLLM

*Last modified: 2026-06-24*

This guide moves a LiteLLM proxy deployment to SBproxy. Your OpenAI-format clients keep working unchanged; you translate the config once and point traffic at SBproxy.

## TL;DR

```bash
sbproxy config import-litellm litellm_config.yaml --out sb.yml
sbproxy sb.yml
```

`import-litellm` reads a LiteLLM `config.yaml` and writes an equivalent SBproxy `sb.yml` with one `ai_proxy` origin. It prints a warnings report to stderr listing every key that needs manual attention, and never fails on an unmapped key (only on a YAML parse error). Clients that already speak the OpenAI API need no change: keep calling `/v1/chat/completions`, `/v1/embeddings`, and the rest. `os.environ/VAR` references become SBproxy's `${VAR}` interpolation.

## Why migrate

- SBproxy is a native-Rust proxy today. LiteLLM is mid-rewrite of its transformation core to Rust; you can skip the wait and run a Rust proxy now.
- One config covers both the AI gateway and a general reverse proxy, so the gateway, routing, auth, rate limiting, and WAF live in a single binary.
- The guardrail stack (injection, PII, jailbreak, toxicity, schema, context-poisoning, agent-alignment) is built in.

## Automated migration

`sbproxy config import-litellm <path>` writes to stdout by default, or to a file with `--out`. The warnings report goes to stderr, so you can pipe a clean `sb.yml` while still seeing what needs review:

```bash
sbproxy config import-litellm litellm_config.yaml --out sb.yml
# warning: callback 'my_module.CustomHandler' looks like a Python hook ...
# config import-litellm: 1 key(s) need manual attention (see warnings above)
```

Validate the result before serving:

```bash
sbproxy validate sb.yml
```

## Field-by-field mapping

| LiteLLM | SBproxy |
|---|---|
| `model_list[].model_name` | public model name (routable) and `model_map` key |
| `model_list[].litellm_params.model` | upstream model; a `provider/model` prefix splits into `provider_type` + model |
| `litellm_params.api_key` / `api_base` / `api_version` / `organization` | `providers[].api_key` / `base_url` / `api_version` / `organization` |
| `litellm_params.rpm` / `tpm` | `model_rate_limits[model].requests_per_minute` / `tokens_per_minute` |
| `litellm_params.weight` | `providers[].weight` |
| Two `model_list` entries sharing a `model_name` | a model group: two providers listing that model, load-balanced by the routing strategy |
| `router_settings.routing_strategy` | `routing` (`simple-shuffle`->`round_robin`, `latency-based-routing`->`lowest_latency`, `usage-based-routing`->`least_token_usage`, `least-busy`->`least_connections`, `cost-based-routing`->`cost_optimized`) |
| `litellm_settings.cache` | `semantic_cache.enabled` |
| `os.environ/VAR` (anywhere) | `${VAR}` |
| `general_settings.master_key` | proxy authentication (configure manually) |
| `general_settings.database_url` | runtime key/spend store (enterprise) |
| `guardrails[]` | a built-in or external guardrail adapter (review per entry) |

## Worked example

LiteLLM `config.yaml`:

```yaml
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4o
      api_key: os.environ/OPENAI_API_KEY
      rpm: 100
  - model_name: claude
    litellm_params:
      model: anthropic/claude-haiku-4-5
      api_key: os.environ/ANTHROPIC_API_KEY
router_settings:
  routing_strategy: latency-based-routing
litellm_settings:
  cache: true
```

Translated `sb.yml`:

```yaml
proxy:
  http_bind_port: 8080
origins:
  ai.local:
    action:
      type: ai_proxy
      routing: lowest_latency
      providers:
        - name: openai
          provider_type: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4]
          default_model: gpt-4
          model_map: { gpt-4: gpt-4o }
        - name: anthropic
          provider_type: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude]
          default_model: claude
          model_map: { claude: claude-haiku-4-5 }
      model_rate_limits:
        gpt-4: { requests_per_minute: 100 }
      semantic_cache: { enabled: true }
```

## What needs manual migration

These have no automatic translation; the importer warns and points here.

- Python hooks given as module paths: `custom_auth`, `custom_sso`, `custom_key_generate`, and callback classes. SBproxy's analog is CEL, Lua, JavaScript, or WebAssembly scripting; rewrite the logic in one of those.
- Open-ended `litellm_params` keyword arguments: the importer maps the known keys and warns on the rest, so review each warned key.
- External guardrail providers (Presidio, Lakera, Aporia, Bedrock): map each to a built-in SBproxy guardrail or an external guardrail adapter.
- `general_settings.master_key`: set up proxy authentication explicitly.

## What is deferred

Runtime parity for callback sinks, external guardrail adapters, multi-window budgets, per-error retry policy, and the `/model/info` family of endpoints is tracked separately and lands incrementally. The importer emits warnings where a target is not yet available so nothing is silently dropped.

## See also

- [docs/ai-gateway.md](ai-gateway.md) for the AI gateway and routing strategies.
- [docs/configuration.md](configuration.md) for the full config schema.
