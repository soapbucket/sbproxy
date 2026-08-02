# Local external guardrail

This example runs SBproxy beside two local HTTP fixtures. The first fixture is an OpenAI-compatible model endpoint. The second is a generic guardrail webhook. A prompt containing `blocked` receives a 400 before SBproxy calls the model. Any other prompt reaches the model and receives a fixed response.

## Run it

```bash
cd examples/ai-external-guardrails
docker compose up --build
```

The first build compiles SBproxy into a local image. No provider account or real key is used. The `fixture-local-token` value exists only because OpenAI-shaped provider configuration carries a credential field; the fixture ignores it.

Send a prompt that passes:

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  --data-binary '{"model":"fixture-model","messages":[{"role":"user","content":"allowed prompt"}]}'
```

The response is HTTP 200 and contains `fixture response`. Then send the blocked case:

```bash
curl -sS -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  --data-binary '{"model":"fixture-model","messages":[{"role":"user","content":"blocked prompt"}]}'
```

That response is HTTP 400 with `error.type` set to `guardrail_violation` and `error.code` set to `local-policy`. The fixture log shows only `method`, `path`, `model`, `phase`, and `verdict`. It deliberately does not print prompts, request bodies, headers, or credentials.

## What the configuration does

`proxy.http_bind_port: 8080` exposes the gateway listener. The `ai.local` origin selects the AI request pipeline when the client supplies `Host: ai.local`.

The `fixture-model` provider uses `provider_type: openai` because the model fixture accepts OpenAI chat completions. `base_url` points at `127.0.0.1:18080/v1`. `allow_private_base_url: true` is required because loopback targets are blocked by default to prevent server-side request forgery. The provider's `models` list declares what it serves, while the action's `allowed_models` list rejects any other client-selected model. `default_model` keeps routing deterministic when the client omits a model.

The `guardrails.external` entry uses the generic adapter. `name` is an operator-defined identifier used in logs and client error codes. Metrics use bounded provider, phase, and outcome labels. `url` points at the fixture webhook, and `allow_private_url: true` makes this local test explicit. `mode: pre_call` evaluates the request before any provider call. `default_on: true` automatically enables the input check on this route. `failure_posture: closed` returns a blocking result if the webhook is unavailable, malformed, slow, or oversized; the older `fail_open: false` spelling still parses and means the same thing (see [docs/degradation.md](../../docs/degradation.md) for the shared vocabulary). `timeout_ms: 500` bounds each webhook call.

Compose uses `network_mode: service:fixture` for SBproxy. Containers cannot reach another container's loopback address, so this makes `127.0.0.1:18080` and `127.0.0.1:18081` refer to the same network namespace. The fixture service publishes port 8080 because the gateway owns that listener.

## Clean up

```bash
docker compose down -v
```

Run the checked smoke cases with:

```bash
cd ../..
bash scripts/examples-smoke.sh examples/ai-external-guardrails
```

For hosted adapters and their field requirements, read [the external guardrail reference](../../docs/guardrails.md).
