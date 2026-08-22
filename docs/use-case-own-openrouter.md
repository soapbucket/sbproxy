# API keys everywhere, accounting nowhere: stand up your own OpenRouter

*Last modified: 2026-08-21*

![Minting a virtual key, calling OpenAI and Anthropic through one governed endpoint, reading the spend ledger, and tripping a budget cap](assets/use-case-own-openrouter.gif)

Somewhere in your company there is an OpenAI key in a CI secret, an Anthropic key in a notebook, and a third key nobody remembers minting. Every tool points at a different provider, and when the invoice lands there is no way to say which team spent what. SBproxy's pitch is "Call any model. Serve your own. Govern both.": one Apache-2.0 binary that puts a single OpenAI-compatible endpoint in front of 70 providers, or serves the weights on your own GPUs, with keys, budgets, and accounting under your control. This guide builds the hosted-gateway half of that sentence. In about twenty minutes you get your own OpenRouter, running on a box you own.

## What you will build

One endpoint on port 8080 that speaks the OpenAI API in front of OpenAI and Anthropic, where the request's `model` field picks the vendor. An admin API on port 9090 where you mint a virtual key per team at runtime; the real provider keys stay in the gateway's environment and teams only ever hold their SBproxy key. Each key carries a daily token budget that the gateway enforces before dispatch, refusing over-budget requests with `402`. And a usage ledger on disk that records every completed call with provider, model, tokens, cost, and the key that spent it, hash-chained so past entries cannot be quietly edited.

## Prerequisites

- An OpenAI key (`OPENAI_API_KEY`) and an Anthropic key (`ANTHROPIC_API_KEY`). These are the demo pair; any of the 70 providers configures the same way.
- `curl` for requests and `jq` for reading JSON.
- No Rust toolchain. The published binary is all you need.

## Install

```bash
# Prebuilt release executable for Linux amd64/arm64 (glibc) or Apple Silicon macOS.
# No Rust, Python, JVM, or Node toolchain/runtime is required.
curl -fsSL https://download.sbproxy.dev | sh

# macOS via Homebrew:
brew install soapbucket/tap/sbproxy

# Docker / Kubernetes:
docker pull soapbucket/sbproxy:latest
```

The full install matrix, including checksums and air-gapped installs, is in the [manual](manual.md).

## Minimal config

The assembled file lives at [`examples/use-case-own-openrouter/sb.yml`](../examples/use-case-own-openrouter/sb.yml), with a docker-compose next to it. It reads in four parts.

First, the two servers. Port 8080 is the data plane your teams call. The admin server on 9090 is the control plane where keys are minted; it is off by default and admits only loopback clients until you say otherwise. (The example file also sets `bind`, an `allow_ips` allowlist, and reads the admin password from `${SB_ADMIN_PASSWORD:-change-this-before-running}` rather than a literal value, because it binds wide for the docker-compose port mapping and a guessable password on a wide bind hands the whole admin API to anyone who can route to the port. Running the binary directly, admin stays on loopback by default, so this guide keeps a literal demo password below; still change it before anything real.)

```yaml
proxy:
  http_bind_port: 8080

  admin:
    enabled: true
    port: 9090
    username: admin
    password: admin   # demo credentials; change both before any real use
```

Second, dynamic key management. This is what makes keys a runtime resource instead of lines of YAML: you mint, revoke, and rotate them through the admin API, and each change takes effect on the next request with no reload. Inbound keys are stored as HMAC-SHA256 hashes under a server pepper, so the store never holds anything a thief could replay. The demo uses inline pepper and master values so the file boots standalone; in production point them at `env:NAME` or `file:PATH`, because a changed pepper means previously stored hashes stop verifying.

```yaml
  key_management:
    enabled: true
    store:
      backend: embedded   # single node; use redis when replicas share keys
      path: /tmp/sbproxy-own-openrouter-keys.redb
    cache:
      ttl_secs: 60
    crypto:
      pepper: demo-pepper-not-for-production
      master_key: demo-master-not-for-production
    failure_posture: closed     # store down means deny, never ungoverned traffic
```

Third, the origin. Two providers sit behind one hostname. Before any routing strategy runs, the gateway narrows the provider set to those that declare the requested model, so `gpt-4o-mini` reaches OpenAI and `claude-haiku-4-5` reaches Anthropic through the same URL. Clients switch vendors by changing one string in the request body; nothing else about their code moves.

```yaml
origins:
  "ai.local":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          default_model: gpt-4o-mini
          models:
            - gpt-4o-mini
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          default_model: claude-haiku-4-5
          models:
            - claude-haiku-4-5
```

Fourth, governance: a budget and the ledger. The `api_key` scope gives every virtual key its own daily bucket, and `on_exceed: block` refuses the first request past the line with `402` before any provider is contacted. Three hundred tokens is a small cap chosen so you can watch it trip in one sitting: the OpenAI call below spends about 64 tokens and the Anthropic call about 187, so two calls fit and a third does not; a real deployment would set something like `max_cost_usd: 50` with `period: monthly`, or use `on_exceed: downgrade` to swap expensive models for cheap ones instead of refusing. A request presenting no key is not exempt: it falls into a shared `__unattributed__` bucket that is still capped, so one unauthenticated caller cannot bypass the budget by omitting a key, though every caller without one shares that single bucket, which is a reason to add an auth gate in front when every caller must carry its own. The ledger sink appends one entry per completed call, each hash-chained to the previous entry; add a `signing_seed_hex` and entries are Ed25519-signed too.

```yaml
      budget:
        on_exceed: block
        limits:
          - scope: api_key
            max_tokens: 300
            period: daily

      usage_sinks:
        - type: ledger
          path: /tmp/sbproxy-own-openrouter-ledger.jsonl
```

## Run it

Export your provider keys and start the gateway (or run `docker compose up` from the example directory):

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
sbproxy serve -f sb.yml
```

Mint a key for your first team. The plaintext token comes back exactly once; after this response the gateway holds only the hash.

```console
$ curl -s -u admin:admin -X POST http://127.0.0.1:9090/admin/keys \
    -H 'Content-Type: application/json' \
    -d '{"name":"team-payments"}'
{
  "token": "sbp_4fa2b91cd8e6a013_...",
  "key": { "key_id": "4fa2b91cd8e6a013", "name": "team-payments", "status": "active", ... }
}
```

Hand that token to the payments team and mint another for the next team. A key is more than a credential: the record can carry `allowed_models`, `max_requests_per_minute` and `max_tokens_per_minute`, tags for attribution, and a pinned `route_to_model`, all editable later with `PATCH /admin/keys/{id}` and all live on the next request. Revoking is one `POST /admin/keys/{id}/revoke`, and rotation keeps the old secret valid for a grace window while clients pick up the new one. The details are in [key-management.md](key-management.md).

If you would rather click than curl, builds that carry the embedded admin UI serve it at `http://127.0.0.1:9090/admin/ui`, driving these same endpoints from the browser (see [admin.md](admin.md) for how the UI is enabled and secured). The Keys page mints, edits, revokes, and rotates the same records:

![The admin UI Keys page listing virtual keys with status, limits, and mint and revoke controls](assets/admin-keys.png)

Now spend some of the budget. Save the token and send a normal OpenAI-shaped request through the gateway. The model field says `gpt-4o-mini`, so OpenAI serves it:

```console
$ TOKEN=sbp_4fa2b91cd8e6a013_...
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"One sentence: why route LLM calls through a gateway?"}]}' \
  | jq -r '.model, .choices[0].message.content'
gpt-4o-mini
A gateway gives every application one endpoint while centralizing keys, failover, and cost controls.
```

Change one string and the same key reaches Anthropic through the same URL. The answer still comes back in OpenAI chat-completion shape, because the gateway translates natively in both directions:

```console
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"In about 120 words, why give each team its own gateway key?"}]}' \
  | jq '{model, usage}'
{
  "model": "claude-haiku-4-5",
  "usage": { "prompt_tokens": 29, "completion_tokens": 158, "total_tokens": 187 }
}
```

The admin UI covers this step too: the Playground page sends a test completion through the same dispatch path as production traffic, so you can sanity-check a model or a key without opening a terminal:

![The admin UI playground sending a test chat completion and showing the model's response](assets/admin-playground.png)

Both calls are now in the ledger, attributed to the key that spent them by its `key_id` (the stable public id from the mint response, not the `name` you gave it):

```console
$ tail -n 2 /tmp/sbproxy-own-openrouter-ledger.jsonl \
    | jq -c '{provider: .event.provider, model: .event.model, tokens: .event.total_tokens, cost_usd: .event.cost_usd, key: .event.key_id}'
{"provider":"openai","model":"gpt-4o-mini","tokens":64,"cost_usd":0.0000209,"key":"4fa2b91cd8e6a013"}
{"provider":"anthropic","model":"claude-haiku-4-5","tokens":187,"cost_usd":0.000819,"key":"4fa2b91cd8e6a013"}
```

Each entry's hash covers the entry before it, so the file is tamper-evident, and you can prove it:

```console
$ sbproxy ai ledger verify /tmp/sbproxy-own-openrouter-ledger.jsonl
ledger verify: OK (2 entries, chain only)
```

Edit any `cost_usd` in the file and verification fails at that sequence number. [ai-usage-ledger.md](ai-usage-ledger.md) covers signing and the exactly-once replay behavior.

Those two calls also spent most of that 300-token cap, which is the point. The key's daily bucket has too little left for a third call, so the next request is refused before any provider sees it:

```console
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"one more?"}]}' \
  | sed -n '1p;$p'
HTTP/1.1 402 Payment Required
{"error":{"type":"budget_exceeded","scope":"api_key","message":"..."}}
```

Every other key keeps working. Buckets are per key, so one team burning its budget never throttles another, and the window resets daily.

## You are done when

- The same bearer token gets answers from both vendors through `http://127.0.0.1:8080/v1/chat/completions`, with `.model` reading `gpt-4o-mini` on one response and `claude-haiku-4-5` on the other.
- `tail` on the ledger file shows one entry per call, with `provider` values `openai` and `anthropic` and both entries carrying the same `key_id`.
- `sbproxy ai ledger verify` prints `ledger verify: OK` and exits 0.
- A further request with the spent key returns `HTTP/1.1 402 Payment Required` with `"type":"budget_exceeded"` and `"scope":"api_key"` in the body.

## Next steps

- [ai-gateway.md](ai-gateway.md) - the provider array, model-based selection, routing strategies, and the full budget reference
- [key-management.md](key-management.md) - key lifecycle, rotation grace windows, per-key policy, and the store backends for replica fleets
- [ai-usage-ledger.md](ai-usage-ledger.md) - ledger entry format, Ed25519 signing, and verification in CI
- [admin.md](admin.md) - locking down the admin server: roles, TLS, remote access, and the web UI
- [configuration.md](configuration.md) - the full configuration schema
