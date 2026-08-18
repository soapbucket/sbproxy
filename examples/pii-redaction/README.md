# PII redaction at the AI request boundary

*Last modified: 2026-08-16*

![PII redaction at the AI request boundary](../../docs/assets/pii-redaction.gif)

When `pii.enabled: true` is set on an AI proxy origin, the gateway redacts well-known PII shapes from the parsed JSON request body before forwarding to the upstream provider. `defaults: true` enables the built-in rule set: email, US SSN, credit card with Luhn check, phone, IPv4, and common API key shapes (OpenAI, Anthropic, AWS, GitHub). Custom regex rules layer on top of the defaults, so an organisation can also redact internal ticket references, codenames, or any other shape the default catalogue does not catch. `redact_request: true` rewrites every string leaf in the JSON request body before it is forwarded; `redact_response: false` leaves response bodies untouched so the model output is delivered as-is to the client.

## Run

```bash
# The upstream must be up first so it can echo the redacted body back.
python3 fixture.py &

export OPENAI_API_KEY=...
sbproxy serve -f sb.yml
```

The example points the OpenAI provider at a local body-echoing fixture (`fixture.py`, `http://127.0.0.1:8098`) so you can see the exact body the upstream would have received, with PII already redacted. The shared `test.sbproxy.dev` fixture used to serve this role, but its `/anything` route stopped echoing the request body (it now returns only `method`, `url`, `headers`, `query`, and `timestamp`), so `jq .json` against it is always `null`. `fixture.py` is a stdlib-only stand-in that echoes any JSON body it receives back under `"json"`, matching the shape `/anything` used to return.

## Try it

```bash
# Email and credit card in the user prompt are redacted before
# forwarding. An upstream that echoes the request body (httpbin-style)
# lets you see what it actually received.
curl -s -H 'Host: ai.localhost' http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "gpt-4o",
    "messages": [
      {"role":"user","content":"Email me at alice@example.com about card 4111-1111-1111-1111"}
    ]
  }' | jq -r .json.messages[0].content
# Email me at [REDACTED:EMAIL] about card [REDACTED:CARD]
```

```bash
# US SSN gets redacted by the built-in rules.
curl -s -H 'Host: ai.localhost' http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role":"user","content":"my SSN is 123-45-6789"}]
  }' | jq -r .json.messages[0].content
# my SSN is [REDACTED:SSN]
```

```bash
# Custom rule fires for internal ticket references.
curl -s -H 'Host: ai.localhost' http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role":"user","content":"Look up TICKET-098765 for me."}]
  }' | jq -r .json.messages[0].content
# Look up [REDACTED:TICKET] for me.
```

## What this exercises

- `ai_proxy.pii.enabled` and `pii.defaults` - turn on the built-in redaction catalogue
- `pii.redact_request: true` - rewrite string leaves in the JSON request body before forwarding
- `pii.rules[]` - operator-defined custom regex rules layered on top of the defaults
- Built-in detectors: email, US SSN, credit card with Luhn validation, phone, IPv4, OpenAI / Anthropic / AWS / GitHub key shapes

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
