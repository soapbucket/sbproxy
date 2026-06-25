# AI usage ledger

A verifiable, tamper-evident record of every completed LLM call. Each
event is hash-chained to the previous one and (optionally) Ed25519-signed,
so spend is provable, not just logged.

See [`docs/ai-usage-ledger.md`](../../docs/ai-usage-ledger.md) for the full
reference.

## Run

```bash
export OPENAI_API_KEY=sk-...
# Optional, to sign each entry (any 32-byte value as 64 hex chars):
export LEDGER_SIGNING_SEED_HEX=$(openssl rand -hex 32)

make run CONFIG=examples/ai-usage-ledger/sb.yml
```

Drive a request:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}' \
  | jq -r '.choices[0].message.content'
```

## Inspect and verify

```bash
cat /tmp/sb-usage-ledger.jsonl | jq .

sbproxy ai ledger verify /tmp/sb-usage-ledger.jsonl \
  --signing-seed-hex "$LEDGER_SIGNING_SEED_HEX"
```

`verify` exits 0 when the chain (and signatures, if a seed is given) check
out, and 1 otherwise.

## Tamper test

Edit a `cost_usd` value in `/tmp/sb-usage-ledger.jsonl`, then re-run
`verify`. It fails and names the first broken sequence number: changing one
past entry breaks every link after it.
