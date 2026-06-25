# Verifiable usage ledger
*Last modified: 2026-06-24*

The usage ledger turns the stream of completed LLM calls into a
tamper-evident, optionally signed record. Where a plain usage sink ships
events outward best-effort and unsigned, the ledger lets you *prove* what
was spent: each entry is hash-chained to the one before it, so editing any
past record breaks every link after it, and with a signing seed configured
each entry is Ed25519-signed so the record is attributable to the proxy
that wrote it.

This is open source. Anchoring receipts to an external transparency log or
a reporting portal is an enterprise extension that consumes the same
entries.

## How it works

Configure a `ledger` usage sink on an `ai_proxy` origin:

```yaml
action:
  type: ai_proxy
  providers:
    - name: openai
      provider_type: openai
      api_key: ${OPENAI_API_KEY}
      default_model: gpt-4o-mini
      models: [gpt-4o-mini]
  usage_sinks:
    - type: ledger
      path: /var/lib/sbproxy/usage-ledger.jsonl
      # Optional. A 32-byte Ed25519 seed as 64 hex chars. When set, every
      # entry is signed. Resolve it from a secret manager in production.
      signing_seed_hex: ${LEDGER_SIGNING_SEED_HEX}
```

After every completed call the gateway appends one entry:

```json
{
  "seq": 0,
  "recorded_at": "2026-06-24T18:00:00.000000000+00:00",
  "prev_hash": "0000...0000",
  "entry_hash": "9f86d0...",
  "signature": "a1b2c3...",
  "event": {
    "provider": "openai",
    "model": "gpt-4o-mini",
    "prompt_tokens": 12,
    "completion_tokens": 8,
    "total_tokens": 20,
    "cost_usd": 0.0000035,
    "latency_ms": 240,
    "status": 200,
    "key_id": "team-a",
    "request_id": "req-..."
  }
}
```

- `entry_hash` is the SHA-256 of `prev_hash || seq || recorded_at ||
  event`, so the chain binds the order, the timestamp, and the event
  content. Changing any field of any past entry changes its `entry_hash`,
  which no longer matches the next entry's `prev_hash`.
- `signature`, when present, is the Ed25519 signature over the entry's raw
  digest. A receipt verifies against the public key derived from the seed;
  a forged or re-signed entry does not.
- `request_id` is the dedup key. The ledger file is replayed on open, so a
  retried or at-least-once delivery of the same request collapses to a
  single entry (exactly-once).

### Durability

The ledger file is its own write-ahead log. Each entry is serialized,
written, and flushed before the append returns, all under a lock. A local
append is sub-millisecond, so it stays off the network hot path while
never dropping an event under a burst. Emission happens from the
end-of-request hook, after the response is already sent, so it never adds
latency to the call it records, and a ledger problem can never fail the
request.

## Verifying

Re-derive the chain and check every link:

```bash
sbproxy ai ledger verify /var/lib/sbproxy/usage-ledger.jsonl
```

Add the seed to also verify signatures:

```bash
sbproxy ai ledger verify /var/lib/sbproxy/usage-ledger.jsonl \
  --signing-seed-hex "$LEDGER_SIGNING_SEED_HEX"
```

On success it prints the entry count and exits 0. On a broken chain or a
bad signature it names the first failing sequence number and exits 1, so
it slots into a cron check or CI gate. `--format json` emits a structured
object for tooling.

## Try it

The runnable example is in
[`examples/ai-usage-ledger/`](../examples/ai-usage-ledger/). Drive a
request through it, inspect the JSONL, then edit a `cost_usd` in the file
and watch `verify` fail at the mutated sequence number.
