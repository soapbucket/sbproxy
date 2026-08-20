# Verifiable usage ledger
*Last modified: 2026-08-19*

The usage ledger turns the stream of completed LLM calls into a
tamper-evident, optionally signed record. Where a plain usage sink ships
events outward best-effort and unsigned, the ledger lets you *prove* what
was spent: each entry is hash-chained to the one before it, so editing any
past record breaks every link after it, and with a signing seed configured
each entry is Ed25519-signed so the record is attributable to the proxy
that wrote it.

All of this ships in the Apache-2.0 binary. The proxy writes the chain and
verifies it. It does not publish entries to an external transparency log or
a reporting portal, so anchoring to one is something you build on top of
the same entries.

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

## Reconciling against a provider export

Verification proves the ledger has not been tampered with. It cannot
prove the ledger is *complete*: a call that never went through this
gateway never produces a ledger entry to check. `ledger reconcile`
closes part of that gap by comparing the ledger against a usage export
you download from the provider directly, per day and model:

```bash
sbproxy ai ledger reconcile /var/lib/sbproxy/usage-ledger.jsonl \
  --provider-export openai-usage-export.json \
  --format openai-usage --strict
```

`--provider-export` is a file you fetch yourself, ahead of time, with an
Admin API key:
`GET /v1/organization/usage/completions?bucket_width=1d&group_by[]=model`
against
[OpenAI's organization Usage API](https://platform.openai.com/docs/api-reference/usage/completions)
(worked example:
[the OpenAI cookbook](https://developers.openai.com/cookbook/examples/completions_usage_api)).
`openai-usage` is the only supported `--format` today; it was picked
over
[Anthropic's Admin usage/cost API](https://platform.claude.com/docs/en/manage-claude/usage-cost-api)
because Anthropic's usage rows split input tokens across
`uncached_input_tokens`, `cache_read_input_tokens`, and a nested
`cache_creation` object, which needs a policy decision about which of
those count toward "what the ledger should have seen" before they are
comparable; OpenAI's flat `input_tokens` / `output_tokens` pair does
not.

The command always re-derives the ledger's hash chain first (the same
check `ledger verify` runs) and refuses to reconcile an unverified one.
It then reports two things:

- **Bypass evidence**: a (day, model) row the export shows requests for
  that the ledger has no matching request for at all. This is the
  strongest signal: spend the provider counted that the gateway's own
  metering path never recorded.
- **Ledger-only rows**: a (day, model) row the ledger recorded that the
  export does not show. Not bypass evidence by itself; see the caveats
  below.

Without `--strict` the command always exits 0, so a first run can be
read before it is wired into anything. With `--strict` it exits 1 when
bypass evidence is found, so it slots into a scheduled reconciliation
job the way `ledger verify` slots into a CI gate.

**What this does and does not prove.** A clean reconcile run proves
only that, for the org and API key that produced this export, every
request the provider billed also has a matching entry in this gateway's
ledger. It does not prove nothing else was spent: a call made under a
different key, project, or provider organization produces no row at
all, on either side, so it is invisible to this check. A ledger-only
row is usually a clock-window edge (the export's daily bucket boundary
and the ledger's `recorded_at` are not guaranteed to land on the same
side of midnight UTC) or provider usage data that has not caught up yet
(both OpenAI and Anthropic can lag by minutes), not evidence of
anything wrong.

### Example run

The fixture this repository ships for its own tests,
`crates/sbproxy-ai/tests/fixtures/openai-usage-export.json`, is a real
OpenAI organization Usage API shape (with invented numbers) covering two
days and three (day, model) rows. Running `reconcile` against a freshly
created, empty ledger shows the report at its most stark: every
provider-side row has nothing on the ledger side to match.

```bash
sbproxy ai ledger reconcile /var/lib/sbproxy/usage-ledger.ndjson \
  --provider-export crates/sbproxy-ai/tests/fixtures/openai-usage-export.json \
  --format openai-usage
```

```text
usage ledger reconcile: /var/lib/sbproxy/usage-ledger.ndjson vs crates/sbproxy-ai/tests/fixtures/openai-usage-export.json (openai-usage)
chain: verified (chain only, no signing seed given)
rows compared: 3

bypass evidence (provider export shows usage the ledger never recorded):
  2026-06-24 gpt-4o                   47 request(s) unseen by the ledger (125500 token(s))
  2026-06-24 gpt-4o-mini              210 request(s) unseen by the ledger (60500 token(s))
  2026-06-25 gpt-4o-mini              63 request(s) unseen by the ledger (19300 token(s))
  total: 320 request(s) unseen by the ledger

ledger-only: none.

This only proves bypass for usage visible to the provider org and API key that produced this export: a different org, project, or key would not appear here at all. Clock-window edges (the export's bucket boundary vs. the ledger's recorded_at) and key/org attribution differences can also put a row on one side only; treat a ledger-only row as a lead, not proof.
```

An empty ledger is the degenerate case: every provider row reads as
bypass evidence because there is nothing on the ledger side to match it
against. A ledger that has actually been recording usage would show
real matches wherever the gateway saw the traffic, and bypass evidence
only on the rows it didn't. Add `--strict` to make that distinction
actionable: the command exits 1 the moment `bypass evidence` is
non-empty, which is what a scheduled reconciliation job wants, rather
than a first, exploratory run.

## Try it

The runnable example is in
[`examples/ai-usage-ledger/`](../examples/ai-usage-ledger/). Drive a
request through it, inspect the JSONL, then edit a `cost_usd` in the file
and watch `verify` fail at the mutated sequence number.

## See also

- [ai-gateway.md#budgets](ai-gateway.md#budgets) - the `budget` block whose spend this ledger records.
- [ai-predictive-budget.md](ai-predictive-budget.md) - soft-landing downgrades carry a `budget_soft_landing` tag that lands in this ledger's entries.
- [agent-budget.md](agent-budget.md) - a separate, per-agent rate limit; it does not write to this ledger.
