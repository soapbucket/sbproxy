# Usage bridge: a served request lands one durable row

The metering half of [docs/payment-settlement.md](../../docs/payment-settlement.md). `proxy.payments.usage_reporters.stripe_meter` ships a reporter, a durable queue, and a recovery worker that drains it. This config is the smallest pairing of that block with something that actually produces usage: one AI call through a governed key, one row on the queue.

The request path enqueues and returns, and that is the design rather than a limitation of the fixture. The HTTP call to the provider belongs to the worker, behind its own lease and its own idempotency key, so nothing on the request path ever waits on Stripe. A row is therefore written `queued`, and the worker is the only thing that moves it on.

The worker gets to it inside a second here, because `reconcile_interval_ms` is 1000. It calls the reporter's API root, which is a compiled-in `https://api.stripe.com` with no override, using the demo key in `stripe.key`, which is not a real credential. Stripe answers that it is not, authoritatively, so the row settles at `terminal` with `failure_category` `rejected`. On a host with no route to Stripe the category is `unavailable` instead and the row is retried rather than closed. Either way the queue is what survives the request, which is the property this example is about.

The customer a row bills comes from the authenticated credential's metadata, never from a request header. A caller who could name the account their usage bills to could name somebody else's, so the run mints a governed key carrying `metadata.stripe_customer_id` first.

## Run

Metering is behind the same cargo feature the Stripe rail is, and no payment feature is in the default build:

```bash
CARGO_TARGET_DIR=target/payments cargo build --release -p sbproxy --features payment-stripe
```

Then, from the repository root:

```bash
mkdir -p /tmp/sbproxy-usage-bridge
printf '%s' "$(openssl rand -hex 16)" > /tmp/sbproxy-usage-bridge/binding.key
printf '%s' 'sk_test_usage_bridge_demo' > /tmp/sbproxy-usage-bridge/stripe.key
chmod 600 /tmp/sbproxy-usage-bridge/*.key
python3 examples/usage-bridge-queue/fixture.py &
target/payments/release/sbproxy serve -f examples/usage-bridge-queue/sb.yml
```

The two secret files are named rather than inlined, because an inline credential in a payments field is rejected at load with the field path. `binding.key` serves as the recovery key too, and its length is load bearing: the recovery cipher is AES-256-GCM and checks that the resolved secret is exactly 32 bytes, rather than checking where it came from. `openssl rand -hex 16` emits exactly 32 characters, which satisfies it. `-hex 32` emits 64, and the proxy prints a fatal naming `proxy.payments.recovery_encryption.key`, the 64 bytes it got, and the 32 it needed, then exits before it binds a listener. The check is a startup check rather than a validation one, so `serve --check` passes on the same file.

There is no `docker-compose.yml`, and the reason is the build rather than the stack: `Dockerfile.cloudbuild` compiles the default feature set, so the shared image would start this config and fail on the configured reporter. `scripts/examples-smoke.sh` gates on a compose file and therefore skips this directory.

[`e2e/tests/usage_bridge.rs`](../../e2e/tests/usage_bridge.rs) is what covers it instead. Most of that file drives the proxy directly, starting from an HTTP request and finishing by reading the same SQLite file. One test does something narrower and worth knowing about if you edit this page: it runs `bin/bill-one-call.sh` and every `sqlite3` command below, against a stack of its own. A command here that stops working fails there, which is the hole this example fell through once already.

## Bill one call

```bash
bash examples/usage-bridge-queue/bin/bill-one-call.sh
```

<!-- CAPTURE: bash examples/usage-bridge-queue/bin/bill-one-call.sh -->

```
minted a governed key naming customer=cus_demo_usage_bridge
chat completion               status=200
rows on the usage queue       1
```

## What landed

One row per billable unit. There is no `quantity` column: the number lives inside `event_jcs`, the canonicalized event the worker hands the reporter, so the row and the thing that gets signed and sent cannot drift apart. `json_extract` reads it back out. `status` and `failure_category` together are the visible half of the split above, and which of the two states you catch depends on how fast you type: the worker ticks once a second, so the row reads `queued` for about that long and `terminal` afterwards.

```bash
sqlite3 /tmp/sbproxy-usage-bridge/payments.sqlite3 \
  "select reporter, usage_identifier, tenant_id, origin_id, status, failure_category, json_extract(event_jcs, '\$.quantity') as quantity from usage_reports order by created_at_ms"
```

<!-- CAPTURE: sqlite3 /tmp/sbproxy-usage-bridge/payments.sqlite3 "select reporter, usage_identifier, tenant_id, origin_id, status, failure_category, json_extract(event_jcs, '\$.quantity') as quantity from usage_reports order by created_at_ms" -->

```
stripe_meter|sbu-<USAGE>|tenant-a|billing.local|terminal|rejected|1020
```

The full event the worker will hand the reporter, including the resource attribution and the customer the charge lands on:

```bash
sqlite3 /tmp/sbproxy-usage-bridge/payments.sqlite3 \
  'select event_jcs from usage_reports order by created_at_ms limit 1'
```

<!-- CAPTURE: sqlite3 /tmp/sbproxy-usage-bridge/payments.sqlite3 'select event_jcs from usage_reports order by created_at_ms limit 1' -->

```
{"attributes":{"claim_id":"019fc4332bc872f0bbfbb36cb735cc14","resource_name":"openai/gpt-4o-mini","resource_type":"ai_model","stripe_customer_id":"cus_demo_usage_bridge","unit":"total_tokens"},"event_name":"sbproxy_ai_tokens","occurred_at_ms":1785703115773,"origin_id":"billing.local","quantity":1020,"reporter":"stripe_meter","tenant_id":"tenant-a","usage_identifier":"sbu-019fc4332bc872f0bbfbb36cb735cc14-edba0b3d3dfd9c8ddd3718560501eb69"}
```

Two counters describe the bridge, both labelled by tenant, because a billing number that merged every tenant into one series answers a question nobody asks:

```bash
curl -s http://127.0.0.1:8080/metrics | grep sbproxy_usage_bridge
```

```
# HELP sbproxy_usage_bridge_enqueued_total Billable units the request path queued for a usage reporter, by tenant, reporter, resource type, and whether the row was new
# TYPE sbproxy_usage_bridge_enqueued_total counter
sbproxy_usage_bridge_enqueued_total{reporter="stripe_meter",resource_type="ai_model",result="queued",tenant_id="tenant-a"} 1
```

`sbproxy_usage_bridge_enqueued_total` splits on `result`. A `duplicate` is the idempotency contract working and is expected on a retry; a series that is entirely `duplicate` means an identifier is not varying when it should, which is the shape of a silently dropped charge. `sbproxy_usage_bridge_gap_total` is the one to alert on: nonzero means a served request produced a billable unit that never reached the queue.

Only one of the two is in the scrape above, and that is worth knowing before you write the alert. Neither series is created until something increments it, so a bridge that has had no gap publishes no gap series at all. In a scrape that is indistinguishable from a build that never records one, and an alert written as a threshold on a series that does not exist never fires. Alert on `absent()` alongside the threshold, or scrape after deliberately provoking a gap once so you have seen the series exist.

The `usage_identifier` in the row above is the key Stripe deduplicates on, and it is derived from five things: the claim the receipt names, the reporter, the resource type, the resource name, and the unit. All five, because one request routinely produces several billable units and keying them on the request alone would report the first and let the provider discard the rest.

## What this example does not show

- **The Stripe leg.** The reporter's API root is a constant and refuses anything that is not an HTTPS root, so there is no configuration that points it at a local stub the way the Core Lightning rail points the settler at a Unix socket. The reporter's wire contract is covered against a stub transport in `crates/sbproxy-billing/tests/stripe_meter_contract.rs`.
- **A settlement.** Meter events record consumption. They are a different registry, a different queue, and a different return type, and no meter report can move an intent to `Succeeded`. [`examples/settlement-gate-local/`](../settlement-gate-local/) is the settling half.
- **`source: http` or `source: mcp`.** Both are configured the same way; `http` additionally needs `proxy.attestation` with a role that writes receipts, because the outcome table is what decides whether the request was billable at all.

## Clean up

```bash
kill %1
rm -rf /tmp/sbproxy-usage-bridge
```

## Read more

- [docs/payment-settlement.md](../../docs/payment-settlement.md) - the reporter's fields, the three sources, and the deduplication identifier
- [docs/metering.md](../../docs/metering.md) - the signed receipt chain the `http` source reads from
- [docs/key-management.md](../../docs/key-management.md) - minting, revoking, and rotating the governed keys this example mints
