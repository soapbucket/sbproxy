# Settlement gate, end to end, with no payment provider

The runnable half of [docs/payment-settlement.md](../../docs/payment-settlement.md). A declared crawler is challenged with a Lightning invoice, pays it out of band, retries, and reaches the origin exactly once. A replay of the same settled quote buys nothing.

Lightning is the one rail that runs hermetically. Core Lightning is not an HTTP endpoint, it is a Unix socket speaking newline-delimited JSON-RPC, so `fixture.py` stands in for a node with no TLS, no certificate, and no reachable host. The x402, Stripe, and LND rails all require an HTTPS endpoint a local fixture cannot be, which is why this example exists beside them rather than instead of them.

Nothing here holds value. The stub node never moves money; it answers `getinfo`, `invoice`, and `listinvoices`, which is the complete surface the settlement path uses, and a control endpoint flips its one invoice to `paid` when you ask it to.

## What the fixture provides

| Endpoint | What it is |
|---|---|
| `/tmp/sbproxy-settlement/lightning-rpc` | The stub node's Unix socket. `getinfo` reports `v26.06` so the startup version probe passes, `invoice` records the label and amount, `listinvoices` reports the status. |
| `http://127.0.0.1:18080/article` | The origin, counting every article it actually serves. |
| `POST http://127.0.0.1:18080/__pay` | Marks the outstanding invoice paid, standing in for a Lightning wallet. |
| `POST http://127.0.0.1:18080/__reset` | Forgets the invoice and zeroes the counter. |
| `GET http://127.0.0.1:18080/__hits` | Reads the counter without incrementing it. |

The fixture also writes the two secret files `sb.yml` names, because both are per-run values that must never be vendored: a fresh 32-byte challenge binding key and a throwaway rune, each `0600`.

## Run

Settlement lives behind cargo features and none of them are in the default build. A configured rail whose feature is missing is a startup failure that names the feature, so build the pair first:

```bash
CARGO_TARGET_DIR=target/payments cargo build --release -p sbproxy \
  --features payment-lightning-cln
```

Then, from the repository root:

```bash
python3 examples/settlement-gate-local/fixture.py &
target/payments/release/sbproxy serve -f examples/settlement-gate-local/sb.yml
```

There is no `docker-compose.yml`, and the reason is the build rather than the stack: `Dockerfile.cloudbuild` compiles the default feature set, so the image the other examples share would start this config and fail on the rail. That also means `scripts/examples-smoke.sh` skips this directory; `smoke.json` records the contract it would assert, and [`e2e/tests/settlement_gate.rs`](../../e2e/tests/settlement_gate.rs) drives the same stub node and the same counting origin from Rust. It pays before its first retry, so it proves the challenge, the settle, and the replay refusal, and it does not cover the reconciliation the script below walks through.

## The whole sequence, with the origin's own counter

The proxy can claim whatever it likes about a payment. Only the origin knows how many times it actually served the article, so the script prints that counter after every step:

```bash
bash examples/settlement-gate-local/bin/settle-once.sh
```

<!-- CAPTURE: bash examples/settlement-gate-local/bin/settle-once.sh -->

Step 3 retries in a loop instead of asking once, and the reason is worth reading before you write a crawler against this. Step 2 retried before the invoice was paid, which is ordinary client behavior and is also what leaves the intent in `needs_reconciliation`: the rail verified the payment and did not settle it. From there the request path never tries again, because a second attempt is how a payer gets charged twice, so paying the invoice does not on its own get the crawler in. The recovery worker clears it on its next sweep, `worker.reconcile_interval_ms` apart and 1000 ms in this config, and the retry after that reaches the origin. That is what the 503's `Retry-After: 2` is asking a client to do.

The loop is bounded at 100 attempts 0.2s apart, which is twenty times the sweep interval. Running out is a failure and says so, printing the intent's durable status, because a walkthrough that prints a 503 where a 200 belongs teaches the wrong thing quietly. Every status the script prints is asserted for the same reason. `SETTLE_ATTEMPTS` and `SETTLE_INTERVAL` move the bound if you raise `reconcile_interval_ms`.

## Step by step

A reader is never in this story. No challenge, no intent, no row:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: blog.local' \
  -H 'User-Agent: Mozilla/5.0' http://127.0.0.1:8080/article
```

<!-- CAPTURE: curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: blog.local' -H 'User-Agent: Mozilla/5.0' http://127.0.0.1:8080/article -->

A declared crawler is priced. The policy denies with a 402, the gate intercepts it before it is written, commits a `Pending` intent, asks the node for an invoice, and renders the challenge. The signed quote token rides the header the policy configured, and the `challenge` object carries the BOLT 11 invoice the payer settles:

```bash
curl -is -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' \
  http://127.0.0.1:8080/article
```

<!-- CAPTURE: curl -is -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' http://127.0.0.1:8080/article -->

Retrying before the invoice is paid is the case the gate exists for. The quote token authenticates and names a live intent, so this is not a refusal; it is verified-but-not-settled, which is a 503 with `Retry-After` and never origin access. It is also what strands the intent in `needs_reconciliation` until the worker sweeps, so run this and the crawler's next successful request is one sweep away rather than immediate:

```bash
TOKEN=$(curl -sS -D - -o /dev/null -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' http://127.0.0.1:8080/article | tr -d '\r' | awk '/^crawler-payment:/ {print $2}'); curl -is -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' -H "crawler-payment: $TOKEN" http://127.0.0.1:8080/article
```

<!-- CAPTURE: TOKEN=$(curl -sS -D - -o /dev/null -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' http://127.0.0.1:8080/article | tr -d '\r' | awk '/^crawler-payment:/ {print $2}'); curl -is -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' -H "crawler-payment: $TOKEN" http://127.0.0.1:8080/article -->

A client that asks for a rail this route does not advertise gets a 406 naming what it could have asked for, rather than a challenge it cannot pay:

```bash
curl -is -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' \
  -H 'Accept-Payment: x402' http://127.0.0.1:8080/article
```

<!-- CAPTURE: curl -is -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' -H 'Accept-Payment: x402' http://127.0.0.1:8080/article -->

## What is left behind

`state_path` is the authority, and it is an ordinary SQLite file. After the sequence above, the intent carries its terminal status and the receipt names the provider reference the node reported:

```bash
sqlite3 /tmp/sbproxy-settlement/payments.sqlite3 \
  'select status, settlement_rail, amount_micros, currency from payment_intents order by created_at_ms'
```

<!-- CAPTURE: sqlite3 /tmp/sbproxy-settlement/payments.sqlite3 'select status, settlement_rail, amount_micros, currency from payment_intents order by created_at_ms' -->

```bash
sqlite3 /tmp/sbproxy-settlement/payments.sqlite3 \
  'select rail, method, provider_reference from payment_receipts'
```

<!-- CAPTURE: sqlite3 /tmp/sbproxy-settlement/payments.sqlite3 'select rail, method, provider_reference from payment_receipts' -->

The admin surface reports which rails registered and what the recovery worker has done. It deliberately carries no intent id, tenant, amount, or provider reference:

```bash
curl -s -u admin:demo-change-me http://127.0.0.1:9090/admin/payments/status
```

<!-- CAPTURE: curl -s -u admin:demo-change-me http://127.0.0.1:9090/admin/payments/status -->

The metrics carry four labels and no more: `rail`, `operation`, `outcome`, and `provider_class`.

```bash
curl -s http://127.0.0.1:8080/metrics | grep sbproxy_payment_settlement_total
```

<!-- CAPTURE: curl -s http://127.0.0.1:8080/metrics | grep sbproxy_payment_settlement_total -->

## Validate without holding anything

Config load checks shape, ranges, and the rules that cross fields. It resolves no secret, opens no SQLite file, and dials no node, so this runs on a machine that holds none of the credentials and needs no payments feature to parse:

```bash
sbproxy validate -f examples/settlement-gate-local/sb.yml
```

<!-- CAPTURE: sbproxy validate -f examples/settlement-gate-local/sb.yml -->

## What this example does not show

- **Any other rail.** x402, Payment HTTP Authentication, direct Stripe, and LND all require an HTTPS endpoint, and there is no configuration escape hatch that relaxes that. `examples/rail-x402-base-sepolia/` is the wire-shape reference for x402; it emits 402s offline and cannot settle.
- **A mesh.** Settlement state is one SQLite file and nothing replicates it. A node that configures both `proxy.payments` and `proxy.cluster` refuses to start.
- **A wallet.** SBproxy holds no keys that move value. The stub node here holds none either.

## Clean up

```bash
kill %1
rm -rf /tmp/sbproxy-settlement
```

## Read more

- [docs/payment-settlement.md](../../docs/payment-settlement.md) - the five phases, the state table, every field, and the boundaries
- [docs/ai-crawl-control.md](../../docs/ai-crawl-control.md) - deciding which requests are payable and what they cost
- [docs/402-challenge.md](../../docs/402-challenge.md) - the exact bytes of each challenge, credential, error, and receipt
- [examples/rail-lightning/](../rail-lightning/) - the same rail against a real node, with LND as the alternative backend
