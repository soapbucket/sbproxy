# Payments and metering

*Last modified: 2026-08-16*

If you want to charge for access to an API, an AI endpoint, or your
content, this page is the map across three separate things SBproxy
ships that are easy to conflate: getting paid before serving a
request, proving how much was consumed after the fact, and pricing AI
crawler traffic specifically. Each has its own page; this one says
which to read first.

## Getting paid: `proxy.payments`

[`payment-settlement.md`](payment-settlement.md) is the operator guide.
`proxy.payments` is off unless configured, Apache-2.0, and holds one
rule above everything else: a request reaches the origin only after a
durable, committed record says the payment settled. Verified is not
settled; a timeout, an open circuit breaker, or a write with an
unknown fate all stop the request short of the origin.

It supports multiple rails behind one settlement state machine: x402,
Payment HTTP Authentication (MPP), Stripe, and Lightning (Core
Lightning or LND, alternative backends for one advertised rail, never
both at once). If you only need the exact bytes on the wire, read
[`402-challenge.md`](402-challenge.md) directly, it is the wire
reference: every challenge, credential, and receipt shape.

**Before you configure this on a clustered deployment:** read
[`payment-clustering.md`](payment-clustering.md) first. A node that
configures both `proxy.payments` and `proxy.cluster` refuses to start.
Settlement runs on one node against one SQLite file today; the page
explains why the cluster mesh cannot hold it and what a shared
transactional store would need to look like to lift the restriction.
This is the single most common way a payments rollout gets blocked in
planning, so check it before you design around clustering.

Runnable examples:
[`examples/rail-x402-base-sepolia/`](../examples/rail-x402-base-sepolia/),
[`examples/rail-mpp-stripe-test/`](../examples/rail-mpp-stripe-test/),
[`examples/rail-lightning/`](../examples/rail-lightning/),
[`examples/multi-rail-accept-payment/`](../examples/multi-rail-accept-payment/),
[`examples/quote-token-replay-jwks/`](../examples/quote-token-replay-jwks/).

## Pricing AI crawler traffic: Pay Per Crawl

[`ai-crawl-control.md`](ai-crawl-control.md) is the policy that decides
which requests are payable and what they cost, specifically for AI
crawler traffic: an AI crawler without a valid payment token gets a
402 with a JSON challenge; it pays out-of-band and retries with a
token that redeems exactly once. This policy does not settle payments
itself. With `proxy.payments` configured, settlement takes over the
402 issuance from this policy; without it, an in-memory or HTTP ledger
redeems tokens on their own.

Runnable examples:
[`examples/ai-crawl-control/`](../examples/ai-crawl-control/),
[`examples/ai-crawl-tiered/`](../examples/ai-crawl-tiered/),
[`examples/use-case-meter-crawlers/`](../examples/use-case-meter-crawlers/).

## Proving what was consumed: metering and the usage ledger

Two different ledgers answer two different questions, and neither one
settles a payment:

- [`metering.md`](metering.md) (`proxy.attestation`) cuts a signed,
  hash-chained receipt for every request an attesting origin serves:
  who consumed, on which route, how many units, at what outcome. A
  buyer holding nothing but your published key set can re-derive the
  whole chain and catch a tampered entry. This is the record for a
  billing dispute; `sbproxy_meter_*` metrics are for dashboards and
  alerts, and the page explains why they cannot substitute for the
  chain.
- [`ai-usage-ledger.md`](ai-usage-ledger.md) does the same
  hash-chained, optionally Ed25519-signed treatment specifically for
  completed LLM calls on an `ai_proxy` origin, turning best-effort
  usage events into a record you can prove.
- [`value-ledger-economics.md`](value-ledger-economics.md) is a
  different kind of accounting: it tracks the dollar value saved by
  routing to a local or self-hosted model instead of a configured
  cloud reference price, split into local-lane and cloud-lane
  completions. This is savings reporting for an operator, not a
  buyer-facing receipt.

Runnable example:
[`examples/metering-verify/`](../examples/metering-verify/).

## What is not shipped

[`l402.md`](l402.md) is design notes only. There is no macaroon
primitive, no L402 issuer or verifier, and no invoice-provider seam in
the codebase today; the page exists to agree the wire shape before any
code lands. If you need Lightning payments today, the Lightning rail
under `proxy.payments` (`examples/rail-lightning/`) is what actually
ships; do not build against `l402.md`.

## Who this is for

**Developers** monetizing an API or AI endpoint for the first time:
start at `payment-settlement.md`, then read `payment-clustering.md`
before you assume this scales horizontally the way the rest of the
proxy does. **AI users** charging for model access specifically: the
same `payment-settlement.md` path applies to an `ai_proxy` origin, and
`ai-usage-ledger.md` gives you a provable spend record on top.
**Advanced/operator users** billing based on consumption rather than
gating access: `metering.md` is the signed receipt chain a buyer can
independently verify, distinct from settlement entirely.
