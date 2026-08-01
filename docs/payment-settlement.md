# Payment settlement

*Last modified: 2026-08-01*

`proxy.payments` is how SBproxy charges for a request and proves it was
paid. It is Apache-2.0, it is off unless you configure it, and it holds
one rule above everything else: a paid request reaches the origin only
after a durable record says the payment settled.

Verified is not settled. A timeout, an open circuit breaker, a provider
response the proxy cannot parse, an unpaid invoice, or a write whose fate
is unknown all stop the request in front of the origin. There is exactly
one transition that opens the route, and it is a committed row in SQLite.

If you only want the wire bytes, read
[402-challenge.md](402-challenge.md). If you only want to price crawler
traffic, read [ai-crawl-control.md](ai-crawl-control.md). This page is
the operator guide that sits between them.

## Vocabulary

These nine words appear in every error message, metric, and table below.

| Term | What it is |
|---|---|
| Requirement | The normalized statement of what is owed: amount, currency, rail, recipient, network, expiry. Built from the route's price and `proxy.payments`, and from nothing else. |
| Challenge | The requirement rendered onto the wire in one protocol, signed and bound to the proxy that issued it. |
| Credential | What the client sends back. An `Authorization: Payment` value, an x402 `PAYMENT-SIGNATURE` value, or a legacy `Crawler-Payment` token. |
| Intent | The durable row that owns one logical payment. It has exactly one state at a time. |
| Attempt | One numbered interaction with a provider under one idempotency key. An intent can have several. |
| Settlement | The rail reaching its own authoritative paid state, confirmed by the provider. |
| Receipt | The record of that settlement, carrying the provider's own reference. Written before any origin call. |
| Usage report | Consumption accounting. It never proves payment and cannot settle an intent. |
| Reconciliation | Asking a provider what happened to a write whose outcome was never recorded. It is a read. |

## The five phases, in order

Keeping these separate is the whole design. Collapsing any two of them is
how a gateway ends up serving content it was not paid for.

1. **Negotiation.** The client says which methods it can pay with. The
   proxy picks one. Nothing is charged and nothing is promised.
2. **Challenge.** The route computes a price. The proxy builds one
   normalized requirement, persists it as a `Pending` intent, signs it,
   and answers 402. For a rail that needs a provider object first, such
   as a manual-capture PaymentIntent or a Lightning invoice, that object
   is created here under a durable idempotency key. Preparation never
   captures funds, never calls the origin, and never emits a receipt.
3. **Authorization.** The client retries with a credential. The proxy
   verifies the signed requirement locally, loads the intent the
   challenge created, reserves the credential's digest against that one
   intent, stamps a dispatch record, and performs the rail's required
   verify and settle inside one bounded deadline.
4. **Delivery.** Only after `Succeeded` is committed and read back does
   the request reach the origin.
5. **Usage reporting.** Separate queue, separate registry, separate
   types. A reporter cannot construct a receipt.

## The state table

Every durable intent is in exactly one of these states, and each one
answers the only question that matters the same way.

| State | Provider work allowed | Origin access |
|---|---|---|
| `Pending` | Challenge preparation, or waiting for a credential | No |
| `Processing` | One bounded authoritative operation | No |
| `RetryWait` | A retry proven not to have been dispatched | No |
| `NeedsReconciliation` | Provider status query only | No |
| `Terminal` | None | No |
| `Succeeded` | No repeat charge, receipt lookup only | Yes |

The mapping from a failed authorization to a durable state is decided by
the dispatch gate, not by the error text:

| What happened | Durable transition | What the client sees |
|---|---|---|
| The rail settled and the receipt committed | `Succeeded` | The origin's response |
| The provider refused | `Terminal` | 402 with a problem document |
| The deadline elapsed before anything was dispatched | `RetryWait` | 503 with `Retry-After` |
| The deadline elapsed after dispatch | `NeedsReconciliation` | 503 with `Retry-After` |
| The provider's success response could not be parsed | `NeedsReconciliation` | 503 with `Retry-After` |
| The rail verified but did not settle | `NeedsReconciliation` | 503 with `Retry-After` |

A `NeedsReconciliation` intent is never retried by the request path. A
second attempt is how a payer gets charged twice, so the client waits for
the recovery worker instead.

## Which rail to reach for

| Rail | Reach for it when |
|---|---|
| x402 v2 `exact` | The payer is an autonomous agent with a wallet, you want per-request settlement with no account relationship, and you already trust a facilitator. |
| Payment HTTP Authentication with `stripe` and `charge` | The payer speaks the IETF Payment scheme and you want the credential to arrive in a standard `Authorization` field with a body digest bound to it. |
| Stripe PaymentIntents, advertised directly | You already have a Stripe account, the payer is a normal client, and you want challenge, client confirmation, and capture in three explicit steps. |
| Core Lightning | You run CLN v26.06 or newer and want sub-cent amounts settled over your own node. |
| LND | Same, on an LND node. CLN and LND are alternative backends for one advertised `lightning` rail, never both at once. |

The proxy performs no currency conversion. Every rail one route advertises
has to declare the same `quote_currency`, and config load rejects a mixed
challenge by name.

## Build features

The settlement machinery lives in the `sbproxy-billing` crate and none of
it is in the default build. Each surface names the exact feature that
compiles it, and a configured surface whose feature is missing is a
startup failure that prints the feature name rather than a surprise on the
first paid request.

| Configured surface | Cargo feature |
|---|---|
| `proxy.payments` | `payments` |
| `proxy.payments.protocols.payment_auth` | `payment-mpp` |
| `proxy.payments.rails.x402` | `payment-x402` |
| `proxy.payments.rails.stripe` | `payment-stripe` |
| `proxy.payments.usage_reporters.stripe_meter` | `payment-stripe` |
| `proxy.payments.rails.lightning_cln` | `payment-lightning-cln` |
| `proxy.payments.rails.lightning_lnd` | `payment-lightning-lnd` |

Every provider feature implies `payments`, and no payment feature is in
the binary's default set. Build the pair you actually use:

```bash
cargo build -p sbproxy --release --features payments,payment-x402
```

One adapter registers per settlement rail. If a rail is configured, its
feature is compiled, and no adapter registered for it, a credential on
that rail is answered `rail_unsupported` and the request stops in front of
the origin. There is no path where an unregistered rail lets a request
through.

## The configuration, field by field

The block below is the reference document the config crate validates
against. Every field is explained after it. Nothing here is resolved,
opened, or dialled at load: `sbproxy validate` runs this on a machine that
holds none of the credentials.

```yaml
proxy:
  payments:
    state_path: /var/lib/sbproxy/payments.sqlite3
    challenge_binding_key: secret://env/SBPROXY_PAYMENT_BINDING_KEY
    authorization_timeout_ms: 2000
    max_body_bytes: 1048576
    recovery_encryption:
      key_id: payments-2026-07
      key: secret://env/SBPROXY_PAYMENT_RECOVERY_KEY
      max_age_hours: 23
    worker:
      reconcile_interval_ms: 1000
      max_reconcile_batch: 32
      shutdown_timeout_ms: 5000
    protocols:
      payment_auth:
        draft: draft-ryan-httpauth-payment-01
        realm: api.example.com
        method: stripe
        intent: charge
    rails:
      x402:
        scheme: exact
        network: "eip155:84532"
        asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
        quote_currency: USD
        asset_decimals: 6
        pay_to: "0x1111111111111111111111111111111111111111"
        max_timeout_seconds: 60
        extra:
          name: USDC
          version: "2"
        facilitators:
          - facilitator_url: https://facilitator.example/api
        verify_timeout_ms: 700
        settle_timeout_ms: 1200
        breaker:
          failure_threshold: 3
          open_ms: 5000
          half_open_max: 1
      stripe:
        api_key: secret://env/STRIPE_SECRET_KEY
        api_version: 2026-06-24.dahlia
        account_context: platform
        business_network_id: profile_test_example
        quote_currency: USD
        currency_decimals: 2
        payment_method_types: [card]
        direct_payment_intent:
          enabled: true
          capture_method: manual
      lightning_cln:
        socket_path: /run/lightning/lightning-rpc
        rune: secret://env/CLN_RUNE
        minimum_version: "26.06"
        quote_currency: BTC
        settlement_decimals: 11
        invoice_expiry_seconds: 300
      lightning_lnd:
        endpoint: https://lnd.internal:10009
        tls_certificate_path: /run/secrets/lnd/tls.cert
        macaroon: secret://env/LND_MACAROON_HEX
        quote_currency: BTC
        settlement_decimals: 11
        invoice_expiry_seconds: 300
    usage_reporters:
      stripe_meter:
        event_name: sbproxy_ai_tokens
        customer_field: stripe_customer_id
```

Every block under `payments` rejects unknown keys, so a typo is a load
error rather than a silently ignored setting.

### Top level

| Field | Default | What it does, and what changes if you move it |
|---|---|---|
| `state_path` | required | Absolute path to the SQLite file that owns intents, attempts, proofs, and receipts. It is the authority: a request is allowed because a row here says so. A relative path is rejected. |
| `challenge_binding_key` | required | Names the key that binds a challenge to the proxy that issued it. Must be a reference such as `secret://env/NAME`, `env:NAME`, or `file:/path`; an inline key is rejected. Rotating it invalidates every outstanding challenge. |
| `authorization_timeout_ms` | `2000` | Total budget for the one synchronous provider interaction a paid request gets. Accepted range is 1 through 2000. Lowering it makes the proxy give up sooner, which moves more outcomes into `RetryWait` or `NeedsReconciliation` rather than letting a payer wait. 2000 is also the hard ceiling, because a longer wait turns a paid request into an availability problem for the origin behind it. |
| `max_body_bytes` | `1048576` | Largest request body the payment path buffers. A paid request with a body is read once in full so its digest can be bound to the challenge, so this caps what one request pins in memory. A larger body is answered 413 before any challenge or provider work. Range is 1 through 1048576. |

### `recovery_encryption`

Required whenever `rails.stripe` is set, and rejected as incomplete
otherwise. A Stripe create that crashed between the dispatch stamp and the
recorded response can only be resolved by replaying byte-identical request
bytes under the same idempotency key. Those bytes contain a single-use
payment token in the Payment Auth form, so they are only ever stored
encrypted with AES-256-GCM.

| Field | Default | What it does |
|---|---|---|
| `key_id` | required | Stored beside each ciphertext so a rotation knows which key decrypts which envelope. Drain or expire outstanding envelopes before retiring a key id. |
| `key` | required | Reference to the key. Load-time validation checks only that it names a secret; startup requires exactly 32 decoded bytes. |
| `max_age_hours` | `23` | Hard expiry for an envelope. Range is 1 through 23. The ceiling sits one hour below Stripe's documented 24-hour idempotency-key retention, so a same-key recovery can never race the provider forgetting the original request. |

The envelope never holds the API key or any authorization header.

### `worker`

The background worker recovers. It expires challenges nobody redeemed,
takes back leases whose holder went away, asks providers about writes left
outstanding, drains queued usage accounting, and purges expired recovery
envelopes. There is no code path from the worker to a settlement, and no
counter for one, because it cannot settle.

| Field | Default | What it does |
|---|---|---|
| `reconcile_interval_ms` | `1000` | Delay between sweeps. Range 10 through 300000. Raising it lengthens the window in which an ambiguous write stays unresolved. |
| `max_reconcile_batch` | `32` | Records claimed per sweep. Range 1 through 1024. Every queue has its own batch size so a backlog in one cannot starve the others. |
| `shutdown_timeout_ms` | `5000` | How long shutdown waits for the current tick to drain. Range 100 through 120000. An aborted tick cannot corrupt anything, because each transition is its own committed transaction, but the status reports the abort truthfully. |

### `protocols.payment_auth`

Payment HTTP Authentication. Absent means the proxy never emits a
`WWW-Authenticate: Payment` field.

| Field | Default | What it does |
|---|---|---|
| `draft` | `draft-ryan-httpauth-payment-01` | Declared rather than assumed. A configuration written against a different draft fails loudly instead of emitting bytes the client cannot parse. No other value is accepted. |
| `realm` | required | The protection space, echoed in every challenge and credential. It is the first slot of the challenge binding, so changing it invalidates outstanding challenges. A quote or backslash is rejected, because the value is quoted verbatim into a header field. |
| `method` | `stripe` | The only registered method in this release. |
| `intent` | `charge` | The only registered intent in this release. |

The core draft's intent registry is empty, so the method-specific
registration supplies the exact request, credential, and receipt
semantics. Configuring this block without `rails.stripe` is a load error,
since `stripe` plus `charge` is what settles it.

### `rails.x402`

| Field | Default | What it does |
|---|---|---|
| `scheme` | `exact` | The only x402 scheme this release implements. |
| `network` | required | CAIP-2 chain identifier such as `eip155:84532`. A short nickname like `base` is rejected: a signed payment requirement must not depend on a translation table. |
| `asset` | required | Asset contract address or identifier on that network. |
| `quote_currency` | required | Three uppercase letters. Every rail one route advertises must agree on this. |
| `asset_decimals` | required | Decimal places in the asset's atomic unit, 0 through 11. Used for the exact conversion from quote micros. A price that does not convert without remainder is a config error, never a rounding. |
| `pay_to` | required | Recipient address on `network`. |
| `max_timeout_seconds` | required | Copied into the requirement's `maxTimeoutSeconds`. Range 1 through 3600. |
| `extra` | `{}` | Scheme extras copied verbatim into the signed requirement. Its canonical encoding is byte-stable so the client can echo it and the proxy can compare it exactly. Capped at 4 KiB encoded. |
| `facilitators` | required, non-empty | Ordered candidates. Each `facilitator_url` is the facilitator's complete API root over HTTPS, with no query, fragment, userinfo, empty segment, relative segment, or endpoint suffix. Fallback to the next candidate is allowed only by issuing a fresh challenge; a signed requirement is bound to the one facilitator it selected. |
| `verify_timeout_ms` | `700` | Budget for the verify call. Range 1 through 2000. |
| `settle_timeout_ms` | `1200` | Budget for the settle call. Range 1 through 2000. The sum of the two may not exceed `authorization_timeout_ms`, because both legs share one request-path deadline. |
| `breaker.failure_threshold` | `3` | Consecutive transport failures that open the breaker. Range 1 through 1024. |
| `breaker.open_ms` | `5000` | How long it stays open. Range 100 through 60000. While open, the adapter returns immediately without a call. |
| `breaker.half_open_max` | `1` | Probes admitted while half open. Exactly 1 is accepted. A second concurrent probe against an unhealthy facilitator can dispatch a settlement whose response nobody is waiting to record, which is the one outcome the state machine cannot resolve on its own. |

The adapter builds endpoints by keeping every configured path segment,
stripping only trailing slashes, and appending exactly `/verify` or
`/settle`. A root of `https://facilitator.example/base/` yields
`https://facilitator.example/base/verify` and
`https://facilitator.example/base/settle` and nothing else. No version
segment is injected and no other path is ever constructed.

### `rails.stripe`

| Field | Default | What it does |
|---|---|---|
| `api_key` | required | Reference to the Stripe secret key. Never inline. |
| `api_version` | `2026-06-24.dahlia` | The only version accepted. A Stripe version bump changes PaymentIntent semantics, and a settlement path that silently followed the account's dashboard default would authorize requests against a contract nobody reviewed. |
| `account_context` | `platform` | The only value accepted. No `Stripe-Account` header is sent. Connect routing is deliberately unreachable from a challenge or a credential, because a client-controlled destination account would let a payer choose who gets paid. |
| `business_network_id` | required | Copied into the method details of a Payment Auth request. |
| `quote_currency` | required | Must be in the built-in ISO-4217 table. |
| `currency_decimals` | required | Checked against that table. A mis-declared currency would otherwise charge a hundred times the quoted price. |
| `payment_method_types` | required, non-empty | Offered on the PaymentIntent. |
| `direct_payment_intent.enabled` | `false` | Whether the direct PaymentIntent mode is advertised alongside Payment Auth. |
| `direct_payment_intent.capture_method` | `manual` | The only value accepted. Preparation must not capture funds or deliver the resource, so automatic capture is refused. |

### `rails.lightning_cln` and `rails.lightning_lnd`

CLN and LND are alternative backends for one advertised `lightning` rail.
Configure both only during a migration; set `rails.lightning_backend` to
`cln` or `lnd` before any route advertises `lightning`, or the load fails
as ambiguous. With exactly one configured, the backend is inferred.

| Field | Default | What it does |
|---|---|---|
| `lightning_cln.socket_path` | required | Absolute path to the `lightning-rpc` Unix socket. |
| `lightning_cln.rune` | required | Reference to the rune that authorizes the RPC calls. |
| `lightning_cln.minimum_version` | `26.06` | Cannot be set lower. The adapter depends on the documented `xpay` label and the `listinvoices` status that v26.06 defines, and startup checks the live version through `getinfo`. |
| `lightning_lnd.endpoint` | required | gRPC endpoint. Must be absolute and TLS-bearing. |
| `lightning_lnd.tls_certificate_path` | required | Absolute path to the node's certificate. |
| `lightning_lnd.macaroon` | required | Reference to the hex-encoded macaroon. Attached as call metadata and redacted everywhere else. |
| `quote_currency` | required | For both backends. |
| `settlement_decimals` | required | Decimal places in the settlement unit, 0 through 11. `11` prices BTC in millisatoshis. |
| `invoice_expiry_seconds` | `300` | Invoice lifetime. Range 30 through 86400. |

All three of endpoint, certificate, and macaroon are required for LND,
because a connection missing any one of them cannot be established, and
discovering that at first payment would fail a paid request instead of a
boot.

### `usage_reporters.stripe_meter`

| Field | Default | What it does |
|---|---|---|
| `event_name` | required | The meter event name registered in the Stripe dashboard. |
| `customer_field` | required | The request-context field carrying the Stripe customer identifier. |

Meter events record consumption. They are a different registry, a
different queue, and a different return type from settlement, and no
meter report can move an intent to `Succeeded`. Configuring this block
without `rails.stripe` is a load error, because the reporter borrows that
rail's API credentials.

## Secret references

Every credential field names a secret. An inline value is rejected at
load with the offending field path.

```yaml
challenge_binding_key: secret://env/SBPROXY_PAYMENT_BINDING_KEY
api_key: env:STRIPE_SECRET_KEY
macaroon: file:/run/secrets/lnd/macaroon.hex
```

Do not write `${STRIPE_SECRET_KEY}` in a payments field. Environment
interpolation runs before parsing, so the field would arrive holding the
literal credential and be rejected as inline. See
[secrets.md](secrets.md) for the backends behind each scheme.

## Startup and health

Validation and startup do different amounts of work, on purpose.

`sbproxy validate` checks shape, ranges, pinned constants, and the rules
that cross fields. It does not resolve a secret, open the SQLite file,
create a provider object, or start a worker, so it runs anywhere:

```bash
sbproxy validate -f examples/rail-x402-base-sepolia/sb.yml
```

Startup does the rest. It resolves secrets, opens and migrates the
database, checks that the recovery key decodes to exactly 32 bytes,
verifies the CLN node version through `getinfo` where that rail is
enabled, registers one adapter per rail, and starts the worker. A
configured rail whose cargo feature is absent fails here, naming the
feature. A reload keeps the previous runtime until the new one is fully
healthy, and drains the old worker only after the new one is published.

## Durable state and backups

`state_path` is the authority. Losing it does not lose money that already
moved at the provider, but it does lose the proof that a payer is owed
access, and it loses the record of writes that were outstanding.

- Back it up the way you back up any ledger. WAL mode is on, so copy the
  database and its sidecar files together or use SQLite's own backup API.
- Restoring an older copy can resurrect an intent the provider already
  settled. Reconciliation resolves that by asking the provider, on the
  rails that can answer.
- Do not point two proxies at one database over a network filesystem.
  Leases assume local durable writes.

## Timeouts, breakers, retries, and crashes

- One synchronous provider interaction per paid request, inside
  `authorization_timeout_ms`. The x402 rail spends that budget on verify
  and then settle; whatever the first leg does not use is still available
  to the second, and an exhausted budget fails before dispatch rather than
  starting a call it cannot finish.
- The breaker is per facilitator endpoint. Open means the adapter returns
  immediately with no call at all, which is why an open breaker can never
  produce an ambiguous write.
- A retry is only offered when the dispatch gate can prove nothing was
  sent. The gate commits a dispatch stamp before the network write is
  polled, so a process that dies mid-call leaves a record saying a write
  may have landed, and that record becomes `NeedsReconciliation` rather
  than a second attempt.
- A repeat of a request that already succeeded, with the same client
  `Idempotency-Key` and the same credential, returns the stored receipt.
  It does not settle again.
- A credential replayed against a different intent is refused as
  `proof_replayed` before any provider call.

## Reconciliation

Reconciliation is a read. It calls the rail's status query and nothing
else. It cannot create, confirm, capture, or retry, and there is no
force-success endpoint.

| What the provider proves | Result |
|---|---|
| The payment settled | The receipt commits and the intent becomes `Succeeded` |
| The write never landed | A later client retry may create a new attempt |
| The payment failed with no funds moved | The intent becomes terminal |
| The object exists and is unresolved | Stays in reconciliation |
| The rail has no documented way to answer | Stays in reconciliation |

x402 v2 in this release has no assumed public status endpoint, so an
ambiguous settle stays in reconciliation until an operator resolves it
with the facilitator. The adapter does not guess at a status or reorg
path, and it does not retry the settle on its own.

Resolving reconciliation never rescues the request that failed. That
response has already been sent. A later retry from the client observes
`Succeeded` and is allowed through.

## Metrics and logs

Payment metrics carry four labels and no more: `rail`, `operation`,
`outcome`, and `provider_class`. The allowed outcomes are `succeeded`,
`terminal`, `retry_wait`, and `needs_reconciliation`.

No quote id, challenge id, tenant id, address, provider reference,
PaymentIntent id, invoice, single-use token, credential, client secret,
macaroon, rune, provider error text, or usage customer id is ever a metric
label. Access logs may carry the rail and a one-way receipt correlation
digest, and never a sensitive header or a provider body. The failure
categories in durable records are a closed set for the same reason.

## Try it locally

```bash
sbproxy serve -f examples/rail-x402-base-sepolia/sb.yml
```

Then walk the three cases in
[`examples/rail-x402-base-sepolia/`](../examples/rail-x402-base-sepolia/):
a reader who is never charged, a declared crawler who gets a price, and a
credential the proxy never issued that buys nothing. The recorded
walkthrough of that sequence is `docs/assets/payment-settlement.gif`,
generated from `docs/tapes/payment-settlement.tape`:

```bash
scripts/record-tapes.sh payment-settlement
```

The other configurations are linked rather than copied here, so there is
one place to fix when a field moves:

- [`examples/rail-x402-base-sepolia/sb.yml`](../examples/rail-x402-base-sepolia/sb.yml) - x402 v2 `exact`.
- [`examples/rail-mpp-stripe-test/sb.yml`](../examples/rail-mpp-stripe-test/sb.yml) - Payment HTTP Authentication settling on Stripe.
- [`examples/rail-lightning/sb.yml`](../examples/rail-lightning/sb.yml) - CLN and LND as alternative backends.
- [`examples/multi-rail-accept-payment/sb.yml`](../examples/multi-rail-accept-payment/sb.yml) - several rails on one route in one currency.

## What this release does not do

The boundaries are as load-bearing as the features.

- **One node, not a mesh.** Settlement state is a single SQLite file at
  `proxy.payments.state_path`, and it is authoritative: a request is
  authorized because a row in that file says so. Nothing replicates it.
  A node that configures both `proxy.payments` and `proxy.cluster`
  therefore refuses to start rather than serving a ledger that only it
  can see. Three things break across a mesh, and the refusal exists
  because the middle one costs money: a challenge issued on one node
  cannot be redeemed on another, replay protection stops at the node
  boundary so the same payment can settle once per node, and a node lost
  before its worker drains leaves settlements no other node will
  reconcile. Run payments on one node until the store has a shared
  backend.
- **No wallet.** SBproxy holds no keys that move value and custodies
  nothing. It talks to a facilitator, to Stripe, or to your own Lightning
  node.
- **No x402 status or reorg API.** The adapter constructs `/verify` and
  `/settle` from the configured API root and no other path. An ambiguous
  settle stays in reconciliation. A status or reorg surface could only
  arrive as a separately configured, versioned extension with its own
  contract fixture.
- **Meter events do not settle.** They are usage accounting. The reporter
  type cannot build a receipt, and the store refuses to settle an intent
  from a meter attempt.
- **The worker does not settle.** It has no way to reach the settlement
  call, and no counter for one.
- **No Stripe Connect routing.** `account_context` accepts `platform`
  only, and no `Stripe-Account` header is sent.
- **No `Payment-Receipt` on x402.** That header belongs to Payment HTTP
  Authentication. A settled x402 request adds `PAYMENT-RESPONSE` and
  nothing else.
- **No proof material in `Accept-Payment`.** It is a preference list of
  methods and intents. It never authorizes anything.
- **No cleartext Payment flows.** TLS 1.2 or newer is required for public
  Payment Auth and provider endpoints. Plain HTTP is reachable only from a
  test-only loopback constructor that no configuration document can set.
- **One method and one intent.** Payment HTTP Authentication here is
  `stripe` plus `charge`. There is no generic provider schema and no
  negotiation to a second method.

## Related

- [402-challenge.md](402-challenge.md) - the exact bytes of each challenge, credential, error, and receipt.
- [ai-crawl-control.md](ai-crawl-control.md) - deciding which requests are payable and what they cost.
- [l402.md](l402.md) - the separate L402 macaroon credential surface.
- [secrets.md](secrets.md) - the backends behind `secret://`, `env:`, and `file:`.
- [observability.md](observability.md) - where payment metrics land alongside everything else.
