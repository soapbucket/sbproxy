# Lightning settlement on your own node

*Last modified: 2026-08-02*

An article route priced at 2100 satoshis, settling over a Lightning node
you run. Core Lightning and LND are alternative backends for one
advertised `lightning` rail, and this example is mostly about making that
choice explicit rather than accidental.

Core Lightning is the live backend. The LND block ships commented out,
because no build registers an adapter for that rail yet and a config
naming it stops at startup. The section below on choosing between them
says what changes when it lands.

There is no hermetic Lightning stub in this repository, so serving this
example needs a reachable node.

## What is in the bundle

| File | Role |
|---|---|
| `sb.yml` | The Core Lightning backend, with the LND block alongside it in comments |
| `smoke.json` | Liveness manifest for `scripts/examples-smoke.sh` |

## Validate it

```bash
cargo build -p sbproxy --release --features payments,payment-lightning-cln
sbproxy validate -f examples/rail-lightning/sb.yml
```

Validation resolves no rune, opens no socket, and dials no node.

The feature list has to match the blocks the file configures. A rail that
is configured and not compiled fails startup by name, so uncommenting
`lightning_lnd` means adding `payment-lightning-lnd` to that build line
too. Validation does not check this: it is a startup check, because a
binary is what has features and a config file is not.

## Serve it

```bash
export SBPROXY_PAYMENT_BINDING_KEY="$(openssl rand -hex 32)"
export CLN_RUNE=...
sbproxy serve -f examples/rail-lightning/sb.yml
```

Every credential field in `sb.yml` names a secret rather than carrying
one. `env:NAME` reads the environment at startup and `file:/path` reads a
file, and neither needs any other configuration. A provider URI such as
`secret://<backend>/<name>` also resolves, but only against a backend
declared under `proxy.secrets.backends`; writing one without that block
validates fine and then fails startup on the field that names it.

Startup dials the CLN socket and checks the version through `getinfo`, so
a config pointed at a socket that is not there stops at boot rather than
at the first paid request. That is also why the probe below is the first
thing worth running: a proxy that answered the boot is a proxy that
reached the node.

## One rail, two backends

`lightning` is what a route advertises. `lightning_cln` and
`lightning_lnd` are what settle it. Exactly one adapter registers per
settlement rail, so an advertised `lightning` rail has to resolve to one
of them.

With one backend block configured, the selector is inferred, which is why
`lightning_backend: cln` is redundant in the file as it ships. Uncomment
the LND block and it stops being redundant: with both configured and no
selector, a route that advertises `lightning` is refused at load:

```text
proxy.payments.rails configures both lightning_cln and lightning_lnd; set
proxy.payments.rails.lightning_backend to `cln` or `lnd` so an advertised
lightning rail resolves to exactly one adapter
```

Naming a backend whose block is absent is refused the same way. Having
both blocks and advertising neither is allowed, because that is what a
migration looks like halfway through.

## Choosing between them

| | Core Lightning | LND |
|---|---|---|
| Transport | Unix domain socket, JSON-RPC | gRPC over TLS |
| Credential | A rune | A hex-encoded macaroon |
| Minimum version | v26.06 | Pinned to `v0.20.1-beta` protobufs |
| Extra file needed | None | The node's TLS certificate |
| Ships usable today | Yes | No, the gRPC transport is a separate slice |

Neither backend is preferred once both work. Until then, LND is
configurable and not servable: the settler and its contract tests are
done, but nothing gives it a channel to talk through, so a config that
names the rail is refused at startup rather than at a payer's expense:

```text
proxy.payments.rails.lightning_lnd is configured and the
`payment-lightning-lnd` cargo feature is compiled in, but no adapter
registered for it; refusing to publish a runtime that would answer a
payer's credential with an unsupported rail
```

## Core Lightning needs v26.06 or newer

The adapter reads the documented `xpay` label and the `listinvoices`
status that v26.06 defines. Setting the floor lower is refused at load:

```text
proxy.payments.rails.lightning_cln.minimum_version is "24.11", below the
26.06 this adapter requires for the documented `xpay` label and
`listinvoices` status
```

Startup then checks the live node through `getinfo` and refuses to
register the adapter if the running version is older. A version check that
only ran at first payment would fail a paid request instead of a boot.

## LND needs all three of endpoint, certificate, and macaroon

A connection missing any one of them cannot be established, so all three
are required at load rather than discovered at first payment. The endpoint
must be absolute and TLS-bearing, the certificate path must be absolute,
and the macaroon must be a secret reference. The macaroon is attached as
call metadata and redacted everywhere else. Those rules already hold for
the commented block, which is why it is worth keeping in the file: the
shape does not change when the transport lands.

## Currency, and why the route is priced in BTC

The live rail declares `quote_currency: BTC`, so the route is priced in
BTC. The commented LND block declares the same, so the price does not
move when that backend goes live. The proxy performs no currency
conversion, and one challenge cannot mix
currencies, because that would offer the payer two different prices for
one resource. Add a USD rail to this route and it is refused by name:

```text
advertised rails lightning and x402 are priced in BTC and USD; one
challenge cannot mix currencies because the proxy performs no
foreign-exchange conversion
```

Serving both means separately priced routes, each advertising rails that
agree on currency.

`settlement_decimals: 11` prices BTC in millisatoshis. The tier's
`amount_micros: 21` is 21 micro-BTC, which is 2100 satoshis. That
conversion is exact integer arithmetic; a price that does not convert
without a remainder is a config error rather than a rounding.

## What settlement actually requires

A transport success is not a payment. The rail queries the exact labeled
invoice and requires the node's own paid status before anything reaches
the origin. An RPC call that returned 200 while the invoice is still
unpaid settles nothing.

Recovery uses the same durable label. Every invoice the proxy creates
carries a unique label persisted before the write, so a process that
crashed mid-create can find the invoice it made instead of making a second
one.

## Clean up

Nothing to tear down. This example starts no containers.

## Related

- [docs/payment-settlement.md](../../docs/payment-settlement.md) - every `proxy.payments` field, the state table, and the unsupported boundaries.
- [docs/402-challenge.md](../../docs/402-challenge.md) - the exact challenge and credential bytes.
- [docs/l402.md](../../docs/l402.md) - the separate L402 macaroon credential surface.
- `examples/rail-x402-base-sepolia/` - x402 v2 `exact`.
- `examples/rail-mpp-stripe-test/` - Payment HTTP Authentication settling on Stripe.
