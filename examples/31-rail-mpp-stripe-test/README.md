# 31 - rail-mpp-stripe-test
*Last modified: 2026-05-02*

Stripe MPP (Merchant Payment Protocol) paywall in front of a markdown
feed origin, configured to talk to Stripe in test mode. Operators
bring their own `STRIPE_SECRET_KEY=sk_test_...`; the example never
ships a real key.

The README covers two paths:

1. The default stack with Stripe test mode. Requires a Stripe
   account and a test key; the redemption flow exercises the real
   Stripe API.
2. A wiremock fallback. Useful for CI environments that cannot
   reach the Stripe API or do not have a test key. The wiremock
   container stands in for `api.stripe.com` and returns
   PaymentIntents-shaped JSON so the proxy's redemption path stays
   exercised end-to-end.

## How it composes

| Service     | Image                              | Role                                                              |
|-------------|------------------------------------|-------------------------------------------------------------------|
| sbproxy     | built from `Dockerfile.cloudbuild` | Reverse proxy on `:8080` enforcing `ai_crawl_control` per `sb.yml`. |
| mock-origin | `nginx:1.27.3-alpine`              | Markdown feed origin. Returns one canned Markdown body on `/feed/*`. |
| wiremock    | `wiremock/wiremock:3.10.1`         | Optional. Stripe API stand-in when no test key is available.       |

`wiremock` lives behind the `wiremock` profile so a default `up`
does not start it:

```bash
docker compose up -d --wait                    # Stripe test mode
docker compose --profile wiremock up -d --wait # Offline / wiremock mode
```

## How to get a Stripe test key

The full setup is documented in Stripe's dashboard, but the short
form is:

1. Sign in at <https://dashboard.stripe.com>. New accounts default
   to test mode.
2. Open `Developers > API keys` and copy the **Secret key**. It
   starts with `sk_test_`.
3. Install the Stripe CLI: `brew install stripe/stripe-cli/stripe`
   (or follow the platform instructions in the Stripe docs).
4. `stripe login` to bind the CLI to your test mode account.
5. `stripe listen --forward-to http://127.0.0.1:8080/_stripe/webhook`
   to receive webhook events; the CLI prints a one-off `whsec_*`
   webhook signing secret on first run. Use it as
   `STRIPE_WEBHOOK_SECRET`.

The example reads both env vars from the operator's shell:

```bash
export STRIPE_SECRET_KEY=sk_test_...
export STRIPE_WEBHOOK_SECRET=whsec_...
docker compose up -d --wait
```

The proxy's Wave 3 emission path does not call Stripe (the 402 body
embeds a placeholder `pi_pending_<quote_id>` id; the worker (G3.3)
creates the real PaymentIntent on the redeem path), so the env vars
are unused for the 402 walk-through and only matter for the
end-to-end redemption demo below.

## How to run

```bash
cd examples/31-rail-mpp-stripe-test
docker compose up -d --wait
```

Tear down:

```bash
docker compose down -v
```

The `Makefile` wraps the same calls (`make up`, `make up-wiremock`,
`make down`, `make logs`, `make test`).

## What to expect

### 1. Browser, no Accept-Payment

Browser UA never matches the crawler list, so the policy never
charges and the proxy forwards to the mock origin.

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
     -H 'Host: feed.test.sbproxy.dev' \
     -H 'Accept: text/markdown' \
     http://127.0.0.1:8080/feed/articles/2026
# => 200
```

### 2. AI crawler, Accept-Payment: mpp

The agent opts in via `Accept-Payment: mpp`. The policy emits a 402
with `Content-Type: application/sbproxy-multi-rail+json` and one
`mpp` rail entry in the body.

```bash
curl -i \
     -H 'Host: feed.test.sbproxy.dev' \
     -H 'User-Agent: ClaudeBot/1.0' \
     -H 'Accept: text/markdown' \
     -H 'Accept-Payment: mpp' \
     http://127.0.0.1:8080/feed/articles/2026
# HTTP/1.1 402 Payment Required
# Content-Type: application/sbproxy-multi-rail+json
# {
#   "rails": [
#     {
#       "kind": "mpp",
#       "version": "1",
#       "stripe_payment_intent": "pi_pending_<quote_id>",
#       "amount_micros": 5000,
#       "currency": "USD",
#       "expires_at": "2026-05-02T...",
#       "quote_token": "eyJhbGc..."
#     }
#   ],
#   "agent_choice_method": "header_negotiation",
#   "policy": "first_match_wins"
# }
```

`stripe_payment_intent` is a placeholder (`pi_pending_*`) in Wave 3.
The agent does not confirm the placeholder; it confirms the real
`pi_*` the worker creates on redeem.

### 3. Walking through PaymentIntents end-to-end

With `STRIPE_SECRET_KEY` set, the agent's redemption flow looks
like this (the proxy's MPP worker handles the Stripe-side dance):

1. Agent fetches the URL, receives the 402 with the `mpp` rail
   entry and a `quote_token` JWS.
2. Agent fetches `/.well-known/sbproxy/quote-keys.json` from the
   admin port and verifies the JWS.
3. Agent posts the quote to the proxy's redeem endpoint. The MPP
   worker creates a real PaymentIntent against the configured
   `STRIPE_SECRET_KEY` and returns the `client_secret`.
4. Agent confirms the PaymentIntent against `api.stripe.com` (or
   the wiremock if running offline).
5. Agent retries the original request with the redeemed quote
   token in the `Crawler-Payment` header. The proxy validates and
   forwards.

For a full hands-on walkthrough you can fire a synthetic
`payment_intent.succeeded` from the Stripe CLI:

```bash
stripe trigger payment_intent.succeeded
```

The proxy's webhook handler (gated on `STRIPE_WEBHOOK_SECRET`)
verifies the signature and audits the event.

### 4. Simulating a dispute

Stripe in test mode lets you create disputes synthetically:

```bash
stripe trigger charge.dispute.created
```

The agent SDK's response to a dispute is out of scope for the proxy
(disputes are settled through the Stripe dashboard); the proxy only
audits the dispute event so the operator has a paper trail.

## Wiremock fallback

When `STRIPE_SECRET_KEY` is not available (CI without Stripe
credentials, air-gapped network, etc.), the wiremock profile spins
up a Stripe stand-in:

```bash
docker compose --profile wiremock up -d --wait
```

The wiremock container serves Stripe-shaped JSON on the same
endpoints the worker would call (`POST /v1/payment_intents`,
`POST /v1/payment_intents/<id>/confirm`). Mappings live under
`wiremock-stripe/mappings/`. The proxy will not actually call
wiremock during the 402-emission path on Wave 3, so this profile is
mostly here for offline development of the redemption side.

To point a redemption-flow test at the wiremock instead of
`api.stripe.com`, override the proxy's MPP base URL via env. The
exact override knob lands with G3.3 (worker); for now the wiremock
container is wired but unused.

## What if I do not have a Stripe key?

The Wave 3 emission path is independent of Stripe. The proxy mints
the placeholder `pi_pending_*` id from the quote-token's
`quote_id`, signs the JWS, and returns the multi-rail body. So
without a Stripe key:

- Liveness probes pass.
- The 402 emission walkthrough above works exactly as documented.
- The end-to-end redemption flow does not work, because the worker
  cannot create a real PaymentIntent.

`scripts/examples-smoke.sh` runs only the liveness check, so this
example passes CI without a Stripe key. The `smoke.json`
`skip_unless_env` field is a soft hint for a future smoke runner
that wants to gate an additional probe on the env var.

## Cargo features

The example assumes a default-features `sbproxy` build (which
includes `tiered-pricing`, `agent-class`, and `http-ledger`). The
multi-rail emission path is unconditional in the `sbproxy-modules`
crate; no operator-set cargo feature is needed to enable MPP itself.
The `Dockerfile.cloudbuild` image used by `docker-compose.yml` ships
the default feature set.

## Related docs

- `docs/billing-rails.md` - operator-facing billing rails reference.
- `docs/adr-multi-rail-402-challenge.md` (A3.1) - wire shape of the
  402 body.
- `docs/adr-quote-token-jws.md` (A3.2) - quote-token JWS shape and
  JWKS publication.
- `docs/adr-billing-rail-x402-mpp-mapping.md` - rail / asset mapping.
- `examples/30-rail-x402-base-sepolia/` - x402 rail counterpart.
- `examples/32-multi-rail-accept-payment/` - both rails wired
  together with q-value negotiation.
- `examples/33-quote-token-replay-jwks/` - JWKS endpoint and
  single-use quote token enforcement.
