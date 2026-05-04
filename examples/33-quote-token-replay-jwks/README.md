# 33 - quote-token-replay-jwks
*Last modified: 2026-05-02*

Demonstrates the quote-token JWKS endpoint, end-to-end JWS
verification, and single-use replay protection.

The example boots the proxy with admin enabled on port 9090 so the
JWKS document is reachable from outside the docker network. A small
helper script (`verify-quote.sh`) walks the full flow: fetch the
JWKS, provoke a 402, decode the JWS, verify against the published
public key, and document the redeem and replay paths.

## How it composes

| Service                | Image                              | Role                                                                         |
|------------------------|------------------------------------|------------------------------------------------------------------------------|
| sbproxy                | built from `Dockerfile.cloudbuild` | Reverse proxy on `:8080`. Admin listener on `:9090` serves the JWKS.         |
| mock-x402-facilitator  | `nginx:1.27.3-alpine`              | Reused from example 30; only here so the x402 rail config is well-formed.    |
| mock-origin            | `nginx:1.27.3-alpine`              | Article server. Returns one canned HTML body on `/article`.                  |

## How to run

```bash
cd examples/33-quote-token-replay-jwks
docker compose up -d --wait
```

Tear down:

```bash
docker compose down -v
```

`make up` / `make down` / `make logs` wrap the same calls. `make
jwks` does a one-shot GET against the JWKS endpoint; `make test`
runs the full `verify-quote.sh` helper.

## The JWS shape

Quote tokens are RFC 7515 JWS Compact Serialisation. Three
base64url-encoded segments separated by `.`:

```
<header>.<payload>.<signature>
```

The header is pinned to:

```json
{"alg":"EdDSA","typ":"sbproxy-quote+jws","kid":"<key-id>"}
```

Three pins worth calling out:

- `alg=EdDSA` (Ed25519 over the message
  `<header>.<payload>` rendered as ASCII).
- `typ=sbproxy-quote+jws` (vendor-specific media type so verifiers
  reject ordinary application JWTs masquerading as quote tokens
  before any signature work happens).
- `kid` matches an entry in the JWKS document. Verifiers reject any
  token whose `kid` does not resolve.

The payload is the quote claim set (per `docs/adr-quote-token-jws.md`):

```json
{
  "iss":   "https://blog.test.sbproxy.dev",
  "sub":   "<resolved agent id>",
  "aud":   "ledger",
  "iat":   1746219000,
  "exp":   1746219300,
  "nonce": "01HW...",
  "quote_id": "01HW...",
  "route": "/article",
  "shape": "html",
  "price": {"amount_micros": 1000, "currency": "USD"},
  "rail":  "x402",
  "facilitator": "http://mock-x402-facilitator:80"
}
```

`nonce` is the single-use identifier the verifier consults the
[`NonceStore`] for. `quote_id` is a stable identifier separate from
`nonce` so logs can correlate without revealing the redemption
secret.

## The JWKS document

The admin server serves the public key set at:

```
GET http://127.0.0.1:9090/.well-known/sbproxy/quote-keys.json
```

This path is unauthenticated. The keys themselves are public; the
admin server gates the JWKS route ahead of the basic-auth check.

The body is a standard JWKS document:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "use": "sig",
      "alg": "EdDSA",
      "kid": "replay-demo-2026",
      "x":   "<32-byte-public-key-base64url>"
    }
  ]
}
```

The proxy aggregates kids across every origin that has an
`ai_crawl_control` policy with a `quote_token:` block. A
multi-tenant deployment publishes one JWKS document covering all of
its issuers; the verifier cache key is the body hash, so the proxy
keeps the document stable across calls (BTreeMap-ordered) so a
verifier on the other side does not re-fetch on every cache miss.

The kid is stamped into both the JWS header and the JWKS entry. To
rotate, the operator adds a new key alongside the old one (so
existing issued tokens continue to verify), bumps the
`quote_token.key_id` in `sb.yml`, hot-reloads, and removes the old
key once the longest plausible TTL has passed.

## End-to-end walkthrough

`verify-quote.sh` walks every step the README describes. Run it
against a live stack:

```bash
make up
./verify-quote.sh
```

The script:

1. Fetches the JWKS from `:9090` and asserts the alg/crv pins.
2. Provokes a 402 by sending `Accept-Payment: x402` with a crawler
   UA. Pulls `rails[0].quote_token` from the multi-rail body.
3. Decodes the JWS header + payload (base64url) and pretty-prints.
4. Verifies the signature against the published public key using
   `openssl pkeyutl -verify`. Real bytes; no pseudocode.
5. Documents the redeem and replay paths (the OSS in-memory ledger
   does not implement the verify-then-redeem handshake; that wiring
   lands with `policies[].ledger:` against an HTTP ledger).

### Step 1: GET JWKS

```bash
curl -s http://127.0.0.1:9090/.well-known/sbproxy/quote-keys.json | jq .
# {
#   "keys": [
#     {
#       "kty": "OKP",
#       "crv": "Ed25519",
#       "use": "sig",
#       "alg": "EdDSA",
#       "kid": "replay-demo-2026",
#       "x":   "..."
#     }
#   ]
# }
```

### Step 2: GET /article -> 402

```bash
curl -s -o /tmp/resp.json -w '%{http_code}\n' \
     -H 'Host: blog.test.sbproxy.dev' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'Accept-Payment: x402' \
     http://127.0.0.1:8080/article
# => 402

jq -r '.rails[0].quote_token' /tmp/resp.json
# eyJhbGciOiJFZERTQSI...
```

### Step 3: Decode

```bash
TOKEN="$(jq -r '.rails[0].quote_token' /tmp/resp.json)"
echo "$TOKEN" | cut -d. -f1 | base64 --decode | jq .
# {"alg":"EdDSA","typ":"sbproxy-quote+jws","kid":"replay-demo-2026"}

echo "$TOKEN" | cut -d. -f2 | base64 --decode | jq .
# Payload claims (iss, sub, aud, iat, exp, nonce, quote_id, ...)
```

### Step 4: Verify

`verify-quote.sh` does this with `openssl pkeyutl -verify`. The
signature path needs the raw 32-byte public key from the JWK `x`
field wrapped in the SubjectPublicKeyInfo DER prefix (RFC 8410).
The script handles the wrapping inline.

### Step 5: Redeem (documented; not exercised in OSS)

The OSS in-memory ledger seeds tokens from `valid_tokens:` in
`sb.yml`. This example leaves `valid_tokens` empty because the
quote-token JWS shape is what the example demonstrates, and an
HTTP-ledger backend (rather than the in-memory list) verifies the
JWS directly. To exercise the full redeem path:

```yaml
policies:
  - type: ai_crawl_control
    # ... rest of the config above ...
    ledger:
      url: https://your-ledger.example.com
      key_id: ledger-hmac-2026
      secret_ref:
        env: SBPROXY_LEDGER_HMAC_HEX
      workspace_id: default
```

Build the proxy with the `http-ledger` cargo feature on (the default
`sbproxy` binary already has it on; the e2e harness's release build
does too) and the redeem path verifies the JWS against the JWKS
internally.

### Step 6: Replay (documented; not exercised in OSS)

The proxy's [`InMemoryNonceStore`] implements the
[`NonceStore`] trait used by the verifier. Once a nonce has been
consumed, the verifier's check returns `NonceCheck::AlreadyConsumed`,
which the proxy translates to:

```
HTTP/1.1 409 Conflict
Content-Type: application/json
{"error":"ledger.token_already_spent","retryable":false}
```

The OSS in-memory ledger does not implement the verify-then-redeem
handshake (the path through the HTTP ledger does); the unit tests
in `crates/sbproxy-modules/src/policy/quote_token.rs` cover the
single-use behaviour directly.

## Cargo features

The example assumes a default-features `sbproxy` build. The JWKS
endpoint and quote-token signing are both unconditional in the
`sbproxy-modules` and `sbproxy-core` crates; no operator-set cargo
feature is needed.

## Related docs

- `docs/billing-rails.md` - operator-facing billing rails reference.
- `docs/adr-quote-token-jws.md` (A3.2) - quote-token JWS shape and
  JWKS publication contract.
- `docs/adr-multi-rail-402-challenge.md` (A3.1) - the 402 body that
  carries the JWS.
- `examples/30-rail-x402-base-sepolia/` - x402 rail with the same
  JWKS publication path.
- `examples/31-rail-mpp-stripe-test/` - MPP rail counterpart.
- `examples/32-multi-rail-accept-payment/` - Accept-Payment
  negotiation across both rails.
