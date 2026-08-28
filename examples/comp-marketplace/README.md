# CoMP marketplace bridge

Sell a standing license to an AI buyer instead of negotiating a
micropayment on every crawl. The buyer reads your catalog once, asks
for a signed price, pays, and redeems that acceptance for a license
token good for a day.

The token is an OLP token signed with this origin's own
`olp.signing_key`, under the same `kid`, so the same origin's
`/.well-known/olp/introspect` verifies it with no extra trust
configuration. That wire-format match is why there is no second issuer
here.

Three endpoints, all on the configured origin:

| Method | Path | What it does |
|---|---|---|
| `GET` | `/.well-known/iab-comp/manifest.json` | The catalog: publisher, tiers, prices, endpoint URLs. Cached five minutes. |
| `POST` | `/.well-known/iab-comp/quote` | A signed price for a named tier and a requested volume. Good for one hour. `no-store`. |
| `POST` | `/.well-known/iab-comp/redeem` | A signed, paid acceptance, exchanged for a license token. `no-store`. |

## Run it

```bash
export COMP_MASTER_KEY="$(head -c 32 /dev/urandom | base64)"
export OLP_SIGNING_KEY="$(head -c 32 /dev/urandom | xxd -p -c 64)"
make run CONFIG=examples/comp-marketplace/sb.yml
```

### 1. The catalog

```bash
curl -s -H 'Host: licensing.local' \
  http://127.0.0.1:8080/.well-known/iab-comp/manifest.json | jq
```

Two tiers come back. Only `tier_ai_inference` carries
`"authorization": "olp"`, and only an OLP tier can be redeemed for a
token. `manifest_hash` is computed by the proxy over the document it
just served, with the field itself cleared.

### 2. A signed price

```bash
curl -s -H 'Host: licensing.local' -H 'content-type: application/json' \
  -d '{"comp_version":"1.0",
       "buyer":{"agent_id":"agent_acme_001","organization":"Acme AI Inc."},
       "tier_id":"tier_ai_inference",
       "requested_volume":{"model":"per_request","expected_count":10000,"duration_days":30},
       "audience":"licensing.local"}' \
  http://127.0.0.1:8080/.well-known/iab-comp/quote | jq
```

10,000 requests at $0.0025 each quotes at `25000000` micros, and
`signature.kid` starts with `comp-`. That prefix is the point: quotes
sign under their own key namespace, so a quote signature can never be
replayed as a license token.

### 3. Redeem it

Redeeming needs an Ed25519 signature over the request body with the
buyer key the config onboarded. The demo private key is the 32-byte
seed `0x5a` repeated, whose public half is the `public_key` in
`sb.yml`. Never ship a demo key in a real catalog: everyone who has
read this file holds the private half.

```bash
python3 - <<'EOF'
import base64, json, subprocess
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

quote = json.loads(subprocess.check_output([
    "curl", "-s", "-H", "Host: licensing.local",
    "-H", "content-type: application/json",
    "-d", json.dumps({
        "comp_version": "1.0",
        "buyer": {"agent_id": "agent_acme_001", "organization": "Acme AI Inc."},
        "tier_id": "tier_ai_inference",
        "requested_volume": {"model": "per_request", "expected_count": 10000,
                             "duration_days": 30},
        "audience": "licensing.local",
    }),
    "http://127.0.0.1:8080/.well-known/iab-comp/quote",
]))

# The acceptance hash is the SHA-256 of the same canonical bytes the
# quote's own signature covers. See "signing is not JCS" below.
import hashlib
signed_fields = dict(quote)
signed_fields.pop("signature")
canonical = json.dumps(signed_fields, separators=(",", ":")).encode()
accepted_quote_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()

import datetime
body = {
    "comp_version": "1.0",
    "quote_id": quote["quote_id"],
    "buyer_signature": {"alg": "ed25519", "kid": "buyer-demo-001", "value": ""},
    "buyer_acceptance": {
        "accepted_quote_hash": accepted_quote_hash,
        "accepted_at": datetime.datetime.now(datetime.timezone.utc)
                       .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "buyer_legal_entity": "Acme AI Inc.",
    },
    "payment_proof": {"rail": "x402", "txhash": "0xdeadbeef", "chain": "base"},
}
signing_input = json.dumps(body, separators=(",", ":")).encode()
key = Ed25519PrivateKey.from_private_bytes(bytes([0x5A]) * 32)
body["buyer_signature"]["value"] = base64.urlsafe_b64encode(
    key.sign(signing_input)).decode().rstrip("=")
print(json.dumps(body))
EOF
```

Pipe that into the redeem endpoint and you get back a `license_token`,
its `expires_in`, the `license` URN, a derived `agent_id`, and the
tier's `route_glob`.

The script is fiddly on purpose, and the fiddly part is the byte order:
see [Signing is not JCS](#signing-is-not-jcs).

### 4. What fails closed

None of these need a signature to try:

```bash
# A body that is not JSON: 400 malformed
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: licensing.local' \
  -H 'content-type: application/json' -d '{not json' \
  http://127.0.0.1:8080/.well-known/iab-comp/quote

# A tier this publisher does not sell: 404 unknown_tier
curl -s -H 'Host: licensing.local' -H 'content-type: application/json' \
  -d '{"comp_version":"1.0","buyer":{"agent_id":"a","organization":"b"},
       "tier_id":"tier_that_does_not_exist",
       "requested_volume":{"model":"per_request","expected_count":1,"duration_days":1},
       "audience":"licensing.local"}' \
  http://127.0.0.1:8080/.well-known/iab-comp/quote | jq
```

Change `kid` in the redeem script to a key this config never onboarded
and you get `401 unknown_key`. Change `quote_id` to something the
proxy never issued and you get `403 unknown_quote`. Neither refusal
carries a token.

### 5. The operator view

```bash
curl -s http://127.0.0.1:9090/admin/licensing | jq
```

`active_signing_kid` is the one worth watching: `null` means no
rotation has been activated and every quote request fails closed until
one is. `olp_tier_count` is how many of `tier_count` a buyer can
actually redeem, which is 1 of 2 here.

## Two things to know before you ship this

### The quote ledger does not survive a restart

It is in memory, by design. A buyer holding a quote from before a
reload is refused with `unknown_quote` and pays one extra round trip
for a fresh quote. `allow_unknown_quotes: true` removes that refusal,
and removes with it the only thing standing between an onboarded buyer
key and a token per call with a fabricated `quote_id`.

### Signing is not JCS

Both signatures cover `serde_json`'s rendering of the Rust struct, so
the field order is the struct's declaration order rather than the
sorted key order [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
defines. The Python above happens to match because `json.dumps`
preserves insertion order and the dict is written in declaration order.
A client that builds the body differently has to reproduce that order
byte for byte.

See [docs/comp-marketplace.md](../../docs/comp-marketplace.md) for the
full configuration reference, the metrics, the decision events, and the
rest of the honest limits.
