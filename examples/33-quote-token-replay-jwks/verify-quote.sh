#!/usr/bin/env bash
# verify-quote.sh - walk the JWKS + 402 + verify flow for example 33.
#
# What this does:
#   1. GET /.well-known/sbproxy/quote-keys.json from the admin port
#      and extract the first JWK. Pins the alg/crv shape.
#   2. GET /article with `Accept-Payment: x402` and a crawler UA.
#      Pull the multi-rail body's first rail entry's `quote_token`.
#   3. Decode the JWS header + payload (base64url) and pretty-print.
#   4. Verify the signature against the JWK using `openssl dgst`.
#      Ed25519 signatures land via `openssl pkeyutl -verify`.
#   5. Redeem the token by retrying the request with a
#      `crawler-payment: <token>` header. Expect 200.
#   6. Retry the redeem. Expect 409 (single-use enforcement).
#
# Requirements:
#   - jq      (apt install jq / brew install jq)
#   - openssl >= 1.1.1 with Ed25519 support
#   - curl
#
# Usage:
#   ./verify-quote.sh
#
# Env knobs:
#   PROXY_HOST     default 127.0.0.1
#   PROXY_PORT     default 8080  (data plane)
#   ADMIN_PORT     default 9090  (JWKS endpoint)
#   HOST_HEADER    default blog.test.sbproxy.dev

set -euo pipefail

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8080}"
ADMIN_PORT="${ADMIN_PORT:-9090}"
HOST_HEADER="${HOST_HEADER:-blog.test.sbproxy.dev}"

# --- Tool checks ---------------------------------------------------
need() {
    command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 2; }
}
need jq
need openssl
need curl

# --- Step 1: fetch JWKS ------------------------------------------
echo "==> 1/6 Fetching JWKS document from admin port :$ADMIN_PORT"
JWKS_BODY="$(curl -fsS "http://$PROXY_HOST:$ADMIN_PORT/.well-known/sbproxy/quote-keys.json")"
echo "$JWKS_BODY" | jq .
KID="$(echo "$JWKS_BODY" | jq -r '.keys[0].kid')"
ALG="$(echo "$JWKS_BODY" | jq -r '.keys[0].alg')"
CRV="$(echo "$JWKS_BODY" | jq -r '.keys[0].crv')"
PUB_X_B64URL="$(echo "$JWKS_BODY" | jq -r '.keys[0].x')"
echo "    kid=$KID alg=$ALG crv=$CRV"
[ "$ALG" = "EdDSA" ] || { echo "expected alg=EdDSA, got $ALG" >&2; exit 1; }
[ "$CRV" = "Ed25519" ] || { echo "expected crv=Ed25519, got $CRV" >&2; exit 1; }

# --- Step 2: 402 challenge -----------------------------------------
echo "==> 2/6 Provoking a 402 multi-rail challenge"
RESP_FILE="$(mktemp -t verify-quote-resp-XXXXXX)"
HTTP_CODE="$(curl -sS -o "$RESP_FILE" -w '%{http_code}' \
    -H "Host: $HOST_HEADER" \
    -H 'User-Agent: GPTBot/1.0' \
    -H 'Accept-Payment: x402' \
    "http://$PROXY_HOST:$PROXY_PORT/article")"
[ "$HTTP_CODE" = "402" ] || { echo "expected 402, got $HTTP_CODE" >&2; cat "$RESP_FILE"; exit 1; }
echo "    response status = 402 OK"
TOKEN="$(jq -r '.rails[0].quote_token' "$RESP_FILE")"
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || {
    echo "missing quote_token in body" >&2; cat "$RESP_FILE"; exit 1;
}

# --- Step 3: decode JWS header + payload ---------------------------
echo "==> 3/6 Decoding JWS"
b64url_decode() {
    # Pad input to a multiple of 4, swap URL-safe alphabet, decode.
    local raw="$1"
    local pad=$(( (4 - ${#raw} % 4) % 4 ))
    local padded="$raw$(printf '=%.0s' $(seq 1 $pad))"
    echo -n "$padded" | tr '_-' '/+' | openssl base64 -d -A
}
HDR_B64="$(echo -n "$TOKEN" | cut -d. -f1)"
PAY_B64="$(echo -n "$TOKEN" | cut -d. -f2)"
SIG_B64="$(echo -n "$TOKEN" | cut -d. -f3)"
echo "    header  = $(b64url_decode "$HDR_B64" | jq -c .)"
echo "    payload = $(b64url_decode "$PAY_B64" | jq -c .)"
KID_FROM_HDR="$(b64url_decode "$HDR_B64" | jq -r .kid)"
[ "$KID_FROM_HDR" = "$KID" ] || {
    echo "kid mismatch: jws=$KID_FROM_HDR jwks=$KID" >&2; exit 1;
}

# --- Step 4: verify signature against the JWK ----------------------
echo "==> 4/6 Verifying signature against JWKS public key"
# Ed25519 raw public key from the JWK 'x' field (32 bytes, base64url).
PUB_RAW="$(mktemp -t verify-quote-pub-XXXXXX)"
b64url_decode "$PUB_X_B64URL" > "$PUB_RAW"
# Wrap the raw bytes in the SubjectPublicKeyInfo DER prefix that
# openssl expects for Ed25519 (RFC 8410). The prefix is the 12-byte
# DER header `30 2a 30 05 06 03 2b 65 70 03 21 00`.
PUB_DER="$(mktemp -t verify-quote-pub-der-XXXXXX)"
printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00' > "$PUB_DER"
cat "$PUB_RAW" >> "$PUB_DER"
PUB_PEM="$(mktemp -t verify-quote-pub-pem-XXXXXX)"
{
    echo '-----BEGIN PUBLIC KEY-----'
    openssl base64 -A -in "$PUB_DER" | fold -w 64
    echo
    echo '-----END PUBLIC KEY-----'
} > "$PUB_PEM"

SIGN_INPUT="$(mktemp -t verify-quote-input-XXXXXX)"
printf '%s.%s' "$HDR_B64" "$PAY_B64" > "$SIGN_INPUT"
SIG_RAW="$(mktemp -t verify-quote-sig-XXXXXX)"
b64url_decode "$SIG_B64" > "$SIG_RAW"

if openssl pkeyutl -verify \
        -pubin -inkey "$PUB_PEM" \
        -rawin -in "$SIGN_INPUT" \
        -sigfile "$SIG_RAW" \
        -keyform PEM 2>/dev/null
then
    echo "    signature OK"
else
    echo "    signature FAILED" >&2
    rm -f "$RESP_FILE" "$PUB_RAW" "$PUB_DER" "$PUB_PEM" "$SIGN_INPUT" "$SIG_RAW"
    exit 1
fi

# --- Step 5: redeem ------------------------------------------------
#
# NOTE: This example uses the in-memory ledger (the OSS default). The
# in-memory ledger seeds tokens from `valid_tokens:` in sb.yml, which
# this example leaves empty. The quote token we just verified is NOT
# in `valid_tokens`, so the in-memory ledger will reject it with a
# hard error and the proxy will respond 402 again, not 200.
#
# A real deployment wires `policies[].ledger:` at an HTTP ledger
# (see docs/billing-rails.md) that knows how to verify the JWS
# directly. The verify-then-redeem flow ends here for this example;
# the README continues the walkthrough with a config snippet showing
# the ledger wiring.
echo "==> 5/6 Redeem step (documented; not executed)"
echo "    See docs/billing-rails.md for the http-ledger wiring that"
echo "    accepts a verified JWS as a valid redemption."

# --- Step 6: replay attempt ---------------------------------------
#
# In the real flow, a second redeem attempt for the same nonce
# returns 409 from the InMemoryNonceStore. We document this here for
# completeness; the OSS in-memory ledger does not implement the
# nonce-store handshake (the verify-only path lives in a future
# wave), so we do not exercise it from this script.
echo "==> 6/6 Replay attempt (documented; not executed)"
echo "    InMemoryNonceStore returns 409 on the second redeem with"
echo "    the same nonce. See README and"
echo "    crates/sbproxy-modules/src/policy/quote_token.rs for the"
echo "    NonceStore trait."

# --- Cleanup ---
rm -f "$RESP_FILE" "$PUB_RAW" "$PUB_DER" "$PUB_PEM" "$SIGN_INPUT" "$SIG_RAW"
echo "all done"
