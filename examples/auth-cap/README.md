# CAP token authentication

*Last modified: 2026-05-07*

![CAP token authentication](../../docs/assets/auth-cap.gif)

Validates Crawler Authorization Protocol (CAP) tokens on every request. CAP tokens are EdDSA-signed JWTs bound to an agent identity (`sub`), a request audience (`aud`), and a route allow-list (`glob`); they also carry a `rps` rate limit and a daily `bytes` budget that the proxy can enforce. The verifier in this example trusts a single Ed25519 public key supplied inline via `jwks_static`. Production deployments should swap that for `jwks_url` so the issuer can rotate keys without a config reload.

The example is offline-friendly: a TEST Ed25519 keypair lives under `tokens/`, and `mint.py` signs sample tokens with the private half so you do not need an issuer running anywhere to try the flow.

## Files

```
auth-cap/
  sb.yml                 - proxy config; auth.type: cap with static JWKS
  mint.py                - mints a sample CAP token from tokens/test-private.pem
  tokens/
    test-private.pem     - Ed25519 private key (TEST KEY, do not reuse)
    test-public.pem      - matching public key in PEM form, for reference
  README.md              - this file
  smoke.json             - declarative cases: missing / tampered / wrong-aud / valid
```

## Run

```bash
make run CONFIG=examples/auth-cap/sb.yml
```

No env vars required.

Mint a sample token (defaults match `sb.yml`):

```bash
python3 examples/auth-cap/mint.py > /tmp/cap.jwt
```

If the script complains it cannot import `cryptography`, install it once:

```bash
python3 -m pip install cryptography
```

## Try it

Missing token, request rejected:

```bash
$ curl -i -H 'Host: cap.localhost' http://127.0.0.1:8080/blog/article
HTTP/1.1 401 Unauthorized
WWW-Authenticate: CAP error="missing_token"
```

Valid token in the documented `CAP-Token` header, request forwarded:

```bash
$ TOKEN=$(cat /tmp/cap.jwt)
$ curl -i -H 'Host: cap.localhost' -H "CAP-Token: $TOKEN" \
       http://127.0.0.1:8080/blog/article
HTTP/1.1 200 OK
```

The token also flows through the `Authorization: CAP <jwt>` scheme:

```bash
$ curl -i -H 'Host: cap.localhost' -H "Authorization: CAP $TOKEN" \
       http://127.0.0.1:8080/blog/article
HTTP/1.1 200 OK
```

Tampered signature, rejected with 401:

```bash
$ BAD="${TOKEN%.*}.AAAAtamperedSignatureBytesAreNotARealEd25519Signature"
$ curl -is -H 'Host: cap.localhost' -H "CAP-Token: $BAD" \
       http://127.0.0.1:8080/blog/article | head -n 1
HTTP/1.1 401 Unauthorized
```

Wrong audience, rejected with 403 (the token is signed correctly but does not authorise this host):

```bash
$ python3 examples/auth-cap/mint.py --aud api.different.com > /tmp/cap-bad-aud.jwt
$ curl -is -H 'Host: cap.localhost' -H "CAP-Token: $(cat /tmp/cap-bad-aud.jwt)" \
       http://127.0.0.1:8080/blog/article | head -n 1
HTTP/1.1 403 Forbidden
```

Path outside the token's `glob` allow-list, rejected with 403:

```bash
$ curl -is -H 'Host: cap.localhost' -H "CAP-Token: $TOKEN" \
       http://127.0.0.1:8080/api/private | head -n 1
HTTP/1.1 403 Forbidden
```

## What this exercises

- `authentication.type: cap` with an inline `jwks_static` document
- `CAP-Token: <jwt>` header extraction and the `Authorization: CAP <jwt>` fallback
- Standard CAP claims: `iss`, `sub`, `aud`, `cap_v`, `rps`, `bytes`, `glob`, `iat`, `exp`, `jti`
- Verdict mapping: missing or tampered tokens map to 401; audience and path mismatches map to 403
- Pre-upstream rejection: failed verifications never reach the configured upstream

## smoke.json

`smoke.json` ships four declarative cases mirroring the four scenarios above (missing, tampered, wrong audience, valid). It is consumed by `scripts/examples-smoke.sh` for examples that bundle a `docker-compose.yml`; this example does not, so the file is informational and pinned to the same shape as siblings such as `observability-stack/`.

## Production notes

- Use `jwks_url` in production so the issuer can rotate keys (the `kid` header on each minted token tells the verifier which key to pick). Inline `jwks_static` is for offline / pre-issued-token deployments.
- The bundled `tokens/test-private.pem` is a **test key**. Do not reuse it. Generate a fresh keypair with `openssl genpkey -algorithm Ed25519` and publish the matching public key through your JWKS endpoint.
- The `cap_v: 1` claim is mandatory; the verifier rejects any other value.
- The `bytes` budget is per UTC day; rotate `jti` when minting fresh tokens so the rate-limit bucket resets.

## See also

- [docs/configuration.md](../../docs/configuration.md) - configuration schema reference
- [examples/auth-jwt](../auth-jwt) - generic JWT auth (HS256 with a shared secret)
- [examples/auth-forward](../auth-forward) - delegated auth via a subrequest
