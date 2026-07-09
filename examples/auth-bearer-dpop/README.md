# DPoP-bound Bearer tokens (RFC 9449)

*Last modified: 2026-07-09*

A stolen Bearer token is only useful if the attacker can also replay it. RFC 9449 (DPoP, "Demonstrating Proof of Possession") binds each token to a key the legitimate client signs with on every request. The proxy reads the `DPoP:` header, verifies the proof, and checks the proof's JWK thumbprint against the operator-stamped `dpop_jkt` metadata on the matched token entry. A bare `Authorization: Bearer` header without a matching proof is rejected with 401 before `test.sbproxy.dev` is contacted.

## Run

```bash
make run CONFIG=examples/auth-bearer-dpop/sb.yml
```

No env vars required.

## Try it

Bearer token alone, no DPoP proof, rejected:

```bash
$ curl -i http://127.0.0.1:8080/anything \
       -H 'Host: api.local' \
       -H 'Authorization: Bearer service-token-1'
HTTP/1.1 401 Unauthorized
```

Bearer token plus a valid DPoP proof signed by the key whose RFC 7638 thumbprint is `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`, request forwarded:

```bash
$ curl -i http://127.0.0.1:8080/anything \
       -H 'Host: api.local' \
       -H 'Authorization: Bearer service-token-1' \
       -H "DPoP: $DPOP_PROOF"
HTTP/1.1 200 OK
```

Generating a DPoP proof is the client's job; libraries exist for Python, Go, Java, and JavaScript (search for "dpop client library"). The proof's claims must include `htm` (request method), `htu` (request URL), `jti` (unique id), and `iat`; the JWS header carries `typ: "dpop+jwt"` and the JWK of the signing key. The thumbprint in this example's `sb.yml` matches the sample key from RFC 7638, so a proof signed with your own key needs its own `dpop_jkt` value in the config.

## What this exercises

- `authentication.type: bearer` - opaque token allowlist
- `require_dpop: true` - every request must carry a valid DPoP proof
- `tokens[].metadata.dpop_jkt` - RFC 7638 SHA-256 thumbprint (base64url, no padding) the proof's JWK must hash to

## See also

- [examples/auth-bearer](../auth-bearer) - plain Bearer allowlist without proof-of-possession
- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
