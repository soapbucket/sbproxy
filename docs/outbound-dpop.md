# Outbound DPoP

*Last modified: 2026-07-26*

SBproxy can use RFC 9449 Demonstrating Proof of Possession when an origin's
`outbound_credential` acquires or carries a sender-constrained access token.
The feature is opt-in. Existing outbound credentials continue to use their
current Bearer behavior.

## Configure an origin

Add a `dpop` block to `client_credentials`, `token_exchange`, or
`vault_secret`:

```yaml
outbound_credential:
  type: client_credentials
  token_endpoint: https://idp.example/token
  client_id: sbproxy
  client_secret: secret://prod/oauth-client-secret
  dpop:
    key: secret://prod/api-dpop-private-key
    alg: ES256
    jwk:
      kty: EC
      crv: P-256
      x: DpZdjog3y9hgIyKgEPltBi5ptXKUeuRwVOAPSmoQAu4
      y: bfVVYV9slbMcg4dvtvYbeekYtpFXsYCWcIa9RCrBmTc
```

`dpop.key` must be an existing provider URI or `file:` secret reference to a
PKCS#8 PEM private key. Inline PEM is rejected, and SBproxy does not generate
a key. The public-only `jwk` must match the private key and `alg`.

For `vault_secret`, set `header: authorization` or leave the header at its
default. DPoP access tokens always use `Authorization: DPoP <token>`.

## Boot and request behavior

Live pipeline construction resolves and parses the private key. Missing,
unavailable, malformed, unsupported, private-JWK, and mismatched key
configurations stop the pipeline from loading. Validation commands check the
reference and public configuration without contacting an external secret
provider.

On a token cache miss, SBproxy sends a fresh DPoP proof with the token endpoint
POST. On every protected-resource attempt, including cache hits and retries, it
sends a newly signed proof with:

- the final outbound method, preserving extension-method case exactly;
- the actual upstream transport scheme, final Host authority, and final path;
- no query or fragment in `htu`;
- `ath` bound to the final validated `Authorization: DPoP <token>` value;
- a fresh `jti`, signature, and current `iat`.

Authorization-server and protected-resource nonces are separate. A valid token
endpoint challenge can cause one retry. A valid protected-resource challenge
can cause one replay when Pingora has the complete request body in its bounded
retry buffer. A second, malformed, duplicate, or wrong-scheme challenge is not
retried.

DPoP is currently rejected on load-balanced actions, including load-balanced
forward-rule targets. A nonce retry must return to the exact server that issued
the nonce, and target pinning is not yet part of the load-balancer retry model.
Requests whose resolved inbound key selects a separate bound credential are
also rejected for DPoP-enabled origins; arbitrary bound credential headers
cannot safely satisfy the origin's sender constraint.

DPoP proof headers are non-loggable. Access-log header capture drops `dpop`
even when an operator lists it by exact name, and the common structured-log
redactor protects the same field in other sinks.

See [examples/outbound-dpop/sb.yml](../examples/outbound-dpop/sb.yml) for a
complete configuration shape.
