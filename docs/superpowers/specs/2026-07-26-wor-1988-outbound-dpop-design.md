# WOR-1988 Outbound DPoP Design

*Last modified: 2026-07-26*

## Goal

Wire RFC 9449 proof minting into each origin's existing
`outbound_credential` flow. DPoP remains opt-in, existing configurations keep
their behavior, and an enabled configuration fails closed unless its signing
key is available and valid at boot.

## Configuration and key scope

Each token-bearing outbound credential may add:

```yaml
outbound_credential:
  type: client_credentials
  token_endpoint: https://idp.example/token
  client_id: sbproxy
  client_secret: secret://prod/oauth-client-secret
  dpop:
    key: secret://prod/origins/api-example-dpop-key
    alg: ES256
    jwk:
      kty: EC
      crv: P-256
      x: ...
      y: ...
```

The DPoP key is scoped to that origin and outbound credential. This prevents
an access token or nonce issued for one upstream from being reused with
another origin. `dpop.key` accepts the existing secret-provider reference
surface. It never accepts inline PEM and the process never generates a key.
The public JWK is explicit and must match the resolved private key.

At runtime pipeline construction resolves the private key, rejects an
unavailable reference, parses the selected asymmetric algorithm, rejects
private JWK members, and signs and verifies a probe to prove the PEM and JWK
match. Validation-only construction checks the reference and public
configuration without dereferencing an unavailable external provider.

## Runtime

The compiled credential holds a shared per-origin DPoP runtime. It contains a
parsed signer, the public JWK thumbprint used in the token-cache identity, and
separate authorization-server and resource-server nonce slots. It does not
expose private key material through `Debug`, logs, or errors.

On a token cache miss, token exchange or client credentials sends a fresh
proof on the actual POST to the configured token endpoint. The proof has the
actual `htm`, a canonical `htu` without query or fragment, a fresh `jti` and
signature, the current `iat`, and the authorization-server nonce when one is
known. It does not have `ath`.

The token cache stores only the minted token. Its key includes the origin,
credential configuration identity, subject isolation, and DPoP JWK
thumbprint. A cached token therefore cannot cross an incompatible key or
credential reload. A token cache hit still mints a new resource proof.

For every resource attempt, after request modifiers have produced the final
method, authority, and path, the proxy sends:

```text
Authorization: DPoP <access-token>
DPoP: <fresh-proof>
```

The proof's `htu` is built from the actual upstream transport scheme, final
Host authority, and final path, with query and fragment removed. Its `ath` is
the base64url-no-pad SHA-256 hash of the access token. Each attempt, including
an ordinary upstream retry, mints a new proof.

## Nonce challenges

Authorization-server and resource-server nonces are never shared.

The token client retries once only when all of these conditions hold:

- the response status is 400;
- the JSON error is `use_dpop_nonce`;
- exactly one syntactically valid `DPoP-Nonce` header is present.

The resource path retries once only when all of these conditions hold:

- the response status is 401;
- a `WWW-Authenticate` DPoP challenge contains `error="use_dpop_nonce"`;
- exactly one syntactically valid `DPoP-Nonce` header is present;
- Pingora can replay the request within its bounded buffer.

The retry stores the new nonce and mints a new proof. A second challenge,
malformed or duplicate nonce, wrong status, Bearer-only challenge, or any
other failure passes through without retry, downgrade, or general loop.
Successful responses may rotate the nonce for later calls as RFC 9449
permits.

## Failure behavior

Existing non-DPoP outbound credentials retain their current compatibility
behavior. When DPoP is enabled, key resolution, signer construction, token
acquisition, proof minting, and header construction fail closed. The request
is never sent without the configured sender constraint.

## Verification

Focused unit and local-server integration tests cover:

- signature verification through the existing inbound verifier;
- exact token and resource `htm` and canonical `htu`;
- `ath` token binding and the `DPoP` authorization scheme;
- fresh `jti` and signature for every attempt and cache hit;
- exactly one authorization-server and resource-server nonce retry;
- separate nonce state;
- missing, inline, unavailable, malformed, unsupported, and mismatched keys;
- schema-v1 configurations without DPoP;
- generated schema, example validation, docs, formatting, targeted Clippy,
  and affected crate tests.

