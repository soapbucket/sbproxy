# content_digest policy
*Last modified: 2026-05-31*

The `content_digest` policy verifies an inbound request body against the digest the client advertises in the `Content-Digest:` header (RFC 9530). On mismatch, malformed header, or unsupported algorithm, the proxy rejects the request before forwarding. The intended audience is integrity-critical inboxes: webhook receivers, agent endpoints, payment callbacks, audit-ingest paths.

The policy honours `Content-Digest:` first and falls back to `Repr-Digest:` if `Content-Digest:` is absent. RFC 9530 §2 makes the two interchangeable for inbound traffic that does not decode `Content-Encoding`. SHA-256 and SHA-512 are supported; unknown algorithms fall through to the configured failure mode.

Verification runs in `request_body_filter` once the body is fully buffered. The pairing enforcer sets `ctx.validate_request_body = true` so the proxy buffers the body for hashing; bypass it on routes that do not need this check.

## Config

```yaml
origins:
  "webhook.example.com":
    upstream: https://api.internal
    policies:
      - type: content_digest
        # What to do when the client did not send any digest header.
        # `require` (default): reject. `skip`: pass through unverified
        # (useful when the origin mixes integrity-required and
        # integrity-optional traffic on the same hostname).
        on_missing: require
        # HTTP status returned on every failure path (missing when
        # required, mismatch, malformed, unsupported algorithm).
        reject_status: 400
```

## Failure modes

| Condition | Behaviour |
|---|---|
| Header present, digest matches | Pass; sets `ctx.content_digest_verified = true` |
| Header present, digest mismatch | Reject with `reject_status` |
| Header present, algorithm not in {sha-256, sha-512} | Reject with `reject_status` |
| Header present, parse error | Reject with `reject_status` |
| Header absent, `on_missing: require` | Reject with `reject_status` |
| Header absent, `on_missing: skip` | Pass through unverified |

## Why the verified flag matters

`ctx.content_digest_verified = true` propagates the verification result to downstream phases. HTTP Message Signatures audit can attest that the body matches the signed digest component without re-hashing, and billing surfaces that quote by body size get an integrity guarantee for free. The flag is consumed inside the proxy; it does not leak to clients.

## Out of scope

RFC 9530 §6.4 trailer-section digests are not supported because Pingora 0.8's `ProxyHttp` trait does not expose an `request_trailer_filter` hook. Clients that send the digest in the trailer section are treated as if the header is absent, so `on_missing: require` rejects them (the safer default).

## See also

* [features.md](./features.md) - tour with policy examples.
* [examples/content-digest/](../examples/content-digest/) - runnable webhook receiver fixture.
* [configuration.md](./configuration.md) - the full schema.
