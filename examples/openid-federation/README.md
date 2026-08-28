# OpenID Federation entity and peer trust

> **Partially runnable.** `trust-anchor.example` is an RFC 2606 reserved
> placeholder, so a peer chain cannot actually resolve against it and every
> peer this proxy is asked about will be refused. The identity half works as
> shipped once you supply a key: the served entity statement is a real,
> verifiable compact JWS. Point `authority_hints` and `peer_trust.trust_anchors`
> at a federation you belong to to complete the trust half.

Publishes this proxy's OpenID Federation 1.0 entity configuration on the
listener it already runs, and verifies a caller's claimed entity against a
pinned trust anchor before the request reaches authentication.

Run it:

```bash
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out /etc/sbproxy/federation-signing-key.pem
sbproxy serve -f sb.yml
```

The `published_jwks` block carries a placeholder public half. Swap in the
`x` and `y` of the key you just generated, or startup refuses to boot:
signing with a key the published JWKS does not carry serves a document
every peer rejects with `UnknownKid`, for the whole 24-hour lifetime, with
nothing on this side going red.

What proves it is working:

```bash
curl -si localhost:8080/.well-known/openid-federation
```

- `Content-Type: application/entity-statement+jwt` and a three-segment
  compact JWS body.
- `Cache-Control: public, max-age=<remaining lifetime>`, which counts down
  and resets when the statement is re-signed at `refresh_margin_secs`.
- The payload carries `authority_hints`, which is what a peer's resolver
  walks. Decode it with
  `cut -d. -f2 | base64 -d` to check.
- `sbproxy_federation_well_known_serves_total{outcome="served"}` moves on
  every fetch, and `sbproxy_federation_well_known_cache_remaining_seconds`
  samples the lifetime left. Both are drawn by
  [`dashboards/grafana/sbproxy-federation.json`](../../dashboards/grafana/sbproxy-federation.json).
- `GET /admin/federation` on the admin listener reports what is published
  and how many anchors are pinned.

The trust half, with a real anchor. Note that `egress.federation.hosts`
has to name every host a walk dials, and the first fetch of any walk is
the peer's own entity configuration at the peer's own host: an allowlist
of anchors alone refuses every peer at `chain_unresolved`. An open
federation should leave the block off entirely; the unconditional layer
still refuses every private, loopback, link-local, and CGNAT
destination, and `max_chain_fetches` bounds what one walk can spend.

- A request carrying `X-Federation-Entity-Id: https://peer.example` whose
  chain terminates at a pinned anchor is admitted, the header is rewritten
  to the entity id the chain proved, and
  `sbproxy_federation_peer_decisions_total{outcome="trusted"}` moves.
- One whose chain does not is refused with `403`, and the same family moves
  at `outcome="refused"`. The reason is in the
  `sbproxy_federation::decision` log line, never on the wire: a peer URL
  can itself be what a probe is asking about.

What this example does not show:

- **Binding a caller to the entity it names.** The header is a claim, not a
  credential. This answers "does an anchor I pinned vouch for that entity",
  not "is this caller that entity". Pair it with mTLS or an
  `authentication:` provider, or what you have is an allowlist keyed on an
  unauthenticated header.
- **Serving subordinate statements.** This proxy publishes its own
  configuration and consumes other entities' chains; it does not act as an
  intermediate that issues statements about anyone else.

See [`docs/federation.md`](../../docs/federation.md) for the full reference.
