# ADR: outbound credential resolver, OSS vs enterprise line
*Last modified: 2026-05-24*

Status: accepted. Drives WOR-802 (move outbound-credential-resolver basics into OSS).

## Context

SBproxy's stated differentiator is the outbound credential resolver: the
gateway mints or exchanges the right credential for each upstream so the
agent or client never handles a per-upstream secret. A request arrives
with one identity; the proxy presents a different, correctly-scoped
credential to each upstream it talks to.

Until now the whole resolver was an enterprise capability. The OSS binary
shipped `sbproxy-vault` (secret resolution and rotation) but no outbound
*minting*: RFC 8693 token exchange, the OAuth client-credentials grant,
broker JWT re-sign, DPoP, and stored per-user OAuth grants were all paid.

Two things changed that make this line wrong:

1. **The basic mechanism is no longer category-unique.** Per-upstream
   outbound credential brokering is now offered by AWS Bedrock AgentCore
   Gateway, Pomerium, Auth0 / Okta Token Vault, Arcade, and Scalekit. RFC
   8693 token exchange is generally available in Keycloak 26.2 and Okta.
   A self-hostable gateway whose headline differentiator is paywalled
   looks behind on its own pitch.

2. **Two open competitors are racing the same square.** agentgateway
   (Rust, open) and Bifrost (Go, open) target the self-hostable agent
   gateway niche. If the OSS binary cannot even demonstrate the resolver,
   the wedge is undefended.

The differentiator has to move up the stack. The basic minting mechanism
becomes table-stakes that OSS must show; the durable, monetizable value
moves to operating that mechanism at scale.

## Decision

OSS ships the **mechanism**: enough to resolve a per-upstream outbound
credential three ways, single-tenant, statically configured, with the
safety rails that make exchange safe to run. Enterprise keeps **operation
at scale**: per-user delegated identity, sender-constrained tokens,
broker-as-issuer, multi-tenant and multi-source entitlements, and the
hardware-backed and compliance tooling around all of it.

This mirrors the split already used elsewhere in the product: the
mechanism is OSS; the operational, multi-tenant, hardware-backed, and
compliance-grade layers are enterprise.

### OSS (the basics)

- **RFC 8693 token exchange.** Exchange a subject token for an
  upstream-audience token (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`).
- **OAuth client-credentials grant** per upstream.
- **Vault-resolved static secret** per upstream (already in OSS; exposed
  through the unified resolver).
- **The unified `outbound_credential_resolver` config surface**: per
  origin, select one of the three modes. This is the artifact that
  demonstrates the wedge.
- **The safety rails that ride with exchange**, shipped together with it
  and never separable: `subject_token_issuers` and
  `allowed_token_exchange_audiences` allowlists, the `act` delegation
  chain with a depth cap, and a single-process minted-token cache with
  TTL. A basic feature must not ship in an unsafe configuration; security
  rails are not a paid add-on.

### Enterprise (operation at scale)

- **Stored OAuth grants / per-user token vault**: device-code and
  interactive-consent flows, refresh-token lifecycle, per-user delegated
  identity. This is the operationally hard, high-value capability that
  comparable products charge for.
- **Broker JWT re-sign and issuer-vouched / broker-augmented identity
  (CIMD)**: the broker becomes the issuer. Needs hardware-backed keys and
  is compliance-grade.
- **Sender-constrained tokens (DPoP, mTLS-bound).**
- **Multi-source entitlements, multi-tenant credential isolation, and
  hardware-backed broker keys.** Combining identity across an identity
  provider, workload identity, and an entitlement service, isolated per
  tenant, is the enterprise operational job.

### The crux: RFC 8693 itself is OSS

The one genuinely debatable item is token exchange. It is OSS. Keeping it
paid is indefensible now that it is generally available across the IdP
market, and an open binary that cannot show token exchange cedes the
narrative to the open competitors. The differentiator survives because
the operational layer (stored per-user grants, broker-as-issuer,
multi-tenant, hardware-backed, audited) stays enterprise, and that is
where buyers actually spend.

## Consequences

- The OSS binary can demonstrate, end to end and without a license:
  "per-upstream credentials, minted three ways, no client-side secret
  handling, self-hosted." That is the wedge, defended.
- Enterprise sells the operational story: "operate that for thousands of
  users across dozens of upstreams, sender-constrained, broker-issued,
  and audited."
- The OSS resolver is single-tenant and statically configured by design.
  Multi-tenant isolation and dynamic, per-user credential lifecycle are
  the natural upgrade boundary, so the line is legible to operators
  rather than arbitrary.
- The resolver is a closed enum of modes, so an operator who needs a mode
  the OSS binary does not implement gets a config-load error rather than
  a silent fallback to an unsafe default.

## Implementation

PR 1 lands this ADR and the OSS resolver subsystem: the config surface,
the three minting modes, the allowlists, and the `act`-chain depth cap,
with unit coverage including a mock token endpoint. A follow-up wires the
resolver into the outbound request path per upstream and adds the
end-to-end test (request to upstream A gets credential A; request to
upstream B gets credential B).
