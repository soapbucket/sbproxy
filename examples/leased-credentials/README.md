# Leased upstream credentials

*Last modified: 2026-08-28*

Upstream credentials minted on demand with a lease, for the platforms that can
actually mint them.

The record stores a dynamic-secrets mount rather than a credential. Each
resolution that cannot be served from cache reads the mount, which mints, and
the resolved material is cached for at most the lease and never longer. That
ceiling is the whole difference from a `vault_ref` credential.

The scope is cloud IAM (AWS for Bedrock, GCP for Vertex, Azure for Azure
OpenAI) and Vault-fronted database credentials. Most AI provider API keys have
no short-TTL issuance to lease against, so `lease` on one is refused with that
limitation named rather than accepted and silently turned into a static read.

`sb.yml` shows both: a working AWS lease, and the refusal.

sbproxy re-leases lazily at the next resolution rather than renewing ahead of
expiry, and does not revoke a lease it stops using. See
`docs/key-management.md` for what that costs.
