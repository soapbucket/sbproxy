# Customer-managed root of trust

*Last modified: 2026-08-28*

The customer holds the key that opens sbproxy's stored upstream credentials,
and revoking their grant stops decryption within a stated window.

Pointing `master_key` at a vault reference has always been possible, and it
does not make the customer's key load bearing: the read happens once at boot
and the copy is sbproxy's. `key_management.crypto.root_of_trust` routes the
envelope's data key through HashiCorp Vault's Transit engine instead, which
returns ciphertext and plaintext and never the key. Revoking sbproxy's Transit
policy stops decryption within `unwrap_cache_ttl_secs`, or at the next failed
liveness probe, whichever comes first.

`sb.yml` walks the full cycle against a dev Vault: configure, store a
credential, **send a real request so the decrypted credential is cached**,
revoke the grant, and watch the decrypt stop. That third step is the one worth
doing, because a revocation has to reach the cache a live deployment actually
serves from, not only the wrapped data keys.

Read the scope in `docs/key-management.md` before quoting the claim. It covers
the upstream-credential envelope for records sealed after the switch. It does
not cover the pepper that hashes inbound keys, `vault_ref` credentials, or
envelopes sealed before the root of trust was configured.
