# Dynamic key management

Inbound virtual keys as a live, governed resource instead of lines of YAML.

The `proxy.key_management:` block turns on a mutable key store (hashed at rest
with HMAC-SHA256 + a server pepper), a fail-closed policy cache, and at-rest
crypto. Keys are minted, revoked, and rotated at runtime through the admin API
under `/admin/keys`; the change takes effect on the next request without a
reload, because every request resolves the key through the cache then the store.

This example seeds one key at boot so it is self-contained. In production, leave
the seed empty and create keys with `POST /admin/keys`, which returns the
plaintext token exactly once.

See `sb.yml` for the runnable config and the curl recipes, and
`docs/key-management.md` for the full reference (backends, cache topology,
envelope encryption for upstream credentials, OIDC claim mapping, and the
security model).
