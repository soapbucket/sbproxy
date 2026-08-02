# Admin operators: config or runtime state

Status: accepted. Operators stay config-defined; the admin console shows
them read-only; passwords are hashed at rest.

## Context

1. The config authority work establishes that the config editor is
   read-only wherever config is not locally owned. A runtime-state users
   page would be editable on some fleet nodes and not others, for reasons
   an operator can't see from the UI.
2. Inbound API keys faced the identical fork and became mutable runtime
   records (KeyRecord) seeded from config, gaining hashing, rotation, and
   an audit trail for free. Operators could copy that shape, at the cost
   of a second record kind and a fleet config that no longer fully
   describes the fleet.
3. AdminOperator.password is plaintext in YAML today. Once the config
   authority work signs and distributes config to every node in a
   fleet, that plaintext ships to every node in cleartext.

## Decision

Operators stay config-only. No admin API, no CRUD, no runtime record.
The admin console adds a read-only view showing who can sign in and
their role.

`AdminOperator.password: String` becomes `AdminOperator.password_hash:
String`, hashed with the same HMAC-SHA256-plus-pepper primitive
`sbproxy-keystore` already uses for inbound API keys
(`KeyCrypto::hash_secret`/`verify_secret`), not a new scheme. Login
checks become `verify_secret(supplied, pepper, stored_hash)` instead of
a plaintext comparison. The hash value can be supplied via the existing
`${VAR}` textual interpolation, which works automatically today, no new
code required. Wiring the `sbproxy-vault` secret-reference resolver
(`vault://`, `secretfile://`, etc.) at the point AdminOperator config
converts into the runtime type, so the hash can live out of the YAML
file entirely, is a possible follow-up; it is not implemented by this
decision.

## Consequences

- Rotating an operator's password still means editing config and
  reloading, same as today's "edit YAML" plaintext model, just now with
  a computed hash instead of a literal password. The `sbproxy admin
  hash-password` CLI helper ships alongside this decision, so operators
  don't need to invoke the HMAC primitive by hand.
- The `/admin/config` read endpoint already returns raw config text
  verbatim, unredacted for this struct. A password_hash is
  low-sensitivity to expose (an HMAC hash isn't directly usable to log
  in when the pepper is pinned), unlike the plaintext password it
  replaces, so this is an improvement even without adding new
  redaction.
- The bigger "should admin identity generally be runtime state" question
  (the alternative this decision rejected) stays open. This decision
  resolves only the operator-password shape; it does not preclude
  revisiting runtime operators later if self-service rotation becomes a
  real requirement.
