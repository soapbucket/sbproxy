# Wave 1 e2e fixtures

*Last modified: 2026-04-30*

Fixture pack consumed by the Q1.1 through Q1.7 e2e tests. Per
`docs/AIGOVERNANCE-BUILD.md` § 4.5 and the Q2.13 fixture-refresh
requirement, regenerable artefacts (signed bot-auth directory bodies,
HMAC keys, WBA conformance vectors) are produced by a single binary so
they can be re-cut on key rotation without hand-editing.

Layout:

| Subdir | Owner test | Contents |
|---|---|---|
| `tiers/` | Q1.1 | `sb.yml` exercising three pricing tiers, two content shapes, one free-preview window |
| `ledger/` | Q1.2 | Mock-ledger HMAC key file, sample request + response envelopes |
| `agent_class/` | Q1.3 | UA strings, reverse-DNS stub mapping, bot-auth keyid vectors |
| `bot_auth_directory/` | Q1.4 | Mock JWKS bodies, self-signature material, expired and missing-key variants |
| `wba_conformance/` | Q1.7 | `draft-meunier-*-05` test vectors (valid signature, missing component, wrong key, wrong digest) |

## Regenerating signed artefacts

```bash
cargo run --release -p sbproxy-e2e --bin wave1-regen
```

The binary is wired in at `e2e/fixtures/wave1/regenerate.rs` (registered
as a `[[bin]]` target on the `sbproxy-e2e` crate, gated behind
`feature = "fixture-regen"` so the default build does not pull the
extra crypto deps). It overwrites the static fixtures under each
subdir with a fresh keypair, a new signed-directory body, and a new
WBA conformance vector pack. Commit the resulting diff in a fixture
refresh PR.

## Why a regen binary, not `build.rs`

A `build.rs` would re-cut the fixtures on every workspace build, which
is hostile to deterministic test runs (the public-key bytes would
change every CI run and a test asserting on a specific `kid` would
flap). A one-shot binary keeps the fixtures static between rotations
and makes the rotation visible in `git diff`.
