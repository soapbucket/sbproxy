# Test fixtures
*Last modified: 2026-05-01*

This directory holds the keying material and seeds the fixture-refresh
tool consumes when regenerating the signed e2e fixtures. The fixtures
themselves live under `e2e/fixtures/`; this directory only holds the
inputs that drive their generation.

## Layout

| Path | Owner ADR | Contents |
|---|---|---|
| `wave2/registry/keys.json` | `adr-agent-registry-feed.md` (G2.1) | Ed25519 seed for the agent-registry feed signing key. Used by Q2.3 and Q2.11. |
| `wave2/kya/` | (Wave 5 placeholder) | Reserved for KYA-token seeds; populated when Wave 5 lands. |
| `wave1/bot_auth_directory/keys.json` | `adr-bot-auth-directory.md` (A1.3) | Ed25519 seed for the JWKS directory self-signature. Used by Q1.4 and Q2.13. |
| `refresh.sh` | Q2.13 | Wrapper that invokes the regenerator. |
| `refresh-tool/` | Q2.13 | Standalone Rust crate that writes the fixtures. Lives outside the main workspace so its crypto dependencies do not bloat the proxy's `Cargo.lock`. |

## Regenerating fixtures

```bash
bash test/fixtures/refresh.sh
```

Running the script twice produces a clean `git diff`. CI verifies
this in `.github/workflows/fixture-freshness.yml`.

## Production-key contract

The seeds in `keys.json` files are NOT real production keys. The
production agent-registry feed is signed by a key held in the
`feed.sbproxy.dev` publisher's KMS; the production Bot Auth
directories are signed by each vendor with their own keys. Test
seeds let the e2e suite verify the wire format without depending
on the production key material.

When a production key rotates, the affected fixtures must
regenerate too. The CI freshness check (Q2.13) catches the case
where a developer changes `refresh-tool/src/main.rs` (or one of
the seed files) and forgets to rerun the script: the workflow
runs `refresh.sh` and asserts `git diff --exit-code` is clean.

## How to rotate a test seed

1. Edit the relevant `keys.json` to a new 32-byte hex seed.
2. Run `bash test/fixtures/refresh.sh`.
3. Commit the diff. The fixture-freshness CI job verifies
   regeneration is reproducible from the new seed.

## Why the regen tool lives outside the workspace

The tool depends on `ed25519-dalek` and `sha2` for the signing
work. Pulling those crates into the main workspace's
`Cargo.lock` adds ~80 KB to the lockfile and makes a `cargo
build --workspace` slower for every developer. A standalone
crate with its own lockfile keeps the cost local: only
contributors who run the refresh script pay for the dependency
tree.

The trade-off is one extra `Cargo.lock` to maintain. We accept
it; the alternative (one shared lockfile) is worse for everyday
edit-compile-test loops.

## Why deterministic timestamps

Signature material depends on the body bytes. A `generated_at`
field that drifts between regen runs would produce a different
signature every time and the `git diff --exit-code` check would
flap. The tool freezes the timestamp at `2026-05-01T00:00:00.000Z`
for every regenerated artefact; production publishers obviously
use real wall-clock time. Tests that exercise expiry logic do so
by rewriting the timestamps inline rather than relying on the
regen tool.
