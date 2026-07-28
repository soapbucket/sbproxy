# WOR-1988 Outbound DPoP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add fail-closed RFC 9449 DPoP proof minting, token binding, and bounded nonce retries to per-origin outbound credentials.

**Architecture:** Compile an optional per-origin DPoP runtime from a referenced private key and explicit public JWK. Token acquisition and resource dispatch both mint proofs at their final request seams, while separate nonce slots and an expanded token-cache identity prevent cross-server and cross-key reuse.

**Tech Stack:** Rust, Pingora proxy callbacks, reqwest token client, jsonwebtoken, existing sbproxy vault resolver, serde/schemars, local TCP integration servers.

## Global Constraints

- Preserve schema-v1 compatibility for all existing configurations.
- Never generate an implicit process key or accept inline DPoP private key material.
- Mint a fresh proof for every actual request attempt and never cache a proof.
- Retry exactly once only for a valid RFC 9449 nonce challenge.
- Keep authorization-server and resource-server nonce state separate.
- Add no dependency unless the existing cryptography stack cannot implement the requirement.
- Do not use em dashes in user-facing content.

---

### Task 1: Signer and configuration invariants

**Files:**
- Modify: `crates/sbproxy-modules/src/auth/dpop_outbound.rs`
- Modify: `crates/sbproxy-modules/src/auth/dpop.rs`
- Test: `crates/sbproxy-modules/src/auth/dpop_outbound.rs`

**Interfaces:**
- Produces: `DpopRuntime`, `DpopOutboundConfig`, `mint_token_proof`, `mint_resource_proof`, JWK thumbprint identity, and separate nonce accessors.

- [ ] Add failing tests for `ath`, fresh `jti`, private JWK rejection, mismatched PEM/JWK rejection, inline key rejection, malformed key rejection, and separate nonce slots.
- [ ] Run `cargo test -p sbproxy-modules --lib auth::dpop_outbound` and confirm the new tests fail for missing behavior.
- [ ] Implement the minimal signer/runtime/config validation with existing crypto and vault abstractions.
- [ ] Re-run the focused signer tests and keep the existing inbound round trip green.

### Task 2: Token endpoint DPoP and cache isolation

**Files:**
- Modify: `crates/sbproxy-modules/src/auth/outbound_credential.rs`
- Test: `crates/sbproxy-modules/src/auth/outbound_credential.rs`

**Interfaces:**
- Consumes: compiled `DpopRuntime`.
- Produces: token requests with fresh proofs, one bounded AS nonce retry, DPoP resource credentials, and cache keys containing configuration plus JWK identity.

- [ ] Add local-server failing tests for exact token endpoint `POST` and canonical `htu`, valid signature, fresh retry proof, exactly one valid 400 nonce retry, no retry for malformed or non-DPoP responses, and cache separation across JWK identities.
- [ ] Run the focused outbound credential tests and confirm expected failures.
- [ ] Add DPoP to each token-bearing config, resolve and compile referenced keys at boot, attach token proofs, parse valid AS challenges, return `Authorization: DPoP`, and expand the cache identity.
- [ ] Re-run the focused tests and existing outbound credential tests.

### Task 3: Resource proof mutation and bounded retry

**Files:**
- Modify: `crates/sbproxy-core/src/context.rs`
- Modify: `crates/sbproxy-core/src/pipeline.rs`
- Modify: `crates/sbproxy-core/src/server/request_phase.rs`
- Modify: `crates/sbproxy-core/src/server/proxy_http.rs`
- Test: `crates/sbproxy-core/src/server/proxy_http.rs`
- Test: `e2e/tests/outbound_credential.rs`

**Interfaces:**
- Consumes: compiled credential runtime and minted DPoP access token.
- Produces: final resource proof header and one Pingora retry for a valid RS nonce challenge.

- [ ] Add failing tests for final method/authority/path canonicalization, query removal, challenge classification, second-challenge refusal, and fresh resource proofs on retries and token-cache hits.
- [ ] Run the focused core tests and the outbound credential e2e test to observe the missing behavior.
- [ ] Mint after all request mutations, store only nonce/retry state in request context, enable bounded replay, and prioritize the single DPoP challenge retry before configured status retries.
- [ ] Re-run core and e2e coverage.

### Task 4: Schema, example, and operator documentation

**Files:**
- Modify: `crates/sbproxy-config/src/types.rs`
- Modify: `docs/configuration.md`
- Create: `examples/outbound-dpop/sb.yml`
- Create: `examples/outbound-dpop/README.md`
- Regenerate: `schemas/sb-config.schema.json`

**Interfaces:**
- Documents the nested per-origin `outbound_credential.dpop` surface and referenced-key lifecycle.

- [ ] Add config compatibility tests proving old schema-v1 and non-DPoP outbound credential configurations still compile.
- [ ] Document key scope, accepted references, DPoP authorization behavior, nonce retry bound, and rotation.
- [ ] Regenerate the JSON schema with `cargo run -p sbproxy-config --bin generate-schema > schemas/sb-config.schema.json`.
- [ ] Run config tests, example validation, and the schema consistency check.

### Task 5: Security review and focused verification

**Files:**
- Review all changed files.

**Interfaces:**
- Produces verified code and a clean committed worktree.

- [ ] Review Debug, logs, and errors for private key, token, and proof leakage.
- [ ] Review canonical URI construction, nonce parsing, concurrency, token/proof cache separation, retries, and every DPoP fail-open branch.
- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run focused nextest suites for `sbproxy-modules`, `sbproxy-core`, and `sbproxy-config`, plus the outbound credential e2e test.
- [ ] Run targeted `cargo check` and Clippy for affected crates.
- [ ] Commit all intentional changes with `WOR-1988` in the message.
- [ ] Run `scripts/cleanup-build-artifacts.sh`.
