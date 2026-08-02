# OSS payment settlement implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task by task. Use `superpowers:test-driven-development` for each behavior change and `superpowers:verification-before-completion` before each commit and before the PR.

**Goal:** Ship authoritative Apache-2.0 OSS settlement for x402 v2, Payment HTTP Authentication, Stripe PaymentIntents, Core Lightning, and LND. A paid request reaches the origin and receives a success receipt only after the durable intent is `Succeeded`.

**Architecture:** Add a feature-gated `sbproxy-billing` crate that owns normalized payment requirements, proof handling, provider adapters, a SQLite intent and attempt store, authoritative synchronous authorization, reconciliation, and usage reporting. The existing AI crawl policy constructs one signed `PaymentRequirement` from its quote and the compiled `proxy.payments` configuration, and the billing service persists that pending challenge before returning 402. On a credential retry, the service loads the intent and first persists the proof digest, provider idempotency key, and attempt. It durably stamps `dispatch_started_at_ms` before any provider network write, then performs the rail's required verification and settlement within a bounded synchronous path. Only a durable `Succeeded` transition can return `RedeemResult::Settled`; every other state fails closed before the origin. The worker recovers leases, queries ambiguous provider attempts, expires challenges, and reports usage. It never performs the normal settlement that authorizes a request.

**Tech Stack:** Rust 1.82, Tokio, `async-trait`, `rusqlite` with bundled SQLite and WAL, workspace `aes-gcm` 0.10 and `zeroize` 1 for bounded recovery material, existing `sbproxy-httpkit`, existing quote JWS support, Pingora request pipeline, `tonic` 0.12, `prost` 0.13, `tonic-build` 0.12, exactly pinned `protoc-bin-vendored` 3.2.0, deterministic local HTTP, Unix socket, and gRPC fixtures.

## Pinned public contracts

Implementation and fixtures in this PR are frozen to these primary contracts. Do not substitute blog posts, SDK behavior, or historical enterprise code.

| Surface | Pinned contract |
| --- | --- |
| Payment HTTP Authentication | [`draft-ryan-httpauth-payment-01`](https://datatracker.ietf.org/doc/html/draft-ryan-httpauth-payment-01), dated 18 March 2026. The wire scheme is `Payment`; no protocol version is placed on the wire. |
| Stripe MPP method and intent | [`draft-stripe-charge-00`](https://paymentauth.org/draft-stripe-charge-00), published 29 July 2026. It registers `method="stripe"` with `intent="charge"` and defines the SPT request, credential, synchronous PaymentIntent, and receipt contract. |
| Stripe API | [`2026-06-24.dahlia`](https://docs.stripe.com/api/versioning), the current stable Stripe API version on 29 July 2026. Every Stripe request in this PR sends this exact `Stripe-Version`; config rejects any other value. |
| Stripe PaymentIntents | Current stable [`PaymentIntents`](https://docs.stripe.com/api/payment_intents) create, retrieve, confirm, and capture contracts. |
| Stripe usage reporting | Current stable [`Meter Events`](https://docs.stripe.com/api/billing/meter-event/create) contract. Meter Events are usage accounting only and never prove payment settlement. |
| x402 | x402 v2 `exact` contract from [`x402-foundation/x402`](https://github.com/x402-foundation/x402/tree/895f3505a6c0beb767555344cb97130c3da7c8b2) at revision `895f3505a6c0beb767555344cb97130c3da7c8b2`, the repository HEAD verified on 29 July 2026. |
| Core Lightning | Core Lightning v26.06 or newer, including the documented `xpay` label. Startup verifies the version through `getinfo`; invoice recovery uses `listinvoices` by label and its documented status. |
| LND | [`lightningnetwork/lnd` tag `v0.20.1-beta`](https://github.com/lightningnetwork/lnd/tree/v0.20.1-beta), commit `848b72ce96eb68fa90fd4336523ca4c59bddcd4c`. Vendor only the required upstream protobuf files and the upstream MIT license. |

The core Payment Auth draft's intent registry is initially empty, but `draft-stripe-charge-00` supplies the method-specific registration and exact semantics used here. This plan therefore implements only the selected pair `stripe` plus `charge`. It does not invent a generic MPP provider schema.

## Non-negotiable authorization invariant

The implementation must preserve this state and response table:

| Durable intent state | Provider work allowed | Origin access | 2xx paid response | `Payment-Receipt` |
| --- | --- | --- | --- | --- |
| `Pending` | Challenge preparation or waiting for a credential | No | No | No |
| `Processing` | One bounded authoritative operation | No | No | No |
| `RetryWait` | A retry that is proven not to have been dispatched | No | No | No |
| `NeedsReconciliation` | Provider status query only | No | No | No |
| `Terminal` | None | No | No | No |
| `Succeeded` | No repeat charge; receipt lookup only | Yes | Yes | Yes, for Payment Auth only |

For Payment Auth, x402, Stripe, and Lightning, "verified" is not enough. The synchronous request path must reach the rail's authoritative settled state and commit `Succeeded` before proxying to the origin. A timeout, open breaker, malformed response, `processing`, `requires_action`, unpaid invoice, ambiguous write, or reconciliation requirement cannot authorize access.

The request path may make only protocol-required provider calls:

- x402: `verify` followed by `settle`, within one total deadline of at most 2,000 ms.
- Payment Auth Stripe charge: create and confirm the PaymentIntent from the SPT, then retrieve or inspect the authoritative result, within 2,000 ms.
- Direct Stripe PaymentIntent mode: retrieve the challenge-bound PaymentIntent, capture or confirm when appropriate, then verify `succeeded`, within 2,000 ms.
- Lightning: query the exact labeled invoice or payment hash and require `paid` or `settled`, within 2,000 ms.

Challenge preparation may create only the challenge record and provider object needed to fulfill it, such as a manual-capture Stripe PaymentIntent or Lightning invoice. It must not call the origin, capture funds, deliver the resource, or emit a receipt.

## Global constraints

- This is a distinct PR after the RAG and distributed semantic-cache work. Rebase on merged `main`; do not stage either unrelated untracked plan.
- All shipped behavior is Apache-2.0 OSS. Do not reference `sbproxy-enterprise`, an enterprise edition, Phoenixd, ACP, AP2, revenue analytics, wallets, or merchant-of-record reporting in runtime code, examples, or current public docs.
- Create `crates/sbproxy-billing` with `default = []`. It must not depend on `sbproxy-core`, `sbproxy-modules`, `sbproxy-ai`, or `sbproxy-config`.
- Add binary features `payments`, `payment-mpp`, `payment-stripe`, `payment-x402`, `payment-lightning-cln`, and `payment-lightning-lnd`. Provider features imply `payments`; no payment feature joins the binary default set.
- Preserve behavior when `proxy.payments` is absent. A configured protocol, rail, or reporter that was not compiled fails startup with the missing feature name.
- Use `CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target` for every Cargo command. Run focused package and integration tests, not a full workspace test cycle.
- Provider calls use the shared bounded outbound client. Never log authorization headers, raw Payment credentials, SPTs, Stripe client secrets, macaroons, runes, proof bodies, payer addresses, or live provider responses. The only durable SPT material is the exact Stripe create request body encrypted for same-key idempotent response recovery, with a 23-hour hard expiry and authenticated attempt binding.
- Runtime and public prose use ASCII punctuation and no em or en dashes.
- Never commit keys, signing seeds, PEM material, macaroons, runes, values from `/Users/rick/projects/soapbucket/test/.env`, or fixture output derived from live providers.
- TLS 1.2 or newer is required for public Payment Auth and provider endpoints. Plain HTTP is allowed only for loopback test fixtures under an explicit test-only constructor.
- SQLite is authoritative for this PR. It uses transactions and unique constraints for requirements, proofs, provider attempts, idempotency keys, receipts, meter events, and reconciliation results.
- An adapter cannot perform a network write directly. All provider writes pass through `DispatchContext`, which persists the provider idempotency key first and commits `dispatch_started_at_ms` immediately before invoking the HTTP, Unix socket, or gRPC operation.

## File and responsibility map

| Path | Responsibility |
| --- | --- |
| `Cargo.toml` | Workspace membership and pinned shared dependencies. |
| `Cargo.lock` | Locked new workspace crate and optional provider/build dependencies. |
| `crates/sbproxy-billing/Cargo.toml` | Empty defaults, provider features, Stripe and x402 HTTP support, and deterministic LND generation. |
| `crates/sbproxy-billing/build.rs` | LND protobuf generation with vendored `protoc`. |
| `crates/sbproxy-billing/proto/lnd/v0.20.1-beta/lnrpc/{lightning.proto,routerrpc/router.proto}` | Exact required upstream LND definitions at the pinned commit. |
| `crates/sbproxy-billing/proto/lnd/v0.20.1-beta/LICENSE` | Exact upstream MIT license. |
| `crates/sbproxy-billing/src/{lib,money,types,error}.rs` | Feature-independent normalized requirements, state model, and redaction. |
| `crates/sbproxy-billing/src/registry.rs` | Runtime-gated settlement adapter and usage reporter registries. |
| `crates/sbproxy-billing/src/{store,sqlite,dispatch,recovery_crypto,service,worker}.rs` | Durable transitions, encrypted write-ahead recovery envelopes, synchronous authorization, and recovery-only worker. |
| `crates/sbproxy-billing/src/payment_auth.rs` | Draft-01 challenge, credential, body-digest, binding, error, and receipt codec. |
| `crates/sbproxy-billing/src/{x402,stripe_payment,stripe_meter}.rs` | x402 authorization, Stripe settlement, and separate Stripe usage reporting. |
| `crates/sbproxy-billing/src/lightning/{mod,cln,lnd}.rs` | CLN Unix JSON-RPC and LND gRPC adapters. |
| `crates/sbproxy-billing/tests/*.rs` | State, crash, protocol byte, provider, timeout, breaker, reconciliation, and privacy tests. |
| `crates/sbproxy-config/src/types.rs` | Schema-visible `PaymentsConfig` under `ProxyServerConfig`. |
| `crates/sbproxy-config/tests/payments_config.rs` | Parse, validation, feature, URL, version, and bridge cases. |
| `crates/sbproxy-modules/Cargo.toml` | Lightweight dependency on the billing domain types and optional protocol integration. |
| `crates/sbproxy-modules/src/policy/{quote_token,ai_crawl/{mod,types,http_ledger,tests}}.rs` | One signed `PaymentRequirement`, quote binding, async ledger, preference parsing, and exact paid response semantics. |
| `crates/sbproxy-core/src/{billing_runtime,pipeline,server/lifecycle}.rs` | Runtime assembly, secret resolution, candidate health checks, reload, and shutdown. |
| `crates/sbproxy-core/src/{builtin_enforcers/ai_crawl,server/request_phase,context}.rs` | Credential extraction, multi-value headers, strict origin gating, and response writing. |
| `crates/sbproxy-core/tests/payment_settlement.rs` | Running proxy tests that count origin calls and inspect every response header. |
| `crates/sbproxy-observe/src/{telemetry,access_log}.rs` | Closed-cardinality metrics and redacted correlation fields. |
| `schemas/sb-config.schema.json` | Generated payment configuration schema. |
| `examples/{rail-x402-base-sepolia,rail-mpp-stripe-test,rail-lightning,multi-rail-accept-payment}/` | Deterministic, runnable rail examples. |
| `scripts/test-fixtures/payments/*.sh` | Local contract smoke tests. |
| `docs/tapes/payment-settlement.tape` | Deterministic VHS recording source. |
| `docs/assets/payment-settlement.gif` | Generated terminal walkthrough. |
| `docs/{402-challenge,ai-crawl-control,payment-settlement}.md` | Exact protocol and operations documentation. |

## Public interfaces and durable model

These names and ownership boundaries are the contract between tasks.

```rust
// crates/sbproxy-billing/src/types.rs
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdvertisedRail {
    X402,
    Mpp,
    Stripe,
    Lightning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SettlementRail {
    X402,
    Stripe,
    LightningCln,
    LightningLnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentProtocol {
    X402V2,
    PaymentAuthDraft01,
    StripePaymentIntentV1,
    LightningInvoice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentStatus {
    Pending,
    Processing,
    RetryWait,
    Succeeded,
    Terminal,
    NeedsReconciliation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttemptOperation {
    PrepareChallenge,
    Verify,
    Settle,
    Confirm,
    Capture,
    Query,
    MeterReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    pub amount_micros: u64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequirementTerms {
    X402Exact {
        facilitator_url: String,
        max_timeout_seconds: u32,
        extra: BTreeMap<String, serde_json::Value>,
    },
    PaymentAuthStripeCharge {
        business_network_id: String,
        payment_method_types: Vec<String>,
        account_context: String,
    },
    StripePaymentIntent {
        payment_method_types: Vec<String>,
        capture_method: String,
        account_context: String,
    },
    LightningInvoice {
        backend: String,
        invoice_expiry_seconds: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequirementDraft {
    pub requirement_id: String,
    pub protocol: PaymentProtocol,
    pub advertised_rail: AdvertisedRail,
    pub settlement_rail: SettlementRail,
    pub method: String,
    pub intent: String,
    pub network: Option<String>,
    pub asset: Option<String>,
    pub pay_to: Option<String>,
    pub amount: Money,
    pub settlement_amount: String,
    pub settlement_decimals: u8,
    pub terms: RequirementTerms,
    pub quote_id: String,
    pub tenant_id: String,
    pub origin_id: String,
    pub route: String,
    pub expires_at_ms: i64,
    pub request_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequirement {
    pub draft: PaymentRequirementDraft,
    pub provider_handle: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPaymentRequirement {
    pub requirement: PaymentRequirement,
    pub draft_digest: [u8; 32],
    pub requirement_digest: [u8; 32],
    pub quote_token: String,
}

pub struct PaymentProof {
    scheme: String,
    credential: zeroize::Zeroizing<String>,
    digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_key: String,
    pub intent_id: String,
    pub rail: SettlementRail,
    pub method: String,
    pub provider_reference: String,
    pub settled_at_ms: i64,
}
```

`PaymentRequirement` is the single bridge between advertised AI crawl rail configuration and `PaymentsConfig`. `RequirementTerms` carries every rail-specific value later projected onto a challenge or provider call; adapters cannot consult a second price, address, facilitator, network ID, payment-method list, capture mode, backend, or expiry source. Preparation is deliberately two phase for rails whose provider handle does not exist yet. First, persist `PaymentRequirementDraft` and its `draft_digest`; then persist the `PrepareChallenge` attempt and idempotency key before creating the provider object. After the provider returns, add only its non-secret handle, JCS hash the final `PaymentRequirement`, sign that complete `requirement_digest` in the quote JWS, and atomically finalize the pending challenge. Stripe direct-mode metadata binds the immutable `draft_digest` because the PaymentIntent ID cannot be part of its own create request; the final quote binds that draft digest and the returned PaymentIntent ID together. Payment Auth Stripe, which creates its PaymentIntent on credential retry, can bind the final requirement digest directly. Stripe client secrets remain only in the immediate 402 response object and are never persisted.

```rust
// crates/sbproxy-billing/src/store.rs
#[async_trait::async_trait]
pub trait SettlementStore: Send + Sync {
    async fn create_or_get_challenge(
        &self,
        draft: &PaymentRequirementDraft,
        draft_digest: [u8; 32],
        request_idempotency_key: &str,
    ) -> Result<CreateIntent, BillingError>;

    async fn finalize_requirement(
        &self,
        intent_id: &str,
        signed: &SignedPaymentRequirement,
    ) -> Result<(), BillingError>;

    async fn prepare_attempt(
        &self,
        intent_id: &str,
        operation: AttemptOperation,
        provider_idempotency_key: &str,
        known_provider_handle: Option<&str>,
        now_ms: i64,
    ) -> Result<PreparedAttempt, BillingError>;

    async fn mark_dispatch_started(
        &self,
        attempt_id: &str,
        lease_token: &str,
        now_ms: i64,
    ) -> Result<(), BillingError>;

    async fn mark_succeeded(
        &self,
        attempt_id: &str,
        lease_token: &str,
        receipt: SettlementReceipt,
    ) -> Result<(), BillingError>;

    async fn mark_retry_wait_before_dispatch(
        &self,
        attempt_id: &str,
        lease_token: &str,
        retry_at_ms: i64,
        failure: SafeFailure,
    ) -> Result<(), BillingError>;

    async fn mark_terminal(
        &self,
        attempt_id: &str,
        lease_token: &str,
        failure: SafeFailure,
    ) -> Result<(), BillingError>;

    async fn mark_needs_reconciliation(
        &self,
        attempt_id: &str,
        lease_token: &str,
        failure: SafeFailure,
    ) -> Result<(), BillingError>;
}
```

`mark_retry_wait_before_dispatch` rejects any attempt with non-null `dispatch_started_at_ms`. A dispatched attempt that lacks an authoritative recorded response can transition only to `NeedsReconciliation`. A provider-specific query may later prove success or a definite no-op; only then may the reconciliation path transition to `Succeeded` or create a new attempt.

```rust
// crates/sbproxy-billing/src/registry.rs
#[async_trait::async_trait]
pub trait PaymentMethodAdapter: Send + Sync {
    fn rail(&self) -> SettlementRail;

    async fn prepare_challenge(
        &self,
        request: ChallengePreparation,
        dispatch: &DispatchContext,
    ) -> Result<ChallengeMaterial, BillingError>;

    async fn authorize_and_settle(
        &self,
        request: AuthoritativePayment,
        dispatch: &DispatchContext,
    ) -> Result<SettlementReceipt, BillingError>;

    async fn query_attempt(
        &self,
        attempt: &ProviderAttempt,
        dispatch: &DispatchContext,
    ) -> Result<ProviderQueryResult, BillingError>;
}

#[async_trait::async_trait]
pub trait UsageReporter: Send + Sync {
    fn reporter_name(&self) -> &'static str;
    async fn report(
        &self,
        event: &UsageEvent,
        dispatch: &DispatchContext,
    ) -> Result<UsageReportReceipt, BillingError>;
}
```

`StripeMeterReporter` implements only `UsageReporter`. It never implements `PaymentMethodAdapter`, never creates a `SettlementReceipt`, and cannot change an access-payment intent to `Succeeded`.

```rust
// crates/sbproxy-billing/src/service.rs
pub enum AuthorizationDecision {
    Settled(SettlementReceipt),
    PaymentRequired(PaymentProblem),
    Unavailable { retry_after_seconds: u32 },
}

pub struct BillingService {
    store: Arc<dyn SettlementStore>,
    adapters: RailRegistry,
    #[cfg(feature = "recovery-crypto")]
    recovery_cipher: Option<RecoveryCipher>,
    deadline: Duration,
}

impl BillingService {
    pub async fn prepare_requirement(
        &self,
        input: RequirementInput,
    ) -> Result<PreparedPaymentResponse, BillingError>;

    pub async fn authorize(
        &self,
        request: RedemptionRequest,
    ) -> Result<AuthorizationDecision, BillingError>;
}
```

No API named `authorize_and_enqueue` is introduced. Enqueueing is not authorization.

## Provider call and crash rules

Derive every provider idempotency identity before dispatch as:

```text
material = "sbproxy-settlement-v1\0" || rail || "\0" || operation || "\0" ||
           tenant_id || "\0" || requirement_id || "\0" || attempt_generation ||
           "\0" || proof_digest_or_empty
provider_idempotency_key = "sbp1_" || base64url_nopad(SHA-256(material))
```

`attempt_generation` starts at zero. A pre-dispatch retry reuses the same attempt, generation, body, and key. It can increase only after a documented provider query proves the prior dispatch did not occur; ambiguity can never increase it. Use the full key where the provider accepts it. Where a label has a tighter documented limit, persist the full key and use the longest unambiguous prefix plus checksum that fits; test that mapping for collisions. Never derive a key from an SPT or credential in plaintext.

Challenge preparation for direct Stripe and Lightning follows this order:

1. Compile and locally validate the complete draft fields.
2. Persist the draft, `draft_digest`, challenge idempotency key, and `PrepareChallenge` attempt.
3. Commit `dispatch_started_at_ms` immediately before the provider write.
4. Create the provider object without capturing funds or delivering the origin resource.
5. Persist the non-secret provider handle.
6. Finalize and sign the complete requirement, then return the 402.

Credential authorization follows this order:

1. Verify the final signed requirement, quote, expiry, body digest, route, origin, amount, currency, network, asset, recipient, and provider handle locally.
2. Atomically load the durable intent and consume or reserve the proof digest.
3. Atomically create the provider attempt with its final provider idempotency key and `dispatch_started_at_ms = NULL`.
4. Commit `dispatch_started_at_ms` in a separate transaction immediately before the network write.
5. Perform the bounded provider call.
6. Persist the complete typed result or `NeedsReconciliation`.
7. Commit the receipt and `Succeeded` in one transaction.
8. Only after step 7 return `AuthorizationDecision::Settled`.

If the process stops after a dispatch stamp and before recording the response, another process sees a dispatched unresolved attempt and does not create a new write attempt or a new idempotency key. Recovery may use a documented provider status query. Where Stripe's public idempotency contract applies and no provider handle was returned, recovery may replay the byte-equivalent POST with the same persisted idempotency key solely to recover the original response, then retrieve the returned PaymentIntent.

Before a replayable Stripe dispatch, persist the exact content type, account context, API version, and body as an AES-256-GCM recovery envelope; never persist the API key or any authorization header. Bind the ciphertext with AAD over rail, attempt ID, operation, provider idempotency key, and requirement digest. Resolve the 32-byte key from `proxy.payments.recovery_encryption.key`, store `proxy.payments.recovery_encryption.key_id` with the ciphertext, and hold plaintext only in a zeroizing buffer. Purge the envelope when a response is recorded, the attempt becomes definitely terminal, or it reaches its configured hard expiry.

Same-key response recovery is allowed only while the dispatch is younger than the configured age, capped at 23 hours below Stripe's documented minimum 24-hour idempotency retention. A missing or wrong recovery key, authentication failure, changed request bytes, or older attempt remains `NeedsReconciliation`; it never falls back to a new key. Operators must drain or expire outstanding Stripe reconciliation records before rotating away the configured recovery key. If neither a query nor documented idempotent response recovery exists, the record remains `NeedsReconciliation`. A challenge-preparation crash follows the same rule; the service never creates a second provider object under a new key.

## Feature matrix

| Cargo feature | Compiles | Runtime selector | Authorization behavior |
| --- | --- | --- | --- |
| none | Domain types only | no `proxy.payments` | Existing ledger behavior remains unchanged. |
| `payments` | Store, service, dispatch, registry, recovery worker | `proxy.payments` | Fails startup if an advertised rail has no compiled adapter. |
| `payment-mpp` | Draft-01 Payment Auth codec and policy integration | `protocols.payment_auth` | Requires an explicitly configured method and intent. This PR accepts only `stripe` plus `charge`. |
| `payment-stripe` | `StripePaymentIntentSettler` and separate `StripeMeterReporter` | `rails.stripe`, `usage_reporters.stripe_meter` | PaymentIntent settlement is synchronous and authoritative. Meter reporting is asynchronous and never authorizes. |
| `payment-x402` | x402 v2 exact adapter | `rails.x402` | Synchronous `verify` plus `settle` within a total 2-second deadline. |
| `payment-lightning-cln` | CLN Unix JSON-RPC adapter | `rails.lightning_cln` | Invoice status must be `paid`; outbound `xpay` uses durable labels. |
| `payment-lightning-lnd` | Generated LND gRPC adapter | `rails.lightning_lnd` | Invoice must be `SETTLED`; outgoing payment must be `SUCCEEDED`. |

`protocols.payment_auth` with method `stripe` requires both `payment-mpp` and `payment-stripe`. `usage_reporters.stripe_meter` requires `payment-stripe` but does not require or imply that any route advertises Stripe.

---

### Task 1: Create the billing crate and normalized domain contract

**Files:**

- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/sbproxy-billing/Cargo.toml`
- Create: `crates/sbproxy-billing/src/lib.rs`
- Create: `crates/sbproxy-billing/src/{money,types,error}.rs`
- Create: `crates/sbproxy-billing/tests/domain_contract.rs`

**Dependencies:** None.

**Produces:** `AdvertisedRail`, `SettlementRail`, `PaymentProtocol`, `IntentStatus`, `AttemptOperation`, `Money`, `RequirementTerms`, `PaymentRequirementDraft`, `PaymentRequirement`, `SignedPaymentRequirement`, `PaymentProof`, `SettlementReceipt`, and `BillingError`.

- [ ] **Step 1: Write failing domain tests**

Add tests for checked positive money, uppercase stored ISO currency and lowercase provider conversion, canonical draft and final requirement hashing, typed rail-term canonicalization, proof redaction, and constant-time proof digest comparison. Prove that adding a provider handle changes only the final requirement digest and that `AdvertisedRail::Mpp` maps to `SettlementRail::Stripe` in the normalized requirement without inventing an `Mpp` settlement rail.

- [ ] **Step 2: Run the failing test**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --test domain_contract
```

Expected: FAIL because the crate does not exist.

- [ ] **Step 3: Add exact workspace and feature wiring**

Add this exact entry to the root workspace dependency table:

```toml
[workspace.dependencies]
protoc-bin-vendored = "=3.2.0"
```

Define these member-crate tables in `crates/sbproxy-billing/Cargo.toml`:

```toml
[features]
default = []
runtime = ["dep:rusqlite", "dep:tokio"]
x402 = ["runtime", "dep:sbproxy-httpkit"]
mpp = []
recovery-crypto = ["dep:aes-gcm"]
stripe = ["runtime", "dep:sbproxy-httpkit", "recovery-crypto"]
lightning-cln = ["runtime"]
lightning-lnd = [
  "runtime",
  "dep:tonic",
  "dep:prost",
  "dep:tonic-build",
  "dep:protoc-bin-vendored",
]

[dependencies]
rusqlite = { workspace = true, optional = true }
tokio = { workspace = true, optional = true }
sbproxy-httpkit = { workspace = true, optional = true }
aes-gcm = { workspace = true, optional = true }
tonic = { workspace = true, optional = true }
prost = { workspace = true, optional = true }

[build-dependencies]
tonic-build = { workspace = true, optional = true }
protoc-bin-vendored = { workspace = true, optional = true }
```

Reuse the existing workspace pins for every other dependency, including `tonic-build = "0.12"`. Every `dep:` member in the feature table resolves to an optional dependency in the correct dependency table. A default build therefore compiles only the domain contract and does not activate the LND compiler toolchain. Gate store, dispatch, service, worker, and recovery modules behind `runtime`; gate recovery cryptography behind `recovery-crypto`. Use workspace package metadata, `publish = false`, and `#![forbid(unsafe_code)]`. Do not add provider features to defaults.

- [ ] **Step 4: Implement validated domain types**

Keep the existing quote unit as positive `u64` micros, normalize ISO currency to three uppercase ASCII characters, and provide explicit checked conversion to each provider's base unit. Store the resulting decimal string and declared decimals in the requirement, and reject any conversion with a remainder or overflow. Serialize `PaymentRequirement` with the workspace `serde_json_canonicalizer` before SHA-256. Make `PaymentProof` hold `zeroize::Zeroizing<String>`, expose only `digest()`, and redact `Debug` and `Display`.

- [ ] **Step 5: Verify and commit**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo fmt --check
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --test domain_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo clippy -p sbproxy-billing --tests -- -D warnings
```

Expected: PASS.

Commit:

```bash
git add Cargo.toml Cargo.lock crates/sbproxy-billing
git commit -m "feat: add normalized payment domain"
```

### Task 2: Implement durable intent, attempt, dispatch, and receipt storage

**Files:**

- Modify: `Cargo.lock`
- Modify: `crates/sbproxy-billing/Cargo.toml`
- Modify: `crates/sbproxy-billing/src/lib.rs`
- Create: `crates/sbproxy-billing/src/{store,sqlite,dispatch,recovery_crypto,registry}.rs`
- Create: `crates/sbproxy-billing/tests/sqlite_store.rs`
- Create: `crates/sbproxy-billing/tests/dispatch_crash.rs`

**Dependencies:** Task 1.

**Produces:** `SettlementStore`, `SqliteSettlementStore`, `PreparedAttempt`, `ProviderAttempt`, `DispatchContext`, `RecoveryCipher`, `SafeFailure`, `PaymentMethodAdapter`, `UsageReporter`, `RailRegistry`, and numbered SQLite migration 1.

- [ ] **Step 1: Write failing transactional state tests**

Use a temporary on-disk database and two independent store handles. Cover:

- identical requirement plus idempotency key returns one intent;
- an idempotency key with a different draft or final requirement digest is rejected;
- one signed quote nonce can bind to only one requirement and proof digest, while the same idempotency key and proof can resume;
- the proof digest is unique per tenant;
- `Pending`, `Processing`, `RetryWait`, `NeedsReconciliation`, and `Terminal` cannot load an access receipt;
- `mark_retry_wait_before_dispatch` succeeds only when `dispatch_started_at_ms` is null;
- receipt key and provider reference uniqueness;
- concurrent success commits create one receipt;
- a stale lease with no dispatch can return to `RetryWait`;
- a stale lease with a dispatch timestamp becomes `NeedsReconciliation`;
- recovery envelope plaintext never appears in SQLite, Debug, Display, or errors; AES-GCM round-trip requires the exact AAD, tampering fails closed, and expiry purges ciphertext;
- duplicate settlement-rail adapter and usage-reporter registrations fail in their separate namespaces.

- [ ] **Step 2: Write the required two-handle crash test**

The fixture provider records calls by idempotency key. Handle A prepares an attempt, commits `dispatch_started_at_ms`, lets the provider record success, and then drops without recording a response. Handle B opens the same database and runs recovery. Assert:

- the intent is `NeedsReconciliation`;
- the provider call count remains one;
- B never calls `authorize_and_settle` again;
- B queries using the persisted provider handle or idempotency key;
- only a query result proving success commits `Succeeded`;
- no receipt or origin permission exists before that proof.

Add a second case where query is unsupported; it remains `NeedsReconciliation`.

- [ ] **Step 3: Run the failing tests**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime,recovery-crypto --test sqlite_store
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime,recovery-crypto --test dispatch_crash
```

Expected: FAIL because the store and dispatch types do not exist.

- [ ] **Step 4: Implement migration 1 and atomic SQL**

Create tables:

- `payment_intents`
- `payment_attempts`
- `payment_receipts`
- `consumed_payment_proofs`
- `provider_events`
- `provider_recovery_envelopes`
- `usage_reports`
- `reconciliation_log`

`payment_intents` stores the JCS draft, `draft_digest`, nullable JCS final requirement, nullable `requirement_digest`, quote token, quote nonce, and nullable reserved proof digest. `payment_attempts` includes `attempt_id`, `intent_id`, `operation`, `attempt_generation`, `provider_idempotency_key`, nullable `provider_handle`, `lease_token`, `lease_expires_at_ms`, `dispatch_started_at_ms`, `response_recorded_at_ms`, `status`, and redacted failure columns. `provider_recovery_envelopes` stores `attempt_id`, key ID, nonce, ciphertext, AAD digest, creation time, and hard expiry, never plaintext. When a handle can be computed locally, such as an LND payment hash, `prepare_attempt` persists it in the same transaction as the attempt and key, before dispatch. Add unique constraints on `(tenant_id, request_idempotency_key)`, `(tenant_id, proof_digest)`, quote nonce, `(rail, provider_idempotency_key)`, `(intent_id, operation, attempt_generation)`, `receipt_key`, `(rail, provider_reference)`, and `(reporter, usage_identifier)`. `finalize_requirement` uses a compare-and-set on the draft digest and rejects a second final value.

Use `user_version = 1`, `journal_mode = WAL`, `foreign_keys = ON`, `synchronous = FULL`, and a bounded busy timeout. Use `BEGIN IMMEDIATE` for create, attempt, dispatch, and terminal transitions.

- [ ] **Step 5: Implement `DispatchContext` as the only network-write gate**

`DispatchContext::run_write` accepts a prepared attempt and a future-producing closure. It commits `dispatch_started_at_ms` before polling the closure. If the closure returns an ambiguous transport result or is dropped after dispatch, it records `NeedsReconciliation`. It cannot write `RetryWait` after dispatch. Read-only provider queries use `run_query` and their own attempt records.

Gate `registry`, store, dispatch, and recovery exports behind `runtime`. Register one adapter per `SettlementRail` and one reporter per reporter name; reject duplicates in both namespaces.

- [ ] **Step 6: Verify and commit**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime,recovery-crypto --test sqlite_store --test dispatch_crash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo clippy -p sbproxy-billing --features runtime,recovery-crypto --tests -- -D warnings
```

Expected: PASS.

Commit:

```bash
git add Cargo.lock crates/sbproxy-billing
git commit -m "feat: persist payment dispatch attempts"
```

### Task 3: Add authoritative billing service and recovery-only worker

**Files:**

- Modify: `crates/sbproxy-billing/src/{lib,store,registry}.rs`
- Create: `crates/sbproxy-billing/src/{service,worker}.rs`
- Create: `crates/sbproxy-billing/tests/authorization_state.rs`
- Create: `crates/sbproxy-billing/tests/worker.rs`

**Dependencies:** Tasks 1 and 2.

**Produces:** `BillingService`, `AuthorizationDecision`, `SettlementWorker`, `SettlementWorkerHandle`, `WorkerConfig`, and `WorkerStatus`.

- [ ] **Step 1: Write failing authorization-state tests**

Use a recording adapter and an origin permission callback. For every non-success state, assert all four values are zero or absent: adapter settlement success, origin callback count, 2xx result, and receipt. Explicitly cover `Pending`, `Processing`, `RetryWait`, `NeedsReconciliation`, `Terminal`, timeout, breaker-open, malformed provider success, and an adapter returning verified but not settled.

Add concurrency tests proving two simultaneous retries with one proof perform at most one settlement and return at most one delivery permission. A repeated request with the same HTTP `Idempotency-Key` and an already succeeded intent returns the stored receipt without repeating settlement.

- [ ] **Step 2: Write failing worker-scope tests**

Assert the worker:

- expires stale pending challenges;
- recovers undispatched expired processing attempts;
- queries `NeedsReconciliation`;
- reports queued usage through `UsageReporter`;
- never calls `authorize_and_settle` for `Pending` or `RetryWait`;
- stops claims and drains within the configured shutdown deadline.

- [ ] **Step 3: Run the failing tests**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime --test authorization_state --test worker
```

Expected: FAIL because the service and worker do not exist.

- [ ] **Step 4: Implement the authoritative path**

`BillingService::authorize` validates the signed requirement, loads the previously persisted and finalized intent, validates or reserves the proof digest for that same intent, prepares the provider attempt and key, and calls the adapter under `tokio::time::timeout`. A credential cannot create an intent; a missing, expired, or non-final challenge fails closed before a provider call. The method maps only a committed receipt from `mark_succeeded` to `AuthorizationDecision::Settled`. A provider timeout after dispatch becomes `NeedsReconciliation`; a local timeout before dispatch may become `RetryWait`. The total configured authorization deadline rejects values above 2,000 ms.

- [ ] **Step 5: Implement recovery-only scheduling**

The worker has separate bounded queues for reconciliation, expiry, and usage reports. It never claims a normal access-payment intent for settlement. Reconciliation calls only `query_attempt`; if a provider proves the write did not occur, the service permits a later client retry to create a new attempt. If it proves success, reconciliation commits the receipt. Unsupported or ambiguous queries remain `NeedsReconciliation`.

- [ ] **Step 6: Verify and commit**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime --test authorization_state --test worker
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo clippy -p sbproxy-billing --features runtime --tests -- -D warnings
```

Expected: PASS.

Commit:

```bash
git add crates/sbproxy-billing
git commit -m "feat: authorize only settled payments"
```

### Task 4: Add exact payments config and compile one signed requirement

**Files:**

- Modify: `crates/sbproxy-config/src/types.rs`
- Modify: `crates/sbproxy-config/src/compiler.rs`
- Modify: `crates/sbproxy-config/src/validate.rs`
- Create: `crates/sbproxy-config/tests/payments_config.rs`
- Modify: `crates/sbproxy-modules/Cargo.toml`
- Modify: `crates/sbproxy-modules/src/policy/quote_token.rs`
- Modify: `crates/sbproxy-modules/src/policy/ai_crawl/{types,mod,http_ledger,tests}.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/sbproxy-core/src/pipeline.rs`
- Modify: `crates/sbproxy/Cargo.toml`
- Modify: `schemas/sb-config.schema.json`

**Dependencies:** Task 1. It can run in parallel with Tasks 2 and 3 after Task 1.

**Produces:** `PaymentsConfig`, exact nested provider config, feature forwarding, `PaymentRequirementCompiler`, `PaymentRequirementDraft`, and one finalized quote-signed requirement representation.

- [ ] **Step 1: Write failing config and bridge tests**

Cover:

- absent `proxy.payments` preserves existing behavior;
- exact valid config for each provider;
- the Stripe settlement rail requires a recovery-encryption key reference, key ID, and maximum age no greater than 23 hours;
- `authorization_timeout_ms = 2001` fails;
- zero or over-limit `max_body_bytes` fails;
- Stripe API version other than `2026-06-24.dahlia` fails;
- Stripe account context other than `platform` fails instead of accepting client-controlled Connect routing;
- x402 network is CAIP-2 and asset is non-empty;
- x402 `max_timeout_seconds` is positive and its bounded `extra` value is preserved with deterministic JCS bytes;
- x402 `facilitator_url` is absolute HTTPS, has no userinfo, query, or fragment, and contains no `/verify` or `/settle` endpoint suffix;
- x402 timeout sums and breaker bounds are validated;
- CLN socket path is absolute and minimum version setting cannot be lower than `26.06`;
- LND endpoint, TLS certificate, and macaroon references are all required;
- configured provider without its Cargo feature fails with the exact feature name;
- every advertised rail resolves to exactly one compiled adapter;
- duplicate adapter mappings fail;
- a route cannot advertise rails with different `quote_currency` values, and no implicit foreign-exchange conversion is performed;
- x402 network, asset, pay-to, amount, quote ID, or facilitator mismatch fails before a provider call;
- exact micros-to-provider conversion succeeds, while fractional Stripe cents, unknown currency decimals, and overflow fail without rounding;
- quote claims whose requirement ID, draft digest, final digest, price, rail, or facilitator projection differs from the persisted requirement fail locally;
- MPP method or intent other than `stripe` and `charge` fails;
- Lightning advertisement with neither CLN nor LND, or both without an explicit backend, fails.

- [ ] **Step 2: Run the failing config test**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-config --test payments_config
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-modules ai_crawl::tests::signed_requirement
```

Expected: FAIL because the config and requirement compiler do not exist.

- [ ] **Step 3: Add the exact schema-visible configuration**

Use this shape and field ownership:

```yaml
proxy:
  payments:
    state_path: /var/lib/sbproxy/payments.sqlite3
    challenge_binding_key: secret://env/SBPROXY_PAYMENT_BINDING_KEY
    authorization_timeout_ms: 2000
    max_body_bytes: 1048576
    recovery_encryption:
      key_id: payments-2026-07
      key: secret://env/SBPROXY_PAYMENT_RECOVERY_KEY
      max_age_hours: 23
    worker:
      reconcile_interval_ms: 1000
      max_reconcile_batch: 32
      shutdown_timeout_ms: 5000
    protocols:
      payment_auth:
        draft: draft-ryan-httpauth-payment-01
        realm: api.example.com
        method: stripe
        intent: charge
    rails:
      x402:
        scheme: exact
        network: "eip155:84532"
        asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
        quote_currency: USD
        asset_decimals: 6
        pay_to: "0x1111111111111111111111111111111111111111"
        max_timeout_seconds: 60
        extra:
          name: USDC
          version: "2"
        facilitators:
          - facilitator_url: https://facilitator.example/api
        verify_timeout_ms: 700
        settle_timeout_ms: 1200
        breaker:
          failure_threshold: 3
          open_ms: 5000
          half_open_max: 1
      stripe:
        api_key: secret://env/STRIPE_SECRET_KEY
        api_version: 2026-06-24.dahlia
        account_context: platform
        business_network_id: profile_test_example
        quote_currency: USD
        currency_decimals: 2
        payment_method_types: [card]
        direct_payment_intent:
          enabled: true
          capture_method: manual
      lightning_cln:
        socket_path: /run/lightning/lightning-rpc
        rune: secret://env/CLN_RUNE
        minimum_version: "26.06"
        quote_currency: BTC
        settlement_decimals: 11
        invoice_expiry_seconds: 300
      lightning_lnd:
        endpoint: https://lnd.internal:10009
        tls_certificate_path: /run/secrets/lnd/tls.cert
        macaroon: secret://env/LND_MACAROON_HEX
        quote_currency: BTC
        settlement_decimals: 11
        invoice_expiry_seconds: 300
    usage_reporters:
      stripe_meter:
        event_name: sbproxy_ai_tokens
        customer_field: stripe_customer_id
```

All blocks are optional, but every advertised rail must have exactly one enabled compiled target. Enabling the Stripe settlement rail makes `recovery_encryption` required because an exact create response must be recoverable after a process crash, and the Payment Auth form contains an SPT; structural validation checks only the secret reference and key ID, while runtime resolution requires exactly 32 decoded key bytes. `max_age_hours` is from 1 through 23.

`max_body_bytes` must be positive and no greater than the proxy's compiled maximum request body size. The compiler requires the tier currency to equal the selected rail's `quote_currency`, converts quote micros to the configured settlement decimals with checked integer arithmetic, and rejects a remainder, so it never rounds or silently performs foreign exchange. A mixed challenge may contain only rails with the same quote currency. Stripe config also validates the declared currency decimals against its built-in ISO-4217 table. `account_context` accepts only `platform` in this release, no `Stripe-Account` header is sent, and any future Connect policy requires a separately typed server-owned config rather than challenge or credential input. The x402 timeout sum must be at most `authorization_timeout_ms`; `max_timeout_seconds` must be from 1 through 3,600; and `extra` must be a JSON object whose JCS form is at most 4 KiB. Breaker thresholds must be positive, `open_ms` must be bounded from 100 through 60,000, and `half_open_max` is exactly 1 in this release. Lightning invoice expiry must be from 30 through 86,400 seconds. `direct_payment_intent.capture_method` accepts only `manual`.

- [ ] **Step 4: Normalize the advertised rail model**

Move the current `Money` type and closed rail enum to `sbproxy-billing`, then re-export them as `Money` and `Rail` from the crawl policy to preserve source compatibility. The rail enum becomes `AdvertisedRail` and gains `Stripe`. Change `ConfiguredRail` so it carries the same normalized fields used by `PaymentsConfig`:

- x402: `network`, `asset`, `pay_to`, selected `facilitator_url`;
- MPP: `method`, `intent`;
- Stripe: direct PaymentIntent selector;
- Lightning: explicit `backend`, `network`, and `asset`.

Preserve the existing wire-only `chain` shape only when `proxy.payments` is absent, so current non-settlement configurations retain their behavior. When settlement is enabled, reject `chain` with a targeted migration error and require CAIP-2 `network`; never silently translate `base` or another short chain name into an authoritative payment requirement.

- [ ] **Step 5: Compile and sign exactly one `PaymentRequirement`**

`PaymentRequirementCompiler::draft` receives the matched tier price, route, origin, quote claims, request digest, advertised rail, and compiled payment config. It:

1. checks the static provider mapping;
2. performs an exact checked amount conversion;
3. copies network, asset, pay-to, method, intent, and the complete typed `RequirementTerms` only from the compiled config;
4. issues the quote ID;
5. JCS serializes the draft and computes `draft_digest`.

The billing service persists that draft before any challenge-preparation provider call. `PaymentRequirementCompiler::finalize` then adds the optional provider handle returned by the adapter, JCS serializes the complete final requirement, adds `requirement_id`, unpadded-base64url `draft_digest`, and unpadded-base64url `requirement_digest` to the existing quote claims, signs the quote JWS, verifies the generated token and every legacy price, rail, route, and facilitator projection against the requirement, and atomically finalizes the challenge before returning the 402. Rails with no preparation call finalize immediately with no provider handle.

The payment path must not consume the existing quote nonce during signature parsing. Add a verification method that authenticates and validates claims without mutation, then let the SQLite intent and proof transaction reserve the nonce for one requirement and proof digest. The same HTTP idempotency key and same proof may resume a retry or read the committed receipt; a different proof cannot reuse the quote. Preserve the existing consume-on-verify behavior only for legacy non-settlement ledger callers, and rewrite the quote-store comments so they describe generic durable OSS storage rather than an edition-specific Postgres implementation.

Remove duplicate rail-specific amount, address, and provider construction from `RailChallenge`. Its JSON views are projections of `SignedPaymentRequirement`, not separate sources of truth.

- [ ] **Step 6: Add binary feature forwarding and generated schema**

Add `sbproxy-billing.workspace = true` unconditionally to `sbproxy-modules` so the closed domain types have one owner even when settlement is disabled. Its feature block is:

```toml
payments = []
payment-mpp = ["payments", "sbproxy-billing/mpp"]
```

Add `sbproxy-billing = { workspace = true, optional = true }` to core. Its feature block is:

```toml
payments = ["dep:sbproxy-billing", "sbproxy-billing/runtime", "sbproxy-modules/payments"]
payment-mpp = ["payments", "sbproxy-billing/mpp", "sbproxy-modules/payment-mpp"]
payment-stripe = ["payments", "sbproxy-billing/stripe"]
payment-x402 = ["payments", "sbproxy-billing/x402"]
payment-lightning-cln = ["payments", "sbproxy-billing/lightning-cln"]
payment-lightning-lnd = ["payments", "sbproxy-billing/lightning-lnd"]
```

The binary forwards:

```toml
payments = ["sbproxy-core/payments", "sbproxy-modules/payments"]
payment-mpp = ["payments", "sbproxy-core/payment-mpp", "sbproxy-modules/payment-mpp"]
payment-stripe = ["payments", "sbproxy-core/payment-stripe"]
payment-x402 = ["payments", "sbproxy-core/payment-x402"]
payment-lightning-cln = ["payments", "sbproxy-core/payment-lightning-cln"]
payment-lightning-lnd = ["payments", "sbproxy-core/payment-lightning-lnd"]
```

Regenerate `schemas/sb-config.schema.json` through the repository command. Validation mode checks shape and features but does not resolve secrets, open SQLite, create provider objects, or start workers.

- [ ] **Step 7: Verify and commit**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-config --test payments_config
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-modules ai_crawl
scripts/check-config-schema.sh
```

Expected: PASS.

Commit:

```bash
git add Cargo.toml Cargo.lock crates/sbproxy-config crates/sbproxy-modules crates/sbproxy-core/src/pipeline.rs crates/sbproxy/Cargo.toml schemas/sb-config.schema.json
git commit -m "feat: compile signed payment requirements"
```

### Task 5: Implement Payment Auth draft-01 bytes and strict request gating

**Files:**

- Create: `crates/sbproxy-billing/src/payment_auth.rs`
- Create: `crates/sbproxy-billing/tests/payment_auth_contract.rs`
- Create: `crates/sbproxy-billing/tests/fixtures/payment_auth_draft01.json`
- Modify: `crates/sbproxy-modules/src/policy/ai_crawl/{types,mod,http_ledger,tests}.rs`
- Create: `crates/sbproxy-core/src/billing_runtime.rs`
- Modify: `crates/sbproxy-core/src/{pipeline,context}.rs`
- Modify: `crates/sbproxy-core/src/{builtin_enforcers/ai_crawl,server/request_phase}.rs`
- Modify: `crates/sbproxy-core/src/server/proxy_http.rs`
- Create: `crates/sbproxy-core/tests/payment_settlement.rs`

**Dependencies:** Tasks 1 through 4.

**Produces:** exact draft-01 codec, async billing ledger, multi-value response headers, and origin gating on durable success.

- [ ] **Step 1: Freeze exact draft-01 fixture bytes**

Use UTF-8 bytes with no trailing newline. The test body is:

```text
{"prompt":"hello"}
```

Its RFC 9530 digest parameter is:

```text
sha-256=:ikRyUhC53NT+/Z8Oyge3CuReaSdKMQX7JetCaiz4u/Q=:
```

The JCS request bytes for `draft-stripe-charge-00` are:

```json
{"amount":"1000","currency":"usd","externalId":"quote_01","methodDetails":{"metadata":{"quote_id":"quote_01"},"networkId":"profile_test_123","paymentMethodTypes":["card"]}}
```

Their unpadded base64url value is:

```text
eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJ1c2QiLCJleHRlcm5hbElkIjoicXVvdGVfMDEiLCJtZXRob2REZXRhaWxzIjp7Im1ldGFkYXRhIjp7InF1b3RlX2lkIjoicXVvdGVfMDEifSwibmV0d29ya0lkIjoicHJvZmlsZV90ZXN0XzEyMyIsInBheW1lbnRNZXRob2RUeXBlcyI6WyJjYXJkIl19fQ
```

The JCS opaque bytes are:

```json
{"intent_id":"stl_01","provider":"stripe"}
```

Their unpadded base64url value is:

```text
eyJpbnRlbnRfaWQiOiJzdGxfMDEiLCJwcm92aWRlciI6InN0cmlwZSJ9
```

With binding key bytes `fixture-payment-binding-key`, the exact seven-slot HMAC input is:

```text
api.example.com|stripe|charge|eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJ1c2QiLCJleHRlcm5hbElkIjoicXVvdGVfMDEiLCJtZXRob2REZXRhaWxzIjp7Im1ldGFkYXRhIjp7InF1b3RlX2lkIjoicXVvdGVfMDEifSwibmV0d29ya0lkIjoicHJvZmlsZV90ZXN0XzEyMyIsInBheW1lbnRNZXRob2RUeXBlcyI6WyJjYXJkIl19fQ|2026-07-29T20:05:00Z|sha-256=:ikRyUhC53NT+/Z8Oyge3CuReaSdKMQX7JetCaiz4u/Q=:|eyJpbnRlbnRfaWQiOiJzdGxfMDEiLCJwcm92aWRlciI6InN0cmlwZSJ9
```

The resulting unpadded base64url challenge ID is:

```text
zALONMyg62ie-ZqvHAWSvZU82ywJfV8mXk-mB2H585E
```

The serializer's exact challenge field value is:

```text
Payment id="zALONMyg62ie-ZqvHAWSvZU82ywJfV8mXk-mB2H585E", realm="api.example.com", method="stripe", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJ1c2QiLCJleHRlcm5hbElkIjoicXVvdGVfMDEiLCJtZXRob2REZXRhaWxzIjp7Im1ldGFkYXRhIjp7InF1b3RlX2lkIjoicXVvdGVfMDEifSwibmV0d29ya0lkIjoicHJvZmlsZV90ZXN0XzEyMyIsInBheW1lbnRNZXRob2RUeXBlcyI6WyJjYXJkIl19fQ", expires="2026-07-29T20:05:00Z", digest="sha-256=:ikRyUhC53NT+/Z8Oyge3CuReaSdKMQX7JetCaiz4u/Q=:", opaque="eyJpbnRlbnRfaWQiOiJzdGxfMDEiLCJwcm92aWRlciI6InN0cmlwZSJ9"
```

The exact compact fixture credential bytes are:

```json
{"challenge":{"digest":"sha-256=:ikRyUhC53NT+/Z8Oyge3CuReaSdKMQX7JetCaiz4u/Q=:","expires":"2026-07-29T20:05:00Z","id":"zALONMyg62ie-ZqvHAWSvZU82ywJfV8mXk-mB2H585E","intent":"charge","method":"stripe","opaque":"eyJpbnRlbnRfaWQiOiJzdGxfMDEiLCJwcm92aWRlciI6InN0cmlwZSJ9","realm":"api.example.com","request":"eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJ1c2QiLCJleHRlcm5hbElkIjoicXVvdGVfMDEiLCJtZXRob2REZXRhaWxzIjp7Im1ldGFkYXRhIjp7InF1b3RlX2lkIjoicXVvdGVfMDEifSwibmV0d29ya0lkIjoicHJvZmlsZV90ZXN0XzEyMyIsInBheW1lbnRNZXRob2RUeXBlcyI6WyJjYXJkIl19fQ"},"payload":{"spt":"spt_test_123"}}
```

The `Authorization` field value after `Payment ` is:

```text
eyJjaGFsbGVuZ2UiOnsiZGlnZXN0Ijoic2hhLTI1Nj06aWtSeVVoQzUzTlQrL1o4T3lnZTNDdVJlYVNkS01RWDdKZXRDYWl6NHUvUT06IiwiZXhwaXJlcyI6IjIwMjYtMDctMjlUMjA6MDU6MDBaIiwiaWQiOiJ6QUxPTk15ZzYyaWUtWnF2SEFXU3ZaVTgyeXdKZlY4bVhrLW1CMkg1ODVFIiwiaW50ZW50IjoiY2hhcmdlIiwibWV0aG9kIjoic3RyaXBlIiwib3BhcXVlIjoiZXlKcGJuUmxiblJmYVdRaU9pSnpkR3hmTURFaUxDSndjbTkyYVdSbGNpSTZJbk4wY21sd1pTSjkiLCJyZWFsbSI6ImFwaS5leGFtcGxlLmNvbSIsInJlcXVlc3QiOiJleUpoYlc5MWJuUWlPaUl4TURBd0lpd2lZM1Z5Y21WdVkza2lPaUoxYzJRaUxDSmxlSFJsY201aGJFbGtJam9pY1hWdmRHVmZNREVpTENKdFpYUm9iMlJFWlhSaGFXeHpJanA3SW0xbGRHRmtZWFJoSWpwN0luRjFiM1JsWDJsa0lqb2ljWFZ2ZEdWZk1ERWlmU3dpYm1WMGQyOXlhMGxrSWpvaWNISnZabWxzWlY5MFpYTjBYekV5TXlJc0luQmhlVzFsYm5STlpYUm9iMlJVZVhCbGN5STZXeUpqWVhKa0lsMTlmUSJ9LCJwYXlsb2FkIjp7InNwdCI6InNwdF90ZXN0XzEyMyJ9fQ
```

The exact success receipt bytes are:

```json
{"method":"stripe","reference":"pi_test_123","status":"success","timestamp":"2026-07-29T20:00:00Z"}
```

The exact unpadded `Payment-Receipt` value is:

```text
eyJtZXRob2QiOiJzdHJpcGUiLCJyZWZlcmVuY2UiOiJwaV90ZXN0XzEyMyIsInN0YXR1cyI6InN1Y2Nlc3MiLCJ0aW1lc3RhbXAiOiIyMDI2LTA3LTI5VDIwOjAwOjAwWiJ9
```

- [ ] **Step 2: Write failing codec and HTTP behavior tests**

Test:

- one separate `WWW-Authenticate: Payment` field per offered challenge;
- required `id`, `realm`, lowercase `method`, selected `intent`, and `request`;
- RFC 8785 JCS plus unpadded base64url for `request` and `opaque`, and unpadded base64url over UTF-8 JSON for credentials and receipts, with the deterministic fixture bytes above;
- exact seven HMAC slots with empty strings for absent optional fields;
- body digest recomputation and mismatch rejection;
- eager buffering of every request body, including POST, PUT, PATCH, and DELETE, up to `max_body_bytes`, with exact byte replay to the origin only after success;
- 413 before challenge or provider work when the body exceeds the configured cap;
- rejection of `=`, standard base64 `+` or `/` in base64url positions, empty values, invalid UTF-8, duplicate JSON keys, wrong challenge echo, expired challenge, and an unselected method or intent;
- exactly one `Authorization: Payment <base64url>` field;
- two Payment credentials return 400;
- malformed or failed credentials return 402, a fresh challenge, `application/problem+json`, and the canonical `https://paymentauth.org/problems/{code}` type; the registered `method-unsupported` case is the explicit 400 exception;
- the exact draft-01 problem codes and statuses are `payment-required` 402, `payment-insufficient` 402, `payment-expired` 402, `verification-failed` 402, `method-unsupported` 400, `malformed-credential` 402, and `invalid-challenge` 402;
- every 402 has `Cache-Control: no-store`;
- only a successful 2xx has `Payment-Receipt` and `Cache-Control: private`;
- no error response carries `Payment-Receipt`;
- no Payment flow is accepted over cleartext except the test-only loopback path.

- [ ] **Step 3: Define the local `Accept-Payment` preference extension**

It is negotiation only. Its grammar contains method, optional `intent`, and optional `q`:

```text
Accept-Payment: stripe;intent=charge;q=1.0, x402;q=0.5
```

It carries no SPT, PaymentIntent, signature, quote token, address, amount, or credential. Duplicate `intent` or `q` parameters invalidate that preference. It never authorizes a request. The selected preference controls which separate challenge is emitted; credentials still arrive only in the protocol-defined header.

- [ ] **Step 4: Run the failing tests**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime,mpp --test payment_auth_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-core --features payments,payment-mpp --test payment_settlement payment_auth
```

Expected: FAIL because the codec, async integration, and response model do not exist.

- [ ] **Step 5: Implement the pinned codec**

Implement the draft ABNF and typed JSON with bounded sizes: keep generated challenges under 8 KiB, accept credentials through a 16 KiB implementation cap so the draft's required 4 KiB minimum is supported, and cap decoded JSON depth. `request` and `opaque` use RFC 8785 JCS. Credentials and receipts are base64url-nopad UTF-8 JSON; do not require incoming credential JSON to use JCS or a particular member order. Ignore unknown core challenge parameters and credential fields as draft-01 requires, while still applying the exact typed Stripe payload schema and rejecting duplicate JSON keys. The HMAC input is exactly `realm|method|intent|request|expires|digest|opaque`; `id` is unpadded base64url HMAC-SHA256. Use constant-time comparison for IDs and proof digests.

Implement only `method="stripe"` and `intent="charge"` through the pinned Stripe intent schema. The credential payload requires `spt` beginning with `spt_`; an optional `externalId` is bounded and never treated as trusted routing input.

- [ ] **Step 6: Make the policy asynchronous and gate the origin**

Change `Ledger::redeem` to accept `RedemptionRequest` asynchronously. The request carries the signed requirement, one parsed protocol credential, host, route, request body digest, and client `Idempotency-Key`. Existing in-memory and HTTP ledgers retain their behavior through async wrappers.

For every paid request carrying a body, including POST, PUT, PATCH, and DELETE, reuse the request phase's existing bounded eager-body pattern. Read the body once before issuing or validating a payment challenge, cap it at `proxy.payments.max_body_bytes`, compute the RFC 9530 SHA-256 digest over those exact bytes, and store the bytes in `RequestContext`. On `Succeeded`, `proxy_http.rs` replays those exact bytes upstream without passing them through a second body read. On a local 400, 402, 413, or 503, discard them. Coordinate with the existing idempotency and content-digest buffers so only one owner reads the stream and all consumers share the same immutable bytes. Requests without bodies use no digest slot; any method carrying a body always includes and verifies `digest`.

Replace `crawl_challenge: Option<(String, String, String)>` with:

```rust
pub struct PaymentResponse {
    pub status: StatusCode,
    pub content_type: HeaderValue,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
}
```

Insert every `WWW-Authenticate` field separately. Before dispatching any origin action, match the durable billing result. Only `AuthorizationDecision::Settled` may return `AllowPaid`. Recheck the stored state is `Succeeded` at the decision boundary. All other decisions render 400, 402, or 503 locally and stop the request.

- [ ] **Step 7: Add the origin-count integration matrix**

Run a local recording origin and assert zero origin calls, zero paid 2xx responses, and no receipt for each non-success state. Assert one origin call and one success receipt for `Succeeded`. Add a race where settlement changes from `Processing` to `Succeeded` after the first request has already failed closed; only a later retry may reach the origin.

- [ ] **Step 8: Verify and commit**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime,mpp --test payment_auth_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-modules ai_crawl
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-core --features payments,payment-mpp --test payment_settlement payment_auth
```

Expected: PASS.

Commit:

```bash
git add crates/sbproxy-billing crates/sbproxy-modules crates/sbproxy-core
git commit -m "feat: enforce Payment Auth settlement"
```

### Task 6: Implement synchronous x402 v2 exact authorization

**Files:**

- Create: `crates/sbproxy-billing/src/x402.rs`
- Create: `crates/sbproxy-billing/tests/x402_contract.rs`
- Create: `crates/sbproxy-billing/tests/fixtures/x402/*.json`
- Modify: `crates/sbproxy-core/src/billing_runtime.rs`
- Modify: `crates/sbproxy-core/tests/payment_settlement.rs`

**Dependencies:** Tasks 1 through 5.

**Produces:** `X402ExactSettler`, safe facilitator URL joining, a bounded breaker, and no undocumented reconciliation behavior.

- [ ] **Step 1: Write failing URL and contract tests**

Treat `facilitator_url` as the facilitator's complete API root. Preserve every configured path segment, remove only trailing slashes, and append only the operation name. For a configured root of `https://facilitator.example/base/`, assert the only endpoints are:

```text
https://facilitator.example/base/verify
https://facilitator.example/base/settle
```

Reject a root URL containing query, fragment, userinfo, an endpoint suffix, a non-HTTPS scheme, or an origin-changing join. Do not inject a version or protocol path segment. A provider can include any required prefix in its configured API root, and the adapter preserves that prefix unchanged. A loopback HTTP constructor exists only under test configuration.

Freeze these exact v2 wire shapes from the pinned revision:

```text
PaymentRequired {
  x402Version: 2,
  error?: string,
  resource: { url, description?, mimeType?, serviceName?, tags?, iconUrl? },
  accepts: [{ scheme: "exact", network, amount, asset, payTo,
              maxTimeoutSeconds, extra? }],
  extensions: { "sbproxy-requirement": { info: { id, quote }, schema } }
}

PaymentPayload {
  x402Version: 2,
  resource: the exact challenged resource,
  accepted: the exact selected PaymentRequirements object,
  payload: the scheme-specific signed object,
  extensions: the exact echoed "sbproxy-requirement" extension
}

FacilitatorRequest {
  x402Version: 2,
  paymentPayload: the decoded PaymentPayload,
  paymentRequirements: the exact selected PaymentRequirements object
}

VerifyResponse { isValid, invalidReason?, payer?, extra? }
SettleResponse { success, errorReason?, payer?, transaction, network, amount?, extensions? }
```

The `sbproxy-requirement` extension uses a checked-in JSON Schema Draft 2020-12 fixture with `type: object`, `additionalProperties: false`, required string properties `id` and `quote`, `id` pattern `^[A-Za-z0-9_-]{16,128}$`, and `quote` length 1 through 4,096. `id` is the durable requirement ID and `quote` is its signed quote JWS. The client must echo the complete `info` and `schema` objects unchanged. This is the only SBProxy extension in the x402 envelope. It is not added as an undocumented top-level facilitator field. Local verification validates the quote and requires its projected resource, scheme, network, amount, asset, pay-to, timeout, and `extra` to equal `accepted` before any facilitator call.

Serialize compact UTF-8 JSON and encode all three HTTP header values with standard RFC 4648 base64, including required padding. The 402 uses exactly one `PAYMENT-REQUIRED`, the retry accepts exactly one `PAYMENT-SIGNATURE`, and only settled success emits one `PAYMENT-RESPONSE`. Reject base64url, missing padding, duplicate JSON keys, duplicate headers, unknown top-level fields, oversized decoded JSON, a changed extension, or any requirement mismatch before the facilitator is called. x402 does not emit the Payment Auth `Payment-Receipt` header.

- [ ] **Step 2: Write failing synchronous authorization tests**

Use a recording facilitator and paused time. Cover:

- verify success followed by settle success commits `Succeeded`;
- verify success without settle success does not authorize;
- verify rejection does not call settle;
- a total elapsed duration over 2,000 ms fails closed;
- verify timeout, settle timeout, and open breaker produce zero origin calls and no receipt;
- the breaker opens after configured consecutive transport failures, returns immediately while open, and half-open permits one probe;
- a settle response lacking an authoritative success field is ambiguous;
- connection loss after settle dispatch becomes `NeedsReconciliation`;
- the adapter never calls `/status`, `/reorg`, or a guessed path;
- no second facilitator is tried after any settle dispatch.

- [ ] **Step 3: Run the failing test**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features x402 --test x402_contract
```

Expected: FAIL because the adapter does not exist.

- [ ] **Step 4: Implement exact endpoint and deadline behavior**

Normalize each configured facilitator API root once at startup by removing only trailing slashes, then append the literal `/verify` or `/settle` suffix. Never add any other path segment. The selected facilitator URL is included in the signed requirement. Ordered facilitator fallback is allowed only by issuing a fresh challenge before any settlement dispatch. The retry for a signed requirement uses exactly its selected facilitator.

On one credential retry:

1. decode the envelope, validate the echoed signed requirement and all local bindings, and hash the opaque scheme payload without pretending to perform the facilitator's cryptographic verification;
2. load the previously persisted finalized intent, reserve the proof digest, and persist the verify attempt and idempotency identity;
3. call `/verify` relative to the configured full API root;
4. require `isValid=true`; otherwise record the typed verification failure and return 402 without preparing or calling settle;
5. persist a settle attempt and idempotency identity;
6. call `/settle` relative to the same configured full API root;
7. require `success=true`, a non-empty transaction, the exact network, matching payer values when both responses include them, and the exact amount whenever the settlement response includes `amount`;
8. commit receipt and `Succeeded`;
9. allow the origin and emit the standard-base64 encoding of that exact `SettleResponse` as `PAYMENT-RESPONSE`.

Wrap both provider calls in one `tokio::time::timeout` whose configured maximum is 2,000 ms. Bound each response body to 64 KiB.

- [ ] **Step 5: Implement conservative reconciliation**

x402 v2 in this release has no assumed public status or reorg endpoint. `query_attempt` returns `ProviderQueryResult::Unsupported` for an ambiguous settle, leaving it in `NeedsReconciliation`. Do not retry the settle automatically. A future status or reorg API can be added only as a separately configured, versioned extension with its own contract fixture.

- [ ] **Step 6: Verify and commit**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features x402 --test x402_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-core --features payments,payment-x402 --test payment_settlement x402
```

Expected: PASS.

Commit:

```bash
git add crates/sbproxy-billing crates/sbproxy-core
git commit -m "feat: settle x402 before origin access"
```

### Task 7: Implement Stripe PaymentIntent settlement and separate Meter reporting

**Files:**

- Create: `crates/sbproxy-billing/src/{stripe_payment,stripe_meter}.rs`
- Create: `crates/sbproxy-billing/tests/stripe_payment_contract.rs`
- Create: `crates/sbproxy-billing/tests/stripe_meter_contract.rs`
- Create: `crates/sbproxy-billing/tests/fixtures/stripe/*.json`
- Modify: `crates/sbproxy-core/src/billing_runtime.rs`
- Modify: `crates/sbproxy-core/tests/payment_settlement.rs`

**Dependencies:** Tasks 1 through 5. It can run in parallel with Task 6.

**Produces:** `StripePaymentIntentSettler`, `StripeMeterReporter`, Stripe status reconciliation, and no Meter Event settlement path.

- [ ] **Step 1: Write failing Stripe version and request tests**

Every fixture request must contain `Stripe-Version: 2026-06-24.dahlia`. Reject runtime config with any other value.

For all PaymentIntent modes, assert exact amount, lowercase currency, server-owned metadata, quote ID, challenge ID, platform account context, absence of a `Stripe-Account` header, and the persisted Stripe idempotency key. Direct mode binds `sbproxy_requirement_draft_digest`; Payment Auth mode, whose PaymentIntent is created after the challenge is final, binds `sbproxy_requirement_digest`. Assert no client-provided metadata can override either digest, `sbproxy_quote_id`, `sbproxy_challenge_id`, tenant routing, account context, amount, or currency.

- [ ] **Step 2: Write failing direct PaymentIntent challenge tests**

The direct Stripe rail follows this safe flow:

1. persist the challenge intent and `PrepareChallenge` idempotency key;
2. mark dispatch before creating a PaymentIntent;
3. create it with exact amount and currency, `capture_method=manual`, `confirmation_method=automatic`, `confirm=false`, the configured `payment_method_types[]`, and binding metadata; do not also send `automatic_payment_methods`, because Stripe treats the two selectors as alternatives;
4. return `RailChallenge::Stripe` with its ID, client secret, signed quote token, and `retry_header: "Crawler-Payment"` in the immediate TLS-protected 402, while persisting only the ID;
5. the client completes confirmation with Stripe and retries with `Crawler-Payment: <quote_token>`; the signed token binds the PaymentIntent ID and no client-supplied ID is accepted;
6. the server retrieves the PaymentIntent;
7. if status is `requires_capture`, the server persists a capture attempt and captures with its own idempotency key;
8. retrieve again and require `status=succeeded`, exact amount, `amount_received`, currency, metadata, and account context;
9. commit `Succeeded` before access.

Test that repeating challenge preparation with the same request idempotency key retrieves and reissues the same PaymentIntent challenge without creating another object. Test that a missing or different quote token, `requires_action`, `requires_payment_method`, `processing`, `canceled`, amount mismatch, currency mismatch, metadata mismatch, wrong account, and a different stored `pi_` ID all deny access. Test that client secrets never enter SQLite, logs, errors, or metrics. Direct mode does not emit `Payment-Receipt`, because that header belongs to the Payment Auth flow; it returns the existing paid crawl correlation only after `Succeeded`.

- [ ] **Step 3: Write failing Payment Auth Stripe charge tests**

Implement `draft-stripe-charge-00` separately from direct mode:

- the challenge request has exact `amount`, lowercase `currency`, `externalId`, `methodDetails.networkId`, `methodDetails.paymentMethodTypes`, and server-owned metadata;
- the client completes any Stripe.js authentication needed to issue the SPT before retry; the server, not the client, creates and confirms the PaymentIntent for this mode;
- the credential echoes the complete challenge and carries one `spt`;
- before the Stripe write, persist idempotency derived from challenge ID and the SPT digest, never the raw SPT in an idempotency key, log, error, or plaintext column;
- create a PaymentIntent using `shared_payment_granted_token`, `confirm=true`, `automatic_payment_methods[enabled]=true`, and `automatic_payment_methods[allow_redirects]=never`;
- retrieve or inspect the result and require `succeeded`;
- any additional action returns 402 with a fresh challenge and no receipt;
- successful receipt reference is the PaymentIntent ID.

The server never reports success merely because Stripe accepted the request.

- [ ] **Step 4: Write the ambiguous-write and query tests**

Simulate a connection loss after PaymentIntent create or capture. Assert `NeedsReconciliation`, no new create or capture attempt, and no access. If create returned no ID, `query_attempt` may recover the original response only by replaying the byte-equivalent create with the same persisted Stripe idempotency key while the attempt is younger than the configured recovery age, which can never exceed 23 hours, then retrieve that ID. At the configured age or older it remains unresolved. If an ID is known, it retrieves directly. Capture reconciliation retrieves the known PaymentIntent and never captures again until retrieval proves no capture occurred. It may commit success only after verifying all bound fields and `succeeded`. A definite pre-dispatch failure may retry with the same key. A post-dispatch unresolved result cannot use a new key or changed parameters.

For the no-ID create case, inspect the SQLite file and all captured logs to prove the SPT and form body do not appear in plaintext. Restart with the same recovery key and prove the exact decrypted bytes and same idempotency key recover one original PaymentIntent. Then cover a wrong key ID, modified AAD, modified ciphertext, changed replay body, and an expired envelope; each stays `NeedsReconciliation`, makes no new-key request, and emits no secret.

- [ ] **Step 5: Write failing Meter Event separation tests**

`StripeMeterReporter` sends `POST /v1/billing/meter_events` with configured event name, integer value, `payload[stripe_customer_id]`, timestamp, and stable `identifier`. Test 429 and 5xx retry, duplicate identifier suppression, and bounded response handling.

Assert:

- it implements `UsageReporter`, not `PaymentMethodAdapter`;
- reporting a Meter Event creates no settlement intent or `SettlementReceipt`;
- a successful Meter Event cannot authorize a request;
- PaymentIntent settlement never calls `/v1/billing/meter_events`;
- no request contains the retired Usage Records endpoint.

- [ ] **Step 6: Run the failing tests**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features mpp,stripe --test stripe_payment_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features stripe --test stripe_meter_contract
```

Expected: FAIL because the adapters do not exist.

- [ ] **Step 7: Implement the two separate components**

Use one bounded, redacting Stripe HTTP client but separate modules, traits, tables, metrics, and error enums. All POSTs use a previously persisted idempotency key. Construct the final form body, encrypt and persist its recovery envelope, and commit that transaction before `DispatchContext` stamps the dispatch and polls the HTTP future. Retrieval is the authoritative status query. The direct rail supports only manual capture. Payment Auth follows `draft-stripe-charge-00` and requires immediate `succeeded`. Do not treat webhook delivery as the request's authorization signal; webhooks may accelerate reconciliation only after signature verification.

- [ ] **Step 8: Verify and commit**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features mpp,stripe --test stripe_payment_contract --test stripe_meter_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-core --features payments,payment-mpp,payment-stripe --test payment_settlement stripe
```

Expected: PASS.

Commit:

```bash
git add crates/sbproxy-billing crates/sbproxy-core
git commit -m "feat: add authoritative Stripe settlement"
```

### Task 8: Implement CLN and deterministic LND adapters

**Files:**

- Modify: `crates/sbproxy-billing/Cargo.toml`
- Create: `crates/sbproxy-billing/build.rs`
- Create: `crates/sbproxy-billing/proto/lnd/v0.20.1-beta/lnrpc/lightning.proto`
- Create: `crates/sbproxy-billing/proto/lnd/v0.20.1-beta/lnrpc/routerrpc/router.proto`
- Create: `crates/sbproxy-billing/proto/lnd/v0.20.1-beta/LICENSE`
- Create: `crates/sbproxy-billing/src/lightning/{mod,cln,lnd}.rs`
- Create: `crates/sbproxy-billing/tests/{cln_contract,lnd_contract}.rs`
- Modify: `crates/sbproxy-core/src/billing_runtime.rs`
- Modify: `crates/sbproxy-core/tests/payment_settlement.rs`
- Modify: `NOTICE`

**Dependencies:** Tasks 1 through 5. It can run in parallel with Tasks 6 and 7.

**Produces:** CLN and LND adapters with authoritative invoice queries and reproducible generated clients.

- [ ] **Step 1: Vendor the exact minimal LND source set**

Copy, byte for byte, from commit `848b72ce96eb68fa90fd4336523ca4c59bddcd4c`:

- `lnrpc/lightning.proto`
- `lnrpc/routerrpc/router.proto`
- repository `LICENSE`

`router.proto` imports only `lightning.proto`; `lightning.proto` has no protobuf import. Do not vendor other RPC packages or historical generated Rust. Record repository, tag, full commit, source paths, retrieval date, and MIT license in `NOTICE`.

- [ ] **Step 2: Add deterministic protobuf generation**

Add build dependencies:

```toml
[build-dependencies]
tonic-build = { workspace = true, optional = true }
protoc-bin-vendored = { workspace = true, optional = true }
```

Use two `main` functions guarded by `#[cfg(feature = "lightning-lnd")]` and its negation so the build script compiles without activating either optional build dependency when the feature is disabled. The disabled function emits rerun directives only. The enabled function obtains the vendored `protoc` path, sets `PROTOC` for the build process, and invokes `tonic_build::configure().build_client(true).build_server(true)` for the two files with include root `proto/lnd/v0.20.1-beta/lnrpc`. Emit rerun directives for both protos and the vendored license. The generated server traits are required by local tests. The checked source plus controlled compiler is the reproducibility boundary; do not check generated `OUT_DIR` files into Git.

- [ ] **Step 3: Write failing CLN version and recovery tests**

Use a newline-delimited Unix JSON-RPC fixture. On startup, the adapter calls `getinfo`, parses an optional leading `v`, and rejects any version below `26.06` before registering the rail. Cover malformed and missing version values.

For invoice acceptance:

- create an invoice with a label derived from durable intent ID;
- retry queries `listinvoices` with that exact label;
- only documented `status="paid"` authorizes;
- `unpaid`, `expired`, missing, duplicate-label ambiguity, malformed result, and timeout deny.

For outgoing operations, assert `xpay` receives the durable label on v26.06 or newer and `xkeysend` persists its payment hash before dispatch. A crash after dispatch reconciles through documented labeled invoice or payment query behavior and never sends a second payment blindly.

- [ ] **Step 4: Write failing LND service tests**

Start `tonic::transport::Server` on an ephemeral loopback listener using the generated `LightningServer` and `RouterServer`. Implement recording test services for:

- `GetInfo`
- `AddInvoice`
- `LookupInvoice`
- `SendPaymentV2`
- `TrackPaymentV2`

The production client uses TLS and `macaroon` metadata; the local test constructor uses plaintext loopback and a fixture macaroon. For `AddInvoice`, generate a random 32-byte preimage in a zeroizing buffer, compute and persist its payment hash on the `PrepareChallenge` attempt before dispatch, pass the preimage to LND, and zeroize it after the call. A two-handle crash after LND records the invoice but before SBProxy records the response must query `LookupInvoice` with that already persisted hash and must not call `AddInvoice` again. If the dispatch stamp exists but lookup proves the hash is absent, a later challenge-preparation attempt may safely generate a new preimage.

Assert only `InvoiceState::Settled` and `PaymentStatus::Succeeded` authorize. Stream end, disconnect, duplicate update, `InFlight`, `Failed`, amount mismatch, payment-hash mismatch, and deadline expiry deny access or enter reconciliation. Test that `TrackPaymentV2` resolves a dispatched ambiguous send without calling `SendPaymentV2` again.

- [ ] **Step 5: Run the failing tests**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features lightning-cln --test cln_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features lightning-lnd --test lnd_contract
```

Expected: FAIL because the adapters and generated modules do not exist.

- [ ] **Step 6: Implement CLN with v26.06 startup health**

Require an absolute Unix socket path and bounded request and response sizes. If configured, add the rune only to the JSON-RPC request and redact it everywhere else. Register the adapter only after `getinfo` proves v26.06 or newer. Use unique durable labels for `invoice` and `xpay`. Reconciliation for incoming access uses `listinvoices { label }` and its exact documented status. Never infer payment from an RPC transport success.

- [ ] **Step 7: Implement LND with bounded TLS gRPC**

Load the configured certificate and macaroon through existing secret and file boundaries, attach the macaroon only as metadata, and cap all unary and streaming operations by the shared 2-second authorization deadline. For incoming payment, supply a locally generated preimage to `AddInvoice`, persist its hash on the attempt before the dispatch stamp, and use `LookupInvoice` on retry or recovery. Never persist or log the plaintext preimage. For outbound payment, decode and validate the BOLT11 invoice, persist its hash before `SendPaymentV2`, and use `TrackPaymentV2` after ambiguity. Do not require a system `protoc`.

- [ ] **Step 8: Verify and commit**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features lightning-cln --test cln_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features lightning-lnd --test lnd_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-core --features payments,payment-lightning-cln,payment-lightning-lnd --test payment_settlement lightning
```

Expected: PASS.

Commit:

```bash
git add crates/sbproxy-billing crates/sbproxy-core NOTICE
git commit -m "feat: add pinned Lightning settlement"
```

### Task 9: Wire lifecycle, reconciliation, and observability

**Files:**

- Modify: `crates/sbproxy-core/src/{billing_runtime,pipeline,admin}.rs`
- Modify: `crates/sbproxy-core/src/server/lifecycle.rs`
- Modify: `crates/sbproxy-observe/src/{telemetry,access_log}.rs`
- Modify: `crates/sbproxy-core/tests/payment_settlement.rs`
- Create: `crates/sbproxy-billing/tests/reconciliation.rs`

**Dependencies:** Tasks 1 through 8.

**Produces:** safe startup and reload, recovery status, provider-backed reconciliation, and closed-cardinality metrics.

- [ ] **Step 1: Write failing lifecycle tests**

Assert:

- startup opens one database and starts one worker;
- CLN and provider health checks complete before pipeline publication;
- a failed reload keeps the old runtime intact;
- a successful reload publishes the new runtime before draining the old worker;
- shutdown stops new claims and waits only the configured finite duration;
- an expired dispatched attempt is never returned to normal settlement;
- x402 unsupported query remains `NeedsReconciliation`;
- Stripe, CLN, and LND query only through their documented status surface;
- no reconciliation result authorizes the already failed request; a later retry observes `Succeeded`.

- [ ] **Step 2: Write failing privacy and metric tests**

Use closed labels:

- `rail`
- `operation`
- `outcome`
- `provider_class`

Allowed outcomes are `succeeded`, `terminal`, `retry_wait`, and `needs_reconciliation`. Assert no quote ID, challenge ID, tenant ID, address, provider reference, PaymentIntent ID, invoice, SPT, credential, client secret, macaroon, rune, error detail, or usage customer ID appears as a metric label.

Access logs may contain rail plus a one-way receipt correlation digest. They must not contain sensitive headers or provider bodies.

- [ ] **Step 3: Run the failing tests**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime --test reconciliation
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-core --no-default-features --features payments,payment-mpp,payment-stripe,payment-x402,payment-lightning-cln,payment-lightning-lnd --test payment_settlement lifecycle
```

Expected: FAIL because final lifecycle and observability behavior is absent.

- [ ] **Step 4: Build and publish a complete candidate runtime**

Resolve secrets, open and migrate SQLite, create configured adapters and reporters, run startup health checks, and start the worker before publishing a candidate. Validation-only construction performs none of these effects. On reload, retain the old runtime until the candidate is fully healthy.

- [ ] **Step 5: Add bounded administrative status and reconciliation**

Expose authenticated status counts by state, age, and rail, plus an explicit reconciliation trigger. It invokes `query_attempt` only. It cannot mark arbitrary attempts successful and does not add a generic "force success" endpoint. Return typed `unsupported` for x402 attempts lacking a versioned query extension.

- [ ] **Step 6: Verify and commit**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime --test reconciliation
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-core --no-default-features --features payments,payment-mpp,payment-stripe,payment-x402,payment-lightning-cln,payment-lightning-lnd --test payment_settlement
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo clippy -p sbproxy-billing --all-features --tests -- -D warnings
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo clippy -p sbproxy-core --no-default-features --features payments,payment-mpp,payment-stripe,payment-x402,payment-lightning-cln,payment-lightning-lnd --tests -- -D warnings
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo clippy -p sbproxy-observe --tests -- -D warnings
```

Expected: PASS.

Commit:

```bash
git add crates/sbproxy-billing crates/sbproxy-core crates/sbproxy-observe
git commit -m "feat: operate payment reconciliation safely"
```

### Task 10: Replace payment examples and record a deterministic VHS walkthrough

**Files:**

- Modify: `examples/rail-x402-base-sepolia/{README.md,sb.yml,sb-testnet.yml,docker-compose.yml,mock-x402-facilitator/default.conf,smoke.json,bin/sign-x402.sh,Makefile}`
- Modify: `examples/rail-mpp-stripe-test/{README.md,sb.yml,docker-compose.yml,smoke.json,wiremock-stripe/mappings/*.json,Makefile}`
- Create: additional `examples/rail-mpp-stripe-test/wiremock-stripe/mappings/{payment_intents_retrieve,payment_intents_capture,meter_events}.json`
- Modify: `examples/rail-lightning/{README.md,sb.yml,smoke.json}`
- Create: `examples/rail-lightning/{docker-compose.yml,cln-mock/Dockerfile,cln-mock/server.py,tests/smoke.sh}`
- Modify: `examples/multi-rail-accept-payment/{README.md,sb.yml,docker-compose.yml,smoke.json,mock-origin/default.conf,Makefile}`
- Modify: `crates/sbproxy-config/tests/validate_examples.rs`
- Create: `scripts/test-fixtures/payments/{x402,mpp,stripe,lightning,multi-rail}.sh`
- Create: `docs/tapes/payment-settlement.tape`
- Create: `docs/assets/payment-settlement.gif`
- Modify: `scripts/record-tapes.sh`

**Dependencies:** Tasks 4 through 9.

**Produces:** four validated examples, five deterministic smoke tests, and one reproducible recording.

- [ ] **Step 1: Write failing smoke tests**

Each test uses a `mktemp -d` state directory, traps cleanup, uses only local fixtures, and checks:

- x402: the configured full API root plus `/verify`, then the same root plus `/settle`, no origin before settle, replay rejected, and no status endpoint;
- MPP: repeated Payment challenges, exact Stripe charge credential, synchronous PaymentIntent success, one receipt;
- direct Stripe: manual-capture PaymentIntent, confirmed retry, capture, retrieve, then access;
- Lightning: labeled invoice, unpaid denial, paid success, recovery lookup;
- multi-rail: same-currency x402, MPP Stripe, and direct Stripe preference order, selected credential only, unsupported preference response, and a validation failure when a BTC Lightning rail is mixed into that USD route without an explicit separately priced route.

Every fixture records redacted operation names and call counts. It must fail if logs contain `sk_`, `spt_`, `client_secret`, `Authorization: Payment`, macaroon, rune, or an unredacted credential.

- [ ] **Step 2: Run one test to prove the old example fails**

Run:

```bash
bash scripts/test-fixtures/payments/x402.sh
```

Expected: FAIL because the current example does not implement authoritative v2 settlement.

- [ ] **Step 3: Rewrite x402 and Stripe examples**

The x402 fixture exposes only the two endpoints formed from its configured full API root plus `/verify` and `/settle`. It keeps the pinned v2 wire shapes. Its testnet YAML is manual, credential-free, and does not claim CI spends funds.

The MPP Stripe fixture implements `draft-stripe-charge-00` and the pinned stable Stripe wire shape. The direct Stripe sub-example demonstrates challenge creation, client confirmation simulation, manual capture, and final retrieval. Clearly distinguish PaymentIntent settlement from Meter Event usage reporting.

- [ ] **Step 4: Rewrite Lightning and multi-method examples**

The CLN fixture implements `getinfo`, `invoice`, `listinvoices`, `xpay`, and `xkeysend` with v26.06 semantics. Document LND as a peer backend and show its exact build feature and config.

Update `Accept-Payment` examples to method and intent preferences only. Do not put proof material in `Accept-Payment`.

- [ ] **Step 5: Validate every config without side effects**

Add structurally valid dummy environment names through the existing example test helper. Config compilation must not open SQLite, resolve a real secret, or contact a provider. Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-config --test validate_examples every_oss_example_compiles
```

Expected: PASS.

- [ ] **Step 6: Add the VHS tape through the existing recording system**

Register `docs/tapes/payment-settlement.tape` in `scripts/record-tapes.sh`. The tape starts deterministic fixtures, shows the initial 402, shows a failed pending retry, completes settlement, shows the successful origin response and receipt, and shows replay denial. It uses no live keys and fits the existing terminal dimensions and timing conventions.

Generate:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo build -p sbproxy --release --no-default-features --features payments,payment-mpp,payment-stripe,payment-x402,payment-lightning-cln
SBPROXY_BIN=/Users/rick/projects/soapbucket/sbproxy/target/release/sbproxy SBPROXY_DEMO_ENV=/dev/null scripts/record-tapes.sh docs/tapes/payment-settlement.tape
```

Confirm the output path is `docs/assets/payment-settlement.gif`, the GIF is non-empty and below 5 MiB after the repository's normal optimization step, and its checked-in tape command output matches the current config and headers. `SBPROXY_DEMO_ENV=/dev/null` is required so the recording cannot load `/Users/rick/projects/soapbucket/test/.env`.

- [ ] **Step 7: Run all example checks and commit**

Run:

```bash
bash scripts/test-fixtures/payments/x402.sh
bash scripts/test-fixtures/payments/mpp.sh
bash scripts/test-fixtures/payments/stripe.sh
bash scripts/test-fixtures/payments/lightning.sh
bash scripts/test-fixtures/payments/multi-rail.sh
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-config --test validate_examples every_oss_example_compiles
```

Expected: PASS. If Docker is unavailable, run each fixture's parser and contract unit test and report the environment limitation. Do not replace it with live-provider testing.

Commit:

```bash
git add examples/rail-x402-base-sepolia examples/rail-mpp-stripe-test examples/rail-lightning examples/multi-rail-accept-payment scripts/test-fixtures/payments docs/tapes/payment-settlement.tape docs/assets/payment-settlement.gif scripts/record-tapes.sh crates/sbproxy-config/tests/validate_examples.rs
git commit -m "docs: add runnable payment settlement examples"
```

### Task 11: Consolidate payment documentation around the authoritative flow

**Files:**

- Modify: `docs/402-challenge.md`
- Modify: `docs/ai-crawl-control.md`
- Create: `docs/payment-settlement.md`
- Modify: `docs/{README.md,configuration.md,llms.txt,llms-full.txt}` only through their established source or generation command
- Modify: `examples/README.md`
- Modify: current linked payment pages found by the accuracy scans below

**Dependencies:** Tasks 4 through 10.

**Produces:** one concise operator guide, accurate protocol pages, and no active stale edition or settlement claims.

- [ ] **Step 1: Use the `personal-voice` skill for public prose**

Read the installed `personal-voice` skill and its full `references/ai-tells.md` catalog before editing public documentation. Run edit mode over every substantial page and example README touched by this task. Preserve protocol keywords, config keys, command lines, and wire fixtures exactly, while making the surrounding prose direct enough for a user learning these concepts for the first time.

Use the skill's minimum-effective-edit rule on existing prose. Audit the top six tells, remove every em and en dash, vary sentence rhythm without adding marketing language, and run the final read-aloud and scoring pass. Record each page's before and after AI-smell score in the task or PR verification notes, not in the published docs. Treat voice and stance as not applicable for purely functional reference pages and score those pages out of 80, as the skill specifies.

- [ ] **Step 2: Establish an accuracy checklist**

The docs must say:

- all current payment functionality is OSS and opt-in;
- payment negotiation, payment authorization, provider settlement, origin delivery, and usage reporting are different phases;
- access is allowed only after durable authoritative settlement;
- x402 supports v2 `exact`, with synchronous verify and settle;
- Payment Auth is pinned to draft-01 and Stripe charge draft-00;
- Stripe PaymentIntents settle payment, while Stripe Meter Events report usage and do not settle;
- CLN and LND are alternative Lightning backends;
- CLN xpay mode requires v26.06 or newer;
- ambiguous writes require provider-backed reconciliation;
- no undocumented x402 status or reorg API is used;
- no wallet, ACP, AP2, Phoenixd, revenue analytics, or merchant-of-record feature ships here.

- [ ] **Step 3: Rewrite the 402 and crawl-control references**

Explain the flow in user order:

1. the route computes a price;
2. SBProxy constructs and signs one normalized requirement;
3. the client selects a method and intent;
4. SBProxy returns a protocol challenge;
5. the client fulfills it and retries with the protocol credential;
6. SBProxy verifies and settles synchronously;
7. SQLite records success;
8. only then does the origin receive the request.

Document `Accept-Payment` as method and intent preference only. Show separate `WWW-Authenticate` fields, one `Authorization: Payment` credential, Problem Details errors, cache controls, body digest binding, receipt encoding, direct Stripe mode, x402 headers, and legacy `Crawler-Payment` compatibility without conflating them.

- [ ] **Step 4: Create the concise settlement guide**

`docs/payment-settlement.md` includes:

- a concepts section for requirement, challenge, credential, intent, attempt, settlement, receipt, usage report, and reconciliation;
- when to use x402, MPP Stripe, direct Stripe, CLN, and LND;
- a field-by-field walkthrough of the validated YAML from Task 4;
- the exact feature table;
- startup and health checks;
- durable state and backup guidance;
- timeout, breaker, retry, and crash behavior;
- safe secret reference examples;
- local example commands and the VHS recording;
- operational metrics and status;
- exact unsupported boundaries.

Link to example YAML rather than copying divergent full configurations.

- [ ] **Step 5: Remove stale claims and regenerate indexes**

Locate the documented generation command before changing `llms.txt`, `llms-full.txt`, or example indexes. Regenerate them from source. Remove active claims about enterprise-only settlement, fake PaymentIntent IDs, Meter Events as settlement, x402 status or reorg endpoints, or worker settlement before access.

- [ ] **Step 6: Run narrow documentation checks**

Run:

```bash
rg -n -i 'sbproxy-enterprise|enterprise.*settlement|settlement.*enterprise|lightning-phoenixd|pi_pending|usage records|meter events.*settle|settle.*meter events' docs examples README.md --glob '!docs/superpowers/**'
rg -n '/status|/reorg|/verify|/settle' docs examples --glob '!docs/superpowers/**'
scripts/check-spec-citations.sh docs
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-config --test validate_examples every_oss_example_compiles
```

Expected: no stale active claims; every x402 endpoint is derived by appending only `/verify` or `/settle` to its documented configured API root; docs and example links resolve.

- [ ] **Step 7: Commit**

```bash
git add -u docs examples/README.md
git add docs/payment-settlement.md
git commit -m "docs: explain authoritative OSS settlement"
```

### Task 12: Run the selective PR gate and prepare the standalone PR

**Files:** Modify only files needed to correct failures found by this gate.

**Dependencies:** Tasks 1 through 11.

**Produces:** one reviewable payment settlement branch and PR.

- [ ] **Step 1: Confirm scope, provenance, and generated inputs**

Run:

```bash
git status --short
git diff --check origin/main...HEAD
git log --oneline origin/main..HEAD
rg -n -i 'sbproxy-enterprise|enterprise.*settlement|phoenixd|\bACP\b|\bAP2\b|usage records|pi_pending' --glob '!docs/superpowers/**' --glob '!target/**' .
rg -n '895f3505a6c0beb767555344cb97130c3da7c8b2|848b72ce96eb68fa90fd4336523ca4c59bddcd4c|2026-06-24\.dahlia|draft-ryan-httpauth-payment-01|draft-stripe-charge-00' crates docs examples NOTICE
```

Expected: payment implementation, focused docs, examples, generated schema or indexes, one tape and GIF, and LND provenance only. Do not stage the unrelated RAG or distributed semantic-cache plan.

- [ ] **Step 2: Run formatting and focused static checks**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo fmt --check
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo clippy -p sbproxy-billing --tests --all-features -- -D warnings
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo clippy -p sbproxy-config --tests -- -D warnings
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo clippy -p sbproxy-modules --tests --features payments,payment-mpp -- -D warnings
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo clippy -p sbproxy-core --tests --no-default-features --features payments,payment-mpp,payment-stripe,payment-x402,payment-lightning-cln,payment-lightning-lnd -- -D warnings
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo clippy -p sbproxy-observe --tests -- -D warnings
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo check -p sbproxy --no-default-features --features payments,payment-mpp,payment-stripe,payment-x402,payment-lightning-cln,payment-lightning-lnd
```

Expected: PASS. The only all-feature command is the focused billing crate; every existing package uses explicit payment features. If unrelated code fails before compiling payment code, record the unrelated failure in the PR and do not expand scope.

- [ ] **Step 3: Run the focused behavioral gate**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --all-features
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-modules ai_crawl
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-core --no-default-features --features payments,payment-mpp,payment-stripe,payment-x402,payment-lightning-cln,payment-lightning-lnd --test payment_settlement
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-config --test payments_config --test validate_examples
scripts/check-config-schema.sh
```

Expected: PASS. Do not run the full workspace suite.

- [ ] **Step 4: Re-run the high-risk matrix individually**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime,recovery-crypto --test dispatch_crash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime --test authorization_state
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime,mpp --test payment_auth_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features x402 --test x402_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features mpp,stripe --test stripe_payment_contract --test stripe_meter_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features lightning-cln --test cln_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features lightning-lnd --test lnd_contract
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target cargo test -p sbproxy-billing --features runtime --test reconciliation
```

Expected: PASS.

- [ ] **Step 5: Manually audit the release invariant**

Inspect the migration and request pipeline and confirm:

- provider idempotency exists before dispatch;
- `dispatch_started_at_ms` commits before every network write;
- dispatched unresolved attempts cannot enter ordinary retry;
- x402 verify and settle share the 2-second bound;
- Stripe Meter Events cannot create settlement receipts;
- CLN startup rejects versions below v26.06;
- LND build does not use system `protoc`;
- `Pending`, `Processing`, `RetryWait`, `NeedsReconciliation`, and `Terminal` cannot call the origin or emit a receipt;
- only `Succeeded` can do both.

- [ ] **Step 6: Stage exact roots and open the PR**

Stage only reviewed payment roots:

```bash
git add Cargo.toml Cargo.lock crates/sbproxy-billing crates/sbproxy-config crates/sbproxy-modules crates/sbproxy-core crates/sbproxy-observe crates/sbproxy schemas/sb-config.schema.json examples/rail-x402-base-sepolia examples/rail-mpp-stripe-test examples/rail-lightning examples/multi-rail-accept-payment examples/README.md scripts/test-fixtures/payments scripts/record-tapes.sh docs/tapes/payment-settlement.tape docs/assets/payment-settlement.gif docs/402-challenge.md docs/ai-crawl-control.md docs/payment-settlement.md
git add -u NOTICE docs/README.md docs/configuration.md docs/llms.txt docs/llms-full.txt
git status --short
git commit -m "fix: harden payment settlement release"
git push -u origin rickcrawford/oss-payment-settlement
```

Create the PR:

```bash
gh pr create --base main --head rickcrawford/oss-payment-settlement --title "feat: add authoritative OSS payment settlement" --body "## Summary
- Adds durable OSS settlement for x402 v2, Payment Auth Stripe charge, direct Stripe PaymentIntents, CLN, and LND.
- Allows origin access only after authoritative settlement is durably Succeeded.
- Separates Stripe Meter Event usage reporting from settlement.
- Replaces payment examples and documents the full challenge, credential, settlement, receipt, and reconciliation flow.

## Contract pins
- Payment Auth draft-ryan-httpauth-payment-01
- Stripe charge draft-stripe-charge-00
- Stripe API 2026-06-24.dahlia
- x402 revision 895f3505a6c0beb767555344cb97130c3da7c8b2
- CLN v26.06 minimum
- LND v0.20.1-beta at 848b72ce96eb68fa90fd4336523ca4c59bddcd4c

## Verification
- Focused format, clippy, feature check, billing, policy, core, config, schema, example, and crash tests from the implementation plan

## Safety
- Provider idempotency is durable before dispatch.
- Dispatch start is durable before every provider write.
- Ambiguous writes require provider-backed reconciliation.
- No live key or sensitive credential is logged or committed."
```

Do not claim live-provider validation unless a secret-gated job actually ran and its logs were checked for redaction.

## Dependency graph

```text
Task 1 domain
  |-- Task 2 store and dispatch
  |     `-- Task 3 service and worker
  |-- Task 4 config and signed requirement
  |
  `-- Tasks 2, 3, and 4 complete
          `-- Task 5 Payment Auth and origin gating
                  |-- Task 6 x402
                  |-- Task 7 Stripe
                  `-- Task 8 Lightning
                          `-- Task 9 lifecycle and reconciliation
                                  `-- Task 10 examples and VHS
                                          `-- Task 11 docs
                                                  `-- Task 12 PR gate
```

Tasks 6, 7, and 8 are independent after Task 5 and should be assigned to separate worktree agents. They touch the shared runtime registration files, so each provider commit should be cherry-picked into the integration worktree one at a time with focused conflict review.

## Final acceptance matrix

| Requirement | Primary task | Required proof |
| --- | --- | --- |
| No access or receipt before authoritative success | Tasks 3 and 5 | State matrix plus recording-origin integration tests |
| Durable idempotency and dispatch start | Task 2 | Two-handle crash after provider dispatch |
| x402 verify plus settle under 2 seconds | Task 6 | Timeout, breaker, and no-origin tests |
| Exact Payment Auth draft-01 bytes | Task 5 | Fixed request, HMAC, credential, receipt, and malformed encoding fixtures |
| Real Stripe PaymentIntent settlement | Task 7 | Create or retrieve, confirm or capture, final `succeeded`, exact field checks |
| Meter Events are reporting only | Task 7 | Trait separation and no-receipt tests |
| One signed normalized requirement | Task 4 | Config mismatch and cross-adapter tests |
| Exact x402 URL joins, no guessed status | Task 6 | URL table and unsupported reconciliation test |
| CLN v26.06 and label recovery | Task 8 | Startup rejection and `listinvoices` label/status tests |
| Deterministic pinned LND proto | Task 8 | Vendored source provenance and local generated-server tests |
| Runnable examples and recording | Task 10 | Five smoke tests and generated GIF |
| Accurate concise OSS docs | Task 11 | Accuracy checklist, stale-claim scan, citations, and config validation |
| Selective green PR gate | Task 12 | Recorded command results in PR |

## Self-review

### Type consistency

`AdvertisedRail` describes what the client selects. `PaymentProtocol` describes the wire presentation. `SettlementRail` selects exactly one provider adapter. MPP is a presentation protocol, not a settler. Stripe PaymentIntents are settlement; Stripe Meter Events are reporting. `SignedPaymentRequirement` is the only value that crosses policy configuration, quote signing, credential validation, and provider binding.

### Failure consistency

All tasks use the same rule: a provider response and a durable success transaction are both required. Verification alone, an enqueued job, a Meter Event, a dispatched request, or a recoverable provider state never grants access. A post-dispatch ambiguity always enters `NeedsReconciliation`.

### Contract completeness

The plan pins every public contract needed for implementation. x402 status and reorg behavior are intentionally absent because the pinned public contract does not supply a generic endpoint. LND protobuf source, tag, commit, compiler, include root, services, and test server wiring are fixed. Stripe API, Payment Auth draft, method, intent, byte encoding, status checks, and idempotency behavior are fixed.

### Nonblocking maintenance notes

- A future Payment Auth draft revision requires a new fixture version and an explicit compatibility decision; it does not change this release.
- A future x402 status or reorg API must be a named versioned extension and cannot silently alter the v2 adapter.
- A future Stripe API upgrade must update the pinned header and all Stripe fixtures in one PR.
- A future LND upgrade must vendor a new versioned source directory and update `NOTICE`; it must not overwrite the v0.20.1-beta provenance.

Plan complete. Implementation starts with Task 1 and uses the dependency graph above.
