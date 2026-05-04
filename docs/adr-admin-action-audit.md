# ADR: Admin-action audit envelope

*Last modified: 2026-05-03*

## Status

Accepted. Every state-mutating endpoint emits an audit event using this envelope. The OSS surface ships durable persistence via the structured-log audit sink so every deployment gets an audit trail.

## Context

Auditability has to ship alongside any state-mutating endpoint: every admin or service action has to be recordable, attributable, and tamper-evidence-able. A single envelope shape and a single emission middleware avoid retrofitting later.

The envelope must satisfy three requirements that look like trade-offs but aren't:

1. **Forward compatible.** Reserved fields let downstream signed-batch and hash-chained Merkle layers attach metadata without rewriting events.
2. **Customer-verifiable.** External auditors need to verify entries without reprocessing.
3. **Stable.** New verbs and targets are added by amendment, never reshaped.

This ADR pins the envelope and the append-only contract. Storage backend, batching, and Merkle structure are independent concerns.

## Decision

### `AdminAuditEvent` envelope

A typed Rust struct in the audit module. The OSS surface emits the same envelope through the structured-log audit sink (per `adr-log-schema-redaction.md`) so every deployment gets an audit trail.

```rust
pub struct AdminAuditEvent {
    /// ULID generated at emission. Lexicographically time-sortable;
    /// gives free chronological ordering before any chain layer lands.
    pub event_id: Ulid,

    /// Schema version for forward-compat. v0 today.
    /// See adr-schema-versioning.md for negotiation rules.
    pub schema_version: u16,

    /// Unix epoch ms at emission.
    pub ts_ms: u64,

    /// Tenant scope. "default" in single-tenant deployments.
    pub tenant_id: String,

    /// Who initiated the action.
    pub subject: AuditSubject,

    /// What was done. Verb enum, exhaustive.
    pub action: AuditAction,

    /// What was acted on. Typed target.
    pub target: AuditTarget,

    /// Pre-mutation snapshot (redacted per adr-log-schema-redaction.md).
    /// JSON value; null on pure-read operations (rare, see Read scope below).
    pub before: Option<serde_json::Value>,

    /// Post-mutation snapshot (redacted). Null on failed mutations.
    pub after: Option<serde_json::Value>,

    /// Free-text justification supplied by subject. Optional.
    /// Capped at 4 KiB; over-cap truncates with a marker.
    pub reason: Option<String>,

    /// Outcome of the action.
    pub result: AuditResult,

    /// Correlation: the in-flight HTTP request that triggered this.
    pub request_id: Ulid,

    /// Correlation: OTel trace context.
    pub trace_id: String,        // 32-hex
    pub span_id: String,         // 16-hex

    /// Caller IP (post-trusted-proxy resolution; see security ADRs).
    pub ip: IpAddr,

    /// Caller User-Agent. Capped at 512 bytes; no fingerprint redaction
    /// applies (audit log is internal-sink only by default).
    pub user_agent: Option<String>,

    /// Reserved for a future hash-chained Merkle log.
    /// MUST be None today; an offline migrator backfills.
    pub chain_position: Option<ChainPosition>,
}

pub enum AuditSubject {
    /// Human user authenticated via the portal. user_id is opaque.
    User { user_id: String, session_id: Option<Ulid> },

    /// Service principal (CI, internal automation). principal_id is opaque.
    Service { principal_id: String },

    /// Registered agent acting on its own behalf.
    Agent { agent_id: String, agent_class: Option<String> },

    /// Internal system action (config reload, scheduled job).
    /// Subject of last resort; SHOULD be rare.
    System { component: String },
}

pub enum AuditAction {
    Create, Update, Delete, Read, // CRUD primitives, target carries detail
    Approve, Revoke,              // governance verbs (DCR, registry)
    RotateKey, Disable, Enable,   // operational verbs
    PolicyProjectionRefresh,      // policy-graph projection regen
    Export, Import,               // bulk-operation verbs
    Login, Logout,                // authn verbs (portal)
    PolicyEdit,                   // catch-all for sb.yml mutations
    KyaVerify,                    // KYA verification (sampled)
    Other(String),                // escape hatch; SHOULD be empty
}

pub enum AuditTarget {
    Agent { agent_id: String },
    RegistryEntry { feed: String, entry_id: String },
    Key { kind: KeyKind, key_id: String },
    Policy { policy_path: String },
    Origin { hostname: String },
    User { user_id: String },
    Tenant { tenant_id: String },
    Config { path: String },
    PolicyProjection {
        // hostname/projection_kind/config_version, e.g.
        // "shop.example.com/robots/42".
        id: String,
    },
    KyaVerification { jti: String, iss: String },
    AuditLog,                     // self-referential (export, verify)
    Other { kind: String, id: String },
}

// JSON wire format. The serde discriminator is `target_kind` (not the
// default `kind`) to avoid a field collision with the `Other` variant's
// inner `kind` member. Examples:
//   {"target_kind": "policy", "policy_path": "..."}
//   {"target_kind": "other",  "kind": "rate-limit", "id": "..."}
// Verifier CLIs and replay tooling MUST read the discriminator from
// `target_kind`. The trailing `kind` inside `Other` is opaque payload.

pub enum KeyKind {
    LedgerHmac, OutboundWebhook, RegistryFeed,
    KyaSigning, AuditBatch, Tls, Tenant,
}

pub enum AuditResult {
    Success,
    Failure { error_code: String, error_message: String },
    Denied { reason: String },     // permission denied; no mutation occurred
}

/// Reserved for a future hash-chained Merkle log. Always None today.
pub struct ChainPosition {
    pub batch_id: Ulid,
    pub position_in_batch: u32,
    pub prev_hash: [u8; 32],
    pub leaf_hash: [u8; 32],
}
```

### Append-only contract

The storage backend MUST reject updates and deletes. This is enforced at the trait level:

```rust
pub trait AuditSink: Send + Sync {
    /// Append an audit event. Returns the persisted event_id (same as input).
    /// MUST NOT modify or delete prior events.
    /// MUST be durable on return (fsync / replication ack / object-store ack).
    fn append(&self, ev: &AdminAuditEvent) -> Result<Ulid, AuditError>;

    /// Read range for verification and export. Read-only.
    fn read_range(&self, from_ts_ms: u64, to_ts_ms: u64) -> AuditStream;

    // No update(), no delete(). Compile-time enforcement.
}
```

In-memory adapter: append to a `Vec`; no removal API. Used for tests only.

PII deletion (GDPR Art. 17, CCPA right-to-delete) is handled by tombstoning, not by mutating the audit log. A separate `audit_tombstones` table records the deletion request, and the verifier CLI redacts matching subjects on read. The audit log itself stays append-only.

### Hooks into state-mutating endpoints

A single Axum middleware wraps every endpoint that mutates state. It:

1. Captures `before` by calling the endpoint's `audit_snapshot()` impl (a small trait every state-mutating handler implements).
2. Runs the handler.
3. Captures `after` from the response or from a second `audit_snapshot()` call.
4. Builds and emits the `AdminAuditEvent` with the result outcome.

Endpoints opt in by implementing `Auditable`:

```rust
pub trait Auditable {
    fn audit_action(&self) -> AuditAction;
    fn audit_target(&self, req: &Request) -> AuditTarget;
    fn audit_snapshot(&self, req: &Request) -> Option<serde_json::Value>;
}
```

A clippy lint and a CI grep ensure every mutating handler is wrapped.

### Read scope (when to emit on reads)

By default, audit events are emitted on writes only. Read events (`AuditAction::Read`) are emitted only for:

1. Reads of audit-log itself (export, verify) - always audited (the auditor must be auditable).
2. Reads of secret material (key-management endpoints, even if the response redacts the secret).
3. Bulk-export endpoints.

Routine reads (list agents, get config) are not audited; they live in the access log per `adr-log-schema-redaction.md` and the request-event stream per `adr-event-envelope.md`. Adding read-audit to a routine endpoint requires a follow-up ADR amendment; the cardinality cost is high.

### Redaction

`before` and `after` snapshots are JSON values; the redactor from `adr-log-schema-redaction.md` runs over them with the **internal** profile before persistence. The audit log is internal-sink by default; the **external** profile applies only when an audit-log export is requested.

The `reason` field is operator-controlled free text; it is NOT redacted (operators are trusted callers, and the field is the human "why I did this" record). A guardrail: `reason` MUST NOT contain raw secrets; the linter at portal-input time strips obvious patterns and flags the operator. We do not enforce this server-side; it would silently mangle legitimate justifications.

### Performance budget

Audit emission is on the hot path of every mutating request.

- Build envelope: < 5 us (one ULID gen, one IP copy, one tenant lookup).
- Redact snapshots: < 50 us at p99 for typical 1 KiB before/after pairs.
- In-memory sink: < 1 us append.

Audit emission failure does NOT fail the underlying request. It DOES page (`SLO-AUDIT-WRITE` in `adr-slo-alert-taxonomy.md`) because durable audit is required for compliance evidence. The behavior is: succeed the user-visible action, retry the audit append in the background, page if retry exhausts. This is documented in the operator runbook.

## Consequences

- One envelope, one middleware, one emission contract for every state-mutating endpoint. Zero ad-hoc audit code.
- The append-only contract is enforced at the trait level (no `update`/`delete` methods exist), so a sloppy refactor cannot accidentally introduce mutation.
- `chain_position: Option<ChainPosition>` means a hash-chained layer is a backfill, not a schema break. Customers verifying audit-log entries today will continue to verify the same events post-migration.
- The compile-time `AuditAction` enum forces every new mutation verb through ADR-amendment review. Adding a verb is a 5-minute PR, but it cannot be silently introduced; the enum exhaustiveness catches it.

## Alternatives considered

**Free-form `serde_json::Value` envelope (no typed enum for action / target).** Rejected. Free-form payloads drift; the audit log would accumulate ten variants of the same action with subtly different shapes. The typed enum forces canonicalization.

**Audit on every read.** Rejected. Read traffic dominates; auditing every read multiplies the audit-log volume by two to three orders of magnitude. The request-event stream (per `adr-event-envelope.md`) covers analytics-grade per-request observability; the audit log is for state mutations and high-sensitivity reads only.

**Separate audit log per tenant (per-stream isolation from day one).** Rejected. Single stream with `tenant_id` filter is operationally simpler and matches the SOC 2 evidence model (one log to verify).

**Pluggable audit subscribers (publish-subscribe instead of single sink).** Rejected. Audit is a strong-consistency contract; pub-sub introduces "did the subscriber persist?" ambiguity. The single `AuditSink` trait with a fan-out adapter (one `MultiSink` impl that calls N children) is sufficient and keeps the contract sharp.

## References

- Companion ADRs: `adr-log-schema-redaction.md`, `adr-schema-versioning.md`, `adr-event-envelope.md`.
- ULID spec: <https://github.com/ulid/spec>.
- SOC 2 audit-evidence requirements: AICPA TSC CC7.2.
