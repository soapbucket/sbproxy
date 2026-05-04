# Audit log
*Last modified: 2026-05-03*

Every state-mutating endpoint in SBproxy emits one audit envelope. The envelope is typed and append-only. This guide covers what gets audited, the schema, the `target_kind` JSON discriminator note, and the structured-log audit sink that ships with the OSS distribution.

The OSS surface emits the envelope through the structured-log audit sink so every deployment gets an audit trail. Durable persistence (Postgres, S3, hash-chained verification) lives in the commercial distribution and is out of scope for this repo.

## What is audited

Audit emission is on **writes** by default. Every mutating handler emits one envelope per call: agent registration / approval / revocation, key rotation, registry edit, policy edit, login, logout.

Reads are audited only when:

1. The read targets the audit log itself (export, verify). The auditor must be auditable.
2. The read targets secret material (key-management endpoints, even when the response redacts the secret).
3. The read is a bulk-export endpoint.

Routine reads (list agents, get balance) are not audited; they live in the access log and the request-event stream. Adding read-audit to a routine endpoint requires an ADR amendment because the cardinality cost is high.

The full read-scope policy lives in [adr-admin-action-audit.md](adr-admin-action-audit.md).

## Envelope schema

Every event is an `AdminAuditEvent`. Wire format is JSON; field order is significant only for canonical hashing.

| Field | Type | Required | Notes |
|---|---|---|---|
| `event_id` | ULID (string) | yes | Generated at emission. Lexicographically time-sortable. |
| `schema_version` | u16 | yes | Currently `0`. |
| `ts` | RFC 3339 UTC | yes | Wall-clock time at emission. |
| `tenant_id` | string | yes | `default` in OSS. |
| `subject` | tagged enum | yes | Who initiated the action. See subjects below. |
| `action` | enum | yes | What was done. Closed enum with an `Other(String)` escape hatch. |
| `target` | tagged enum | yes | What was acted on. See targets below. |
| `before` | JSON value | optional | Pre-mutation snapshot, redacted. `None` on pure-read operations. |
| `after` | JSON value | optional | Post-mutation snapshot, redacted. `None` on failed mutations. |
| `reason` | string | optional | Operator justification. Capped at 4 KiB; over-cap truncates with `...[truncated]`. Not redacted. |
| `result` | tagged enum | yes | Outcome: `Success`, `Failure { error_code, error_message }`, `Denied { reason }`. |
| `request_id` | ULID | yes | Correlation: the in-flight HTTP request. |
| `trace_id` | string (32 hex) | yes | Correlation: OTel trace id. Empty string when no trace context. |
| `span_id` | string (16 hex) | yes | Correlation: OTel span id. |
| `ip` | IpAddr | yes | Caller IP, post-trusted-proxy resolution. |
| `user_agent` | string | optional | Capped at 512 bytes. |
| `chain_position` | object | optional | Reserved for future hash-chained log support. Always `None` in OSS. |

### Subjects

```rust
pub enum AuditSubject {
    User    { user_id: String, session_id: Option<Ulid> },
    Service { principal_id: String },
    Agent   { agent_id: String, agent_class: Option<String> },
    System  { component: String },
}
```

`User` is a portal-authenticated human. `Service` is CI or internal automation. `Agent` is a registered agent acting on its own behalf. `System` is the subject of last resort and SHOULD be rare; config reload and scheduled jobs use it.

### Actions

Closed enum. Adding a new variant is an ADR amendment. The current set:

`Create`, `Update`, `Delete`, `Read`, `Approve`, `Revoke`, `RotateKey`, `Disable`, `Enable`, `Export`, `Import`, `Login`, `Logout`, `PolicyEdit`, `Other(String)`.

`Other(String)` is the escape hatch for variants not yet hoisted into the closed enum; persistent uses require an ADR amendment to add a proper variant.

### Targets

```rust
pub enum AuditTarget {
    Agent         { agent_id: String },
    RegistryEntry { feed: String, entry_id: String },
    Key           { kind: KeyKind, key_id: String },
    Policy        { policy_path: String },
    Origin        { hostname: String },
    User          { user_id: String },
    Tenant        { tenant_id: String },
    Config        { path: String },
    AuditLog,
    Other         { kind: String, id: String },
}
```

`KeyKind` is closed: `OutboundWebhook`, `RegistryFeed`, `Tls`, `Tenant`.

## JSON discriminator note: `target_kind`

`AuditTarget` serializes with an external tag named `target_kind`, **not** the serde default `kind`. The rename avoids a field collision: the `Other { kind, id }` variant carries its own `kind` field, and the default tag would silently overwrite it.

The wire format looks like this:

```json
{"target_kind": "registry_entry", "feed": "agents", "entry_id": "openai-gptbot"}
{"target_kind": "other", "kind": "rate-limit", "id": "rl_us_east_1"}
```

Verifier CLIs and replay tooling MUST read the discriminator from `target_kind`. The trailing `kind` inside the `Other` variant is opaque payload.

## Append-only contract

The storage backend MUST reject updates and deletes. The contract is enforced at the trait level:

```rust
#[async_trait::async_trait]
pub trait Emitter: Send + Sync {
    async fn emit(&self, event: AdminAuditEvent) -> Result<Ulid, AuditError>;

    async fn read_range(
        &self,
        from: chrono::DateTime<Utc>,
        to: chrono::DateTime<Utc>,
    ) -> Result<Vec<AdminAuditEvent>, AuditError>;
    // No update(), no delete(). Compile-time enforcement.
}
```

A refactor that wants to mutate prior events would have to add a method to the trait, which is an ADR-amendment-level change.

PII deletion (GDPR Article 17, CCPA right-to-delete) is handled by tombstoning, not by mutating the audit log. A separate `audit_tombstones` table records the deletion request, and the verifier CLI redacts matching subjects on read.

## Adapters

### In-memory

Used for tests. Append to a `Vec`; no removal API.

```rust
use sbproxy_audit::{InMemoryEmitter, AdminAuditEvent};
use std::sync::Arc;

let emitter = Arc::new(InMemoryEmitter::default());
emitter.emit(event).await?;
let range = emitter.read_range(from, to).await?;
```

### Structured log

The default OSS sink writes envelopes to the structured log stream so every deployment gets an audit trail. Pair it with whatever log shipper you already run.

## EmitterMiddleware

A Tower / Axum `Layer` wraps every state-mutating handler. The middleware:

1. Captures envelope context up front (`request_id`, `trace_id`, `span_id`, caller IP, User-Agent, subject).
2. Runs the handler.
3. Pulls the `AuditDescriptor` the handler attached to the response extensions (action, target, before, after, optional reason).
4. Builds the envelope, applies the length caps, redacts `before` and `after` per the internal profile, and emits.

```rust
use axum::Router;
use sbproxy_audit::{AuditLayer, EmitterArc, InMemoryEmitter};
use std::sync::Arc;

let emitter: EmitterArc = Arc::new(InMemoryEmitter::default());
let app: Router = Router::new()
    .route("/agents/:id/approve", axum::routing::post(approve_handler))
    .layer(AuditLayer::new(emitter, "tenant_42"));
```

State-mutating handlers opt in by implementing `Auditable`:

```rust
use sbproxy_audit::{
    AuditAction, AuditDescriptor, AuditTarget, Auditable,
};

impl Auditable for ApproveHandler {
    fn audit_action(&self) -> AuditAction { AuditAction::Approve }

    fn audit_target(&self, req: &axum::extract::Request) -> AuditTarget {
        AuditTarget::Agent { agent_id: extract_agent_id(req) }
    }

    fn audit_snapshot(&self, req: &axum::extract::Request) -> Option<serde_json::Value> {
        Some(snapshot_agent_state(req))
    }
}
```

A clippy lint and a CI grep ensure every mutating handler is wrapped or wears an explicit `#[allow(audit_required)]` with a comment.

### Failure handling

Audit emission failure does not fail the underlying request. The handler succeeds even if the audit append fails; the failure pages on `SLO-AUDIT-WRITE` so durable audit gets restored. The OSS sink logs and drops on emit failure.

## See also

- [adr-admin-action-audit.md](adr-admin-action-audit.md) - envelope schema and append-only contract.
- [adr-log-schema-redaction.md](adr-log-schema-redaction.md) - the redactor that runs over `before` and `after` snapshots.
- [adr-schema-versioning.md](adr-schema-versioning.md) - schema versioning policy across all SBproxy schemas.
- [observability.md](observability.md) - audit metrics (`sbproxy_audit_emit_total`), the `SLO-AUDIT-WRITE` page tier, and the audit-log Grafana dashboard.
