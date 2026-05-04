# ADR: Disaster recovery and data-retention policy

*Last modified: 2026-05-03*

## Status

Accepted. Builds on `adr-admin-action-audit.md`, `adr-log-schema-redaction.md`, `adr-schema-versioning.md`, and `adr-slo-alert-taxonomy.md` (specifically `SLO-DR-RESTORE`).

## Context

Once a deployment holds money and identity, wallet balances, agent registry, audit batches, and billing events all become recoverable artefacts that the business depends on. Without a written DR policy:

1. Each subsystem invents its own backup cadence and the operator runbook accumulates ten different restore procedures.
2. RTO and RPO targets drift from what SLO-DR-RESTORE asserts, and the monthly drill has nothing to verify against.
3. GDPR Art. 17 / CCPA right-to-delete requests get answered ad-hoc, which is exactly the failure mode that ends in a regulator letter.
4. Region-aware deployments inherit a single-region schema and we paint into a corner.

This ADR pins the data-class taxonomy, RTO/RPO per class, backup mechanics, restore drill cadence, deletion mechanics, and the region-awareness invariants that every later wave must respect.

## Decision

### Data classes

| Class | Examples | RTO target | RPO target |
|---|---|---|---|
| Wallet | balance ledger, holds, debit history | 15 min | 5 min |
| Registry | agent registry feed cache, DCR queue, verifier challenge state | 1 h | 1 h |
| Audit log v0 | signed-batch JSONL objects, Postgres index (`audit_events`) | 4 h | 0 (every batch is durable on write) |
| Access log | request-event JSON-line stream | 4 h | 5 min |
| Traces | OTel spans (Tempo / equivalent) | 24 h | 1 h |
| Billing events | RevenueEvent stream into ingest | 1 h | 5 min |

RTO is wall-clock from incident start to "service can take writes again with the affected data class." RPO is "how much of the most recent data are we permitted to lose." The wallet RPO of 5 min matches Postgres WAL archive cadence; tighter than 5 min requires synchronous replication and is out of scope.

The audit log's RPO is **zero** because durability is the contract: the signed-batch writer does not return success to the emitter until the batch is persisted to the off-site object store. If the writer cannot durably persist, the emitter retries; if retry exhausts, the operator is paged via `SLO-AUDIT-WRITE` and the event sits in the in-memory deadletter queue. We never accept "oh, we lost some audit entries to a regional outage."

### Backup mechanics

**Postgres** (wallet, audit `audit_events` index, DCR queue, registry cache):

- Logical `pg_dump --format=directory --jobs=4` every 6 h. Output is encrypted with the workspace KMS key (or operator-supplied AES-256-GCM key in self-hosted deployments) before leaving the database host.
- Continuous WAL archive via `archive_command` to the off-site object store, with a 5-minute archive timeout. This is what makes the wallet RPO achievable.
- Encrypted archives replicate to a second region's object store (S3 cross-region replication, GCS dual-region bucket, or operator-equivalent).
- Retention: 7 daily, 4 weekly, 6 monthly snapshots by default. Operators tune this via the operator runbook RB-DR-RETENTION.

**ClickHouse** (revenue rollups, ingested access log, request-event store):

- Nightly `BACKUP TABLE ... TO Disk('s3_backup', '...')` per the ClickHouse native protocol. Encrypted disk by default.
- Replication is built into the upstream cluster (ReplicatedMergeTree); the backup is the cross-region copy.
- Retention: 14 daily, 8 weekly. The revenue rollup tables are the ones that must survive a region loss; the access log is best-effort beyond 7 days.

**Object store** (audit signed-batch JSONL, traces if archived, future Merkle batches):

- Provider-native cross-region replication (S3 CRR / GCS multi-region / equivalent). Object Lock with COMPLIANCE mode for audit batches: no overwrites, no deletes inside the retention window even by the bucket owner.
- Retention: longest GDPR/CCPA window applicable to the tenant (default 7 years for audit; documented per-customer in the data-processing agreement).

**Secrets** (KMS keys, signing keys, webhook HMACs):

- Out of scope for this ADR. Defer to the existing key-management runbook and `adr-webhook-security.md`. Backup of the **encrypted** material is included in the Postgres / object-store backups above; the **wrapping** keys live in KMS and have their own provider-managed durability story.

### Restore drills

Cadence is `SLO-DR-RESTORE: succeed monthly`.

**Monthly automated drill (CI):**

1. The drill harness pulls the most recent encrypted backup of every data class into an ephemeral environment (kind / k3d cluster + scratch object-store bucket).
2. Restores Postgres and ClickHouse from the latest dump + WAL replay.
3. Pulls a representative audit signed-batch JSONL from the object store.
4. Runs the audit verifier round-trip against the restored audit data; runs the wallet round-trip (top-up + debit + reconcile) against the restored wallet state.
5. Emits a green/red signal that feeds the `SLO-DR-RESTORE` recording rule.

A red drill pages immediately; the runbook RB-DR-DRILL-FAIL covers triage.

**Quarterly manual drill:**

1. Operator simulates a full primary-region loss in a staging environment.
2. Cross-region replicas are promoted; DNS swings; the workspace is re-tested from the customer's side (synthetic agent + synthetic admin operations through the portal).
3. The drill produces a written postmortem in the operator runbook archive even when it succeeds. Surprises become inputs to the next monthly drill's checklist.

### Deletion mechanics (GDPR Art. 17 / CCPA right-to-delete)

The deletion contract:

1. **Self-service.** Workspace owners initiate deletion through the portal. The portal surfaces a typed delete form and a confirmation screen that lists the data classes that will be deleted versus tombstoned.
2. **Cascade walk by `workspace_id`.** A typed deletion job iterates every data class and applies the per-class strategy:
   - Wallet, registry, billing events: hard delete (rows removed, object-store keys deleted).
   - Audit log: tombstone, never mutate. A row in `audit_tombstones` records the deletion request; the verifier CLI redacts matching subjects on read per `adr-admin-action-audit.md` § PII deletion. The audit log itself stays append-only.
   - Access log, traces: hard delete by `workspace_id` partition (ClickHouse `ALTER TABLE ... DROP PARTITION`).
3. **Deletion is itself audited.** The portal action emits an `AdminAuditEvent` with `action: AuditAction::Delete`, `target: AuditTarget::Tenant { tenant_id }`, and a non-redacted `reason` carrying the legal basis (GDPR Art. 17, CCPA, contract termination, etc.). Customers see the audit row in their export; regulators see it in our SOC 2 evidence.
4. **30-day tombstone window.** The deletion job marks state as deleted but does not purge for 30 days. A partial restore from a backup that pre-dates the deletion will replay the deletion on first read and cannot leak deleted data. After 30 days, the purger removes tombstones and the corresponding backup-tier data ages out per the retention windows above.
5. **Crypto-shredding for object-store data.** Audit signed-batches are encrypted with a per-tenant key; the deletion job destroys the per-tenant key in KMS. The encrypted bytes can persist in immutable buckets, but they become unreadable. This is how we satisfy Object Lock + right-to-delete simultaneously.
6. **Operator override.** A regulatory hold pauses the purger for the named workspace. The hold is itself an audited admin action.

### Region awareness (forward-looking)

The default deployment is single-region. The DR design must not paint us into a single-region corner. Invariants:

- **Every backup labels its source region.** The backup metadata header carries `region: us-east-1`-equivalent. Restores that target a region different from the source must pass through an explicit operator step that checks the workspace's configured residency.
- **No global IDs that bake in region.** ULIDs, workspace IDs, agent IDs, wallet IDs are region-independent. We do **not** prefix IDs with region codes. A workspace migrating between regions keeps its IDs.
- **Per-region retention windows.** The retention table above is the global default. Per-region overrides (EU-only customers needing 5-year retention vs. US default of 7) flow through workspace metadata and the deletion job consults this metadata before purging.
- **Cross-region replication configured at the bucket / database level.** No application code assumes single region. The storage adapter trait takes an opaque region tag and adapters can refuse cross-region writes when residency demands it.
- **Wallet, registry, audit are per-region by default.** A workspace's wallet lives in one region; cross-region wallet operations are out of scope.

### What this ADR does NOT decide

- The exact PromQL recording rule for `SLO-DR-RESTORE`. This ADR pins the cadence; the rule is implementation.
- The Postgres backup tooling choice (`pg_dump` vs. `pgBackRest` vs. `wal-g`). The operator picks; the ADR pins the cadence and the encryption + replication invariants.
- Customer-facing data-export tooling.
- Cross-region active-active for wallets. Out of scope.
- Per-tenant encryption-key custody (HYOK / BYOK); this ADR's per-tenant-key-shredding requirement is forward-compatible because the key reference is already opaque.

## Consequences

- One DR policy across six data classes. The runbook collapses to one restore-drill template parameterised per class.
- The audit log RPO of zero is a real engineering constraint: the signed-batch writer must not ack until durable. We pay this in p99 emit latency (50 ms budget per `adr-admin-action-audit.md` § Performance budget).
- The 30-day tombstone window costs us up to 30 days of backup-tier storage per deleted workspace. Acceptable, and it's the only way to avoid leaking deleted data through partial restores.
- Crypto-shredding via per-tenant keys means we need per-tenant KMS keys. This is a non-trivial operational lift but it's the cleanest answer to "Object Lock + right-to-delete."
- Region-awareness invariants cost a small amount of schema discipline (no region prefixes in IDs, opaque region tag in storage adapters). The cost is now; the benefit is preserving optionality for the multi-region story.
- Monthly automated drills are CI cost (one extra job per month). Quarterly manual drills are operator time. Both are cheaper than a single failed restore.

## Alternatives considered

**Provider-native point-in-time recovery only, no logical dumps.** Rejected. PITR is excellent for same-region recovery but does not produce a portable artefact. A logical dump that we encrypt and ship cross-region is the only thing that survives a regional control-plane outage.

**Hard-delete audit on right-to-delete request.** Rejected. Hard-deleting audit log entries breaks the append-only contract from `adr-admin-action-audit.md` and breaks SOC 2 evidence integrity. Tombstoning + redact-on-read is the right answer; the audit log itself never mutates.

**Single global RPO target (e.g. 5 min for everything).** Rejected. Trace data does not need 5-minute RPO and the cost of providing it (continuous trace replication) is enormous. Per-class RPO matches each class's actual loss tolerance.

**Skip region-aware design and add it later.** Rejected. The cost of preserving optionality now (no region prefixes, opaque region tags) is hours; the cost of retrofitting is months. We pay the small tax now.

**Hot-spare in a second region (active-active wallet).** Considered. Rejected; the consistency story for active-active wallet is its own architecture problem and the wallet adapter is single-region by design.

## References

- Companion ADRs: `adr-admin-action-audit.md`, `adr-schema-versioning.md`, `adr-slo-alert-taxonomy.md`, `adr-log-schema-redaction.md`, `adr-capacity-rate-limits.md`, `adr-db-migration-policy.md`.
- Postgres WAL archive: <https://www.postgresql.org/docs/current/continuous-archiving.html>.
- ClickHouse BACKUP/RESTORE: <https://clickhouse.com/docs/en/operations/backup>.
- GDPR Art. 17 right to erasure: <https://gdpr-info.eu/art-17-gdpr/>.
- CCPA right to delete: <https://oag.ca.gov/privacy/ccpa>.
