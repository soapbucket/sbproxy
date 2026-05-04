# ADR: Database migration policy

*Last modified: 2026-05-03*

## Status

Accepted. Database-side companion to `adr-schema-versioning.md`, which explicitly excluded Postgres ALTER TABLE rules from its scope. Builds on `adr-admin-action-audit.md` (the existing append-only audit table sets the baseline) and `adr-disaster-recovery-retention.md` (restore drills must accept migrated DBs).

## Context

Multiple Postgres tables back the deployment: wallet ledger, audit log v0 index, agent registry cache, and DCR queue. Without a written migration policy:

1. Each crate invents its own migration tooling, file layout, and rollback discipline.
2. CI has nothing to gate on; a destructive ALTER TABLE merges to main and the operator finds out at deploy time.
3. The existing audit-log table grows new columns through ad-hoc ALTERs, which silently break the append-only contract.
4. Long-running migrations on hot tables block production traffic with no review process.

The schema-versioning ADR covers wire formats and explicitly punted on database schema. This ADR is the database-side counterpart. It pins the tooling, the file layout, the migration shape rules, the lifecycle gates, and the rollback discipline.

## Decision

### Tooling: `refinery`

Pick **one** migration tool and stick with it. Recommendation: `refinery` (https://crates.io/crates/refinery).

Rationale:

- Works with `tokio-postgres`, which is what the audit-log writer already uses.
- Handles non-transactional DDL (`CREATE INDEX CONCURRENTLY`, `VACUUM`) without forcing the migration into a transaction it cannot complete.
- Checksum-based mismatch detection: if a migration's content changes after it ran, refinery refuses to start. This is the only thing that prevents the "someone edited migration 003" foot-gun.
- Embeds migrations in the binary via `mod_migrations!`, so a deployed sbproxy carries its own schema. No separate migration tarball to coordinate.

`sqlx migrate` was the runner-up; rejected because it prefers a transactional DDL model that fights `CREATE INDEX CONCURRENTLY`, and it does not check sums by default.

### File layout

```
crates/<crate>/migrations/
    {NNN}_{slug}.sql            # the forward migration
    {NNN}_{slug}_revert.sql     # the reverse migration (always present)
```

`NNN` is monotonically increasing. The audit table sits at `20260430_001_audit_log_v0.sql`; the wallet schema lands at `20260501_002_wallet_ledger_v0.sql` and so on. We use `YYYYMMDD_NNN` so two parallel branches don't collide on the same number, and so the directory listing sorts by date.

Each migration file starts with the canonical header:

```sql
-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Soap Bucket LLC
--
-- <one-line summary>.
--
-- Reverse migration: <filename>_revert.sql
-- ADR reference: adr-db-migration-policy.md
-- Online safety: <"online" | "requires maintenance window">
-- Estimated runtime on prod-shape data: <duration>
```

The header is required; CI greps for it. The "Online safety" line is the gate signal for the operator: anything that says "requires maintenance window" cannot deploy on the green-build path.

### Migration shape rules (mandatory)

**Rule 1: Idempotent.** Every migration uses the safe DDL forms:

- `CREATE TABLE IF NOT EXISTS`
- `CREATE INDEX IF NOT EXISTS`
- `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
- `DROP TABLE IF EXISTS` (only in revert scripts; never in forward)

Re-running a migration on an up-to-date DB is a no-op. The audit-log v0 migration is the model: it only uses `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS` and is safe to re-run.

**Rule 2: Reversible.** Every migration ships a `_revert.sql` companion in the same PR. The revert is allowed to be "fail with a clear message" for data-loss-prone cases, but the file must exist:

```sql
-- 20260501_002_wallet_ledger_v0_revert.sql
-- This revert is destructive. It drops the wallet_ledger table and
-- all its data. Run only as part of a documented rollback procedure
-- (operator runbook RB-WALLET-ROLLBACK).
DROP TABLE IF EXISTS wallet_ledger;
```

Or for non-destructive forward migrations:

```sql
-- 20260520_005_wallet_ledger_add_currency_col_revert.sql
ALTER TABLE wallet_ledger DROP COLUMN IF EXISTS currency;
```

The revert is what the operator runbook RB-DB-ROLLBACK runs when the operator decides to roll back.

**Rule 3: Online by default.** No exclusive lock held longer than 5 seconds. Operationally:

- `CREATE INDEX` becomes `CREATE INDEX CONCURRENTLY`. Refinery's non-transactional mode (`#[refinery(no_transaction)]`) handles this.
- `ALTER TABLE ... ADD COLUMN` without a default is online in Postgres 11+. Adding a column with a default is online in Postgres 11+ for `NOT NULL DEFAULT <constant>` but requires a backfill for `DEFAULT <volatile-expression>`. In the latter case the migration adds the column with no default, and a separate backfill job populates it.
- `ALTER TABLE ... ADD CONSTRAINT ... NOT VALID` followed by `ALTER TABLE ... VALIDATE CONSTRAINT` is the online pattern for new check constraints. The migration adds the constraint as `NOT VALID`; a separate maintenance job validates it.
- `VACUUM FULL`, `CLUSTER`, and any operation that rewrites a table is **never** an online migration. These require an explicit maintenance window declared in the migration header.

If a migration cannot satisfy "5 seconds maximum lock", the header must declare `Online safety: requires maintenance window` and CI marks the PR as needing operator scheduling.

**Rule 4: No data-mutating migrations on the live path.** Backfills do not run inside the migration. The migration adds the new schema (column, index, constraint); a separate background worker job, opt-in by the operator, populates the column. This keeps the migration short and predictable.

The pattern:

1. Migration `00X` adds the new column nullable. Online. Fast.
2. Operator deploys the new code that writes both old and new columns (dual-write).
3. Background worker job `backfill-X` populates the new column for historical rows. Logs progress; runs in batches; sleeps between batches to avoid replication lag.
4. Migration `00Y` (next release) adds the `NOT NULL` constraint as `NOT VALID`, then validates it.

This is a multi-release dance. It is correct, and it is the only safe pattern for hot tables. Operators get the same dance; the dual-write window matches the schema-versioning ADR's deprecation window.

**Rule 5: Versioned and signed.** Every migration is recorded in a `_migrations` audit table:

```sql
CREATE TABLE IF NOT EXISTS _migrations (
    id              BIGSERIAL PRIMARY KEY,
    migration_name  TEXT NOT NULL UNIQUE,
    checksum        TEXT NOT NULL,        -- SHA-256 of the file at run time
    applied_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_by      TEXT NOT NULL,        -- role that applied it
    duration_ms     BIGINT NOT NULL,
    adr_link        TEXT NOT NULL,        -- e.g. "adr-db-migration-policy.md"
    git_sha         TEXT NOT NULL         -- commit that contained the migration
);
```

Refinery already tracks names + checksums in `refinery_schema_history`; we add the `adr_link`, `git_sha`, and `applied_by` columns via a thin wrapper around refinery's runner.

### Lifecycle

**Develop.** Engineer writes the migration, the revert, a unit test that applies forward + revert against a local Postgres, and a doc note in the crate's CHANGELOG. PR includes:

- The two SQL files.
- A test that runs both directions.
- A canary fixture (`tests/fixtures/migrations/00X_canary.sql`) that seeds prod-shape data so the runtime estimate in the header is verifiable.

PR requires two reviewers: the workspace owner (e.g. wallet adapter owner for wallet migrations) **and** the dba-on-call rotation. The dba-on-call gate is a CODEOWNERS rule.

**Pre-prod gate.** CI runs the migration against a canary DB seeded with prod-shape data (volume = production size, anonymized via the redactor from `adr-log-schema-redaction.md`). The CI job:

1. Applies the migration; measures duration; fails if it exceeds 2x the header's estimate.
2. Runs the test suite against the migrated schema.
3. Applies the revert; verifies the schema returns to baseline.
4. Re-applies the forward migration; verifies idempotency.

A red CI job blocks merge.

**Production.** Applied by the K8s operator (`sbproxy-k8s-operator`, already exists). The operator:

1. Reads the migration set from the deployed binary (refinery embedded migrations).
2. Compares against `_migrations` table.
3. For each pending migration, checks the header's `Online safety` line. If "requires maintenance window", the operator pauses and surfaces a manual-approval prompt to the operator runbook; otherwise applies in order.
4. Records outcome (success / failure / duration) in the cluster status CRD.
5. On failure, halts the deploy and pages via `SLO-CONFIG-RELOAD` (existing alert).

**Rollback.** The operator runs the revert script via the same path. The runbook RB-DB-ROLLBACK is the operator playbook:

1. Identify the migration to revert by name + checksum.
2. Confirm dependent code has been rolled back to a version that does not require the new schema.
3. Run the revert script. Record outcome in `_migrations` (a new row with negative `id` and `revert_of` reference; we do not delete the original row).
4. Page if the revert fails (data-shape might be incompatible; manual recovery from backup per `adr-disaster-recovery-retention.md`).

### Baseline: existing `audit_events` table

The first migration in main is `20260430_001_audit_log_v0.sql`. This ADR accepts it as the baseline:

- It uses `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` (Rule 1 satisfied).
- It uses the canonical header (SPDX, copyright, ADR reference). Going forward, the header must also include the explicit `Online safety:` and `Estimated runtime` lines.
- It uses external grant blocks (`GRANT INSERT, SELECT ON audit_events ...`) instead of inlining grants. This pattern is endorsed: grants are operator-managed and do not belong in the migration file because they vary across deployments.
- It documents the chain_position columns as future-fill targets for a future backfill migration. The backfill is a "separate maintenance role with UPDATE granted" pattern, fully consistent with Rule 4 (no data mutation in the migration file itself; the backfill is a separate worker).

### Out of scope (revisit later)

- **Online schema changes that require dual-write windows** for type changes (e.g. `text` to `jsonb` on a hot table). These follow the schema-versioning ADR's N+2 deprecation window in addition to this ADR's online-by-default rule.
- **Multi-region schema sync.** When wallet/audit move to multi-region, schema migrations need a coordinator to apply across regions in lockstep. Out of scope.
- **Postgres major-version upgrades.** A separate runbook concern, not a per-migration concern.
- **Per-tenant table partitioning at scale.** If wallet ledger or audit_events grow beyond what a single table handles (>1B rows), partitioning is a one-time architectural shift, not a per-migration policy.

### What this ADR does NOT decide

- The wallet ledger schema itself.
- The DCR queue schema.
- Postgres tuning (`shared_buffers`, `work_mem`, etc.). Operator concern; not migration-policy.
- ClickHouse schema migrations. ClickHouse uses different tooling (native `ALTER TABLE` semantics); a separate, parallel ADR will pin those rules when ClickHouse migrations start to ship.

## Consequences

- One migration tool, one file layout, one review process. Onboarding a new engineer is one ADR, not five.
- Every migration ships its revert script in the same PR. Forgetting the revert is a CI failure, not a 3am page.
- The `Online safety` header turns "is this safe to deploy on green-build?" into a grep, not a code-review judgement call.
- The dual-write + backfill dance is multi-release work, but it's correct. The cost is engineering time across releases; the benefit is zero-downtime deploys on hot tables.
- The dba-on-call CODEOWNERS rule means migrations cannot land without a database-aware reviewer. This is a small bottleneck; we accept it because schema mistakes are very expensive to undo.
- The `_migrations` audit table grows by one row per migration. At an expected migration cadence of ~3-5 per quarter, this is negligible. The `_migrations` table is itself append-only and follows the same shape rules.
- Accepting the existing `20260430_001_audit_log_v0.sql` as baseline means the policy applies cleanly without a retroactive churn.

## Alternatives considered

**`sqlx migrate` instead of `refinery`.** Rejected. `sqlx migrate` runs migrations inside a transaction by default, which fights `CREATE INDEX CONCURRENTLY` and other non-transactional DDL. Refinery's no-transaction mode is the right default for a migration policy that requires online-by-default operations.

**`flyway` (JVM-based).** Rejected. Adds a JVM dependency to the deploy pipeline. We're a Rust shop; the embedded-migrations property of refinery is exactly what we want.

**Hand-rolled migration scripts driven by a shell wrapper.** Rejected. Loses the checksum check, the embedded-in-binary deployment property, and the standard `_migrations` table. The reinvention cost is real.

**No revert scripts; rely on backups for rollback.** Rejected. Restoring a 100GB Postgres from backup is hours. A revert script is seconds for additive migrations and is the right first option. Backups are the second option for destructive migrations.

**Allow data-mutating migrations on the live path for "small" backfills.** Rejected. There is no reliable definition of "small"; a 100k-row backfill on a hot table can saturate replication for minutes. The dual-write + backfill dance is mandatory for correctness; the engineering overhead is the price.

**Single global `migrations/` directory at the workspace root.** Rejected. Each crate owns its own schema; a wallet migration is independent from an audit migration. Per-crate `migrations/` keeps ownership clear.

## References

- Companion ADRs: `adr-schema-versioning.md` (the wire-format companion), `adr-admin-action-audit.md` (the existing migration baseline), `adr-disaster-recovery-retention.md` (restore drills), `adr-capacity-rate-limits.md`.
- Refinery: <https://github.com/rust-db/refinery>.
- Postgres online DDL guidance: <https://www.postgresql.org/docs/current/sql-altertable.html> § Notes.
- gh-ost / pt-osc as prior art for the dual-write backfill dance: <https://github.com/github/gh-ost>.
