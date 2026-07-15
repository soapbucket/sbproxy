# SH-15 Option A — SDD Progress Ledger

Plan: `scratchpad/2026-07-14-sh15-option-a.md`
Branch: `rickcrawford/wor-1835-governance`
Base commit: `54f2a8e4`

Execution model (repo constraint): subagents edit only; orchestrator runs all `cargo`/`check.sh` in the foreground. Tasks serial.

## Tasks
- Task 1 (governance_crdt G-Counter): complete (1cac45c7, 17 tests pass)
- Task 2 (InMemory counts peer usage): complete (eb51723c)
- Task 3 (dissemination run_loop): complete (2 tests pass; run_loop unused until Task 4)
- Task 4 (spawn + boot-order fix): complete (2 tests pass, dead-code cleared)
- Task 5 (Phase 1 gate): not started
- Task 6 (reserve/settle in ai_dispatch): complete (compiles + 4 helper tests pass)
- Task 7 (per-token rate): not started
- Task 8 (fail-closed strict): not started
- Task 9 (Phase 2 gate): not started
- Task 10 (admin UI): complete (174 UI tests pass)
- Task 11 (multi-gateway e2e): not started
- Task 12 (docs / WOR-1889): not started
- Task 13 (final gate + PR + worktree cleanup): not started

## Design notes (discovered during execution)
- Task 4 spawn site: `cluster.rs:1517` (`cluster_runtime().spawn(crate::cluster_metrics::run_loop(handle.clone(), 15))`), NOT lifecycle.rs. Add a sibling `governance_cluster::run_loop` spawn there.
- Task 4 store access: `run_loop` needs concrete `Arc<InMemoryGovernanceStore>`, but `KeyPlane` holds `Arc<dyn GovernanceStore>` (`build_governance_store` key_plane.rs:370 returns the trait object). FIX: retain the concrete approximate store on `KeyPlane` and add `KeyPlane::approximate_store() -> Option<Arc<InMemoryGovernanceStore>>`; spawn dissemination only when it is Some (approximate mode). Redis/strict owns its own coherence, no dissemination.
- Task 4 test: pure predicate `should_spawn_governance_dissemination(clustered, approximate)` is unit-testable; the spawn wiring itself is boot glue.

## Session checkpoint (phase0 merged)
- PHASE 0 (capability registry, PR #689) MERGED to main as 2cbf558d after 4 CI iterations (fixed: stale llms-full.txt; hooks test read wrong registry; dropped allow(deprecated); 4 broken intra-doc field-links).
- SH-15 committed+verified on rickcrawford/wor-1835-governance (NOT pushed): Tasks 1,2,3,4,6,10. Phase 1 (approximate cross-node tier) complete + functional; strict reserve/settle wired; admin UI done (174 UI tests).
- REMAINING: Task 7 (per-token rate + missing-rate policy — needs the model cost/pricing path design, config on KeyGovernanceConfig or model config, schema regen), Task 8 (GovernanceFailureMode fail-closed/AllowUnreserved on backend outage — edits Task 6 reserve block + config + schema regen), Task 11 (two-gateway + Redis e2e load test), Task 12 (docs describing both tiers, WOR-1889), Tasks 5/9/13 gates.
- LANDMINE for the final gate: this branch sits on the ~4000-line uncommitted rewrite 54f2a8e4 that was NEVER gated; a full `scripts/check.sh` will surface pre-existing clippy/doc issues in the rewrite, not just the new tasks. Budget a reconciliation pass.
