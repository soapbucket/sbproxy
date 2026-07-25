# WOR-1980 Production Routing Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the registered first-healthy, bandit, GPU-aware, LoRA, and LoRA-aware strategies selectable on the production load-balancer path with live target projections and reload-stable bandit feedback.

**Architecture:** `LoadBalancerAction` owns an optional compiled registry strategy and projects only its already-eligible targets into the existing `RoutingRequest` and `TargetState` types. A default no-op feedback method on `RoutingStrategy` lets core report one bounded outcome per upstream attempt; bandit implementations reuse a bounded process registry across hot reloads while all other strategies ignore feedback.

**Tech Stack:** Rust, serde/serde_json, inventory, Pingora `ProxyHttp`, Tokio test fixtures, nextest.

## Global Constraints

- Preserve all existing `load_balancer` behavior when `strategy` is omitted.
- Keep `sbproxy-ai::Router` and its Phase 4 strategy work unchanged.
- Registry strategies only see targets that passed deployment, backup, priority, health, breaker, and outlier filtering.
- Unknown strategy names and malformed plugin config fail config compilation.
- Bandit state survives hot reload of the same origin but may reset on process restart.
- Do not add GPU polling, cloud provisioning, scheduled GPU work, or fabricated cost feedback.
- Do not add unbounded metric labels or unbounded process state.
- Do not use em dashes in user-facing text.
- Use red-green-refactor for every behavior change and run the complete repository gate before completion.

---

### Task 1: Outcome Contract and Reload-Stable Bandit State

**Files:**
- Modify: `crates/sbproxy-modules/src/action/routing/mod.rs`
- Modify: `crates/sbproxy-modules/src/action/routing/bandit.rs`

**Interfaces:**
- Produces: `RoutingOutcome { success: bool, latency: Duration }`.
- Produces: default `RoutingStrategy::record_outcome(&self, target_url: &str, outcome: RoutingOutcome)`.
- Produces: bandit config field `state_namespace: Option<String>`, populated by the load-balancer compiler in Task 2.
- Preserves: existing third-party `RoutingStrategy` implementations compile unchanged because the new method has a default body.

- [ ] **Step 1: Write failing compatibility and reward tests**

Add tests that prove an implementation defining only `select` and `name` remains object-safe, two successful arms with different latencies prefer the faster arm after both are sampled, failures lose to successful arms, maximum-duration input cannot poison scores, and two bandit instances built with one namespace observe the same history while different namespaces do not.

Use deterministic `epsilon: 0.0` and explicit outcomes:

```rust
strategy.record_outcome(
    "http://slow",
    RoutingOutcome {
        success: true,
        latency: Duration::from_millis(500),
    },
);
strategy.record_outcome(
    "http://fast",
    RoutingOutcome {
        success: true,
        latency: Duration::from_millis(10),
    },
);
assert_eq!(strategy.select(&request, &targets), Some(1));
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
cargo nextest run -p sbproxy-modules routing::bandit routing::tests --no-fail-fast
```

Expected: compile failure because `RoutingOutcome`, the callback, and namespace reuse do not exist.

- [ ] **Step 3: Add the feedback interface**

In `routing/mod.rs`, add:

```rust
#[derive(Debug, Clone, Copy)]
pub struct RoutingOutcome {
    pub success: bool,
    pub latency: std::time::Duration,
}

pub trait RoutingStrategy: Send + Sync {
    fn select(&self, request: &RoutingRequest, targets: &[TargetState]) -> Option<usize>;
    fn name(&self) -> &str;
    fn record_outcome(&self, _target_url: &str, _outcome: RoutingOutcome) {}
}
```

Re-export `RoutingOutcome` from `action/mod.rs` and `lib.rs`.

- [ ] **Step 4: Replace binary bandit counters with bounded reward state**

Use `reward = 0.0` for failure and
`1.0 / (1.0 + latency.as_secs_f64())` for success. Store `reward_sum` and
`total` per target and compare mean reward. Saturate the observation counter
and clamp every computed reward to the finite `0.0..=1.0` range defensively.

Add a process registry shaped as:

```rust
struct BanditStateRegistry {
    order: VecDeque<String>,
    states: HashMap<String, Arc<Mutex<HashMap<String, ArmStats>>>>,
}
```

Cap namespaces and targets with named constants. Reuse an existing namespace
on build. When the namespace cap is reached, evict the oldest registry entry;
an action already holding its `Arc` continues safely.

- [ ] **Step 5: Run focused tests and lint**

Run:

```bash
cargo nextest run -p sbproxy-modules routing::bandit routing::tests --no-fail-fast
cargo clippy -p sbproxy-modules --all-targets -- -D warnings
```

Expected: all selected tests pass and clippy emits no warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/sbproxy-modules/src/action/routing \
  crates/sbproxy-modules/src/action/mod.rs \
  crates/sbproxy-modules/src/lib.rs
git commit -m "feat(routing): retain bounded bandit feedback (WOR-1980)"
```

---

### Task 2: Compile and Select Registry Strategies

**Files:**
- Modify: `crates/sbproxy-modules/src/action/loadbalancer.rs`
- Modify: `crates/sbproxy-modules/src/action/routing/mod.rs`
- Modify: `crates/sbproxy-modules/src/compile.rs`
- Modify: `crates/sbproxy-core/src/pipeline.rs`

**Interfaces:**
- Consumes: `build_routing_strategy`, `RoutingRequest`, `TargetState`.
- Produces: `compile_action_for_origin(config: &Value, origin_id: &str) -> Result<Action>`.
- Produces: `LoadBalancerAction::select_target_for_request(&self, request: RoutingRequest) -> Result<TargetSelection>`.
- Produces: `TargetSelection { host, port, tls, target_index, selection_method }`.
- Produces: `LoadBalancerAction::record_strategy_outcome(target_index, RoutingOutcome)`.
- Preserves: existing `select_target(client_ip, uri, headers)` wrapper for non-core callers and tests.

- [ ] **Step 1: Write failing config tests**

Cover:

```yaml
type: load_balancer
algorithm: least_connections
lb_method: plugin
strategy: first-healthy
strategy_config: {}
targets:
  - url: http://one
    metadata: { gpu_utilization: 0.8 }
  - url: http://two
    metadata: { gpu_utilization: 0.2 }
```

Assert a known strategy compiles, an unknown name fails and names the value,
`lb_method: plugin` without `strategy` fails, non-object `strategy_config`
fails, and an omitted strategy preserves the current default.

- [ ] **Step 2: Run config tests and confirm RED**

Run:

```bash
cargo nextest run -p sbproxy-modules loadbalancer compile --no-fail-fast
```

Expected: plugin fields are ignored and the assertions fail.

- [ ] **Step 3: Add typed strategy and target metadata config**

Add optional `strategy`, `strategy_config`, and `lb_method` fields to the
private deserialization config. Add:

```rust
#[serde(default)]
pub metadata: HashMap<String, serde_json::Value>,
```

to `Target`. Reject a metadata map over 64 entries and keys over 64 bytes.
Clone the strategy config, inject a stable internal namespace based on
`origin_id`, strategy name, and ordered target URLs, then call
`build_routing_strategy`.

- [ ] **Step 4: Add origin-aware action compilation**

Keep `compile_action(config)` as a compatibility wrapper and add
`compile_action_for_origin(config, origin_id)`. Only the load-balancer arm
uses the origin value. Update main-origin and forward-rule compilation in
`pipeline.rs` with stable origin/rule identities.

- [ ] **Step 5: Write failing production-selection tests**

Create compiled actions and prove:

- `first-healthy` selects the first eligible target;
- `gpu-aware` selects the eligible target with lower metadata utilization;
- `lora-aware` reads `X-LoRA-Adapter` and selects a warm target;
- a strategy returning `None` falls back to `algorithm`;
- an out-of-range result cannot panic and falls back;
- filtered targets never appear in the strategy projection;
- `list_routing_strategies()` is sorted and contains the five selectable
  built-ins exactly once in a production build.

- [ ] **Step 6: Implement request and target projection**

Build `RoutingRequest` from method, path plus query, headers, client address,
hostname, and bounded model/adapter extraction. Build `TargetState` only from
the final eligible target slice with live connection counts and current
metadata. Map the strategy's slice index back to the original target index.
Run the existing algorithm over the same slice on `None` or invalid index.

- [ ] **Step 7: Run focused tests and lint**

Run:

```bash
cargo nextest run -p sbproxy-modules loadbalancer routing compile --no-fail-fast
cargo nextest run -p sbproxy-core pipeline --no-fail-fast
cargo clippy -p sbproxy-modules -p sbproxy-core --all-targets -- -D warnings
```

Expected: all selected tests pass and clippy emits no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/sbproxy-modules/src/action/loadbalancer.rs \
  crates/sbproxy-modules/src/action/routing/mod.rs \
  crates/sbproxy-modules/src/compile.rs \
  crates/sbproxy-core/src/pipeline.rs
git commit -m "feat(routing): select registered load balancers (WOR-1980)"
```

---

### Task 3: Wire Attempt Feedback Through Pingora

**Files:**
- Modify: `crates/sbproxy-core/src/context.rs`
- Modify: `crates/sbproxy-core/src/server/proxy_http.rs`
- Test: existing unit-test modules in both files

**Interfaces:**
- Consumes: `TargetSelection` and `RoutingOutcome`.
- Produces: one outcome callback per selected upstream attempt.
- Produces: the actual strategy or fallback algorithm in
  `ctx.admin_load_balancer_strategy`.

- [ ] **Step 1: Write failing outcome-deduplication tests**

Add pure helper tests for these sequences:

1. selection, 200 response, logging cleanup: one success;
2. selection, 503 response, retry selection: one failure for the first arm;
3. selection, connect failure, retry selection: one failure;
4. selection, timeout callback followed by generic error callback: one failure;
5. a strategy deferral records the built-in algorithm as the selection method.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
cargo nextest run -p sbproxy-core proxy_http context --no-fail-fast
```

Expected: compile failure because per-attempt timing and deduplication state do
not exist.

- [ ] **Step 3: Add per-attempt context**

Add:

```rust
pub lb_attempt_started_at: Option<Instant>,
pub lb_outcome_recorded: bool,
```

Initialize them in `RequestContext::new`. Reset both when a new target is
selected.

- [ ] **Step 4: Select with the full request projection**

In the load-balancer `upstream_peer` arm, build the production
`RoutingRequest`, call `select_target_for_request`, set
`lb_attempt_started_at`, and store `selection_method` in the existing admin
field.

- [ ] **Step 5: Record exactly one outcome**

Add one helper that takes the current target index, success boolean, and
elapsed time. It no-ops after the first call for an attempt. Invoke it on
response headers, connect/TLS failure, read/write timeout, and terminal
upstream error before retry state is cleared. Status below 500 is success;
5xx and transport failures are failure.

- [ ] **Step 6: Run focused tests and lint**

Run:

```bash
cargo nextest run -p sbproxy-core proxy_http context --no-fail-fast
cargo clippy -p sbproxy-core --all-targets -- -D warnings
```

Expected: all selected tests pass and clippy emits no warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/sbproxy-core/src/context.rs \
  crates/sbproxy-core/src/server/proxy_http.rs
git commit -m "feat(routing): feed live outcomes to strategies (WOR-1980)"
```

---

### Task 4: Production Integration Coverage and Operator Documentation

**Files:**
- Create: `e2e/tests/routing_registry.rs`
- Modify: `e2e/Cargo.toml`
- Modify: `docs/routing-strategies.md`
- Modify: `docs/configuration.md`
- Modify: `examples/lora-aware-routing/README.md`
- Modify: `examples/lora-aware-routing/sb.yml`
- Modify: `docs/llms-full.txt` by generator
- Modify: generated schema/catalog files only when their checks require it

**Interfaces:**
- Consumes: production config and routing behavior from Tasks 1 through 3.
- Produces: executable acceptance evidence and accurate public docs.

- [ ] **Step 1: Write the failing E2E**

Start two local mock upstreams. Configure a `load_balancer` action with
`strategy: bandit`, `epsilon: 0.0`, and the slow target first. Return 200 from
both, delaying one response. Send enough sequential requests to sample both
arms and assert the final requests select the faster target.

Add compiled production-action cases for `first-healthy`, `gpu-aware`, and
`lora-aware` if their network fixtures fit naturally in the same file.

- [ ] **Step 2: Run E2E and confirm RED before final wiring**

Run:

```bash
cargo nextest run -p sbproxy-e2e --test routing_registry --no-fail-fast
```

Expected before Tasks 1 through 3 are present: config compilation or routing
assertions fail.

- [ ] **Step 3: Update public documentation and example**

Remove every statement that the plugin path is forward-looking or ignored.
Document exact config fields, fallback semantics, metadata bounds, bandit
reward, hot-reload retention, process-restart reset, and the absence of
fabricated cost or GPU polling. Make the LoRA-aware example runnable against
the production path.

- [ ] **Step 4: Regenerate and check docs/schema/catalogs**

Run:

```bash
./scripts/regen-llms-full.sh
./scripts/check-config-schema.sh
./scripts/check.sh
```

Expected: generated docs and config/capability catalogs are current.

- [ ] **Step 5: Run ticket verification**

Run:

```bash
cargo nextest run -p sbproxy-modules -p sbproxy-core --no-fail-fast
cargo nextest run -p sbproxy-e2e --test routing_registry --no-fail-fast
cargo fmt --all -- --check
cargo clippy -p sbproxy-modules -p sbproxy-core -p sbproxy-e2e --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p sbproxy-modules -p sbproxy-core --no-deps --document-private-items
git diff --check
```

Expected: every command passes.

- [ ] **Step 6: Commit**

```bash
git add e2e docs examples schemas
git commit -m "test(routing): certify registered strategies (WOR-1980)"
```

---

### Task 5: Phase Integration Gate

**Files:**
- Modify only files required by failures attributable to WOR-1980.

**Interfaces:**
- Consumes: complete ticket branch.
- Produces: review-ready commits with fresh full-gate evidence.

- [ ] **Step 1: Run the complete repository gate**

Run:

```bash
cargo fmt --all -- --check
cargo build --workspace
cargo nextest run --workspace --exclude sbproxy-e2e --locked --profile ci
cargo test --workspace --exclude sbproxy-e2e --locked --doc
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
./scripts/check.sh
```

Expected: all commands pass.

- [ ] **Step 2: Inspect final scope**

Run:

```bash
git status --short
git diff --check
git log --oneline codex/phase0-1..HEAD
git diff --stat codex/phase0-1...HEAD
```

Expected: clean worktree, only WOR-1980 design, implementation, tests, docs,
and generated artifacts.

- [ ] **Step 3: Submit for independent spec and code-quality review**

The reviewer must map every Linear acceptance criterion to code and tests,
check reload-state bounds and outcome deduplication, and return either CLEAN or
actionable findings with exact file locations.
