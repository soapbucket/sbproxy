# PR B report: WOR-2712 + WOR-2708

Branch: `fix/wor-2712-2708-events-policy`
Worktree: `/Users/rick/projects/soapbucket/sbproxy/.worktrees/events-policy-wor-2712-2708`
Base: `origin/main` at `4f0a9b61d`
Not pushed. No GitHub PR.

## Red evidence

### WOR-2708 (Rego load-time trial timeout)

Wrote `a_load_time_trial_timeout_is_inconclusive_not_a_semantic_fault` first.
`cargo test -p sbproxy-extension --lib a_load_time_trial_timeout_is_inconclusive` failed:

```
a trial that exceeds budget_ms must not refuse compile: policy `rego`: rule
`data.sbproxy.allow` could not be evaluated. The module parsed, so this is a
semantic fault: an unsafe variable, or a query naming a rule the module does
not define: execution exceeded time limit (elapsed=242152208ns, limit=5000000ns)
```

That is the ticket: a `TimeLimitExceeded` was wrapped as an unsafe-variable / missing-rule fault.

After the `prove_evaluable` classification change, the same test passed (0.30s).

### WOR-2712 (events webhook SSRF allowlist)

Wrote `usage_sinks_allow_private_lets_a_loopback_events_webhook_start` in
`lifecycle.rs` first. It compiles a real `egress.usage_sinks` block with
`allow_private: true` and `hosts: ["127.0.0.1"]`, calls
`arm_egress_gates_from_config`, then `build_event_egress` against a loopback
stub. `cargo test -p sbproxy-core --lib usage_sinks_allow_private_lets_a_loopback`
failed:

```
loopback collector on an allow_private usage_sinks host must start:
events.url is refused by the SSRF guard: blocked: IP address 127.0.0.1 is private/internal
```

Production `ssrf_allowlist()` still returned an empty vec, so the guard ran
before the config-driven egress authorizer and never saw the listed host.

After arming the process-wide list from `usage_sinks`, the same test passed.

## What changed

### WOR-2712

- `arm_egress_gates_from_config` now also calls
  `sbproxy_observe::arm_webhook_ssrf_allowlist` with
  `EgressAuthorizer::ssrf_private_hosts(Webhook)`.
- When `allow_private` is true, those hosts are the SSRF exemption list.
  When usage_sinks is absent or `allow_private` is false, the list stays
  empty: the guard still runs and still blocks private addresses.
- Production `ssrf_allowlist()` reads that process-wide list.
  The test override still defaults to `None` (skip).
- Docs: `docs/events.md` and `docs/configuration.md` say the events
  webhook destination and its SSRF allowlist are taken at boot. A SIGHUP
  cannot newly permit a private collector that was refused at start.

### WOR-2708

- `prove_evaluable` downcasts to `regorus::LimitError::TimeLimitExceeded`.
  A trial timeout logs (site, rule, elapsed/limit) and lets `compile()`
  proceed. Genuine semantic faults still use the existing message and do
  not mention a time limit as if it were that fault.
- The execution timer is still bound before the trial.
- `docs/scripting.md` failure-posture table has an explicit row for a
  load-time trial timeout.

## Files

- `crates/sbproxy-observe/src/event_sink.rs`
- `crates/sbproxy-observe/src/lib.rs`
- `crates/sbproxy-security/src/egress.rs`
- `crates/sbproxy-core/src/server/lifecycle.rs`
- `crates/sbproxy-extension/src/rego/mod.rs`
- `docs/events.md`
- `docs/configuration.md`
- `docs/scripting.md`
- `docs/.changes/20260829-the-events-webhook-ssrf-allowlist-now.json`
- `docs/.changes/20260829-a-rego-policy-whose-load-time.json`

## Tests

- `event_sink::tests::usage_sinks_allow_private_listed_host_lets_loopback_webhook_start_and_deliver`
- `event_sink::tests::loopback_webhook_is_refused_when_usage_sinks_does_not_permit_private`
- `event_sink::tests::arm_webhook_ssrf_allowlist_stores_the_hosts_production_reads`
- `event_egress_tests::usage_sinks_allow_private_lets_a_loopback_events_webhook_start`
- `event_egress_tests::a_loopback_events_webhook_is_refused_without_usage_sinks_allow_private`
- `egress::tests::ssrf_private_hosts_follow_allow_private`
- `rego::tests::a_load_time_trial_timeout_is_inconclusive_not_a_semantic_fault`
- existing `a_module_that_parses_but_cannot_be_analysed_is_refused_at_load` still asserts `semantic fault` and now also asserts the message does not say `time limit`

## Verification

- `cargo test -p sbproxy-extension --lib rego`: 59 passed
- `cargo test -p sbproxy-observe --lib event_sink -- --test-threads=1`: 28 passed
- `cargo test -p sbproxy-security --lib ssrf_private_hosts`: passed
- `cargo test -p sbproxy-core --lib usage_sinks_allow_private_lets_a_loopback`: passed
- `cargo test -p sbproxy-core --lib a_loopback_events_webhook_is_refused`: passed
- `cargo nextest run -E 'package(sbproxy-observe) + package(sbproxy-extension) + package(sbproxy-core)' --offline`: `Summary [121.701s] 5170 tests run: 5170 passed (1 leaky), 16 skipped`
- `bash scripts/check-fast.sh`: `check-fast passed in 32s (34 checks).`
- `RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p sbproxy-observe -p sbproxy-extension -p sbproxy-security --no-deps`: exit 0

## Commits

- `69e291000` `fix(observe): honor usage_sinks allow_private on the events webhook SSRF allowlist`
- `f78eb19dc` `fix(extension): treat a Rego load-time trial timeout as inconclusive`

## Concerns

- `allow_by_default` on `usage_sinks` still compiles to `None` (inert, same as the egress gate). `allow_private` on that mode does not arm SSRF hosts. Operators who want a private collector must set `mode: deny_by_default`.
- Compiled hosts are lowercased; the SSRF guard is an exact string match. `events.url` should use the same hostname spelling as `egress.usage_sinks.hosts` after lowercasing.
- The process-wide SSRF list is a `RwLock` and is rewritten on every `arm_egress_gates_from_config` (boot and reload). That can refresh the per-batch check. It cannot newly permit a collector that was refused at `start_webhook_worker`, because `install_event_egress` is set-once and the process never started. That caveat is in the docs.
- The observe inverse test does not call `EventEgress::start` with `SsrfGuard::enforced_for(&[])`. An empty process-wide override would refuse sibling loopback stubs under `cargo test` parallelism. The lifecycle test (observe compiled as a non-test crate) is the one that pins the `SSRF guard` boot message.
- `cargo test -p sbproxy-observe --lib event_sink` without `--test-threads=1` can still flake on shared Prometheus drop counters. That is pre-existing. nextest isolates processes and was green.
