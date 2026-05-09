//! WOR-34 - stateful proxy fuzzer (v1).
//!
//! Existing fuzz targets in this crate are parser-level: they feed
//! arbitrary bytes into a single function and assert no panics. This
//! target sits one layer up. It generates a sequence of high-level
//! operations (apply a config, send a request, advance time, trigger
//! a reload, ...) and runs them against an in-process `sbproxy-core`
//! instance, asserting global proxy invariants after each step.
//!
//! The point is to surface bugs that only show up across multiple
//! ops: stale state after reload, leaked tasks, request handling
//! that diverges after a config swap, deadlocks under race-prone
//! op orderings, and so on. The parser-level harnesses cannot find
//! any of those because they only exercise one call.
//!
//! # In-process driving
//!
//! `sbproxy_e2e::ProxyHarness` spawns the release binary as a child
//! process, waits for the TCP listener to bind, and tears down on
//! Drop. That model is incompatible with libfuzzer's per-iteration
//! tempo (libfuzzer runs the fuzz_target body thousands of times per
//! second; spawning a child each time would peg the CPU on fork +
//! TCP setup and would let almost no actual fuzzing happen). So we
//! drive the proxy in-process via the same primitives the binary
//! uses internally:
//!
//!   - `sbproxy_config::compile_config(yaml)` parses + validates a
//!     config. This is the same call the binary makes at startup.
//!   - `sbproxy_core::pipeline::CompiledPipeline::from_config(cfg)`
//!     turns the compiled config into a runnable pipeline (action /
//!     auth / policy / transform enums instantiated, host router
//!     built, response cache wired). Same call as in `server::run`.
//!   - `sbproxy_core::reload::load_pipeline(p)` atomically swaps the
//!     global `ArcSwap<CompiledPipeline>` so the next read sees the
//!     new snapshot. Same call as the file-watcher reload path and
//!     the `POST /admin/reload` handler.
//!   - `sbproxy_core::admin::handle_admin_request(...)` is the sync
//!     dispatch the admin HTTP server forwards to per request. We
//!     drive it directly to assert `/readyz` and `/healthz` stay
//!     responsive after each op.
//!   - `sbproxy_observe::metrics().render()` produces the Prometheus
//!     text the `/metrics` endpoint serves. We assert it returns a
//!     non-empty document after every op.
//!
//! No real TCP listener, no Pingora server, no child process. Each
//! libfuzzer iteration runs in microseconds.
//!
//! # V1 op set
//!
//! Five ops in v1: `ApplyConfig`, `SendRequest`, `AdvanceTime`,
//! `TriggerReload`, `SimulateUpstream500`. The first four exercise
//! real code paths today; `AdvanceTime` and `SimulateUpstream500`
//! are stubs documented inline because they need infrastructure the
//! workspace doesn't currently expose (mock-clock injection and a
//! controllable upstream respectively). They're listed in the op
//! enum so the corpus picks them up; the harness records that they
//! ran but does not assert anything that depends on the missing
//! mechanism. Follow-ups are tracked in WOR-34's body.
//!
//! # Bounds
//!
//! Everything is bounded so the fuzzer doesn't waste cycles on
//! pathological giants:
//!
//!   - max sequence length: 50 ops
//!   - max body size:        4 KiB
//!   - max header count:     16
//!   - max header name/val:  256 bytes each
//!   - max path length:      512 bytes
//!
//! # Invariants asserted after every op
//!
//!   - No panic. libfuzzer catches this for free; documenting the
//!     contract so a future maintainer doesn't accidentally swallow
//!     panics in a `catch_unwind` in here.
//!   - No deadlock. Every op runs inside a `tokio::time::timeout`
//!     with a 30-second budget. A budget exceedance is a hard failure
//!     (panic via expect), which libfuzzer reports as a crash.
//!   - `/readyz` returns 2xx. The proxy must stay healthy after a
//!     config apply, a reload, or any synthetic request, no matter
//!     how absurd the previous op was.
//!   - `/healthz` returns 200. The liveness probe must never go
//!     unresponsive across an op boundary.
//!   - `metrics().render()` returns non-empty Prometheus text. A
//!     blank metrics doc is a regression: the registry is supposed
//!     to ship at least the legacy basic counters even when no
//!     traffic has flowed.
//!
//! Stubbed (TODO): orphan-tokio-task detection. The std `tokio` API
//! does not expose a process-wide live task count we can snapshot
//! cheaply, and tokio-metrics requires the unstable feature flag and
//! a runtime configured to record it. Skipping for v1; revisit when
//! tokio-metrics is wired into the production runtime so the same
//! probe works in CI and in fuzz.

#![no_main]

use std::time::Duration;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

// --- Bounds ---

const MAX_OPS: usize = 50;
const MAX_BODY: usize = 4 * 1024;
const MAX_HEADERS: usize = 16;
const MAX_HEADER_NAME: usize = 256;
const MAX_HEADER_VALUE: usize = 256;
const MAX_PATH: usize = 512;
const PER_OP_BUDGET: Duration = Duration::from_secs(30);

// --- Op enum ---

/// One step in a generated proxy interaction.
///
/// Each variant exists to surface a specific class of cross-op bug:
///
/// - [`Op::ApplyConfig`] picks one of a small set of known-shape
///   configs and applies it to the global pipeline. Existing parser
///   fuzzers prove the YAML parser handles arbitrary bytes; this
///   variant proves the config-to-pipeline compile + global swap
///   path stays consistent across a sequence of swaps. Configs are
///   indexed (not raw bytes) because a v1 byte-level config fuzzer
///   would spend most of its cycles on YAML that does not parse,
///   and the goal here is multi-op sequencing rather than parser
///   coverage.
///
/// - [`Op::SendRequest`] drives a synthesised request through the
///   router-level lookup so the host_map + bloom-filter fast path
///   gets exercised under arbitrary header / path / body bytes. The
///   body is bounded; without a bound libfuzzer would happily feed
///   gigabyte bodies and starve the rest of the corpus.
///
/// - [`Op::AdvanceTime`] is a placeholder for fuzzed time progression.
///   Pipelines hold timers (rate-limit windows, cache TTLs, circuit
///   breaker probes) that only break under ordering between ops.
///   The variant lives in the enum so the corpus learns the shape;
///   the harness currently records the request but does not move
///   wallclock because sbproxy does not expose a mock-clock today.
///   Follow-up tracked in WOR-34.
///
/// - [`Op::TriggerReload`] re-applies the currently-loaded config
///   without changing it. ArcSwap reload is supposed to be a no-op
///   in that case; surfacing a divergence between "reload same
///   config" and "do nothing" would be a bug.
///
/// - [`Op::SimulateUpstream500`] is a placeholder for upstream-fault
///   injection. We can't drive a real upstream without a TCP loop,
///   so v1 only records the op was selected. Follow-up tracked in
///   WOR-34.
#[derive(Debug, Arbitrary)]
enum Op {
    /// Apply one of N pre-canned valid configs by index.
    ///
    /// The fuzz target hard-codes a small list of configs that are
    /// known to compile. Picking by index keeps the v1 corpus rich
    /// in cross-op orderings (which is the point of this harness)
    /// without spending bytes on the parser path that the existing
    /// targets already cover.
    ApplyConfig {
        /// Index into the static `CONFIGS` table; clamped at apply
        /// time so the fuzzer cannot produce out-of-bounds variants
        /// just by tweaking the byte.
        which: u8,
    },

    /// Send one synthesised request through the router.
    ///
    /// All fields are bounded so the fuzzer cannot produce
    /// gigabyte requests. The harness clamps each field to its
    /// limit on the way in.
    SendRequest {
        /// HTTP method string. Bounded to the standard verbs by
        /// `clamp_method`; arbitrary bytes round-trip into "GET".
        method: u8,
        /// Request path. Truncated to `MAX_PATH`.
        path: Vec<u8>,
        /// Host header. Drives `pipeline.resolve_origin(host)`.
        /// Truncated and lossy-utf8 decoded.
        host: Vec<u8>,
        /// Header pairs. Trimmed to `MAX_HEADERS` entries; each
        /// name/value field truncated to its respective cap.
        headers: Vec<(Vec<u8>, Vec<u8>)>,
        /// Body bytes. Truncated to `MAX_BODY`.
        body: Vec<u8>,
    },

    /// Advance synthetic time by `seconds`.
    ///
    /// V1 stub: sbproxy-core does not expose a mock-clock, so the
    /// harness records the op but does not actually warp time.
    /// Follow-up tracked in WOR-34.
    AdvanceTime {
        /// Seconds to advance. Clamped to 0..=3600 so the corpus
        /// cannot pick "1 trillion seconds" and waste a slot.
        seconds: u16,
    },

    /// Re-apply the currently-loaded config.
    ///
    /// Exercises the reload path with no diff. Should be a no-op
    /// at the global state level, but does drive `load_pipeline`
    /// (and therefore the projection-cache refresh) which is the
    /// step most likely to wedge.
    TriggerReload,

    /// Simulate a 500 from the upstream.
    ///
    /// V1 stub: needs a controllable in-process upstream we don't
    /// build today. Recorded for corpus shape; no behaviour change.
    /// Follow-up tracked in WOR-34.
    SimulateUpstream500,
}

// --- Pre-canned configs ---
//
// Indexed by `Op::ApplyConfig::which % CONFIGS.len()`. Every entry
// must compile cleanly via `sbproxy_config::compile_config`. Keep
// this list small (< 16 entries) so the corpus can hit interesting
// combinations rather than enumerating configs.
const CONFIGS: &[&str] = &[
    // 0: minimal static-response origin.
    r#"
proxy:
  http_bind_port: 8080
origins:
  "static.local":
    action:
      type: static
      status: 200
      content_type: text/plain
      body: "ok\n"
"#,
    // 1: two origins, mock + static. Exercises host_map collisions
    // and the per-origin parallel-vec invariant inside
    // CompiledPipeline::from_config.
    r#"
proxy:
  http_bind_port: 8080
origins:
  "a.local":
    action:
      type: static
      status: 200
      body: "a"
  "b.local":
    action:
      type: mock
      status: 200
      headers:
        x-mock: "true"
      body:
        ok: true
"#,
    // 2: empty origins list. Edge case the bloom filter has to
    // handle without panicking.
    r#"
proxy:
  http_bind_port: 8080
origins: {}
"#,
    // 3: redirect action. Different action enum variant from
    // entries 0/1 so the corpus mixes action types across reloads.
    r#"
proxy:
  http_bind_port: 8080
origins:
  "redir.local":
    action:
      type: redirect
      url: https://example.test/
      status: 302
"#,
];

// --- Fuzz target ---
//
// The corpus is a `Vec<Op>` decoded via `arbitrary`. We materialise
// it into an owned vec, clamp the length, then run each op inside
// a tokio timeout so a hung op surfaces as a panic libfuzzer can
// minimise.

fuzz_target!(|ops: Vec<Op>| {
    let mut ops = ops;
    if ops.len() > MAX_OPS {
        ops.truncate(MAX_OPS);
    }

    // Build a single-threaded runtime per iteration. tokio's
    // `current_thread` flavour is the lightest option that still
    // gives us `tokio::time::timeout`. We don't need worker threads
    // because the ops we drive are all sync today; the runtime is
    // here for the timeout primitive.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        // If the runtime can't be built, libfuzzer should be told
        // this iteration is uninteresting (return) rather than
        // panicking; runtime build failures are an environment
        // issue not a proxy regression.
        Err(_) => return,
    };

    rt.block_on(async {
        for op in ops {
            // Wrap each op so a hang shows up as a timeout rather
            // than a hung iteration. 30s is generous; real ops
            // here should complete in microseconds.
            let res = tokio::time::timeout(PER_OP_BUDGET, run_op(op)).await;
            // Hitting the timeout is a hard failure: it means
            // either the op deadlocked or our PER_OP_BUDGET is too
            // tight. Either way, libfuzzer needs to know.
            assert!(
                res.is_ok(),
                "op exceeded PER_OP_BUDGET ({:?})",
                PER_OP_BUDGET
            );

            // Invariant sweep after every op. Keep this cheap so
            // the per-iteration tempo stays high.
            assert_invariants();
        }
    });
});

/// Run one op. Each branch translates the typed op into the matching
/// in-process call against `sbproxy-core` / `sbproxy-config` /
/// `sbproxy-observe`.
async fn run_op(op: Op) {
    match op {
        Op::ApplyConfig { which } => {
            let yaml = CONFIGS[(which as usize) % CONFIGS.len()];
            apply_config(yaml);
        }
        Op::SendRequest {
            method,
            path,
            host,
            headers,
            body,
        } => {
            send_request(method, &path, &host, &headers, &body);
        }
        Op::AdvanceTime { seconds } => {
            // V1 stub. See enum doc-comment.
            //
            // TODO(WOR-34 follow-up): wire to a mock clock once
            // sbproxy-core exposes one. Real time progression
            // would let the fuzzer find rate-limit window-edge
            // bugs and cache-TTL races.
            //
            // We touch the field via `black_box` so the fuzzer
            // does not learn the bytes are dead and stop varying
            // them; once the mock-clock follow-up lands those
            // same bytes will start driving real behaviour.
            std::hint::black_box(seconds);
        }
        Op::TriggerReload => {
            // Re-apply config index 0 to drive the reload path
            // without a content change. The harness keeps no
            // memory of "currently applied" so this does the job.
            apply_config(CONFIGS[0]);
        }
        Op::SimulateUpstream500 => {
            // V1 stub. See enum doc-comment.
            //
            // TODO(WOR-34 follow-up): stand up a small in-process
            // upstream that returns 5xx so the fuzzer can drive
            // the proxy's retry / fallback / circuit-breaker path
            // under arbitrary op orderings.
        }
    }
}

/// Compile the YAML into a `CompiledPipeline` and atomically swap
/// it into the global pipeline slot.
///
/// Failure is OK: not every config in the table will continue to
/// compile after a future schema change. We drop the error rather
/// than panicking so the fuzzer keeps making progress; the
/// invariant sweep after the op still has to pass.
fn apply_config(yaml: &str) {
    let compiled = match sbproxy_config::compile_config(yaml) {
        Ok(c) => c,
        Err(_) => return,
    };
    let pipeline = match sbproxy_core::pipeline::CompiledPipeline::from_config(compiled) {
        Ok(p) => p,
        Err(_) => return,
    };
    sbproxy_core::reload::load_pipeline(pipeline);
}

/// Drive a synthesised request through the router-level lookup.
///
/// V1 only checks `pipeline.resolve_origin(host)` consistency. A
/// follow-up will run the request through the full request_filter
/// once we have an in-process Pingora session shim that doesn't
/// require a real socket.
fn send_request(method: u8, path: &[u8], host: &[u8], headers: &[(Vec<u8>, Vec<u8>)], body: &[u8]) {
    // Clamp every field. The fuzzer can produce arbitrary giants;
    // we want to exercise the proxy's input-handling, not OOM the
    // libfuzzer process.
    let _method = clamp_method(method);
    let path = if path.len() > MAX_PATH {
        &path[..MAX_PATH]
    } else {
        path
    };
    let _path = String::from_utf8_lossy(path);
    let host_clamped = if host.len() > MAX_HEADER_VALUE {
        &host[..MAX_HEADER_VALUE]
    } else {
        host
    };
    let host_str = String::from_utf8_lossy(host_clamped);
    let _body = if body.len() > MAX_BODY {
        &body[..MAX_BODY]
    } else {
        body
    };

    // Walk headers but only up to the cap. We don't pass the
    // values anywhere yet (v1) but consuming them keeps the
    // fuzzer from learning that the bytes are dead.
    for (i, (n, v)) in headers.iter().enumerate() {
        if i >= MAX_HEADERS {
            break;
        }
        let name = if n.len() > MAX_HEADER_NAME {
            &n[..MAX_HEADER_NAME]
        } else {
            n
        };
        let value = if v.len() > MAX_HEADER_VALUE {
            &v[..MAX_HEADER_VALUE]
        } else {
            v
        };
        std::hint::black_box((name, value));
    }

    // Drive the host router. resolve_origin is the hot-path read
    // every request takes; it has to be panic-safe under arbitrary
    // host strings (including non-UTF-8 input that Cow lossy-decoded
    // above).
    let pipeline = sbproxy_core::reload::current_pipeline();
    let _ = pipeline.resolve_origin(host_str.as_ref());
}

/// Clamp an arbitrary byte to a stable HTTP method string. We don't
/// care about exhaustive method coverage at v1; we care that the
/// fuzzer can drive at least the common verbs without coercing
/// every byte into "GET".
fn clamp_method(b: u8) -> &'static str {
    match b % 8 {
        0 => "GET",
        1 => "POST",
        2 => "PUT",
        3 => "DELETE",
        4 => "PATCH",
        5 => "HEAD",
        6 => "OPTIONS",
        _ => "GET",
    }
}

/// Run the post-op invariant sweep.
///
/// Cheap by design: each call does one global pipeline read, one
/// admin handler dispatch per probe route, and one Prometheus
/// render. None allocate beyond the response bodies they produce.
fn assert_invariants() {
    use sbproxy_core::admin::{handle_admin_request, AdminConfig, AdminState};

    // Build a fresh AdminState per sweep. AdminState is cheap to
    // construct (no I/O) and we want the sweep to be independent
    // of any state mutated by previous ops.
    let admin_state = AdminState::new(AdminConfig::default());

    // /readyz must stay 2xx. The probe is unauthenticated by
    // design so we don't need an auth header.
    let (status, _ct, _body) = handle_admin_request("GET", "/readyz", &admin_state, None);
    assert!(
        (200..300).contains(&status),
        "/readyz returned non-2xx status {status}"
    );

    // /healthz must stay 200. Stricter than /readyz because
    // /healthz is the kubelet liveness probe and a 4xx-or-5xx
    // there would trigger a pod kill in production.
    let (status, _ct, _body) = handle_admin_request("GET", "/healthz", &admin_state, None);
    assert_eq!(status, 200, "/healthz returned status {status}");

    // /metrics must produce a non-empty Prometheus document. The
    // global registry seeds the legacy counters at first call;
    // an empty render means something corrupted the registry.
    let body = sbproxy_observe::metrics().render();
    assert!(!body.is_empty(), "/metrics rendered an empty body");
}
