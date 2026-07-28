//! OTLP metrics export e2e.
//!
//! `init_otlp_metrics_pipeline` had zero callers; `export_metrics: true`
//! was an inert flag. `crates/sbproxy-observe/src/logging.rs`'s
//! `init_inner` now calls it. Registering `PeriodicReader` with the
//! `runtime::Tokio` binding panics without an ambient multi-thread
//! Tokio runtime already entered, which does not exist yet when `main()`
//! calls this; switching to `runtime::TokioCurrentThread` (which spawns
//! its own dedicated thread and runtime for the reader's export loop)
//! fixes that. This spawns the real binary with `export_metrics: true`
//! and a short `metrics_interval_secs`, sends one request, and asserts
//! the mock OTLP collector receives at least one metric data point
//! through the real boot path -- exercising both the panic fix and the
//! wiring end to end.

#[path = "otlp_span_arrival_common/mod.rs"]
mod common;

use std::time::Duration;

use sbproxy_e2e::ProxyHarness;

fn config(collector_endpoint: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  observability:
    telemetry:
      enabled: true
      endpoint: "{collector_endpoint}"
      transport: grpc
      sample_rate: 1.0
      export_metrics: true
      metrics_interval_secs: 1
origins:
  "metrics.localhost":
    action:
      type: static
      status_code: 200
      body: "ok"
"#
    )
}

#[test]
fn export_metrics_true_ships_a_metric_data_point_over_the_real_boot_path() {
    // Only the async collector bootstrap and the final async poll run
    // inside block_on; the harness's blocking HTTP call runs in plain
    // sync scope. See otlp_shutdown_flush_e2e.rs for why.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    let collector = rt.block_on(common::start_grpc_collector());

    let harness = ProxyHarness::start_with_yaml(&config(&collector.endpoint)).expect("start proxy");

    let resp = harness
        .get("/", "metrics.localhost")
        .expect("request against the static origin");
    assert_eq!(resp.status, 200);

    // metrics_interval_secs: 1, plus PeriodicReader skips its first
    // (immediate) tick to align with the configured interval, so the
    // first export attempt lands roughly one interval after boot.
    // Generous margin over that for a cold, freshly-spawned process.
    let arrived = rt.block_on(common::wait_for_any_metric_data_point(
        &collector,
        Duration::from_secs(15),
    ));
    assert!(
        arrived,
        "no metric data point arrived at the collector; export_metrics: true is still inert, \
         or the boot path panicked initializing the metrics pipeline (check harness stderr)"
    );
}
