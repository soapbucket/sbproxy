// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Boot wiring for the alert evaluation loop.
//!
//! `sbproxy-observe` owns the dispatcher, the rule evaluators, and the pure
//! firing-state engine; this module is the process-side glue that builds them
//! at boot and runs them. It mirrors `cluster_metrics::run_loop`: a
//! dedicated, process-lifetime runtime hosts one async task that samples the
//! live Prometheus registry on a fixed cadence, drives the engine, and
//! dispatches whatever the engine decides to fire.
//!
//! Reading metrics and posting webhooks never touches the request path. A
//! delivery failure is counted on the dropped-telemetry counter inside the
//! dispatcher and the loop keeps going.
//!
//! The channels arrive already resolved: the binary resolves secret references
//! in `url` / `routing_key` (it owns the vault backends) and installs the
//! finished set via `sbproxy_observe::alerting::install_channels`. When nothing
//! is installed, `install` returns without spawning anything, so a proxy that
//! does not configure `proxy.alerting` pays nothing.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use pingora_core::server::ExecutionPhase;
use sbproxy_observe::alerting::{
    self, AlertDispatcher, AlertEngine, EngineConfig, MetricReadings, ProviderCounters,
};
use tokio::sync::broadcast;

/// How often the loop samples the registry and evaluates the rules.
const EVAL_INTERVAL_SECS: u64 = 30;

/// A dedicated, process-lifetime runtime for the alert loop, independent of the
/// Pingora service runtimes. Mirrors `key_plane` and `cluster`.
fn alerting_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("sbproxy-alerting")
            .enable_all()
            .build()
            .expect("build alerting runtime")
    })
}

/// Build the dispatcher and engine from the boot-installed channels and spawn
/// the evaluation loop. A no-op when no channels were installed.
///
/// `phase_rx` is Pingora's execution-phase broadcast; the loop flushes
/// in-flight webhook deliveries when it reports graceful termination.
pub(crate) fn install(phase_rx: broadcast::Receiver<ExecutionPhase>) {
    if !alerting::has_configured_channels() {
        return;
    }
    alerting_runtime().spawn(run(phase_rx, EVAL_INTERVAL_SECS));
}

async fn run(mut phase_rx: broadcast::Receiver<ExecutionPhase>, interval_secs: u64) {
    let dispatcher = Arc::new(AlertDispatcher::new(alerting::configured_channels()));
    let mut engine = AlertEngine::new(EngineConfig::default());

    let mut tick = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first tick returns immediately; take it to establish the counter
    // baseline so the first evaluated window spans a full interval.
    tick.tick().await;
    let mut prev: ProviderCounters = alerting::sample_registry().0;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let (now, budget) = alerting::sample_registry();
                let readings = MetricReadings {
                    budget_utilization: budget,
                    provider_error_rate: alerting::error_burn(prev, now),
                };
                prev = now;
                for alert in engine.evaluate(&readings) {
                    dispatcher.fire(alert);
                }
            }
            phase = phase_rx.recv() => {
                match phase {
                    Ok(ExecutionPhase::GracefulTerminate)
                    | Ok(ExecutionPhase::ShutdownStarted)
                    | Ok(ExecutionPhase::Terminated)
                    | Err(broadcast::error::RecvError::Closed) => {
                        // Flush in-flight deliveries, then stop. An alert is
                        // most likely to fire during the incident that triggers
                        // the shutdown, so dropping the last one is the wrong
                        // default.
                        dispatcher.drain().await;
                        return;
                    }
                    // A lagged receiver or an earlier lifecycle phase: keep
                    // evaluating.
                    _ => {}
                }
            }
        }
    }
}
