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

use std::sync::OnceLock;
use std::time::Duration;

use pingora_core::server::ExecutionPhase;
use sbproxy_observe::alerting::{
    self, Alert, AlertChannelConfig, AlertDispatcher, AlertEngine, AlertRuntime,
    AlertRuntimeSnapshot, EngineConfig, MetricReadings, ProviderCounters,
};
use tokio::sync::{broadcast, mpsc};

/// How often the loop samples the registry and evaluates the rules.
const EVAL_INTERVAL_SECS: u64 = 30;
const ALERT_COMMAND_CAPACITY: usize = 32;

#[derive(Debug)]
enum AlertCommand {
    TestChannel(usize),
}

#[derive(Clone)]
struct AlertControl {
    runtime: AlertRuntime,
    command_tx: mpsc::Sender<AlertCommand>,
}

/// Failure to queue an admin alert-runtime command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AlertControlError {
    /// No alert runtime is installed for this process.
    #[error("alert runtime is unavailable")]
    Unavailable,
    /// The requested channel index is not configured.
    #[error("unknown alert channel index {0}")]
    UnknownChannel(usize),
    /// The bounded command queue is temporarily full.
    #[error("alert command queue is full")]
    QueueFull,
}

static ALERT_CONTROL: OnceLock<AlertControl> = OnceLock::new();

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
/// the evaluation loop. A no-op when no alerting configuration was installed.
///
/// `phase_rx` is Pingora's execution-phase broadcast; the loop flushes
/// in-flight webhook deliveries when it reports graceful termination.
pub(crate) fn install(phase_rx: broadcast::Receiver<ExecutionPhase>) {
    if !alerting::has_alerting_config() {
        return;
    }
    let channels = alerting::configured_channels();
    let (control, command_rx) = build_alert_control(&channels);
    if ALERT_CONTROL.set(control.clone()).is_err() {
        return;
    }
    alerting_runtime().spawn(run(
        phase_rx,
        EVAL_INTERVAL_SECS,
        channels,
        control.runtime,
        command_rx,
    ));
}

fn build_alert_control(
    channels: &[AlertChannelConfig],
) -> (AlertControl, mpsc::Receiver<AlertCommand>) {
    let engine_config = EngineConfig::default();
    let runtime = AlertRuntime::new(&engine_config, channels);
    let (command_tx, command_rx) = mpsc::channel(ALERT_COMMAND_CAPACITY);
    (
        AlertControl {
            runtime,
            command_tx,
        },
        command_rx,
    )
}

/// Current process alert snapshot, if alerting was configured at boot.
pub(crate) fn alert_snapshot() -> Option<AlertRuntimeSnapshot> {
    ALERT_CONTROL
        .get()
        .map(|control| control.runtime.snapshot())
}

/// Queue a targeted channel test without waiting for network delivery.
pub(crate) fn queue_channel_test(channel_index: usize) -> Result<(), AlertControlError> {
    let control = ALERT_CONTROL.get().ok_or(AlertControlError::Unavailable)?;
    control.queue_channel_test(channel_index)
}

impl AlertControl {
    fn queue_channel_test(&self, channel_index: usize) -> Result<(), AlertControlError> {
        if channel_index >= self.runtime.channel_count() {
            return Err(AlertControlError::UnknownChannel(channel_index));
        }
        self.command_tx
            .try_send(AlertCommand::TestChannel(channel_index))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => AlertControlError::QueueFull,
                mpsc::error::TrySendError::Closed(_) => AlertControlError::Unavailable,
            })
    }
}

async fn run(
    mut phase_rx: broadcast::Receiver<ExecutionPhase>,
    interval_secs: u64,
    channels: Vec<AlertChannelConfig>,
    runtime: AlertRuntime,
    mut command_rx: mpsc::Receiver<AlertCommand>,
) {
    let dispatcher = AlertDispatcher::with_runtime(channels.clone(), runtime.clone());
    let engine_config = EngineConfig::default();
    let mut engine = AlertEngine::new(engine_config);

    let mut tick = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first tick returns immediately; take it to establish the counter
    // baseline so the first evaluated window spans a full interval.
    tick.tick().await;
    let mut prev: ProviderCounters = alerting::sample_registry().0;
    let mut commands_open = true;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let (now, budget) = alerting::sample_registry();
                let readings = MetricReadings {
                    budget_utilization: budget,
                    provider_error_rate: alerting::error_burn(prev, now),
                    provider_attempts: alerting::provider_attempt_delta(prev, now),
                };
                prev = now;
                let alerts = engine.evaluate(&readings);
                runtime.record_evaluations(engine.latest_evaluations());
                for alert in alerts {
                    runtime.record_alert(&alert);
                    dispatcher.fire(alert);
                }
            }
            command = command_rx.recv(), if commands_open => {
                match command {
                    Some(AlertCommand::TestChannel(channel_index)) => {
                        if let Some(channel) = channels.get(channel_index) {
                            let alert = channel_test_alert(channel_index, channel);
                            runtime.record_test_alert(channel_index, &alert);
                            let _ = dispatcher.fire_channel(channel_index, alert);
                        }
                    }
                    None => commands_open = false,
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

fn channel_test_alert(channel_index: usize, channel: &AlertChannelConfig) -> Alert {
    Alert {
        rule: "channel_test".to_string(),
        severity: "warning".to_string(),
        message: format!(
            "Operator requested a test of {} alert channel #{channel_index}",
            channel.channel_type
        ),
        timestamp: chrono::Utc::now().to_rfc3339(),
        labels: std::collections::HashMap::from([
            ("channel_index".to_string(), channel_index.to_string()),
            ("channel_type".to_string(), channel.channel_type.clone()),
        ]),
        resolved: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_observe::alerting::runtime::{AlertHistoryEvent, DeliveryStatus};
    use sbproxy_observe::alerting::AlertChannelConfig;

    // Paused time removes the wall clock from this test. A log-channel
    // delivery is synchronous once the loop receives the command, so the
    // only thing a real-time budget measured was how quickly a saturated
    // machine scheduled the spawned task; the full workspace run starved
    // it past ten seconds. With time paused the runtime auto-advances
    // whenever every task is idle, so the poll below resolves as soon as
    // the delivery lands, deterministically and under any load.
    #[tokio::test(start_paused = true)]
    async fn channel_test_command_queues_and_runs_on_the_alert_runtime() {
        let channels = vec![AlertChannelConfig {
            channel_type: "log".to_string(),
            url: None,
            headers: vec![],
            secret: None,
            routing_key: None,
        }];
        let (control, command_rx) = build_alert_control(&channels);
        let runtime = control.runtime.clone();
        let (phase_tx, phase_rx) = broadcast::channel(4);
        let loop_task = tokio::spawn(run(phase_rx, 3_600, channels, runtime.clone(), command_rx));

        control.queue_channel_test(0).unwrap();
        // Sleep between polls rather than spinning on `yield_now`: under
        // paused time a sleep is what lets the clock auto-advance, and the
        // budget is virtual, so it bounds a genuinely broken delivery
        // without ever measuring machine load.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let snapshot = runtime.snapshot();
                if snapshot.history.len() == 1
                    && snapshot.channels[0].health.status == DeliveryStatus::Healthy
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("test delivery should complete asynchronously");

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.history[0].event, AlertHistoryEvent::Test);
        assert_eq!(snapshot.history[0].channel_index, Some(0));
        assert_eq!(snapshot.history[0].alert.rule, "channel_test");
        assert_eq!(
            control.queue_channel_test(4),
            Err(AlertControlError::UnknownChannel(4))
        );

        phase_tx.send(ExecutionPhase::GracefulTerminate).unwrap();
        loop_task.await.unwrap();
    }
}
