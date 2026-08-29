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
    AlertRuntimeSnapshot, CertExpiryReading, CircuitBreakerReading, CircuitBreakerState,
    EngineConfig, MetricReadings,
};
use tokio::sync::{broadcast, mpsc};

/// How often the loop samples the registry and evaluates the rules.
const EVAL_INTERVAL_SECS: u64 = 60;
const ALERT_COMMAND_CAPACITY: usize = 32;

#[derive(Debug)]
enum AlertCommand {
    TestChannel(usize),
    Fire(Alert),
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
pub(crate) fn install(
    phase_rx: broadcast::Receiver<ExecutionPhase>,
    cert_expiry_reader: Option<sbproxy_tls::AcmeExpiryReader>,
) {
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
        cert_expiry_reader,
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

/// Fire an ad-hoc alert on every configured channel (Slack, webhook,
/// PagerDuty). Used for MCP Confirm holds so a parked call pages the
/// same destinations as a metric rule. A no-op when alerting was not
/// installed at boot.
pub(crate) fn fire_event_alert(alert: Alert) {
    let Some(control) = ALERT_CONTROL.get() else {
        return;
    };
    let _ = control.command_tx.try_send(AlertCommand::Fire(alert));
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
    cert_expiry_reader: Option<sbproxy_tls::AcmeExpiryReader>,
) {
    let dispatcher = AlertDispatcher::with_runtime(channels.clone(), runtime.clone());
    let engine_config = EngineConfig::default();
    let mut engine = AlertEngine::new(engine_config);

    let mut tick = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first tick returns immediately; take it to establish the counter
    // baseline so the first evaluated window spans a full interval.
    tick.tick().await;
    let mut prev = alerting::sample_registry();
    let mut commands_open = true;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let now = alerting::sample_registry();
                let p99_latency_ms = alerting::histogram_quantile_delta_ms(
                    &prev.request_latency,
                    &now.request_latency,
                    0.99,
                );
                let minute_sample = now.request_metrics_present.then(|| {
                    alerting::minute_sample_delta(
                        prev.request_counters,
                        now.request_counters,
                        p99_latency_ms,
                    )
                }).flatten();
                let rate_limit_window =
                    alerting::rate_limit_delta(prev.rate_limit_counters, now.rate_limit_counters);
                let gateway_window = alerting::gateway_rejection_delta(
                    prev.gateway_counters,
                    now.gateway_counters,
                );
                let pipeline = crate::reload::current_pipeline();
                let circuit_breakers = sample_circuit_breakers(
                    &pipeline.actions,
                    &pipeline.forward_rules,
                    |action_index, forward_rule_index| {
                        pipeline.config.origins.get(action_index).map(|origin| match forward_rule_index {
                            Some(rule_index) => format!(
                                "{}/{}#forward-rule-{rule_index}",
                                origin.workspace_id, origin.origin_id
                            ),
                            None => format!("{}/{}", origin.workspace_id, origin.origin_id),
                        })
                    },
                );
                let readings = MetricReadings {
                    budget_utilization: now.budget_utilization,
                    provider_error_rate: alerting::error_burn(
                        prev.provider_counters,
                        now.provider_counters,
                    ),
                    provider_attempts: alerting::provider_attempt_delta(
                        prev.provider_counters,
                        now.provider_counters,
                    ),
                    gateway_rejection_rate: gateway_window.map(|(rate, _)| rate),
                    gateway_decisions: gateway_window
                        .map(|(_, decisions)| decisions)
                        .unwrap_or_default(),
                    p99_latency_ms: minute_sample.and(p99_latency_ms),
                    rate_limit_rejections: rate_limit_window.map(|(rejections, _)| rejections),
                    rate_limit_decisions: rate_limit_window
                        .map(|(_, decisions)| decisions)
                        .unwrap_or_default(),
                    cert_expiry: cert_expiry_reader
                        .as_ref()
                        .and_then(sbproxy_tls::AcmeExpiryReader::earliest)
                        .map(|expiry| CertExpiryReading {
                            hostname: expiry.hostname,
                            days_remaining: expiry.days_remaining,
                        }),
                    circuit_breakers,
                    minute_sample,
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
                    Some(AlertCommand::Fire(alert)) => {
                        runtime.record_alert(&alert);
                        dispatcher.fire(alert);
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

fn sample_circuit_breakers<F>(
    actions: &[sbproxy_modules::Action],
    forward_rules: &[Vec<crate::pipeline::CompiledForwardRule>],
    mut action_identity: F,
) -> Option<Vec<CircuitBreakerReading>>
where
    F: FnMut(usize, Option<usize>) -> Option<String>,
{
    let mut readings = Vec::new();
    let mut sample_action = |action_index: usize,
                             forward_rule_index: Option<usize>,
                             action: &sbproxy_modules::Action|
     -> Option<()> {
        let sbproxy_modules::Action::LoadBalancer(load_balancer) = action else {
            return Some(());
        };
        let Some(breakers) = load_balancer.circuit_breakers.as_ref() else {
            return Some(());
        };
        // The compiled origin IDs are bounded configuration values and are
        // parallel to `actions`. They distinguish two load-balancer actions
        // without placing target URLs or process-local pointer values into
        // alert identities.
        let action_identity = action_identity(action_index, forward_rule_index)?;
        readings.extend(breakers.iter().enumerate().map(|(index, breaker)| {
            let state = match breaker.state() {
                sbproxy_platform::CircuitState::Closed => CircuitBreakerState::Closed,
                sbproxy_platform::CircuitState::Open => CircuitBreakerState::Open,
                sbproxy_platform::CircuitState::HalfOpen => CircuitBreakerState::HalfOpen,
            };
            CircuitBreakerReading {
                origin: format!("{action_identity}#target-{index}"),
                state,
            }
        }));
        Some(())
    };
    for (action_index, action) in actions.iter().enumerate() {
        sample_action(action_index, None, action)?;
        if let Some(rules) = forward_rules.get(action_index) {
            for (rule_index, rule) in rules.iter().enumerate() {
                sample_action(action_index, Some(rule_index), &rule.action)?;
            }
        }
    }
    // An available pipeline with no configured breakers is a complete empty
    // snapshot. The engine uses it to resolve incidents removed by reload.
    Some(readings)
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
    use sbproxy_observe::alerting::{RequestCounters, RuleEvaluationState};

    fn breaker_origin_identity(
        action_index: usize,
        forward_rule_index: Option<usize>,
    ) -> Option<String> {
        Some(match forward_rule_index {
            Some(rule_index) => {
                format!("workspace/origin-{action_index}#forward-rule-{rule_index}")
            }
            None => format!("workspace/origin-{action_index}"),
        })
    }

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
        let loop_task = tokio::spawn(run(
            phase_rx,
            3_600,
            channels,
            runtime.clone(),
            command_rx,
            None,
        ));

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

    #[test]
    fn breaker_sampler_reads_configured_load_balancer_state() {
        let load_balancer = std::sync::Arc::new(
            sbproxy_modules::LoadBalancerAction::from_config(serde_json::json!({
                "targets": [{"url": "https://upstream.example"}],
                "circuit_breaker": {
                    "failure_threshold": 1,
                    "success_threshold": 1,
                    "open_duration_secs": 60
                }
            }))
            .unwrap(),
        );
        load_balancer.record_breaker_failure(0);
        let actions = vec![sbproxy_modules::Action::LoadBalancer(load_balancer)];

        let readings = sample_circuit_breakers(&actions, &[], breaker_origin_identity).unwrap();
        assert_eq!(readings.len(), 1);
        assert_eq!(readings[0].origin, "workspace/origin-0#target-0");
        assert_eq!(
            readings[0].state,
            sbproxy_observe::alerting::CircuitBreakerState::Open
        );
        assert_eq!(
            sample_circuit_breakers(&[], &[], breaker_origin_identity),
            Some(Vec::new())
        );
    }

    fn load_balancer_with_breaker(open: bool) -> sbproxy_modules::Action {
        let load_balancer = std::sync::Arc::new(
            sbproxy_modules::LoadBalancerAction::from_config(serde_json::json!({
                "targets": [{"url": "https://shared-upstream.example"}],
                "circuit_breaker": {
                    "failure_threshold": 1,
                    "success_threshold": 1,
                    "open_duration_secs": 60
                }
            }))
            .unwrap(),
        );
        if open {
            load_balancer.record_breaker_failure(0);
        }
        sbproxy_modules::Action::LoadBalancer(load_balancer)
    }

    fn forward_rules_with_breaker(open: bool) -> Vec<Vec<crate::pipeline::CompiledForwardRule>> {
        vec![vec![crate::pipeline::CompiledForwardRule {
            matchers: Vec::new(),
            action: load_balancer_with_breaker(open),
            request_modifiers: Vec::new(),
            parameters: Vec::new(),
            id: None,
            deprecation: None,
        }]]
    }

    #[test]
    fn forward_rule_breakers_open_resolve_and_disappear_by_stable_identity() {
        let actions = vec![sbproxy_modules::Action::Noop];
        let identity = |origin_index: usize, forward_rule_index: Option<usize>| {
            Some(match forward_rule_index {
                Some(rule_index) => {
                    format!("workspace/origin-{origin_index}#forward-rule-{rule_index}")
                }
                None => format!("workspace/origin-{origin_index}"),
            })
        };
        let opened =
            sample_circuit_breakers(&actions, &forward_rules_with_breaker(true), identity).unwrap();
        assert_eq!(
            opened[0].origin,
            "workspace/origin-0#forward-rule-0#target-0"
        );

        let mut engine = AlertEngine::new(EngineConfig::default());
        assert_eq!(
            engine
                .evaluate(&MetricReadings {
                    circuit_breakers: Some(opened),
                    ..MetricReadings::default()
                })
                .len(),
            1
        );
        let recovered =
            sample_circuit_breakers(&actions, &forward_rules_with_breaker(false), identity)
                .unwrap();
        let resolved = engine.evaluate(&MetricReadings {
            circuit_breakers: Some(recovered),
            ..MetricReadings::default()
        });
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].resolved);

        let reopened =
            sample_circuit_breakers(&actions, &forward_rules_with_breaker(true), identity).unwrap();
        let reopened_events = engine.evaluate(&MetricReadings {
            circuit_breakers: Some(reopened),
            ..MetricReadings::default()
        });
        assert_eq!(reopened_events.len(), 1);
        assert!(!reopened_events[0].resolved);

        let removed = sample_circuit_breakers(&actions, &[Vec::new()], identity).unwrap();
        assert!(removed.is_empty());
        let removal_events = engine.evaluate(&MetricReadings {
            circuit_breakers: Some(removed),
            ..MetricReadings::default()
        });
        assert_eq!(removal_events.len(), 1);
        assert!(removal_events[0].resolved);
    }

    #[test]
    fn duplicate_targets_in_separate_actions_keep_independent_breaker_incidents() {
        let actions = vec![
            load_balancer_with_breaker(true),
            load_balancer_with_breaker(false),
        ];
        let readings = sample_circuit_breakers(&actions, &[], breaker_origin_identity).unwrap();
        assert_ne!(readings[0].origin, readings[1].origin);

        let mut engine = AlertEngine::new(EngineConfig::default());
        let fired = engine.evaluate(&MetricReadings {
            circuit_breakers: Some(readings),
            ..MetricReadings::default()
        });
        assert_eq!(fired.len(), 1);
        assert!(!fired[0].resolved);
        assert_eq!(engine.firing_count(), 1);

        let recovered = engine.evaluate(&MetricReadings {
            circuit_breakers: sample_circuit_breakers(
                &[
                    load_balancer_with_breaker(false),
                    load_balancer_with_breaker(false),
                ],
                &[],
                breaker_origin_identity,
            ),
            ..MetricReadings::default()
        });
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].resolved);
        assert_eq!(engine.firing_count(), 0);
    }

    #[test]
    fn removing_the_final_configured_breaker_resolves_its_incident() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        let fired = engine.evaluate(&MetricReadings {
            circuit_breakers: sample_circuit_breakers(
                &[load_balancer_with_breaker(true)],
                &[],
                breaker_origin_identity,
            ),
            ..MetricReadings::default()
        });
        assert_eq!(fired.len(), 1);

        let removed = sample_circuit_breakers(&[], &[], breaker_origin_identity);
        assert_eq!(removed, Some(Vec::new()));
        let resolved = engine.evaluate(&MetricReadings {
            circuit_breakers: removed,
            ..MetricReadings::default()
        });
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].resolved);
        assert_eq!(engine.firing_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_wall_clock_minutes_age_burn_failures_out_of_the_ring() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        let failure = alerting::minute_sample_delta(
            RequestCounters::default(),
            RequestCounters {
                requests: 1.0,
                errors: 1.0,
            },
            None,
        )
        .unwrap();
        // The rule is inactive until the ring holds the shortest objective's
        // full hour, so it takes sixty failing minutes to open the incident
        // this test then ages back out. One failing minute opens nothing.
        let mut fired = Vec::new();
        for _ in 0..60 {
            fired.extend(engine.evaluate(&MetricReadings {
                minute_sample: Some(failure),
                ..MetricReadings::default()
            }));
        }
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, "burn_rate");

        let mut minute = tokio::time::interval(Duration::from_secs(60));
        minute.tick().await;
        let idle = RequestCounters {
            requests: 1.0,
            errors: 1.0,
        };
        let mut recovered = Vec::new();
        for _ in 0..1_440 {
            tokio::time::advance(Duration::from_secs(60)).await;
            minute.tick().await;
            let sample = alerting::minute_sample_delta(idle, idle, None)
                .expect("an idle wall-clock minute must still occupy a ring bucket");
            recovered.extend(engine.evaluate(&MetricReadings {
                minute_sample: Some(sample),
                ..MetricReadings::default()
            }));
        }

        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].resolved);
        assert_eq!(engine.burn_rate_sample_count(), 1_440);
        assert_eq!(
            engine
                .latest_evaluations()
                .iter()
                .find(|evaluation| evaluation.rule == "burn_rate")
                .unwrap()
                .state,
            RuleEvaluationState::Ok
        );
    }
}
