//! Alert notification system.
//!
//! Evaluates alert rules against metric values and fires notifications
//! to configured channels (webhook, log).
//!
//! # Usage
//!
//! ```ignore
//! use sbproxy_observe::alerting::{AlertDispatcher, channels::AlertChannelConfig};
//! use sbproxy_observe::alerting::rules;
//!
//! let dispatcher = AlertDispatcher::new(vec![
//!     AlertChannelConfig { channel_type: "log".into(), url: None, headers: vec![] },
//! ]);
//!
//! if let Some(alert) = rules::check_budget_exhaustion(0.95, &[0.80, 0.95]) {
//!     dispatcher.fire(alert);
//! }
//! ```

pub mod burn_rate;
pub mod channels;
pub mod engine;
pub mod error_rate;
pub mod rate_limit;
pub mod rules;
pub mod runtime;
pub mod slo;

pub use channels::{Alert, AlertChannelConfig, AlertDispatcher};
pub use engine::{
    error_burn, provider_attempt_delta, sample_registry, AlertEngine, EngineConfig, MetricReadings,
    ProviderCounters, RuleEvaluation, RuleEvaluationState,
};
pub use runtime::{AlertRuntime, AlertRuntimeSnapshot};

use std::sync::OnceLock;

/// The alert channels resolved at boot, installed by the binary once secret
/// references in `url` / `routing_key` have been resolved.
///
/// The binary owns secret resolution (it depends on the vault backends);
/// `sbproxy-core`, which spawns the evaluation loop, does not. So the binary
/// resolves and installs the finished channel set here, mirroring
/// [`crate::telemetry::install_resolved_otlp_headers`], and core reads it back
/// with [`configured_channels`] at boot. Empty (never installed) means no
/// dispatcher is built and the loop never spawns.
static RESOLVED_CHANNELS: OnceLock<Vec<AlertChannelConfig>> = OnceLock::new();

/// Install the boot-resolved alert channels. Call once from the binary after
/// resolving secret references; a second call is ignored.
pub fn install_channels(channels: Vec<AlertChannelConfig>) {
    let _ = RESOLVED_CHANNELS.set(channels);
}

/// The boot-resolved alert channels, empty when none were installed (as in
/// `validate` / tests, or a config with no `proxy.alerting.channels`).
pub fn configured_channels() -> Vec<AlertChannelConfig> {
    RESOLVED_CHANNELS.get().cloned().unwrap_or_default()
}

/// Whether any alert channel was installed at boot. Lets core skip building a
/// dispatcher and spawning the loop when alerting is not configured.
pub fn has_configured_channels() -> bool {
    RESOLVED_CHANNELS.get().is_some_and(|c| !c.is_empty())
}
