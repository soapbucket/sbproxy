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

pub mod channels;
pub mod error_rate;
pub mod rate_limit;
pub mod rules;
pub mod slo;

pub use channels::{Alert, AlertChannelConfig, AlertDispatcher};
