//! Billing subsystem (WOR-2672 port of `sbproxy-enterprise-ai::billing`):
//! showback/chargeback, unified bill generation, and spend forecasting.
//!
//! Layers onto this crate's existing usage/cost tracking rather than
//! duplicating it: [`chargeback::ChargebackTracker`] implements
//! [`crate::usage_sink::UsageSink`], the same seam
//! `JsonlFileSink` / `WebhookSink` / `LangfuseSink` / `DatadogSink` (see
//! [`crate::usage_sink`]) already implement, so an embedder registers it
//! as one more sink rather than wiring a parallel capture path. See
//! [`chargeback`]'s module docs for the full account of what changed
//! from the enterprise source and why (storage dropped, employee-scoped
//! chargeback not ported, the sink surface reshaped around one complete
//! event per call instead of three partial ones).
//!
//! ## Modules
//!
//! - [`chargeback`] - Per-event usage attribution and workspace/team cost
//!   aggregation.
//! - [`unified`] - Aggregate chargeback entries into a printable bill.
//! - [`forecast`] - Predictive spend forecasting and budget exhaustion
//!   detection.
//!
//! No dependency on the classifier sidecar or any other WOR-2661 port.
//! See `docs/ai-chargeback.md` and `examples/ai-chargeback-billing/`.

pub mod chargeback;
pub mod forecast;
pub mod unified;

pub use chargeback::{ChargebackEntry, ChargebackTracker, WorkspaceTotals, UNATTRIBUTED};
pub use forecast::{
    days_until_exhaustion, forecast_spend, remaining_budget, will_exceed_budget, UsageDataPoint,
};
pub use unified::{generate_bill, BillLineItem, UnifiedBill};
