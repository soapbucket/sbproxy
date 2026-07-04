// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Value-delivered report (WOR-1665 core).
//!
//! The headline number that justifies the GPU: what the equivalent
//! hosted API would have charged for every completion served locally
//! at near-zero marginal cost, alongside what the cloud lane actually
//! cost. This aggregates the per-model [`crate::hybrid::LaneSplit`]
//! counters (WOR-1657) into a report the admin API can serve as JSON,
//! Prometheus, or CSV. Pure aggregation and formatting; wiring it to an
//! admin-API route is the runtime half.

use std::collections::BTreeMap;

use crate::hybrid::LaneSplit;

/// One model's line in the value report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelValue {
    /// The advertised model name.
    pub model: String,
    /// Completions served locally.
    pub local_completions: u64,
    /// Completions that spilled to a cloud provider.
    pub cloud_completions: u64,
    /// Micro-USD saved by serving locally (displaced cloud cost).
    pub saved_micros: u64,
    /// Micro-USD actually spent on the cloud lane.
    pub cloud_spent_micros: u64,
}

/// The aggregate value-delivered report across all local models.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValueReport {
    /// Per-model lines, sorted by model name for a stable rendering.
    pub models: Vec<ModelValue>,
    /// Total micro-USD saved across every model.
    pub total_saved_micros: u64,
    /// Total micro-USD spent on cloud spill across every model.
    pub total_cloud_spent_micros: u64,
    /// Total local completions.
    pub total_local_completions: u64,
    /// Total cloud completions.
    pub total_cloud_completions: u64,
}

impl ValueReport {
    /// Aggregate a per-model map of lane splits into a report.
    pub fn from_lanes(lanes: &BTreeMap<String, LaneSplit>) -> Self {
        let mut report = ValueReport::default();
        for (model, split) in lanes {
            report.total_saved_micros =
                report.total_saved_micros.saturating_add(split.saved_micros);
            report.total_cloud_spent_micros = report
                .total_cloud_spent_micros
                .saturating_add(split.cloud_spent_micros);
            report.total_local_completions = report
                .total_local_completions
                .saturating_add(split.local_completions);
            report.total_cloud_completions = report
                .total_cloud_completions
                .saturating_add(split.cloud_completions);
            report.models.push(ModelValue {
                model: model.clone(),
                local_completions: split.local_completions,
                cloud_completions: split.cloud_completions,
                saved_micros: split.saved_micros,
                cloud_spent_micros: split.cloud_spent_micros,
            });
        }
        report
    }

    /// Total saved rendered as whole US dollars (micros / 1e6, floored).
    pub fn total_saved_dollars(&self) -> u64 {
        self.total_saved_micros / 1_000_000
    }

    /// Fraction of completions served locally across all models
    /// (0.0 when none yet).
    pub fn local_fraction(&self) -> f64 {
        let total = self.total_local_completions + self.total_cloud_completions;
        if total == 0 {
            0.0
        } else {
            self.total_local_completions as f64 / total as f64
        }
    }

    /// Render as CSV (one header row + one row per model). The admin
    /// API also serves JSON and Prometheus; this is the tabular form.
    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "model,local_completions,cloud_completions,saved_micros,cloud_spent_micros\n",
        );
        for m in &self.models {
            out.push_str(&format!(
                "{},{},{},{},{}\n",
                m.model,
                m.local_completions,
                m.cloud_completions,
                m.saved_micros,
                m.cloud_spent_micros
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::CloudPrice;

    fn cloud() -> CloudPrice {
        CloudPrice {
            prompt_micros_per_mtok: 3_000_000,
            completion_micros_per_mtok: 15_000_000,
        }
    }

    fn lanes() -> BTreeMap<String, LaneSplit> {
        let mut a = LaneSplit::default();
        a.record_local(1000, 500, cloud()); // saves 10_500
        a.record_local(1000, 500, cloud()); // saves 10_500
        let mut b = LaneSplit::default();
        b.record_local(1000, 500, cloud()); // saves 10_500
        b.record_cloud(1000, 500, cloud()); // spends 10_500
        BTreeMap::from([("qwen".to_string(), a), ("glm".to_string(), b)])
    }

    #[test]
    fn aggregates_savings_and_totals() {
        let r = ValueReport::from_lanes(&lanes());
        assert_eq!(r.total_saved_micros, 31_500); // 10.5k * 3
        assert_eq!(r.total_cloud_spent_micros, 10_500);
        assert_eq!(r.total_local_completions, 3);
        assert_eq!(r.total_cloud_completions, 1);
        // 2 models, sorted by name (BTreeMap order: glm, qwen).
        assert_eq!(r.models.len(), 2);
        assert_eq!(r.models[0].model, "glm");
        assert_eq!(r.models[1].model, "qwen");
    }

    #[test]
    fn dollars_and_fraction() {
        // 2_500_000 micros saved -> 2 whole dollars.
        let big = LaneSplit {
            saved_micros: 2_500_000,
            local_completions: 3,
            cloud_completions: 1,
            ..LaneSplit::default()
        };
        let r = ValueReport::from_lanes(&BTreeMap::from([("m".to_string(), big)]));
        assert_eq!(r.total_saved_dollars(), 2);
        assert!((r.local_fraction() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn empty_report_is_zero() {
        let r = ValueReport::from_lanes(&BTreeMap::new());
        assert_eq!(r.total_saved_micros, 0);
        assert_eq!(r.local_fraction(), 0.0);
        assert_eq!(r.total_saved_dollars(), 0);
    }

    #[test]
    fn csv_has_header_and_rows() {
        let csv = ValueReport::from_lanes(&lanes()).to_csv();
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[0].starts_with("model,local_completions"));
        assert_eq!(lines.len(), 3); // header + 2 models
    }
}
