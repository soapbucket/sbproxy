// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Value-delivered report (WOR-1665 core).
//!
//! The headline number that justifies the GPU: what the equivalent
//! hosted API would have charged for every completion served locally
//! at near-zero marginal cost, alongside what the cloud lane actually
//! cost. This aggregates the per-model [`crate::hybrid::LaneSplit`] counters
//! into a report that keeps local-serving value and context-compression value
//! separate. The admin API currently serves this report as JSON. This module
//! also provides a pure CSV formatter for callers that need a tabular export.

use std::collections::BTreeMap;

use crate::hybrid::{CompressionValue, LaneSplit, TokenCountPrecision};

/// One model's line in the value report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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

/// One model and compression lever's contribution to the value report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ModelCompressionValue {
    /// Target model whose input tokens were avoided.
    pub model: String,
    /// Closed compression lever name.
    pub lever: String,
    /// Estimated target-model input tokens avoided.
    pub tokens_saved: u64,
    /// Gross target-model input cost avoided, in micro-USD.
    pub gross_cost_saved_micros: u64,
    /// Precision signal from the target-model token counter.
    pub token_count_precision: TokenCountPrecision,
}

/// The aggregate value-delivered report across all target models.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
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
    /// Per-model, per-lever compression value in stable model/lever order.
    pub compression: Vec<ModelCompressionValue>,
    /// Aggregate compression value keyed by the closed lever name.
    pub compression_totals: BTreeMap<String, CompressionValue>,
    /// Total estimated target-model input tokens avoided by compression.
    pub total_compression_tokens_saved: u64,
    /// Total gross target-model input cost avoided by compression, in
    /// micro-USD.
    pub total_compression_gross_cost_saved_micros: u64,
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
            for (lever, value) in &split.compression {
                report.total_compression_tokens_saved = report
                    .total_compression_tokens_saved
                    .saturating_add(value.tokens_saved);
                report.total_compression_gross_cost_saved_micros = report
                    .total_compression_gross_cost_saved_micros
                    .saturating_add(value.gross_cost_saved_micros);
                use std::collections::btree_map::Entry;
                match report.compression_totals.entry(lever.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(value.clone());
                    }
                    Entry::Occupied(mut entry) => entry.get_mut().record(
                        value.tokens_saved,
                        value.gross_cost_saved_micros,
                        value.token_count_precision,
                    ),
                }
                report.compression.push(ModelCompressionValue {
                    model: model.clone(),
                    lever: lever.clone(),
                    tokens_saved: value.tokens_saved,
                    gross_cost_saved_micros: value.gross_cost_saved_micros,
                    token_count_precision: value.token_count_precision,
                });
            }
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

    /// Render as CSV (one header row plus one row per model).
    ///
    /// The admin route currently serves JSON; this formatter is available to
    /// internal callers and future export surfaces.
    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "model,local_completions,cloud_completions,saved_micros,cloud_spent_micros,compression_tokens_saved,compression_gross_cost_saved_micros\n",
        );
        for m in &self.models {
            let (compression_tokens_saved, compression_cost_saved_micros) = self
                .compression
                .iter()
                .filter(|value| value.model == m.model)
                .fold((0_u64, 0_u64), |(tokens, cost), value| {
                    (
                        tokens.saturating_add(value.tokens_saved),
                        cost.saturating_add(value.gross_cost_saved_micros),
                    )
                });
            out.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                m.model,
                m.local_completions,
                m.cloud_completions,
                m.saved_micros,
                m.cloud_spent_micros,
                compression_tokens_saved,
                compression_cost_saved_micros,
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

    #[test]
    fn exposes_per_model_and_aggregate_compression_value() {
        let mut a = LaneSplit::default();
        a.record_compression("window_fit", 100, 40, TokenCountPrecision::ModelTokenizer);
        a.record_compression(
            "summary_buffer",
            50,
            25,
            TokenCountPrecision::ModelTokenizer,
        );
        let mut b = LaneSplit::default();
        b.record_compression("window_fit", 200, 80, TokenCountPrecision::ModelTokenizer);

        let report = ValueReport::from_lanes(&BTreeMap::from([
            ("alpha".to_string(), a),
            ("beta".to_string(), b),
        ]));

        assert_eq!(report.compression.len(), 3);
        assert_eq!(report.compression[0].model, "alpha");
        assert_eq!(report.compression[0].lever, "summary_buffer");
        assert_eq!(report.compression[1].lever, "window_fit");
        assert_eq!(report.compression[2].model, "beta");
        assert_eq!(report.compression_totals["window_fit"].tokens_saved, 300);
        assert_eq!(
            report.compression_totals["window_fit"].token_count_precision,
            TokenCountPrecision::ModelTokenizer
        );
        assert_eq!(
            report.compression_totals["window_fit"].gross_cost_saved_micros,
            120
        );
        assert_eq!(report.total_compression_tokens_saved, 350);
        assert_eq!(report.total_compression_gross_cost_saved_micros, 145);
        assert_eq!(report.total_local_completions, 0);
        assert_eq!(report.total_cloud_completions, 0);

        let json = serde_json::to_value(&report).expect("report serializes");
        assert_eq!(json["compression"][0]["model"], "alpha");
        assert_eq!(json["compression"][0]["lever"], "summary_buffer");
        assert_eq!(
            json["compression"][0]["token_count_precision"],
            "model_tokenizer"
        );
        assert_eq!(
            json["compression_totals"]["window_fit"]["tokens_saved"],
            300
        );
        assert_eq!(json["total_compression_tokens_saved"], 350);
    }

    #[test]
    fn csv_adds_compression_totals_without_dynamic_columns() {
        let mut split = LaneSplit::default();
        split.record_compression("window_fit", 123, 45, TokenCountPrecision::ModelTokenizer);
        split.record_compression("summary_buffer", 7, 5, TokenCountPrecision::ModelTokenizer);

        let csv = ValueReport::from_lanes(&BTreeMap::from([("m".to_string(), split)])).to_csv();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "model,local_completions,cloud_completions,saved_micros,cloud_spent_micros,compression_tokens_saved,compression_gross_cost_saved_micros"
        );
        assert_eq!(lines[1], "m,0,0,0,0,130,50");
    }
}
