// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Hybrid local/cloud polish (WOR-1657 slice).
//!
//! Pure pieces that make the local lane feel like one array with the
//! paid providers. [`savings_micros`] computes the dollars a local
//! completion saved versus the cloud price it displaced, and
//! [`LaneSplit`] tallies those savings per model alongside target-model token
//! estimates and gross input cost avoided by context compression. Both
//! dimensions feed the value-delivered report without conflating compression
//! with a local or cloud completion.
//!
//! Deterministic and unit-tested here; the value recorder in
//! `sbproxy-ai` persists these tallies and the admin API serves them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Precision signal for the target-model token counter used by compression
/// value accounting.
///
/// Both variants are gateway estimates. `ModelTokenizer` means the target
/// model resolved to a registered BPE tokenizer; `Heuristic` means the
/// documented UTF-8 byte-length fallback was used.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TokenCountPrecision {
    /// A registered target-model tokenizer produced the estimate.
    ModelTokenizer,
    /// The conservative UTF-8 byte-length fallback produced the estimate.
    #[default]
    Heuristic,
}

impl TokenCountPrecision {
    /// Closed JSON and metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelTokenizer => "model_tokenizer",
            Self::Heuristic => "heuristic",
        }
    }

    /// Combine aggregates conservatively: any heuristic contribution makes
    /// the combined token total heuristic.
    pub const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::ModelTokenizer, Self::ModelTokenizer) => Self::ModelTokenizer,
            _ => Self::Heuristic,
        }
    }
}

/// Cloud reference price for a model, in micro-USD per million tokens
/// (micros avoid float drift and match the ledger's cost unit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CloudPrice {
    /// Micro-USD per 1e6 prompt tokens.
    pub prompt_micros_per_mtok: u64,
    /// Micro-USD per 1e6 completion tokens.
    pub completion_micros_per_mtok: u64,
}

/// Micro-USD a local completion saved versus the cloud price it
/// displaced: what the same prompt+completion token counts would have
/// cost at `cloud`. A local completion's marginal API cost is zero, so
/// the displaced cost is the whole saving.
///
/// Uses integer math on micros with rounding, so it reconciles with a
/// ledger that spends in the same unit.
pub fn savings_micros(prompt_tokens: u64, completion_tokens: u64, cloud: CloudPrice) -> u64 {
    let prompt = mul_div_round(prompt_tokens, cloud.prompt_micros_per_mtok, 1_000_000);
    let completion = mul_div_round(
        completion_tokens,
        cloud.completion_micros_per_mtok,
        1_000_000,
    );
    prompt.saturating_add(completion)
}

/// `(a * b + denom/2) / denom` in u128 to avoid overflow, rounded to
/// nearest.
fn mul_div_round(a: u64, b: u64, denom: u64) -> u64 {
    if denom == 0 {
        return 0;
    }
    let num = a as u128 * b as u128 + (denom as u128 / 2);
    (num / denom as u128) as u64
}

/// Value delivered by one context-compression lever.
///
/// The token count comes from the target-model counter used by the
/// compression runner. Cost is the gross target-model input cost avoided;
/// internal summarizer spend remains a separate accounting stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionValue {
    /// Estimated target-model input tokens avoided.
    #[serde(default)]
    pub tokens_saved: u64,
    /// Gross target-model input cost avoided, in micro-USD.
    #[serde(default)]
    pub gross_cost_saved_micros: u64,
    /// Precision of the target-model token counts in this aggregate.
    ///
    /// Missing legacy fields default to `heuristic`, the conservative signal.
    #[serde(default)]
    pub token_count_precision: TokenCountPrecision,
}

impl CompressionValue {
    /// Start an aggregate from one applied compression result.
    pub fn new(
        tokens_saved: u64,
        gross_cost_saved_micros: u64,
        token_count_precision: TokenCountPrecision,
    ) -> Self {
        Self {
            tokens_saved,
            gross_cost_saved_micros,
            token_count_precision,
        }
    }

    /// Add one applied compression result with saturating arithmetic.
    pub fn record(
        &mut self,
        tokens_saved: u64,
        gross_cost_saved_micros: u64,
        token_count_precision: TokenCountPrecision,
    ) {
        self.tokens_saved = self.tokens_saved.saturating_add(tokens_saved);
        self.gross_cost_saved_micros = self
            .gross_cost_saved_micros
            .saturating_add(gross_cost_saved_micros);
        self.token_count_precision = self.token_count_precision.combine(token_count_precision);
    }
}

/// A running per-model tally for the value report: how many completions each
/// lane served, the micro-USD saved by local serving, and independently the
/// value delivered by each context-compression lever.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneSplit {
    /// Completions served locally.
    pub local_completions: u64,
    /// Completions that spilled to a cloud provider.
    pub cloud_completions: u64,
    /// Total micro-USD saved by the local lane.
    pub saved_micros: u64,
    /// Total micro-USD actually spent on the cloud lane.
    pub cloud_spent_micros: u64,
    /// Context-compression value keyed by the closed lever name.
    ///
    /// Defaulting this additive field keeps redb rows written by earlier
    /// releases readable.
    #[serde(default)]
    pub compression: BTreeMap<String, CompressionValue>,
}

impl LaneSplit {
    /// Record a completion served locally, adding its displaced cloud
    /// cost to the savings.
    pub fn record_local(&mut self, prompt_tokens: u64, completion_tokens: u64, cloud: CloudPrice) {
        self.local_completions += 1;
        self.saved_micros = self.saved_micros.saturating_add(savings_micros(
            prompt_tokens,
            completion_tokens,
            cloud,
        ));
    }

    /// Record a completion that spilled to cloud, adding its real cost.
    pub fn record_cloud(&mut self, prompt_tokens: u64, completion_tokens: u64, cloud: CloudPrice) {
        self.cloud_completions += 1;
        self.cloud_spent_micros = self.cloud_spent_micros.saturating_add(savings_micros(
            prompt_tokens,
            completion_tokens,
            cloud,
        ));
    }

    /// Record target-model token estimates and gross input cost avoided by one
    /// compression lever. This does not increment either completion lane.
    pub fn record_compression(
        &mut self,
        lever: &str,
        tokens_saved: u64,
        gross_cost_saved_micros: u64,
        token_count_precision: TokenCountPrecision,
    ) {
        use std::collections::btree_map::Entry;
        match self.compression.entry(lever.to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(CompressionValue::new(
                    tokens_saved,
                    gross_cost_saved_micros,
                    token_count_precision,
                ));
            }
            Entry::Occupied(mut entry) => {
                entry
                    .get_mut()
                    .record(tokens_saved, gross_cost_saved_micros, token_count_precision)
            }
        }
    }

    /// Fraction of completions served locally (0.0 when none yet).
    pub fn local_fraction(&self) -> f64 {
        let total = self.local_completions + self.cloud_completions;
        if total == 0 {
            0.0
        } else {
            self.local_completions as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_lane_split_json_defaults_compression_value() {
        let split: LaneSplit = serde_json::from_str(
            r#"{"local_completions":2,"cloud_completions":1,"saved_micros":21000,"cloud_spent_micros":10500}"#,
        )
        .expect("legacy lane split decodes");

        assert!(split.compression.is_empty());
        assert_eq!(split.local_completions, 2);
        assert_eq!(split.saved_micros, 21_000);
    }

    #[test]
    fn compression_value_saturates_without_changing_lane_counts() {
        let mut split = LaneSplit::default();
        split.record_compression(
            "window_fit",
            u64::MAX,
            u64::MAX - 1,
            TokenCountPrecision::ModelTokenizer,
        );
        split.record_compression("window_fit", 42, 42, TokenCountPrecision::ModelTokenizer);
        split.record_compression("summary_buffer", 7, 3, TokenCountPrecision::ModelTokenizer);

        assert_eq!(split.local_completions, 0);
        assert_eq!(split.cloud_completions, 0);
        assert_eq!(split.saved_micros, 0);
        assert_eq!(split.cloud_spent_micros, 0);
        assert_eq!(split.compression["window_fit"].tokens_saved, u64::MAX);
        assert_eq!(
            split.compression["window_fit"].gross_cost_saved_micros,
            u64::MAX
        );
        assert_eq!(split.compression["summary_buffer"].tokens_saved, 7);
    }

    #[test]
    fn compression_precision_is_preserved_and_combined_conservatively() {
        let mut split = LaneSplit::default();
        split.record_compression("window_fit", 100, 40, TokenCountPrecision::ModelTokenizer);
        assert_eq!(
            split.compression["window_fit"].token_count_precision,
            TokenCountPrecision::ModelTokenizer
        );

        split.record_compression("window_fit", 50, 20, TokenCountPrecision::Heuristic);
        assert_eq!(
            split.compression["window_fit"].token_count_precision,
            TokenCountPrecision::Heuristic
        );
    }

    #[test]
    fn savings_matches_cloud_price() {
        // A cloud model at $3/Mtok prompt, $15/Mtok completion
        // (3_000_000 / 15_000_000 micros per Mtok).
        let cloud = CloudPrice {
            prompt_micros_per_mtok: 3_000_000,
            completion_micros_per_mtok: 15_000_000,
        };
        // 1000 prompt + 500 completion tokens.
        // prompt: 1000 * 3_000_000 / 1e6 = 3000 micros
        // completion: 500 * 15_000_000 / 1e6 = 7500 micros
        assert_eq!(savings_micros(1000, 500, cloud), 10_500);
    }

    #[test]
    fn savings_rounds_to_nearest() {
        let cloud = CloudPrice {
            prompt_micros_per_mtok: 1,
            completion_micros_per_mtok: 0,
        };
        // 1_500_000 prompt tokens * 1 micro / 1e6 = 1.5 -> rounds to 2.
        assert_eq!(savings_micros(1_500_000, 0, cloud), 2);
    }

    #[test]
    fn lane_split_tracks_savings_and_fraction() {
        let cloud = CloudPrice {
            prompt_micros_per_mtok: 3_000_000,
            completion_micros_per_mtok: 15_000_000,
        };
        let mut s = LaneSplit::default();
        s.record_local(1000, 500, cloud); // saved 10_500
        s.record_local(1000, 500, cloud); // saved 10_500
        s.record_cloud(1000, 500, cloud); // spent 10_500
        assert_eq!(s.local_completions, 2);
        assert_eq!(s.cloud_completions, 1);
        assert_eq!(s.saved_micros, 21_000);
        assert_eq!(s.cloud_spent_micros, 10_500);
        assert!((s.local_fraction() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn no_overflow_on_huge_token_counts() {
        let cloud = CloudPrice {
            prompt_micros_per_mtok: 20_000_000,
            completion_micros_per_mtok: 60_000_000,
        };
        // Large but realistic-ceiling counts must not overflow (u128 math).
        let s = savings_micros(u64::MAX / 2, u64::MAX / 2, cloud);
        assert!(s > 0);
    }
}
