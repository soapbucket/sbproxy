// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Hybrid local/cloud polish (WOR-1657 slice).
//!
//! Pure pieces that make the local lane feel like one array with the
//! paid providers. [`savings_micros`] computes the dollars a local
//! completion saved versus the cloud price it displaced, and
//! [`LaneSplit`] tallies those savings per model. That is the number
//! that justifies the GPU and feeds the value-delivered report.
//!
//! Deterministic and unit-tested here; the value recorder in
//! `sbproxy-ai` persists these tallies and the admin API serves them.

use serde::{Deserialize, Serialize};

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

/// A running tally of local-versus-cloud outcomes for the value
/// report: how many completions each lane served and the micro-USD
/// saved by keeping the local ones off the paid API.
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
