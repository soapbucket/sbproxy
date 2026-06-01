//! P99 latency comparison across AI router LB strategies under
//! skewed load.
//!
//! In-process driver that feeds a synthetic skewed workload
//! through the live [`sbproxy_ai::routing::Router`] for each
//! declared strategy, then prints a P50 / P95 / P99 / P99.9 / max
//! comparison table plus a Jain fairness index and (for
//! `prefix_affinity`) a KV-cache hit rate.
//!
//! ## What "skewed" means
//!
//! Three orthogonal skews are layered into the workload generator
//! and each defaults to a realistic AI-inference shape. All are
//! tunable via CLI:
//!
//! 1. **Provider latency heterogeneity.** One of N providers is
//!    `--slow-provider-multiplier` (default 5x) slower than the
//!    others. Exposes herding pathologies in `round_robin` and
//!    `lowest_latency`; rewards `peak_ewma` and `least_connections`.
//! 2. **Prompt-prefix Zipf.** A vocabulary of
//!    `--prefix-vocabulary` distinct prefixes is sampled with Zipf
//!    parameter `--prefix-zipf-s` (default 1.1). Rewards
//!    `prefix_affinity` when the same prefix repeats; degenerates
//!    to round-robin when prefixes never repeat.
//! 3. **Tenant token-burst Zipf.** `--tenants` distinct tenants
//!    sampled with Zipf `--tenant-zipf-s` (default 1.0). The hot
//!    tenant emits a disproportionate share of tokens; rewards
//!    `least_token_usage` (it spreads the hot tenant across
//!    providers) and `least_connections`.
//!
//! ## What the simulated latency model assumes
//!
//! ```text
//! observed_ms = base_ms * provider_factor
//!             - kv_cache_bonus_ms if prefix was seen on this provider
//!                                  in the last K requests
//!             + queue_term_ms (in-flight count * per_req_overhead)
//!             + lognormal noise (mu=0, sigma=0.3)
//! ```
//!
//! The lognormal noise gives the heavy tail that makes P99 the
//! right comparison metric. The KV-cache bonus is what lets
//! `prefix_affinity` show its value in simulation; without it the
//! strategy is indistinguishable from round-robin on a synthetic
//! workload.
//!
//! These assumptions are documented in `docs/ai-lb-benchmark.md`
//! so a reader can challenge them.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::time::Instant;

use anyhow::{bail, Result};
use clap::Parser;
use hdrhistogram::Histogram;
use rand::distributions::Distribution;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use rand_distr::{LogNormal, WeightedAliasIndex};
use sbproxy_ai::ids::ProviderName;
use sbproxy_ai::provider::ProviderConfig;
use sbproxy_ai::routing::{Router, RoutingStrategy};
use sha2::{Digest, Sha256};

/// All strategies the bench exercises. Listed in the order they
/// appear in the printed results table.
fn strategies() -> Vec<(&'static str, RoutingStrategy)> {
    vec![
        ("round_robin", RoutingStrategy::RoundRobin),
        ("random", RoutingStrategy::Random),
        ("least_connections", RoutingStrategy::LeastConnections),
        ("lowest_latency", RoutingStrategy::LowestLatency),
        ("peak_ewma", RoutingStrategy::PeakEwma),
        ("least_token_usage", RoutingStrategy::LeastTokenUsage),
        ("prefix_affinity", RoutingStrategy::PrefixAffinity),
    ]
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "ai-lb-strategy-bench",
    about = "Compare AI LB strategies under skewed load (P50/P95/P99/P99.9)"
)]
struct Cli {
    /// Number of providers in the routing pool.
    #[arg(long, default_value_t = 4)]
    providers: usize,

    /// Total requests per strategy. Equal sample counts give clean
    /// comparative latency stats; prefer this over a duration cap
    /// for histograms.
    #[arg(long, default_value_t = 50_000)]
    total_requests: usize,

    /// Provider 0's latency multiplier vs the others; 1.0 disables
    /// the slow-provider skew.
    #[arg(long, default_value_t = 5.0)]
    slow_provider_multiplier: f64,

    /// Base per-request latency, milliseconds. The slow provider
    /// multiplies this.
    #[arg(long, default_value_t = 200.0)]
    base_latency_ms: f64,

    /// Per-in-flight-request queueing overhead, milliseconds. Makes
    /// `least_connections` informative.
    #[arg(long, default_value_t = 5.0)]
    queue_overhead_ms: f64,

    /// Latency bonus (ms) when the chosen provider has seen this
    /// prefix in its last `prefix_window` requests. The whole reason
    /// `prefix_affinity` exists; under-stating this defeats the
    /// strategy in simulation.
    #[arg(long, default_value_t = 80.0)]
    kv_cache_bonus_ms: f64,

    /// How many recent requests per provider participate in the KV
    /// cache. vLLM/SGLang's prefill caches are roughly this scale.
    #[arg(long, default_value_t = 64)]
    prefix_window: usize,

    /// Distinct prompt-prefix vocabulary size. Larger means fewer
    /// repeats and a weaker affinity signal.
    #[arg(long, default_value_t = 100)]
    prefix_vocabulary: usize,

    /// Zipf exponent for prompt-prefix sampling. 1.1 is realistic
    /// for chat traffic; 0.0 is uniform (worst case for affinity).
    #[arg(long, default_value_t = 1.1)]
    prefix_zipf_s: f64,

    /// Number of tenants emitting traffic.
    #[arg(long, default_value_t = 10)]
    tenants: usize,

    /// Zipf exponent for tenant sampling. 1.0 puts ~half the load
    /// on the hot tenant.
    #[arg(long, default_value_t = 1.0)]
    tenant_zipf_s: f64,

    /// Mean tokens per request. Affects how `least_token_usage`
    /// sees the load.
    #[arg(long, default_value_t = 1000)]
    mean_tokens: u64,

    /// Lognormal sigma for latency noise; higher values fatten the
    /// tail.
    #[arg(long, default_value_t = 0.3)]
    noise_sigma: f64,

    /// RNG seed; pin for byte-for-byte-reproducible runs.
    #[arg(long, default_value_t = 0x5BA0_F0DE_0123_4567)]
    seed: u64,
}

/// Per-request workload sample.
struct Sample {
    prefix_id: u64,
    tenant_id: u64,
    tokens: u64,
}

fn main() -> Result<()> {
    if std::env::var("SBPROXY_BENCH").ok().as_deref() != Some("1") {
        bail!(
            "refusing to run without SBPROXY_BENCH=1 (lab-only harness; protects you from a stray cargo-run)"
        );
    }
    let cli = Cli::parse();
    println!(
        "ai-lb-strategy-bench: providers={} total_requests={} prefix_zipf_s={} tenant_zipf_s={} slow_provider_multiplier={}x",
        cli.providers, cli.total_requests, cli.prefix_zipf_s, cli.tenant_zipf_s, cli.slow_provider_multiplier
    );
    println!();

    let providers = build_providers(cli.providers);
    let workload = generate_workload(&cli);

    let mut rows: Vec<RunResult> = Vec::new();
    for (label, strategy) in strategies() {
        let r = run_strategy(label, strategy, &cli, &providers, &workload)?;
        rows.push(r);
    }

    print_results(&rows);
    Ok(())
}

/// Build N synthetic providers. The router only inspects `name`
/// and `enabled` for the strategies the bench covers, so the rest
/// can stay defaults.
fn build_providers(n: usize) -> Vec<ProviderConfig> {
    (0..n)
        .map(|i| ProviderConfig {
            name: ProviderName::from(format!("p{i}")),
            provider_type: None,
            api_key: None,
            base_url: None,
            models: Vec::new(),
            default_model: None,
            model_map: HashMap::new(),
            weight: 1,
            priority: None,
            enabled: true,
            max_retries: None,
            timeout_ms: None,
            organization: None,
            api_version: None,
            host_override: None,
            disable_forwarded_host_header: false,
            allow_private_base_url: false,
            no_prompt_training: false,
        })
        .collect()
}

/// Generate the workload up front so every strategy sees the same
/// request stream. Without this, two strategies cannot be compared
/// because their RNGs would draw different samples.
fn generate_workload(cli: &Cli) -> Vec<Sample> {
    let mut rng = SmallRng::seed_from_u64(cli.seed);
    let prefix_weights = zipf_weights(cli.prefix_vocabulary, cli.prefix_zipf_s);
    let prefix_dist = WeightedAliasIndex::new(prefix_weights).expect("non-empty prefix weights");
    let tenant_weights = zipf_weights(cli.tenants, cli.tenant_zipf_s);
    let tenant_dist = WeightedAliasIndex::new(tenant_weights).expect("non-empty tenant weights");
    (0..cli.total_requests)
        .map(|_| {
            let prefix_id = prefix_dist.sample(&mut rng) as u64;
            let tenant_id = tenant_dist.sample(&mut rng) as u64;
            // Token counts spread around the mean with a 25% sigma
            // so least_token_usage's signal is not perfectly uniform.
            let factor = LogNormal::new(0.0, 0.25)
                .expect("valid lognormal")
                .sample(&mut rng);
            let tokens = ((cli.mean_tokens as f64) * factor).max(1.0) as u64;
            Sample {
                prefix_id,
                tenant_id,
                tokens,
            }
        })
        .collect()
}

/// Zipf weights for an alias index. Index `i` (1-based) gets weight
/// `1 / i^s`. `s = 0` gives a uniform distribution.
fn zipf_weights(n: usize, s: f64) -> Vec<f64> {
    (1..=n).map(|i| 1.0 / (i as f64).powf(s)).collect()
}

/// Result of running one strategy.
struct RunResult {
    label: &'static str,
    latency: Histogram<u64>,
    requests_per_provider: Vec<u64>,
    tokens_per_provider: Vec<u64>,
    kv_cache_hits: u64,
    decision_overhead_ns: u64,
}

fn run_strategy(
    label: &'static str,
    strategy: RoutingStrategy,
    cli: &Cli,
    providers: &[ProviderConfig],
    workload: &[Sample],
) -> Result<RunResult> {
    let router = Router::new(strategy.clone(), providers.len());
    // 3 sig digits of HDR precision across the latency range we
    // expect (0.5 ms to 30 s).
    let mut latency = Histogram::<u64>::new_with_bounds(1, 30_000_000, 3)?;
    let mut per_provider_count = vec![0u64; providers.len()];
    let mut per_provider_tokens = vec![0u64; providers.len()];
    // Simulated in-flight queue per provider. Decremented after the
    // observed-latency window elapses; for an in-process bench we
    // model "in-flight" as just the most recent K requests landing
    // on that provider.
    let mut in_flight = vec![0u32; providers.len()];
    // Sliding window of (prefix_id, request_index) seen on each
    // provider. A bounded VecDeque per provider is more accurate
    // but a single tail check is cheaper and matches the cache
    // semantics for a per-request bench.
    let mut prefix_seen: Vec<Vec<u64>> =
        (0..providers.len()).map(|_| Vec::with_capacity(cli.prefix_window)).collect();
    let mut kv_cache_hits: u64 = 0;
    let mut decision_overhead_ns: u64 = 0;

    let noise = LogNormal::new(0.0, cli.noise_sigma)?;
    let mut rng = SmallRng::seed_from_u64(cli.seed ^ 0xDEAD_BEEF);

    for sample in workload {
        let prefix_bytes = prefix_key_bytes(sample.prefix_id, sample.tenant_id);
        let decision_start = Instant::now();
        let pick = match strategy {
            RoutingStrategy::PrefixAffinity => {
                router.select_with_prefix(providers, &prefix_bytes)
            }
            _ => router.select(providers),
        };
        decision_overhead_ns += decision_start.elapsed().as_nanos() as u64;
        let pick = match pick {
            Some(p) => p,
            None => continue,
        };

        // Inform the router that a connection is open so
        // least_connections has an in-flight signal.
        router.record_connect(pick);

        // Simulate latency.
        let provider_factor = if pick == 0 {
            cli.slow_provider_multiplier
        } else {
            1.0
        };
        let base = cli.base_latency_ms * provider_factor;
        let queue = cli.queue_overhead_ms * (in_flight[pick] as f64);
        let cache_bonus = if prefix_seen[pick].contains(&sample.prefix_id) {
            kv_cache_hits += 1;
            cli.kv_cache_bonus_ms
        } else {
            0.0
        };
        let observed_ms = ((base + queue - cache_bonus).max(1.0)) * noise.sample(&mut rng);
        let observed_us = (observed_ms * 1000.0) as u64;
        latency.record(observed_us)?;
        router.record_latency(pick, observed_us);
        router.record_tokens(pick, sample.tokens);
        per_provider_count[pick] += 1;
        per_provider_tokens[pick] += sample.tokens;

        // Update prefix window (keep last K).
        prefix_seen[pick].push(sample.prefix_id);
        if prefix_seen[pick].len() > cli.prefix_window {
            prefix_seen[pick].remove(0);
        }

        // Update in-flight counter to model queue depth. Decrement
        // the oldest in-flight every K requests so the queue does
        // not grow without bound; this is a rough model of request
        // completion in the in-process bench.
        in_flight[pick] = in_flight[pick].saturating_add(1);
        if in_flight[pick] > 16 {
            in_flight[pick] -= 1;
            router.record_disconnect(pick);
        }
        // Toss in some random drains so observed in-flight doesn't
        // stick at 16 forever on the popular providers.
        if rng.gen_bool(0.25) {
            in_flight[pick] = in_flight[pick].saturating_sub(1);
            router.record_disconnect(pick);
        }
    }
    Ok(RunResult {
        label,
        latency,
        requests_per_provider: per_provider_count,
        tokens_per_provider: per_provider_tokens,
        kv_cache_hits,
        decision_overhead_ns,
    })
}

/// Build a stable prefix key from (prefix_id, tenant_id). The
/// router hashes this to a provider index; mirror what
/// `extract_prefix_key` in the real dispatcher would produce.
fn prefix_key_bytes(prefix_id: u64, tenant_id: u64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"prompt:");
    h.update(prefix_id.to_le_bytes());
    h.update(b":");
    h.update(tenant_id.to_le_bytes());
    h.finalize().to_vec()
}

/// Print one row per strategy, padding so columns line up.
fn print_results(rows: &[RunResult]) {
    println!(
        "{:<20} {:>10} {:>10} {:>10} {:>10} {:>10}  {:>8} {:>10} {:>9}",
        "strategy", "p50_ms", "p95_ms", "p99_ms", "p99.9_ms", "max_ms", "fairness", "kv_hit_%", "decide_ns"
    );
    println!("{}", "-".repeat(110));
    for r in rows {
        let total: u64 = r.requests_per_provider.iter().sum();
        let kv_pct = if total == 0 {
            0.0
        } else {
            100.0 * (r.kv_cache_hits as f64) / (total as f64)
        };
        let fairness = jain_fairness(&r.requests_per_provider);
        let mean_decision_ns = if total == 0 {
            0
        } else {
            r.decision_overhead_ns / total
        };
        println!(
            "{:<20} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>10.2}  {:>8.3} {:>9.1}% {:>9}",
            r.label,
            us_to_ms(r.latency.value_at_quantile(0.50)),
            us_to_ms(r.latency.value_at_quantile(0.95)),
            us_to_ms(r.latency.value_at_quantile(0.99)),
            us_to_ms(r.latency.value_at_quantile(0.999)),
            us_to_ms(r.latency.max()),
            fairness,
            kv_pct,
            mean_decision_ns,
        );
    }
    println!();
    // Per-provider distribution so a reader can see herding.
    for r in rows {
        let total: u64 = r.requests_per_provider.iter().sum::<u64>().max(1);
        let pct: Vec<String> = r
            .requests_per_provider
            .iter()
            .map(|c| format!("{:>5.1}%", 100.0 * (*c as f64) / (total as f64)))
            .collect();
        let tok_total: u64 = r.tokens_per_provider.iter().sum::<u64>().max(1);
        let tok_pct: Vec<String> = r
            .tokens_per_provider
            .iter()
            .map(|t| format!("{:>5.1}%", 100.0 * (*t as f64) / (tok_total as f64)))
            .collect();
        println!(
            "{:<20} reqs [{}]  tokens [{}]",
            r.label,
            pct.join(" "),
            tok_pct.join(" ")
        );
    }
}

fn us_to_ms(us: u64) -> f64 {
    (us as f64) / 1000.0
}

/// Jain's fairness index. 1.0 == perfectly fair, 1/N == one
/// provider gets everything. The bench reports this so a herding
/// pathology shows up as a small number even when latency looks
/// fine on average.
fn jain_fairness(counts: &[u64]) -> f64 {
    let n = counts.len() as f64;
    let sum: f64 = counts.iter().map(|c| *c as f64).sum();
    let sum_sq: f64 = counts.iter().map(|c| (*c as f64).powi(2)).sum();
    if sum_sq == 0.0 {
        return 0.0;
    }
    (sum * sum) / (n * sum_sq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jain_perfect_is_one() {
        assert!((jain_fairness(&[10, 10, 10, 10]) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn jain_herded_is_one_over_n() {
        // Everything on provider 0; fairness = 1 / N.
        assert!((jain_fairness(&[40, 0, 0, 0]) - 0.25).abs() < 1e-9);
    }

    #[test]
    fn zipf_weights_decrease() {
        let w = zipf_weights(5, 1.1);
        for i in 0..4 {
            assert!(w[i] > w[i + 1], "weight at index {i} should exceed {}", i + 1);
        }
    }

    #[test]
    fn zipf_uniform_when_s_is_zero() {
        let w = zipf_weights(5, 0.0);
        assert!(w.iter().all(|x| (*x - 1.0).abs() < 1e-9));
    }

    #[test]
    fn prefix_key_is_deterministic_for_same_pair() {
        assert_eq!(prefix_key_bytes(42, 7), prefix_key_bytes(42, 7));
    }

    #[test]
    fn prefix_key_differs_when_either_field_differs() {
        let a = prefix_key_bytes(1, 0);
        assert_ne!(a, prefix_key_bytes(2, 0));
        assert_ne!(a, prefix_key_bytes(1, 1));
    }
}
