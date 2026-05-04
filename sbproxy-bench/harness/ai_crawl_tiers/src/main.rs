//! Q1.6 throughput harness: 10k rps across the 402 challenge and
//! redemption paths with five pricing tiers.
//!
//! Drives traffic against a running `sbproxy` instance configured with
//! the Q1.1 tiers fixture (`e2e/fixtures/wave1/tiers/sb.yml`). The
//! proxy is expected to be running locally (or behind a loopback
//! load-balancer) on `--target-url`; this harness does NOT spawn the
//! proxy itself so the bench operator can profile the proxy in
//! isolation (perf, flamegraph, eBPF).
//!
//! Output: per-tier p50/p95/p99 latency, error rate, and total RPS.
//! Histograms are HDR with 3 significant digits, max 60 s.
//!
//! Gated behind the `SBPROXY_BENCH=1` env var so an accidental
//! `cargo run` does not slam the user's loopback during a normal
//! development session.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Parser;
use hdrhistogram::Histogram;
use tokio::sync::Mutex;

#[derive(Parser, Debug, Clone)]
#[command(name = "ai-crawl-tiers-bench")]
struct Args {
    /// Base URL of the running proxy (e.g. `http://127.0.0.1:8080`).
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    target_url: String,
    /// Hostname to send in the `Host` header. Must match an origin in
    /// the proxy's loaded `sb.yml`.
    #[arg(long, default_value = "blog.localhost")]
    host: String,
    /// Target steady-state RPS.
    #[arg(long, default_value_t = 10_000)]
    rps: u64,
    /// Number of distinct tiers in the load mix.
    #[arg(long, default_value_t = 5)]
    tiers: u64,
    /// Test duration in seconds.
    #[arg(long, default_value_t = 30)]
    duration_secs: u64,
    /// Worker concurrency. Tune above `rps / 100` to keep the queue
    /// non-empty without pinning all CPUs.
    #[arg(long, default_value_t = 256)]
    concurrency: usize,
}

#[derive(Default, Debug)]
struct Counters {
    sent: u64,
    succeeded: u64,
    challenged: u64,
    errored: u64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    if std::env::var("SBPROXY_BENCH").ok().as_deref() != Some("1") {
        eprintln!(
            "ai-crawl-tiers-bench is gated behind SBPROXY_BENCH=1 so a stray \
             `cargo run` cannot slam the local proxy. Re-run with \
             `SBPROXY_BENCH=1 cargo run --release -- --rps 10000`."
        );
        std::process::exit(2);
    }

    let args = Args::parse();
    println!("ai-crawl-tiers-bench: rps={} tiers={} duration={}s target={}",
        args.rps, args.tiers, args.duration_secs, args.target_url);

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(args.concurrency)
        .timeout(Duration::from_secs(5))
        .http1_only()
        .build()
        .context("build reqwest client")?;

    let hist_402: Arc<Mutex<Histogram<u64>>> = Arc::new(Mutex::new(
        Histogram::new(3).expect("histogram"),
    ));
    let hist_200: Arc<Mutex<Histogram<u64>>> = Arc::new(Mutex::new(
        Histogram::new(3).expect("histogram"),
    ));
    let counters: Arc<Mutex<Counters>> = Arc::new(Mutex::new(Counters::default()));

    let deadline = Instant::now() + Duration::from_secs(args.duration_secs);
    // Token-bucket-ish RPS gate: each worker sleeps inside the tight
    // loop to roughly hit the global target. Not exact; bench
    // operators are expected to tune `rps` and `concurrency` together.
    let per_worker_inter_arrival_micros = if args.rps > 0 {
        (1_000_000_u64 * args.concurrency as u64) / args.rps
    } else {
        1
    };

    let mut handles = Vec::with_capacity(args.concurrency);
    for worker_id in 0..args.concurrency {
        let client = client.clone();
        let target = args.target_url.clone();
        let host = args.host.clone();
        let tiers = args.tiers;
        let h402 = hist_402.clone();
        let h200 = hist_200.clone();
        let c = counters.clone();

        handles.push(tokio::spawn(async move {
            let mut req_id: u64 = worker_id as u64;
            while Instant::now() < deadline {
                let tier = req_id % tiers;
                // Alternate 402 challenge requests and 200 redemption
                // requests. Even req_ids fire a challenge (no token);
                // odd req_ids include a fresh token so the redemption
                // path is exercised. The proxy's in-memory ledger is
                // expected to admit the token for one request and
                // then 402 the next; the bench rate-limits enough that
                // a fresh token per request is realistic.
                let path = format!("/article/tier-{tier}");
                let send_token = req_id % 2 == 1;
                let mut req = client
                    .get(format!("{target}{path}"))
                    .header("host", &host)
                    .header("user-agent", "GPTBot/2.1");
                if send_token {
                    let tok = format!("bench-token-{req_id}");
                    req = req.header("crawler-payment", tok);
                }

                let started = Instant::now();
                let result = req.send().await;
                let elapsed_micros = started.elapsed().as_micros() as u64;

                let mut counters = c.lock().await;
                counters.sent += 1;
                match result {
                    Ok(resp) => match resp.status().as_u16() {
                        200 => {
                            counters.succeeded += 1;
                            drop(counters);
                            let _ = h200.lock().await.record(elapsed_micros);
                        }
                        402 => {
                            counters.challenged += 1;
                            drop(counters);
                            let _ = h402.lock().await.record(elapsed_micros);
                        }
                        _ => {
                            counters.errored += 1;
                        }
                    },
                    Err(_) => {
                        counters.errored += 1;
                    }
                }

                tokio::time::sleep(Duration::from_micros(per_worker_inter_arrival_micros)).await;
                req_id = req_id.wrapping_add(args.concurrency as u64);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let counters = counters.lock().await;
    let h402 = hist_402.lock().await;
    let h200 = hist_200.lock().await;
    println!("--- Results ---");
    println!("sent:       {}", counters.sent);
    println!("succeeded:  {} (200)", counters.succeeded);
    println!("challenged: {} (402)", counters.challenged);
    println!("errored:    {}", counters.errored);
    println!("rps_actual: {:.1}", counters.sent as f64 / args.duration_secs as f64);
    println!();
    println!("--- 402 challenge latency (microseconds) ---");
    print_histogram(&h402);
    println!();
    println!("--- 200 redemption latency (microseconds) ---");
    print_histogram(&h200);

    Ok(())
}

fn print_histogram(h: &Histogram<u64>) {
    if h.is_empty() {
        println!("(no samples)");
        return;
    }
    println!("count: {}", h.len());
    println!("p50:   {:>8}", h.value_at_quantile(0.50));
    println!("p95:   {:>8}", h.value_at_quantile(0.95));
    println!("p99:   {:>8}", h.value_at_quantile(0.99));
    println!("max:   {:>8}", h.max());
}
