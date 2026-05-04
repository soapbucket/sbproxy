//! Q5.7 throughput / latency-adder harness for TLS fingerprint capture.
//!
//! Drives two parallel `sbproxy` instances:
//!
//!   1. baseline  - built without the `tls-fingerprint` cargo feature
//!      (the no-op path, fingerprint field is always `None`).
//!   2. capture   - built with `tls-fingerprint` feature on; runs the
//!      ClientHello parse + JA3 / JA4 hash + CIDR trust check.
//!
//! Same `sb.yml` fixture, same upstream, same rps, same duration. The
//! harness records p50, p95, p99 latency for each side and writes the
//! pair to `/tmp/sbproxy_tls_fp_bench.json` so the e2e assertion
//! (`tls_fingerprint_latency_bench.rs`) can compare them.
//!
//! Gated behind `BENCH_ENABLE=1` so an accidental `cargo run` during
//! development cannot stomp on a local proxy.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Parser;
use hdrhistogram::Histogram;
use serde::Serialize;
use tokio::sync::Mutex;

#[derive(Parser, Debug, Clone)]
#[command(name = "tls-fingerprint-bench")]
struct Args {
    /// URL of the baseline proxy (built without `tls-fingerprint`).
    #[arg(long, default_value = "http://127.0.0.1:18080")]
    baseline_url: String,
    /// URL of the capture proxy (built with `tls-fingerprint`).
    #[arg(long, default_value = "http://127.0.0.1:18081")]
    capture_url: String,
    /// Hostname in the `Host` header. Must match the bench origin.
    #[arg(long, default_value = "tls-fp.localhost")]
    host: String,
    /// Path served by the configured origin.
    #[arg(long, default_value = "/")]
    path: String,
    /// Target steady-state rps per side.
    #[arg(long, default_value_t = 5_000)]
    rps: u64,
    /// Test duration (seconds).
    #[arg(long, default_value_t = 30)]
    duration_secs: u64,
    /// Worker concurrency per side.
    #[arg(long, default_value_t = 256)]
    concurrency: usize,
    /// Output path for the JSON histograms the e2e assertion reads.
    #[arg(long, default_value = "/tmp/sbproxy_tls_fp_bench.json")]
    output: String,
}

#[derive(Default, Debug, Serialize)]
struct SideStats {
    label: String,
    sent: u64,
    succeeded: u64,
    errored: u64,
    p50_micros: u64,
    p95_micros: u64,
    p99_micros: u64,
}

#[derive(Debug, Serialize)]
struct BenchReport {
    rps: u64,
    duration_secs: u64,
    baseline: SideStats,
    capture: SideStats,
    /// `(capture_p99 - baseline_p99) / baseline_p99` as a percentage.
    p99_adder_percent: f64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    if std::env::var("BENCH_ENABLE").ok().as_deref() != Some("1") {
        eprintln!(
            "tls-fingerprint-bench is gated behind BENCH_ENABLE=1 so a stray \
             `cargo run` cannot slam the local proxy. Re-run with \
             `BENCH_ENABLE=1 cargo run --release -- --rps 5000`."
        );
        std::process::exit(2);
    }

    let args = Args::parse();
    println!(
        "tls-fingerprint-bench: rps={} duration={}s baseline={} capture={}",
        args.rps, args.duration_secs, args.baseline_url, args.capture_url
    );

    let baseline = drive_side("baseline", &args, &args.baseline_url).await?;
    let capture = drive_side("capture", &args, &args.capture_url).await?;

    let p99_adder = if baseline.p99_micros == 0 {
        0.0
    } else {
        100.0 * (capture.p99_micros as f64 - baseline.p99_micros as f64)
            / (baseline.p99_micros as f64)
    };

    let report = BenchReport {
        rps: args.rps,
        duration_secs: args.duration_secs,
        baseline,
        capture,
        p99_adder_percent: p99_adder,
    };

    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(&args.output, &json).context("write bench report")?;
    println!("{}", json);
    println!("wrote report to {}", args.output);
    Ok(())
}

// --- Per-side driver ---------------------------------------------------

async fn drive_side(label: &str, args: &Args, base_url: &str) -> anyhow::Result<SideStats> {
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(args.concurrency)
        .timeout(Duration::from_secs(5))
        .http1_only()
        .build()
        .context("build reqwest client")?;

    let hist: Arc<Mutex<Histogram<u64>>> =
        Arc::new(Mutex::new(Histogram::new(3).expect("histogram")));
    let counters: Arc<Mutex<(u64, u64, u64)>> = Arc::new(Mutex::new((0, 0, 0))); // (sent, ok, err)

    let deadline = Instant::now() + Duration::from_secs(args.duration_secs);
    let mut handles = Vec::new();
    let interval_micros = 1_000_000 / args.rps.max(1);

    for _ in 0..args.concurrency {
        let client = client.clone();
        let url = format!("{}{}", base_url, args.path);
        let host = args.host.clone();
        let hist = Arc::clone(&hist);
        let counters = Arc::clone(&counters);
        handles.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let started = Instant::now();
                let resp = client.get(&url).header("Host", &host).send().await;
                let elapsed = started.elapsed().as_micros() as u64;
                let mut h = hist.lock().await;
                let _ = h.record(elapsed.max(1));
                drop(h);
                let mut c = counters.lock().await;
                c.0 += 1;
                match resp {
                    Ok(r) if r.status().is_success() => c.1 += 1,
                    _ => c.2 += 1,
                }
                drop(c);
                tokio::time::sleep(Duration::from_micros(interval_micros)).await;
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let h = hist.lock().await;
    let c = counters.lock().await;
    Ok(SideStats {
        label: label.to_string(),
        sent: c.0,
        succeeded: c.1,
        errored: c.2,
        p50_micros: h.value_at_quantile(0.50),
        p95_micros: h.value_at_quantile(0.95),
        p99_micros: h.value_at_quantile(0.99),
    })
}
