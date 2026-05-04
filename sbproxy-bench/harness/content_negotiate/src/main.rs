//! Q4.12 throughput harness: 5,000 rps Markdown conversion.
//!
//! Drives traffic against a running `sbproxy` configured with the
//! Wave 4 content-negotiate origin (G4.2 + G4.3). Every request
//! sends `Accept: text/markdown` so the proxy hits the HTML -> Markdown
//! transform on the hot path. The harness records p50, p95, p99
//! latency and the bytes/sec throughput.
//!
//! Gated behind `BENCH_ENABLE=1` so an accidental `cargo run` during
//! development cannot stomp on a local proxy.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Parser;
use hdrhistogram::Histogram;
use tokio::sync::Mutex;

#[derive(Parser, Debug, Clone)]
#[command(name = "content-negotiate-bench")]
struct Args {
    /// Base URL of the running proxy.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    target_url: String,
    /// Hostname in the `Host` header. Must match an origin in the
    /// proxy's `sb.yml` that has the markdown projection enabled.
    #[arg(long, default_value = "blog.localhost")]
    host: String,
    /// Path served by the configured origin.
    #[arg(long, default_value = "/article/8kb-fixture")]
    path: String,
    /// Target steady-state rps.
    #[arg(long, default_value_t = 5_000)]
    rps: u64,
    /// Test duration (seconds).
    #[arg(long, default_value_t = 30)]
    duration_secs: u64,
    /// Worker concurrency. Tune above `rps / 100` to keep the queue
    /// non-empty.
    #[arg(long, default_value_t = 256)]
    concurrency: usize,
}

#[derive(Default, Debug)]
struct Counters {
    sent: u64,
    succeeded: u64,
    errored: u64,
    bytes: u64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    if std::env::var("BENCH_ENABLE").ok().as_deref() != Some("1") {
        eprintln!(
            "content-negotiate-bench is gated behind BENCH_ENABLE=1 so a stray \
             `cargo run` cannot slam the local proxy. Re-run with \
             `BENCH_ENABLE=1 cargo run --release -- --rps 5000`."
        );
        std::process::exit(2);
    }

    let args = Args::parse();
    println!(
        "content-negotiate-bench: rps={} duration={}s target={}",
        args.rps, args.duration_secs, args.target_url
    );

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(args.concurrency)
        .timeout(Duration::from_secs(5))
        .http1_only()
        .build()
        .context("build reqwest client")?;

    let hist: Arc<Mutex<Histogram<u64>>> = Arc::new(Mutex::new(Histogram::new(3).expect("histogram")));
    let counters: Arc<Mutex<Counters>> = Arc::new(Mutex::new(Counters::default()));

    let deadline = Instant::now() + Duration::from_secs(args.duration_secs);
    let per_worker_inter_arrival_micros = if args.rps > 0 {
        (1_000_000_u64 * args.concurrency as u64) / args.rps
    } else {
        1
    };

    let mut handles = Vec::with_capacity(args.concurrency);
    for _worker in 0..args.concurrency {
        let client = client.clone();
        let target = args.target_url.clone();
        let host = args.host.clone();
        let path = args.path.clone();
        let h = hist.clone();
        let c = counters.clone();

        handles.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let req = client
                    .get(format!("{target}{path}"))
                    .header("host", &host)
                    .header("accept", "text/markdown")
                    .header("user-agent", "content-negotiate-bench/1.0");

                let started = Instant::now();
                let result = req.send().await;
                let elapsed_micros = started.elapsed().as_micros() as u64;

                match result {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body_len = match resp.bytes().await {
                            Ok(b) => b.len() as u64,
                            Err(_) => 0,
                        };
                        let mut counters = c.lock().await;
                        counters.sent += 1;
                        if status == 200 {
                            counters.succeeded += 1;
                            counters.bytes += body_len;
                            drop(counters);
                            let _ = h.lock().await.record(elapsed_micros);
                        } else {
                            counters.errored += 1;
                        }
                    }
                    Err(_) => {
                        let mut counters = c.lock().await;
                        counters.sent += 1;
                        counters.errored += 1;
                    }
                }
                tokio::time::sleep(Duration::from_micros(per_worker_inter_arrival_micros)).await;
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }

    let counters = counters.lock().await;
    let h = hist.lock().await;
    let secs = args.duration_secs as f64;
    println!("--- Results ---");
    println!("sent:        {}", counters.sent);
    println!("succeeded:   {}", counters.succeeded);
    println!("errored:     {}", counters.errored);
    println!("rps_actual:  {:.1}", counters.sent as f64 / secs);
    println!("bytes/sec:   {:.1}", counters.bytes as f64 / secs);
    println!();
    println!("--- 200 latency (microseconds) ---");
    print_histogram(&h);

    // Acceptance band per Q4.12: 5k rps sustained, p99 < 50 ms,
    // 0 errors. Print a clear pass/fail line so the perf-lab CI
    // can grep for it.
    let p99 = h.value_at_quantile(0.99);
    let pass = counters.sent as f64 / secs >= (args.rps as f64) * 0.95
        && counters.errored == 0
        && p99 < 50_000;
    println!();
    println!(
        "ACCEPTANCE: {} (rps>={:.0} && errors==0 && p99<50000us, got rps={:.1} errors={} p99={}us)",
        if pass { "PASS" } else { "FAIL" },
        (args.rps as f64) * 0.95,
        counters.sent as f64 / secs,
        counters.errored,
        p99,
    );

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
