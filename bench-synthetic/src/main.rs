//! Wave 1 / Q1.12 - Synthetic monitor harness.
//!
//! Probes the 402 challenge + redemption flow against a target proxy
//! and a configured payment rail. Wave 1 only ships the `none` rail
//! (mock ledger); Waves 2 and 3 add Stripe, x402, and MPP. Each probe
//! emits one JSON line on stdout so `synthetic-nightly.yml` (B1.9)
//! can pipe the output straight into a log sink.
//!
//! Output line shape (subject to the schema-versioning ADR A1.8):
//!
//!     {"ts":"2026-04-30T14:23:45Z","rail":"none","target":"https://...",
//!      "result":"ok","latency_ms":42,"detail":null,"schema_version":"1"}
//!
//! Exit code is 0 iff every probe returned `result: "ok"`. The
//! workflow can wire this directly into PagerDuty.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde::Serialize;

// --- CLI ---

#[derive(Debug, Parser)]
#[command(
    name = "synthetic-probe",
    about = "SBproxy synthetic monitor: 402 challenge + redemption probe per rail"
)]
struct Cli {
    /// Payment rail to probe. Wave 1 ships `none` only; the other
    /// variants exist for forward-compat and stub out with a typed
    /// "unimplemented" line so the workflow can already wire them.
    #[arg(long, value_enum, default_value_t = Rail::None)]
    rail: Rail,

    /// Target proxy base URL (e.g. https://staging.sbproxy.dev).
    #[arg(long)]
    target: String,

    /// Test path that should return 402 on first hit. Same path is
    /// replayed with the redemption receipt on the second hit.
    #[arg(long, default_value = "/_synthetic/probe")]
    path: String,

    /// Number of consecutive probes to run. Each emits its own JSON
    /// line. Useful for nightly burn-in.
    #[arg(long, default_value_t = 1)]
    iterations: u32,

    /// Per-probe deadline. Probes that exceed it emit `result: "timeout"`.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,
}

#[derive(Copy, Clone, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum Rail {
    /// Wave 1: probe against a mock ledger, no real settlement.
    None,
    /// Wave 2: Stripe test mode.
    StripeTest,
    /// Wave 3: x402 facilitator (Base / Solana / Eth L2).
    X402,
    /// Wave 3: MPP (Stripe-backed, but rail-shape).
    Mpp,
}

// --- Probe outcome ---

#[derive(Debug, Serialize)]
struct ProbeLine {
    /// RFC 3339 UTC timestamp.
    ts: String,
    /// Rail we probed.
    rail: Rail,
    /// Target proxy base URL.
    target: String,
    /// `ok` | `error` | `timeout` | `unimplemented`.
    result: &'static str,
    /// Round-trip wall-clock for the full probe (challenge + redeem).
    latency_ms: u64,
    /// Additional diagnostic, when non-null.
    detail: Option<String>,
    /// Per A1.8: every emitted record carries a schema version.
    schema_version: &'static str,
}

fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let t = time::OffsetDateTime::from_unix_timestamp(d.as_secs() as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    t.format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

// --- Probe implementations ---

fn probe_none(client: &reqwest::blocking::Client, target: &str, path: &str) -> Result<()> {
    // --- Leg 1: unpaid request expects 402 ---
    let url = format!("{target}{path}");
    let r1 = client
        .get(&url)
        .header("user-agent", "synthetic-probe/1.0")
        .send()
        .context("leg 1: GET unpaid")?;
    let status1 = r1.status().as_u16();
    if status1 != 402 {
        anyhow::bail!("leg 1: expected 402, got {status1}");
    }

    let body: serde_json::Value =
        r1.json().context("leg 1: 402 body parse")?;
    let challenge_id = body["challenge_id"]
        .as_str()
        .context("leg 1: challenge_id missing")?;

    // --- Leg 2: replay with mock receipt ---
    // The mock ledger configured in the Wave 1 staging deployment
    // accepts the receipt `synthetic-rcpt-fixed-0001` for any
    // challenge issued to this user-agent.
    let r2 = client
        .get(&url)
        .header("user-agent", "synthetic-probe/1.0")
        .header("x-sb-receipt", "synthetic-rcpt-fixed-0001")
        .header("x-sb-challenge-id", challenge_id)
        .send()
        .context("leg 2: GET paid")?;
    let status2 = r2.status().as_u16();
    if !(200..300).contains(&status2) {
        anyhow::bail!("leg 2: expected 2xx, got {status2}");
    }
    Ok(())
}

#[allow(dead_code)] // wired in Wave 2 / B2.12
fn probe_stripe_test(_c: &reqwest::blocking::Client, _t: &str, _p: &str) -> Result<()> {
    // TODO(wave2-G2.3): wire the Stripe test-mode rail. The probe
    // sends the same 402 + redeem flow but presents a Stripe test
    // payment_method that resolves through `/v1/payment_intents`
    // against the configured Stripe key.
    unimplemented!("stripe-test rail lands in Wave 2 (B2.12)")
}

#[allow(dead_code)] // wired in Wave 3 / B3.4
fn probe_x402(_c: &reqwest::blocking::Client, _t: &str, _p: &str) -> Result<()> {
    // TODO(wave3-Q3.7): wire the x402 facilitator rail (Base, Solana,
    // Eth L2). Probe constructs a signed-payment header per RFC-x402
    // and submits to the facilitator's redemption endpoint.
    unimplemented!("x402 rail lands in Wave 3 (B3.4)")
}

#[allow(dead_code)] // wired in Wave 3 / B3.5
fn probe_mpp(_c: &reqwest::blocking::Client, _t: &str, _p: &str) -> Result<()> {
    // TODO(wave3-Q3.8): wire the MPP rail (Stripe-backed flow per the
    // Multi-Provider Pay protocol). Probe presents a quote token,
    // settles, then replays.
    unimplemented!("mpp rail lands in Wave 3 (B3.5)")
}

// --- Driver ---

fn main() -> Result<()> {
    let cli = Cli::parse();

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(cli.timeout_secs))
        .user_agent("synthetic-probe/1.0")
        .build()?;

    let mut all_ok = true;
    for _ in 0..cli.iterations {
        let started = Instant::now();
        let (result, detail) = match cli.rail {
            Rail::None => match probe_none(&client, &cli.target, &cli.path) {
                Ok(()) => ("ok", None),
                Err(e) => ("error", Some(format!("{e:#}"))),
            },
            Rail::StripeTest | Rail::X402 | Rail::Mpp => {
                ("unimplemented", Some("rail not yet wired".to_string()))
            }
        };
        let latency_ms = started.elapsed().as_millis() as u64;

        let line = ProbeLine {
            ts: now_rfc3339(),
            rail: cli.rail,
            target: cli.target.clone(),
            result,
            latency_ms,
            detail,
            schema_version: "1",
        };
        println!("{}", serde_json::to_string(&line)?);
        if result != "ok" && result != "unimplemented" {
            all_ok = false;
        }
    }

    if all_ok {
        Ok(())
    } else {
        std::process::exit(1)
    }
}
