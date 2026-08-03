// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Verifiable usage ledger: the AI gateway's binding of the generic hash
//! chain to the LLM call it records.
//!
//! The chain itself, the digest, the signing, the replay, and the verifier
//! all live in `sbproxy-meter` now, because none of them ever knew anything
//! about tokens. What is left here is the part that genuinely does: the
//! [`LlmUsageEvent`] payload, the [`UsageSink`] that feeds it in, and the
//! promise that the bytes on disk have not moved.
//!
//! Where a plain usage sink ([`crate::usage_sink`]) ships events outward
//! best-effort and unsigned, the ledger turns the same event stream into
//! a chain you can prove. Each [`LlmUsageEvent`] is hash-chained to the
//! previous entry, so mutating any record breaks every link after it, and
//! with a signing seed configured each entry is Ed25519-signed so spend is
//! attributable to the proxy that recorded it, not merely logged.
//!
//! ## The payload is on-disk contract
//!
//! The chain is monomorphized at [`LlmUsageEvent`], and verification
//! re-serializes the event it parsed and requires byte-identical output.
//! So the event's field declaration order and every
//! `skip_serializing_if` on it are part of the file format, not just its
//! Rust shape. `tests/ledger_golden.rs` verifies two files written by an
//! older binary on every run and is what turns that promise into
//! something the build enforces.
//!
//! ## Durability and exactly-once
//!
//! The ledger file is its own write-ahead log: an append serializes one
//! entry, writes it, and flushes, all under a mutex, before returning. A
//! local append is sub-millisecond, so it stays off the network hot path
//! while never dropping an event under load (the lock is the
//! backpressure). On open, the existing file is replayed to rebuild the
//! chain head and the dedup set, so an at-least-once delivery of an event
//! carrying a `request_id` collapses to exactly-once.
//!
//! ## OSS seam
//!
//! This ships the chain, signing, and local verification. Anchoring
//! receipts to an external transparency log or a portal is an enterprise
//! extension via the plugin trait registry; it consumes the same entries.

use crate::usage_sink::{LlmUsageEvent, UsageSink};
use ed25519_dalek::VerifyingKey;
use sbproxy_meter::ledger::LedgerPayload;
use std::path::Path;
use std::sync::Arc;

pub use sbproxy_meter::ledger::{
    ledger_health, verifying_key_from_seed_hex, LedgerHealth, LedgerVerifyResult,
};

/// One link in the LLM usage chain, serialized as a single JSON line.
pub type LedgerEntry = sbproxy_meter::ledger::LedgerEntry<LlmUsageEvent>;

/// A tamper-evident append log of completed-call usage events.
pub type UsageLedger = sbproxy_meter::ledger::UsageLedger<LlmUsageEvent>;

/// The gateway's dedup key is the per-request identifier the capture
/// envelope resolved.
///
/// Events without one are never deduplicated, which is the safe default:
/// two calls that both lack a `request_id` are two calls, and collapsing
/// them would under-report spend rather than over-report it.
/// `chain_contribution` is deliberately left at its `None` default, which
/// keeps this chain out of `sbproxy_meter_divergence_total`.
///
/// Divergence compares units the meter counted against units that reached
/// the chain. This chain is a spend record for LLM calls, not an
/// attestation receipt chain: nothing counts its tokens through the meter's
/// unit path, so reporting them on the chain side would produce a permanent
/// one-sided imbalance and an alert that fires forever without anything
/// being wrong. Implement it when, and only when, the same events are
/// counted on both sides.
impl LedgerPayload for LlmUsageEvent {
    fn dedup_key(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
}

/// Verify a ledger file of LLM usage events: re-derive the hash chain from
/// genesis and, when a `verifying_key` is supplied, check every entry's
/// signature. Reports the first broken link.
///
/// A thin monomorphization of the generic verifier so `sbproxy ai ledger
/// verify` does not have to name a payload type on the command line, and
/// so the payload the CLI checks is always the one the gateway writes.
pub fn verify_ledger(
    path: impl AsRef<Path>,
    verifying_key: Option<&VerifyingKey>,
) -> anyhow::Result<LedgerVerifyResult> {
    sbproxy_meter::ledger::verify_ledger::<LlmUsageEvent>(path, verifying_key)
}

/// A [`UsageSink`] that appends every event to a [`UsageLedger`].
///
/// This is the piece that cannot move to `sbproxy-meter`: [`UsageSink`] is
/// typed to the LLM event, and the metering crate cannot see it.
#[derive(Debug)]
pub struct LedgerSink {
    /// `None` when the ledger could not be opened; records become no-ops
    /// (the failure was logged once at build time) so a misconfiguration
    /// cannot crash the gateway.
    ledger: Option<Arc<UsageLedger>>,
}

impl LedgerSink {
    /// Build a ledger sink from config, logging and degrading to an inert
    /// sink if the ledger cannot be opened. Returned as a trait object so
    /// it slots into the usage-sink list.
    pub fn build(path: &str, signing_seed_hex: Option<&str>) -> Arc<dyn UsageSink> {
        match Self::try_build(path, signing_seed_hex) {
            Ok(sink) => Arc::new(sink),
            Err(e) => {
                tracing::error!(error = %e, path = %path, "usage ledger: disabled (failed to open); events will not be recorded to this sink");
                Arc::new(LedgerSink { ledger: None })
            }
        }
    }

    /// Fallible constructor used by tests and the CLI verify command.
    pub fn try_build(path: &str, signing_seed_hex: Option<&str>) -> anyhow::Result<Self> {
        let ledger = UsageLedger::open(path, signing_seed_hex)?;
        Ok(Self {
            ledger: Some(Arc::new(ledger)),
        })
    }

    /// The underlying ledger, when active.
    pub fn ledger(&self) -> Option<&Arc<UsageLedger>> {
        self.ledger.as_ref()
    }
}

impl UsageSink for LedgerSink {
    fn record(&self, event: &LlmUsageEvent) {
        if let Some(ledger) = &self.ledger {
            ledger.append(event);
        }
    }

    fn name(&self) -> &str {
        "ledger"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn event(rid: Option<&str>, cost: f64) -> LlmUsageEvent {
        LlmUsageEvent {
            provider: "openai".into(),
            model: "gpt-4o-mini".into(),
            prompt_tokens: 10,
            completion_tokens: 5,
            total_tokens: 15,
            cost_usd: cost,
            latency_ms: 120,
            status: 200,
            key_id: Some("k1".into()),
            tenant_id: None,
            project: None,
            user: None,
            team: None,
            tags: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
            request_id: rid.map(|s| s.to_string()),
            session_id: None,
            tag: None,
            priority: None,
            engine_version: None,
            agent_id: None,
            a2a_context_id: None,
            a2a_identity_verified: None,
            workflow_id: None,
            logical_model: None,
            served_model: None,
        }
    }

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sb-ledger-{}-{}-{tag}.jsonl",
            std::process::id(),
            // a per-test discriminator without needing a clock
            tag.len()
        ))
    }

    /// The payload-aware half of the tamper test. The generic chain has its
    /// own version in `sbproxy-meter`; this one edits a field only this
    /// crate knows exists, so it also pins that `cost_usd` is inside the
    /// hashed bytes rather than beside them.
    #[test]
    fn tampering_with_cost_breaks_verification() {
        let path = temp_path("tamper");
        let _ = std::fs::remove_file(&path);
        {
            let ledger = UsageLedger::open(&path, None).unwrap();
            for i in 0..4 {
                ledger.append(&event(None, i as f64));
            }
        }
        // Mutate the cost in the second entry's event.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        assert_eq!(lines.len(), 4, "every append landed");
        lines[1] = lines[1].replace("\"cost_usd\":1.0", "\"cost_usd\":999.0");
        assert!(lines[1].contains("999.0"), "edit landed");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let res = verify_ledger(&path, None).unwrap();
        assert!(!res.ok, "tampered chain must fail");
        assert_eq!(res.broken_seq, Some(1));
        let _ = std::fs::remove_file(&path);
    }

    /// The sink is the only reason this module still exists, so exercise
    /// the whole way through: config-shaped construction, a `record` on the
    /// trait, and a chain that verifies afterwards.
    #[test]
    fn sink_records_through_to_a_verifiable_chain() {
        let path = temp_path("sink");
        let _ = std::fs::remove_file(&path);
        {
            let sink = LedgerSink::try_build(path.to_str().unwrap(), None).unwrap();
            assert_eq!(sink.name(), "ledger");
            sink.record(&event(Some("r1"), 1.0));
            // Same request_id: the dedup set collapses it.
            sink.record(&event(Some("r1"), 1.0));
            sink.record(&event(Some("r2"), 2.0));
            assert!(sink.ledger().is_some(), "sink opened its ledger");
        }
        let res = verify_ledger(&path, None).unwrap();
        assert!(res.ok, "sink-written chain verifies: {res:?}");
        assert_eq!(res.entries, 2, "only r1 and r2 recorded");
        let _ = std::fs::remove_file(&path);
    }

    /// Signing is configured per sink, so pin that the seed reaches the
    /// chain and that the key derived from the same seed accepts it.
    #[test]
    fn signed_sink_entries_verify_against_the_seed_key() {
        let path = temp_path("signedsink");
        let _ = std::fs::remove_file(&path);
        let seed = "1".repeat(64);
        {
            let sink = LedgerSink::try_build(path.to_str().unwrap(), Some(&seed)).unwrap();
            sink.record(&event(Some("s1"), 1.0));
            sink.record(&event(Some("s2"), 2.0));
        }
        let vk = verifying_key_from_seed_hex(&seed).unwrap();
        let res = verify_ledger(&path, Some(&vk)).unwrap();
        assert!(res.ok, "signed chain verifies against its key: {res:?}");
        assert_eq!(res.entries, 2);
        let _ = std::fs::remove_file(&path);
    }
}
