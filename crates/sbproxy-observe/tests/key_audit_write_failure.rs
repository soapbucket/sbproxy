// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! WOR-2572: `sbproxy_audit_write_failures_total` increments on a
//! REAL failed chain append, driven through the public emitters rather
//! than by handing the recorder a hand-rolled `false`.
//!
//! Why the contortion below is the point. A counter whose failure value
//! nothing in the process can produce is an alert that structurally
//! cannot fire, and it looks identical to a healthy system: flat zero
//! forever. That risk is not hypothetical here. `audit.rs`'s own note on
//! the `chain_error` branch records that the fold had no injection point
//! and was "verified by inspection rather than by a second injected
//! failure", and names the two approaches that do not work: a `chmod`
//! never reaches the writer, because the ledger holds its descriptor
//! open for the process lifetime and POSIX checks permissions at
//! `open(2)`; and a serialize-refusing payload would mean changing the
//! entry types' derives.
//!
//! What does reach the held descriptor is `RLIMIT_FSIZE`. With the soft
//! limit at 0 and `SIGXFSZ` ignored, the append's `write(2)` fails with
//! `EFBIG`, `Ledger::append_checked` returns `Err`, the chain returns
//! `false`, and the emitter folds that real result into the counter.
//! Unix-only by construction; the seam itself is platform-neutral.
//!
//! One `#[test]` on purpose: the rlimit is process-wide, and this file
//! being its own test binary keeps the tightened window away from every
//! other test under both nextest (process-per-test) and plain
//! `cargo test` (threads share a process, but only within one binary).
//! The chain installers are one-shot per process for the same reason.

#![cfg(unix)]

use sbproxy_observe::audit_chain::{
    install_admin_audit_chain, install_key_audit_chain, install_key_audit_fingerprint_key,
    AdminActionAuditChain, KeyAuditChain,
};
use sbproxy_observe::{AdminActionAuditEntry, KeyAuditEntry};

/// The counter's value for `channel`, or `None` while no series exists.
/// The distinction carries an assertion of its own: a healthy system
/// must export an explicit 0 (Vault's audit-failure contract), not an
/// absent series an `increase()` alert has no baseline against.
fn failure_count(channel: &str) -> Option<f64> {
    let want = format!("channel={channel}");
    for family in prometheus::gather() {
        if family.name() != "sbproxy_audit_write_failures_total" {
            continue;
        }
        for metric in family.get_metric() {
            let labels: Vec<String> = metric
                .get_label()
                .iter()
                .map(|pair| format!("{}={}", pair.name(), pair.value()))
                .collect();
            if labels.contains(&want) {
                return Some(metric.get_counter().value());
            }
        }
    }
    None
}

#[test]
fn a_real_chain_write_failure_increments_the_failure_counter() {
    let dir = tempfile::tempdir().expect("temp dir");
    let seed = "34".repeat(32);
    let key_chain = KeyAuditChain::open(&dir.path().join("key.jsonl"), &seed, "w2572-test")
        .expect("key chain opens");
    let admin_chain =
        AdminActionAuditChain::open(&dir.path().join("admin.jsonl"), &seed, "w2572-test")
            .expect("admin chain opens");
    install_key_audit_chain(key_chain).expect("first key-chain install in this process");
    install_admin_audit_chain(admin_chain).expect("first admin-chain install in this process");
    install_key_audit_fingerprint_key(b"w2572-test-master");

    // Baseline: successful emits export the series at an explicit 0.
    KeyAuditEntry::new("rotate", "key", "w2572-baseline").emit();
    AdminActionAuditEntry::new(
        "config_edit",
        Some("operator-w2572".to_string()),
        None,
        None,
        None,
        None,
    )
    .emit();
    assert_eq!(
        failure_count("key_path"),
        Some(0.0),
        "a healthy key channel must export an explicit 0, not an absent series"
    );
    assert_eq!(
        failure_count("admin_path"),
        Some(0.0),
        "a healthy admin channel must export an explicit 0, not an absent series"
    );

    // Force the failure. SIGXFSZ's default action would kill the
    // process instead of failing the write, so it is ignored first.
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
    }
    let mut prior = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut prior) },
        0,
        "getrlimit(RLIMIT_FSIZE)"
    );
    let tight = libc::rlimit {
        rlim_cur: 0,
        rlim_max: prior.rlim_max,
    };
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &tight) },
        0,
        "setrlimit(RLIMIT_FSIZE, 0)"
    );

    KeyAuditEntry::new("rotate", "key", "w2572-forced").emit();
    AdminActionAuditEntry::new(
        "config_edit",
        Some("operator-w2572".to_string()),
        None,
        None,
        None,
        None,
    )
    .emit();

    // Restore before asserting, so a failing assertion can still write
    // its own output.
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &prior) },
        0,
        "restore RLIMIT_FSIZE"
    );

    assert_eq!(
        failure_count("key_path"),
        Some(1.0),
        "a failed key-chain append must increment the failure counter"
    );
    assert_eq!(
        failure_count("admin_path"),
        Some(1.0),
        "a failed admin-chain append must increment the failure counter"
    );
}
