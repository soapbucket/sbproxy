// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! On-disk compatibility for the verifiable usage ledger (WOR-2125).
//!
//! Both fixtures were written by a binary that predates the hash chain
//! moving into `sbproxy-meter`. `sbproxy ai ledger verify` has to keep
//! saying `ok` about them, because a ledger nobody can re-check after an
//! upgrade is not evidence, it is a log file with extra steps.
//!
//! What this pins is narrower and more brittle than "the chain works". The
//! verifier re-serializes the event it parsed and demands byte-identical
//! output against what was hashed, so this test fails if anyone reorders a
//! field on the usage event, adds one without `skip_serializing_if`,
//! renames the `event` key, wraps the payload in a serde enum, or changes
//! a single byte of the digest layout. Those are all changes that look
//! harmless in review and silently invalidate every ledger already on a
//! customer's disk.

use std::path::PathBuf;

use sbproxy_ai::usage_ledger::{verify_ledger, verifying_key_from_seed_hex};

/// The seed the signed fixture was written with: the character `1`, 64
/// times, which is 32 bytes of `0x11` once decoded from hex.
const FIXTURE_SEED_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn v1_unsigned_fixture_still_verifies() {
    let path = fixture("ledger-v1-unsigned.jsonl");
    let result = verify_ledger(&path, None).unwrap();
    assert!(
        result.ok,
        "a ledger written before the hoist must still verify: {result:?}"
    );
    assert_eq!(result.entries, 5, "every entry was read");
    assert_eq!(result.broken_seq, None);
    assert_eq!(result.reason, None);
}

#[test]
fn v1_signed_fixture_still_verifies_chain_and_signatures() {
    let path = fixture("ledger-v1-signed.jsonl");

    // Chain only, the way `ledger verify` runs without a seed.
    let chain_only = verify_ledger(&path, None).unwrap();
    assert!(
        chain_only.ok,
        "signed fixture must verify as a chain even with no key: {chain_only:?}"
    );
    assert_eq!(chain_only.entries, 5);

    // Chain plus signatures, against the key derived from the seed it was
    // written with.
    let key = verifying_key_from_seed_hex(FIXTURE_SEED_HEX).unwrap();
    let signed = verify_ledger(&path, Some(&key)).unwrap();
    assert!(
        signed.ok,
        "signed fixture must verify against its own key: {signed:?}"
    );
    assert_eq!(signed.entries, 5);
    assert_eq!(signed.broken_seq, None);
}

#[test]
fn v1_signed_fixture_is_rejected_by_a_different_key() {
    // Without this, a verifier that quietly stopped checking signatures
    // would still pass the test above.
    let path = fixture("ledger-v1-signed.jsonl");
    let other = verifying_key_from_seed_hex(&"2".repeat(64)).unwrap();
    let result = verify_ledger(&path, Some(&other)).unwrap();
    assert!(!result.ok, "a foreign key must reject the fixture");
    assert_eq!(result.broken_seq, Some(0), "it fails on the first entry");
}
