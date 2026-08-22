// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The identifier of the running proxy process.
//!
//! Anything the proxy emits that a receiver has to attribute to one
//! emitter carries this: the alert webhook envelope and its
//! `X-Sbproxy-Instance` header, the callback envelope and its
//! `x-sbproxy-instance` header (through
//! `sbproxy_core::identity::instance_id`, which delegates here), and
//! the per-tenant evidence sequence on `mcp_governance_decision`. A
//! counter, a sequence, or a deduplication key says nothing to a SIEM
//! ingesting two replicas until it knows which process produced it,
//! and it says the wrong thing if two surfaces of one process answer
//! that question differently, which is why this is the only
//! derivation of the identifier in the workspace.
//!
//! Format: `<host>-<8 hex chars>`, for example `sbproxy-7c4d8b9a`. The
//! host part comes from `HOSTNAME` (the pod name under Kubernetes) or
//! from the `hostname` command. The random tag separates two replicas
//! that share a host name, and it is drawn fresh on every start, so a
//! restart is deliberately a new identity: that is what lets a receiver
//! tell a counter that restarted from a counter that rolled back.
//!
//! What the tag is not: a uniqueness proof. It is 32 bits, so the
//! separation between two processes rests mostly on the host part, and
//! the host part collapses to the literal `sbproxy` when neither
//! `HOSTNAME` nor the `hostname` command answers. Under Kubernetes and
//! Docker the environment sets `HOSTNAME` per container, so that
//! fallback is the unusual case rather than the normal one; a
//! deployment that hits it should set `HOSTNAME` rather than rely on
//! the tag alone.

use std::sync::OnceLock;

/// Per-process instance identifier, computed once on first use.
///
/// Stable for the life of the process, and distinct in every process,
/// including two consecutive runs of the same binary on the same host.
pub fn instance_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let host = std::env::var("HOSTNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                std::process::Command::new("hostname")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| "sbproxy".to_string())
            .replace('.', "-");
        let tag: u32 = rand::random();
        format!("{host}-{tag:08x}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_id_is_one_value_for_the_whole_process() {
        // Two records emitted by the same process must carry the same
        // string, or a receiver scoping a sequence to `(instance,
        // tenant)` would read one process as many.
        assert_eq!(instance_id(), instance_id());
        assert!(!instance_id().is_empty());
        // `<host>-<8 hex>`: the tag is what separates two replicas
        // sharing a host name.
        let (_, tag) = instance_id()
            .rsplit_once('-')
            .expect("the identifier carries a random tag");
        assert_eq!(tag.len(), 8, "unexpected instance id: {}", instance_id());
        assert!(tag.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
