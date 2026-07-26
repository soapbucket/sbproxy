//! Fleet capability gate for record fields that older nodes silently drop.
//!
//! [`sbproxy_keystore::record::KeyRecord`] is replicated between nodes as plain
//! JSON and carries no `deny_unknown_fields`, so a node running an older binary
//! drops a field it does not know and carries on serving. For
//! `credential_id` that is not cosmetic: the older node resolves the key,
//! sees no binding, and dispatches on the origin's shared
//! `outbound_credential`, handing that key an upstream identity it was never
//! bound to.
//!
//! You cannot make an already-deployed binary fail closed on a field it
//! ignores. So the gate refuses to *create* records that depend on the field
//! until every member has declared it understands it, and it reasons about the
//! **absence** of a declaration rather than comparing versions. An old node
//! declares nothing, which is exactly the signal, and it needs no code of its
//! own to participate.

use std::collections::HashMap;

/// Capability name for the per-key upstream credential binding.
pub const CAP_CREDENTIAL_BINDING: &str = "credential_binding";

/// Node metadata key carrying the comma-separated capability list.
pub const CAPS_METADATA_KEY: &str = "caps";

/// Whether the fleet can safely hold records that use a given capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetCapability {
    /// Every member declared it.
    Satisfied,
    /// These member ids did not. Minting is refused and they are named so the
    /// operator knows which nodes to upgrade.
    Missing(Vec<String>),
    /// Membership could not be established, so safety cannot be asserted.
    /// Treated as a refusal: absence of evidence is not evidence of a fully
    /// upgraded fleet.
    Unknown(String),
}

/// Capabilities this binary understands, stamped into node metadata at join so
/// peers can gate on it.
pub fn local_capabilities() -> HashMap<String, String> {
    HashMap::from([(
        CAPS_METADATA_KEY.to_string(),
        CAP_CREDENTIAL_BINDING.to_string(),
    )])
}

/// Whether one node's metadata declares `cap`.
fn declares(metadata: &HashMap<String, String>, cap: &str) -> bool {
    metadata
        .get(CAPS_METADATA_KEY)
        .is_some_and(|caps| caps.split(',').any(|entry| entry.trim() == cap))
}

/// Evaluate a membership snapshot against one capability.
///
/// `members` is `(node_id, metadata)` pairs. An empty snapshot is
/// [`FleetCapability::Unknown`] rather than `Satisfied`, because "no members
/// reported" and "no stale members exist" are not the same claim.
pub fn evaluate_members(
    members: &[(String, HashMap<String, String>)],
    cap: &str,
) -> FleetCapability {
    if members.is_empty() {
        return FleetCapability::Unknown("no cluster members reported".to_string());
    }
    let missing: Vec<String> = members
        .iter()
        .filter(|(_, metadata)| !declares(metadata, cap))
        .map(|(id, _)| id.clone())
        .collect();
    if missing.is_empty() {
        FleetCapability::Satisfied
    } else {
        FleetCapability::Missing(missing)
    }
}

/// Evaluate `cap` across the running fleet.
///
/// Single node, meaning no cluster handle is installed: there is no peer that
/// could be on an older binary, so [`FleetCapability::Satisfied`]. This is the
/// common self-hosted shape and must not be blocked.
///
/// Clustered: currently [`FleetCapability::Unknown`], which refuses. The
/// membership snapshot (`ClusterMember`) does not yet carry the per-node
/// metadata that [`local_capabilities`] stamps, so the check cannot be made.
/// Refusing is the honest answer: a mixed-version fleet is exactly the case
/// where an older node would silently drop `credential_id` and dispatch on the
/// origin's shared credential. Exposing node metadata through the membership
/// snapshot is what lets a clustered fleet use bindings.
pub fn check_fleet_capability(_cap: &str) -> FleetCapability {
    if crate::cluster::current_cluster_handle().is_none() {
        return FleetCapability::Satisfied;
    }
    FleetCapability::Unknown(
        "cluster membership does not expose per-node capabilities, so a mixed-version \
         fleet cannot be ruled out"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, caps: Option<&str>) -> (String, HashMap<String, String>) {
        let mut metadata = HashMap::new();
        if let Some(c) = caps {
            metadata.insert(CAPS_METADATA_KEY.to_string(), c.to_string());
        }
        (id.to_string(), metadata)
    }

    #[test]
    fn every_member_declaring_the_capability_satisfies_the_gate() {
        let members = vec![
            node("a", Some(CAP_CREDENTIAL_BINDING)),
            node("b", Some("something_else,credential_binding")),
        ];
        assert_eq!(
            evaluate_members(&members, CAP_CREDENTIAL_BINDING),
            FleetCapability::Satisfied
        );
    }

    #[test]
    fn a_member_with_no_caps_metadata_is_an_old_node() {
        // The whole design: an older binary declares nothing, and that
        // absence is the signal. It needs no code of its own.
        let members = vec![node("a", Some(CAP_CREDENTIAL_BINDING)), node("b", None)];
        assert_eq!(
            evaluate_members(&members, CAP_CREDENTIAL_BINDING),
            FleetCapability::Missing(vec!["b".to_string()])
        );
    }

    #[test]
    fn a_member_declaring_other_capabilities_but_not_this_one_is_missing() {
        let members = vec![node("a", Some("some_other_cap"))];
        assert_eq!(
            evaluate_members(&members, CAP_CREDENTIAL_BINDING),
            FleetCapability::Missing(vec!["a".to_string()])
        );
    }

    #[test]
    fn substring_matches_do_not_count_as_a_declaration() {
        // "credential_binding_v2" must not satisfy "credential_binding".
        let members = vec![node("a", Some("credential_binding_v2"))];
        assert_eq!(
            evaluate_members(&members, CAP_CREDENTIAL_BINDING),
            FleetCapability::Missing(vec!["a".to_string()])
        );
    }

    #[test]
    fn an_empty_membership_is_unknown_not_satisfied() {
        assert!(matches!(
            evaluate_members(&[], CAP_CREDENTIAL_BINDING),
            FleetCapability::Unknown(_)
        ));
    }

    #[test]
    fn this_binary_declares_the_credential_binding_capability() {
        let local = local_capabilities();
        assert!(declares(&local, CAP_CREDENTIAL_BINDING));
    }
}
