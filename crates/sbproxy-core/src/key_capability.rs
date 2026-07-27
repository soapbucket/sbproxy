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

/// Typed cluster-state namespace each node publishes its capabilities under.
///
/// One key per node id, so a member that publishes nothing is visibly absent.
/// Uses typed cluster state rather than the SWIM peer table on purpose: adding
/// a field to the gossip wire format to solve a mixed-version problem would
/// itself be a mixed-version problem.
pub const CAPABILITY_NAMESPACE: &str = "keycap";

/// Schema version of the published capability record.
pub const CAPABILITY_SCHEMA_VERSION: u32 = 1;

/// How long a published capability record stays valid.
///
/// Republished at half this interval, so a node that stops publishing (it
/// died, or was replaced by an older build) falls out of the set within one
/// TTL and the gate starts refusing again.
pub const CAPABILITY_TTL: std::time::Duration = std::time::Duration::from_secs(120);

/// What one node publishes about itself.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapabilityAnnouncement {
    /// Capability names this node understands.
    pub caps: Vec<String>,
}

/// Publish this node's capability set into typed cluster state.
///
/// A no-op when the process is not clustered, where the gate is satisfied
/// without any announcement.
pub async fn announce_local_capabilities(generation: u64) {
    if !has_peers() {
        return;
    }
    let Some(handle) = crate::cluster::current_cluster_handle() else {
        return;
    };
    let node_id = handle.identity().node_id.clone();
    let announcement = CapabilityAnnouncement {
        caps: vec![CAP_CREDENTIAL_BINDING.to_string()],
    };
    if let Err(error) = handle
        .publish_state(
            CAPABILITY_NAMESPACE,
            &node_id,
            CAPABILITY_SCHEMA_VERSION,
            generation,
            CAPABILITY_TTL,
            &announcement,
        )
        .await
    {
        tracing::warn!(
            %error,
            "could not announce node capabilities; credential bindings will be refused \
             fleet-wide until this node is reachable"
        );
    }
}

/// Whether this process has peers that could be running an older build.
///
/// A standalone node still installs a cluster handle, so the presence of a
/// handle proves nothing. What matters is whether a mesh node is running,
/// which is the same condition that decides whether the announcer runs at all:
/// if nothing is publishing, nothing can be read, and treating that as a
/// clustered fleet would refuse every binding on an ordinary single-node
/// install.
fn has_peers() -> bool {
    crate::cluster::current_cluster_handle()
        .and_then(|handle| handle.mesh_node())
        .is_some()
}

/// Evaluate `cap` across the running fleet.
///
/// No mesh: there is no peer that could be on an older binary, so
/// [`FleetCapability::Satisfied`]. This is the common self-hosted shape and
/// must not be blocked.
///
/// Meshed: read one capability record per member. A member that published
/// nothing is either running a build that does not know to publish, or is not
/// currently reachable. Both refuse, because neither can be distinguished from
/// the case this gate exists to prevent.
pub async fn check_fleet_capability(cap: &str) -> FleetCapability {
    if !has_peers() {
        return FleetCapability::Satisfied;
    }
    let Some(handle) = crate::cluster::current_cluster_handle() else {
        return FleetCapability::Satisfied;
    };
    let members = handle.membership();
    if members.is_empty() {
        return FleetCapability::Unknown("no cluster members reported".to_string());
    }

    let mut declared: Vec<(String, HashMap<String, String>)> = Vec::with_capacity(members.len());
    for member in &members {
        let caps = match handle
            .read_state::<CapabilityAnnouncement>(
                CAPABILITY_NAMESPACE,
                &member.node_id,
                CAPABILITY_SCHEMA_VERSION,
            )
            .await
        {
            sbproxy_mesh::cluster_handle::ClusterStateRead::Present(record) => {
                record.payload.caps.join(",")
            }
            // Missing, expired, or a schema this build does not understand all
            // mean the same thing here: no usable declaration from that node.
            _ => String::new(),
        };
        let mut metadata = HashMap::new();
        if !caps.is_empty() {
            metadata.insert(CAPS_METADATA_KEY.to_string(), caps);
        }
        declared.push((member.node_id.clone(), metadata));
    }

    evaluate_members(&declared, cap)
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
    fn a_standalone_node_is_satisfied_without_any_announcement() {
        // The common self-hosted shape, and the one an e2e drill caught: a
        // standalone node still installs a cluster handle, so testing for the
        // handle rather than for a mesh refused every binding on a normal
        // single-node install.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert_eq!(
            rt.block_on(check_fleet_capability(CAP_CREDENTIAL_BINDING)),
            FleetCapability::Satisfied
        );
    }

    #[test]
    fn announcing_on_an_unclustered_process_is_a_no_op() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(announce_local_capabilities(1));
    }

    #[test]
    fn a_published_record_round_trips_through_its_wire_shape() {
        // What a node puts into cluster state has to come back as something
        // `evaluate_members` accepts, or every member would read as missing.
        let announcement = CapabilityAnnouncement {
            caps: vec![CAP_CREDENTIAL_BINDING.to_string()],
        };
        let wire = serde_json::to_value(&announcement).unwrap();
        let back: CapabilityAnnouncement = serde_json::from_value(wire).unwrap();

        let mut metadata = HashMap::new();
        metadata.insert(CAPS_METADATA_KEY.to_string(), back.caps.join(","));
        assert_eq!(
            evaluate_members(&[("node-a".to_string(), metadata)], CAP_CREDENTIAL_BINDING),
            FleetCapability::Satisfied
        );
    }

    #[test]
    fn a_member_that_published_nothing_reads_as_missing() {
        // This is the old-node case as the cluster read produces it: an empty
        // metadata map, because Missing / Expired / IncompatibleSchema all
        // collapse to "no usable declaration".
        let members = vec![
            node("new-node", Some(CAP_CREDENTIAL_BINDING)),
            ("old-node".to_string(), HashMap::new()),
        ];
        assert_eq!(
            evaluate_members(&members, CAP_CREDENTIAL_BINDING),
            FleetCapability::Missing(vec!["old-node".to_string()])
        );
    }

    #[test]
    fn this_binary_declares_the_credential_binding_capability() {
        let local = local_capabilities();
        assert!(declares(&local, CAP_CREDENTIAL_BINDING));
    }
}
