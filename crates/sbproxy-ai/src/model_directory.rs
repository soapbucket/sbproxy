// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Lock-free live directory joining cluster membership with worker snapshots.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use sbproxy_model_host::node_snapshot::{
    NodeArtifactSnapshot, NodeDeviceSnapshot, NodeEngineSnapshot, NodeHealthSnapshot,
    NodeHealthState, NodeIdentitySnapshot, NodeModelSnapshot, NodeReplicaSnapshot, NodeRole,
    NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
};
use sbproxy_model_host::DeploymentRuntimeState;
use serde::{Deserialize, Serialize};

const DIRECTORY_SCHEMA_VERSION: u32 = 1;
const MAX_DIRECTORY_MEMBERS: usize = 1_024;
const MAX_NODE_ID_BYTES: usize = 128;
const MAX_MEMBER_ADDRESS_BYTES: usize = 512;

/// Local membership state observed by the collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryMemberState {
    /// Membership and typed-state transport are live.
    Alive,
    /// SWIM is probing recent failures.
    Suspect,
    /// SWIM declared this member dead.
    Dead,
    /// Membership is live but typed-state transport is unavailable.
    Unreachable,
}

/// One bounded membership observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryMember {
    /// Stable member node ID.
    pub node_id: String,
    /// Last known gossip address.
    pub address: Option<String>,
    /// Current membership state.
    pub state: DirectoryMemberState,
    /// Milliseconds since the last acknowledged probe.
    pub last_ack_age_ms: u64,
    /// Highest observed SWIM incarnation.
    pub incarnation: u64,
}

/// Schema-agnostic typed-state envelope collected for one member.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectorySnapshotEnvelope {
    /// Stable publisher node ID.
    pub publisher_node_id: String,
    /// Payload schema version.
    pub schema_version: u32,
    /// Publisher-monotonic snapshot generation.
    pub generation: u64,
    /// Envelope publication time.
    pub published_at_unix_ms: u64,
    /// Envelope expiry time.
    pub expires_at_unix_ms: u64,
    /// Strict payload JSON.
    pub payload: serde_json::Value,
}

/// Result of collecting one member snapshot.
#[derive(Debug, Clone, PartialEq)]
pub enum DirectorySnapshotRead {
    /// A current envelope was returned.
    Present(DirectorySnapshotEnvelope),
    /// No snapshot exists for the member.
    Missing,
    /// Snapshot expired before collection.
    Expired {
        /// Expired generation.
        generation: u64,
        /// Absolute expiry.
        expires_at_unix_ms: u64,
    },
    /// State owner or peer transport was unreachable.
    Unreachable,
    /// Envelope or payload was malformed. Raw decode detail is intentionally absent.
    Malformed,
    /// Payload schema is newer than this directory can normalize.
    IncompatibleSchema {
        /// Unsupported schema.
        schema_version: u32,
        /// Observed generation.
        generation: u64,
    },
}

/// Stable reason a member is excluded from model placement and routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelDirectoryExclusionReason {
    /// SWIM suspects the member.
    MembershipSuspect,
    /// SWIM declared the member dead.
    MembershipDead,
    /// Typed-state transport is unavailable.
    MembershipUnreachable,
    /// No snapshot was published.
    SnapshotMissing,
    /// Published snapshot expired.
    SnapshotExpired,
    /// Snapshot owner could not be reached.
    SnapshotUnreachable,
    /// Envelope or payload validation failed.
    SnapshotMalformed,
    /// Snapshot schema is unsupported.
    SchemaIncompatible,
    /// Envelope publisher differs from the membership node ID.
    PublisherMismatch,
    /// Snapshot identity differs from the membership node ID.
    IdentityMismatch,
    /// An older publisher generation attempted to replace newer truth.
    OldSnapshotGeneration,
    /// One generation was reused for different contents.
    SnapshotGenerationConflict,
    /// Worker explicitly reported an unhealthy state.
    ReportedUnhealthy,
    /// Member is healthy but does not have the worker role.
    NotWorker,
    /// Worker replica generation trails the active directory generation.
    BehindActiveGeneration,
    /// Nodes disagree on active file-managed deployment content.
    DeploymentDigestMismatch,
}

impl ModelDirectoryExclusionReason {
    /// Stable reason code shared by JSON, CLI, and UI callouts.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MembershipSuspect => "membership_suspect",
            Self::MembershipDead => "membership_dead",
            Self::MembershipUnreachable => "membership_unreachable",
            Self::SnapshotMissing => "snapshot_missing",
            Self::SnapshotExpired => "snapshot_expired",
            Self::SnapshotUnreachable => "snapshot_unreachable",
            Self::SnapshotMalformed => "snapshot_malformed",
            Self::SchemaIncompatible => "schema_incompatible",
            Self::PublisherMismatch => "publisher_mismatch",
            Self::IdentityMismatch => "identity_mismatch",
            Self::OldSnapshotGeneration => "old_snapshot_generation",
            Self::SnapshotGenerationConflict => "snapshot_generation_conflict",
            Self::ReportedUnhealthy => "reported_unhealthy",
            Self::NotWorker => "not_worker",
            Self::BehindActiveGeneration => "behind_active_generation",
            Self::DeploymentDigestMismatch => "deployment_digest_mismatch",
        }
    }

    const fn makes_node_unhealthy(self) -> bool {
        !matches!(self, Self::NotWorker | Self::BehindActiveGeneration)
    }
}

/// Operator-facing aggregate node health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelDirectoryHealth {
    /// No current cluster or model impairment is known.
    Healthy,
    /// Member is live but has an actionable model-plane impairment.
    Degraded,
    /// Member is unsafe for new work or unreachable.
    Unhealthy,
}

/// One eligible ready replica indexed for later peer routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelDirectoryReplica {
    /// Worker node ID.
    pub node_id: String,
    /// Canonical deployment ID.
    pub deployment: String,
    /// Active deployment generation.
    pub deployment_generation: u64,
    /// Logical model ID.
    pub model: String,
    /// Exact selected variant.
    pub variant: Option<String>,
    /// Authenticated model endpoint.
    pub endpoint: Option<String>,
    /// Current local lifecycle.
    pub state: DeploymentRuntimeState,
    /// Active request count.
    pub active_requests: u64,
    /// Admission queue depth.
    pub queue_depth: u64,
}

/// One member in the immutable directory view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelDirectoryNode {
    /// Stable member node ID.
    pub node_id: String,
    /// Last known gossip address.
    pub address: Option<String>,
    /// Membership state.
    pub membership_state: DirectoryMemberState,
    /// Milliseconds since the last probe acknowledgement.
    pub last_ack_age_ms: u64,
    /// Highest observed membership incarnation.
    pub incarnation: u64,
    /// Aggregate operator-facing health.
    pub health: ModelDirectoryHealth,
    /// Stable reasons shown in unhealthy-node callouts.
    pub unhealthy_reasons: Vec<String>,
    /// Whether this worker may receive new model placement or routes.
    pub model_eligible: bool,
    /// Primary deterministic exclusion reason.
    pub exclusion_reason: Option<ModelDirectoryExclusionReason>,
    /// Age of the accepted snapshot.
    pub snapshot_age_ms: Option<u64>,
    /// Accepted publisher generation.
    pub snapshot_generation: Option<u64>,
    /// Schema observed on the wire.
    pub observed_schema_version: Option<u32>,
    /// Current schema after normalization.
    pub normalized_schema_version: Option<u32>,
    /// Authenticated node roles from the last accepted snapshot.
    pub roles: BTreeSet<NodeRole>,
    /// Placement and failure-domain labels.
    pub labels: BTreeMap<String, String>,
    /// Private model endpoint advertised by the node.
    pub model_endpoint: Option<String>,
    /// Worker-reported health, when a snapshot was accepted.
    pub reported_health: Option<NodeHealthSnapshot>,
    /// Active desired-state digest.
    pub active_deployment_digest: Option<String>,
    /// Current local replica summaries.
    pub replicas: Vec<NodeReplicaSnapshot>,
    /// Number of engine capability records.
    pub engine_count: usize,
    /// Number of model-serving devices.
    pub device_count: usize,
    /// Number of ready cached artifacts.
    pub ready_artifact_count: usize,
    /// Full validated snapshot retained for placement, excluded from admin JSON.
    #[serde(skip)]
    pub snapshot: Option<NodeModelSnapshot>,
}

/// Fleet counts rendered directly by the admin view.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ModelDirectorySummary {
    /// Membership entries in this view.
    pub total_nodes: usize,
    /// Nodes with healthy aggregate state.
    pub healthy_nodes: usize,
    /// Live nodes with an actionable impairment.
    pub degraded_nodes: usize,
    /// Nodes requiring an unhealthy callout.
    pub unhealthy_nodes: usize,
    /// Workers currently eligible for new work.
    pub eligible_workers: usize,
    /// Ready replicas in the deployment indexes.
    pub eligible_replicas: usize,
    /// Whether active deployment digests disagree.
    pub deployment_digest_mismatch: bool,
}

/// One immutable directory publication loaded without writer locks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelDirectoryView {
    /// Directory JSON schema.
    pub schema_version: u32,
    /// Collector publication time.
    pub collected_at_unix_ms: u64,
    /// Fleet summary and unhealthy counts.
    pub summary: ModelDirectorySummary,
    /// Every membership node, sorted by stable node ID.
    pub nodes: Vec<ModelDirectoryNode>,
    /// Ready current-generation replicas by deployment.
    pub eligible_replicas: BTreeMap<String, Vec<ModelDirectoryReplica>>,
}

impl Default for ModelDirectoryView {
    fn default() -> Self {
        Self {
            schema_version: DIRECTORY_SCHEMA_VERSION,
            collected_at_unix_ms: 0,
            summary: ModelDirectorySummary::default(),
            nodes: Vec::new(),
            eligible_replicas: BTreeMap::new(),
        }
    }
}

impl ModelDirectoryView {
    /// Find one node by stable ID.
    pub fn node(&self, node_id: &str) -> Option<&ModelDirectoryNode> {
        self.nodes.iter().find(|node| node.node_id == node_id)
    }

    /// Nodes requiring prominent operator callouts.
    pub fn unhealthy_nodes(&self) -> Vec<&ModelDirectoryNode> {
        self.nodes
            .iter()
            .filter(|node| node.health == ModelDirectoryHealth::Unhealthy)
            .collect()
    }
}

/// Directory refresh validation failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ModelDirectoryError {
    /// Membership input violates its bound or contains duplicates.
    #[error("invalid model directory membership: {0}")]
    InvalidMembership(String),
}

#[derive(Default)]
struct ModelDirectoryWriter {
    highest_generation: BTreeMap<String, u64>,
    last_snapshot: BTreeMap<String, NodeModelSnapshot>,
    last_schema: BTreeMap<String, u32>,
}

/// One serialized writer with lock-free immutable readers.
pub struct ModelDirectory {
    writer: Mutex<ModelDirectoryWriter>,
    view: ArcSwap<ModelDirectoryView>,
}

impl std::fmt::Debug for ModelDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ModelDirectory")
            .field("view", &self.view.load())
            .finish_non_exhaustive()
    }
}

impl Default for ModelDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelDirectory {
    /// Create an empty directory.
    pub fn new() -> Self {
        Self {
            writer: Mutex::new(ModelDirectoryWriter::default()),
            view: ArcSwap::from_pointee(ModelDirectoryView::default()),
        }
    }

    /// Load the current immutable view without acquiring the writer lock.
    pub fn load(&self) -> Arc<ModelDirectoryView> {
        self.view.load_full()
    }

    /// Join one complete membership and snapshot observation set and publish it atomically.
    pub fn refresh(
        &self,
        collected_at_unix_ms: u64,
        mut members: Vec<DirectoryMember>,
        mut reads: BTreeMap<String, DirectorySnapshotRead>,
    ) -> Result<Arc<ModelDirectoryView>, ModelDirectoryError> {
        validate_members(&members)?;
        members.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let current_members = members
            .iter()
            .map(|member| member.node_id.clone())
            .collect::<BTreeSet<_>>();
        let mut writer = self
            .writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        writer
            .highest_generation
            .retain(|node_id, _| current_members.contains(node_id));
        writer
            .last_snapshot
            .retain(|node_id, _| current_members.contains(node_id));
        writer
            .last_schema
            .retain(|node_id, _| current_members.contains(node_id));

        let mut nodes = members
            .into_iter()
            .map(|member| {
                let read = reads
                    .remove(&member.node_id)
                    .unwrap_or(DirectorySnapshotRead::Missing);
                build_node(&mut writer, member, read, collected_at_unix_ms)
            })
            .collect::<Vec<_>>();

        let digests = nodes
            .iter()
            .filter_map(|node| node.active_deployment_digest.as_deref())
            .collect::<BTreeSet<_>>();
        let deployment_digest_mismatch = digests.len() > 1;
        if deployment_digest_mismatch {
            for node in nodes
                .iter_mut()
                .filter(|node| node.roles.contains(&NodeRole::Worker) && node.snapshot.is_some())
            {
                exclude_node(
                    node,
                    ModelDirectoryExclusionReason::DeploymentDigestMismatch,
                    ModelDirectoryHealth::Unhealthy,
                );
            }
        } else {
            fence_replica_generations(&mut nodes);
        }
        let eligible_replicas = build_replica_index(&nodes);
        let summary = summarize(&nodes, &eligible_replicas, deployment_digest_mismatch);
        let view = Arc::new(ModelDirectoryView {
            schema_version: DIRECTORY_SCHEMA_VERSION,
            collected_at_unix_ms,
            summary,
            nodes,
            eligible_replicas,
        });
        self.view.store(Arc::clone(&view));
        Ok(view)
    }
}

fn validate_members(members: &[DirectoryMember]) -> Result<(), ModelDirectoryError> {
    if members.len() > MAX_DIRECTORY_MEMBERS {
        return Err(ModelDirectoryError::InvalidMembership(format!(
            "member count exceeds {MAX_DIRECTORY_MEMBERS}"
        )));
    }
    let mut node_ids = BTreeSet::new();
    for member in members {
        if member.node_id.is_empty()
            || member.node_id.len() > MAX_NODE_ID_BYTES
            || !member
                .node_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(ModelDirectoryError::InvalidMembership(
                "member node ID is empty, invalid, or oversized".to_string(),
            ));
        }
        if !node_ids.insert(&member.node_id) {
            return Err(ModelDirectoryError::InvalidMembership(format!(
                "duplicate member {:?}",
                member.node_id
            )));
        }
        if member.address.as_ref().is_some_and(|address| {
            address.is_empty()
                || address.len() > MAX_MEMBER_ADDRESS_BYTES
                || address.chars().any(char::is_control)
        }) {
            return Err(ModelDirectoryError::InvalidMembership(
                "member address is empty, invalid, or oversized".to_string(),
            ));
        }
    }
    Ok(())
}

fn build_node(
    writer: &mut ModelDirectoryWriter,
    member: DirectoryMember,
    read: DirectorySnapshotRead,
    now: u64,
) -> ModelDirectoryNode {
    let membership_exclusion = match member.state {
        DirectoryMemberState::Alive => None,
        DirectoryMemberState::Suspect => Some(ModelDirectoryExclusionReason::MembershipSuspect),
        DirectoryMemberState::Dead => Some(ModelDirectoryExclusionReason::MembershipDead),
        DirectoryMemberState::Unreachable => {
            Some(ModelDirectoryExclusionReason::MembershipUnreachable)
        }
    };
    let mut node = empty_node(member);
    if let Some(reason) = membership_exclusion {
        exclude_node(&mut node, reason, ModelDirectoryHealth::Unhealthy);
        retain_last_snapshot(writer, &mut node, now);
        return node;
    }

    match read {
        DirectorySnapshotRead::Missing => {
            exclude_node(
                &mut node,
                ModelDirectoryExclusionReason::SnapshotMissing,
                ModelDirectoryHealth::Unhealthy,
            );
            retain_last_snapshot(writer, &mut node, now);
        }
        DirectorySnapshotRead::Expired { generation, .. } => {
            node.snapshot_generation = Some(generation);
            exclude_node(
                &mut node,
                ModelDirectoryExclusionReason::SnapshotExpired,
                ModelDirectoryHealth::Unhealthy,
            );
            retain_last_snapshot(writer, &mut node, now);
        }
        DirectorySnapshotRead::Unreachable => {
            exclude_node(
                &mut node,
                ModelDirectoryExclusionReason::SnapshotUnreachable,
                ModelDirectoryHealth::Unhealthy,
            );
            retain_last_snapshot(writer, &mut node, now);
        }
        DirectorySnapshotRead::Malformed => {
            exclude_node(
                &mut node,
                ModelDirectoryExclusionReason::SnapshotMalformed,
                ModelDirectoryHealth::Unhealthy,
            );
            retain_last_snapshot(writer, &mut node, now);
        }
        DirectorySnapshotRead::IncompatibleSchema {
            schema_version,
            generation,
        } => {
            node.observed_schema_version = Some(schema_version);
            node.snapshot_generation = Some(generation);
            exclude_node(
                &mut node,
                ModelDirectoryExclusionReason::SchemaIncompatible,
                ModelDirectoryHealth::Unhealthy,
            );
            retain_last_snapshot(writer, &mut node, now);
        }
        DirectorySnapshotRead::Present(envelope) => {
            ingest_present(writer, &mut node, envelope, now);
        }
    }
    node
}

fn ingest_present(
    writer: &mut ModelDirectoryWriter,
    node: &mut ModelDirectoryNode,
    envelope: DirectorySnapshotEnvelope,
    now: u64,
) {
    node.observed_schema_version = Some(envelope.schema_version);
    node.snapshot_generation = Some(envelope.generation);
    if envelope.publisher_node_id != node.node_id {
        exclude_node(
            node,
            ModelDirectoryExclusionReason::PublisherMismatch,
            ModelDirectoryHealth::Unhealthy,
        );
        retain_last_snapshot(writer, node, now);
        return;
    }
    if envelope.published_at_unix_ms > now
        || envelope.published_at_unix_ms >= envelope.expires_at_unix_ms
    {
        exclude_node(
            node,
            ModelDirectoryExclusionReason::SnapshotMalformed,
            ModelDirectoryHealth::Unhealthy,
        );
        retain_last_snapshot(writer, node, now);
        return;
    }
    if envelope.expires_at_unix_ms <= now {
        exclude_node(
            node,
            ModelDirectoryExclusionReason::SnapshotExpired,
            ModelDirectoryHealth::Unhealthy,
        );
        retain_last_snapshot(writer, node, now);
        return;
    }
    let snapshot = match normalize_snapshot(&envelope) {
        Ok(snapshot) => snapshot,
        Err(NormalizeError::Incompatible) => {
            exclude_node(
                node,
                ModelDirectoryExclusionReason::SchemaIncompatible,
                ModelDirectoryHealth::Unhealthy,
            );
            retain_last_snapshot(writer, node, now);
            return;
        }
        Err(NormalizeError::Malformed) => {
            exclude_node(
                node,
                ModelDirectoryExclusionReason::SnapshotMalformed,
                ModelDirectoryHealth::Unhealthy,
            );
            retain_last_snapshot(writer, node, now);
            return;
        }
    };
    if snapshot.node.node_id != node.node_id {
        exclude_node(
            node,
            ModelDirectoryExclusionReason::IdentityMismatch,
            ModelDirectoryHealth::Unhealthy,
        );
        retain_last_snapshot(writer, node, now);
        return;
    }
    if snapshot.generation != envelope.generation
        || snapshot.published_at_unix_ms > envelope.published_at_unix_ms
        || snapshot.expires_at_unix_ms > envelope.expires_at_unix_ms
    {
        exclude_node(
            node,
            ModelDirectoryExclusionReason::SnapshotMalformed,
            ModelDirectoryHealth::Unhealthy,
        );
        retain_last_snapshot(writer, node, now);
        return;
    }
    if snapshot.expires_at_unix_ms <= now {
        exclude_node(
            node,
            ModelDirectoryExclusionReason::SnapshotExpired,
            ModelDirectoryHealth::Unhealthy,
        );
        retain_last_snapshot(writer, node, now);
        return;
    }

    match writer.highest_generation.get(&node.node_id).copied() {
        Some(highest) if envelope.generation < highest => {
            node.snapshot_generation = Some(highest);
            exclude_node(
                node,
                ModelDirectoryExclusionReason::OldSnapshotGeneration,
                ModelDirectoryHealth::Unhealthy,
            );
            retain_last_snapshot(writer, node, now);
            return;
        }
        Some(highest) if envelope.generation == highest => {
            if writer
                .last_snapshot
                .get(&node.node_id)
                .is_some_and(|last| last != &snapshot)
            {
                exclude_node(
                    node,
                    ModelDirectoryExclusionReason::SnapshotGenerationConflict,
                    ModelDirectoryHealth::Unhealthy,
                );
                retain_last_snapshot(writer, node, now);
                return;
            }
        }
        _ => {
            writer
                .highest_generation
                .insert(node.node_id.clone(), envelope.generation);
            writer
                .last_snapshot
                .insert(node.node_id.clone(), snapshot.clone());
            writer
                .last_schema
                .insert(node.node_id.clone(), envelope.schema_version);
        }
    }
    apply_snapshot(node, snapshot, envelope.schema_version, now);
}

fn empty_node(member: DirectoryMember) -> ModelDirectoryNode {
    ModelDirectoryNode {
        node_id: member.node_id,
        address: member.address,
        membership_state: member.state,
        last_ack_age_ms: member.last_ack_age_ms,
        incarnation: member.incarnation,
        health: ModelDirectoryHealth::Healthy,
        unhealthy_reasons: Vec::new(),
        model_eligible: false,
        exclusion_reason: None,
        snapshot_age_ms: None,
        snapshot_generation: None,
        observed_schema_version: None,
        normalized_schema_version: None,
        roles: BTreeSet::new(),
        labels: BTreeMap::new(),
        model_endpoint: None,
        reported_health: None,
        active_deployment_digest: None,
        replicas: Vec::new(),
        engine_count: 0,
        device_count: 0,
        ready_artifact_count: 0,
        snapshot: None,
    }
}

fn apply_snapshot(
    node: &mut ModelDirectoryNode,
    snapshot: NodeModelSnapshot,
    observed_schema: u32,
    now: u64,
) {
    node.snapshot_age_ms = Some(now.saturating_sub(snapshot.published_at_unix_ms));
    node.snapshot_generation = Some(snapshot.generation);
    node.observed_schema_version = Some(observed_schema);
    node.normalized_schema_version = Some(snapshot.schema_version);
    node.roles = snapshot.node.roles.clone();
    node.labels = snapshot.node.labels.clone();
    node.model_endpoint = snapshot.node.model_endpoint.clone();
    node.reported_health = Some(snapshot.health.clone());
    node.active_deployment_digest = snapshot.active_deployment_digest.clone();
    node.replicas = snapshot.replicas.clone();
    node.engine_count = snapshot.engines.len();
    node.device_count = snapshot.devices.len();
    node.ready_artifact_count = snapshot
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.state == sbproxy_model_host::node_snapshot::NodeArtifactState::Ready
        })
        .count();
    node.snapshot = Some(snapshot.clone());
    match snapshot.health.state {
        NodeHealthState::Ready => {
            node.health = ModelDirectoryHealth::Healthy;
        }
        NodeHealthState::Degraded => {
            node.health = ModelDirectoryHealth::Degraded;
            node.unhealthy_reasons = snapshot.health.reason_codes.clone();
        }
        NodeHealthState::Unhealthy => {
            node.health = ModelDirectoryHealth::Unhealthy;
            node.unhealthy_reasons = snapshot.health.reason_codes.clone();
            node.exclusion_reason = Some(ModelDirectoryExclusionReason::ReportedUnhealthy);
            node.model_eligible = false;
            return;
        }
    }
    if snapshot.node.roles.contains(&NodeRole::Worker) {
        node.model_eligible = true;
    } else {
        node.exclusion_reason = Some(ModelDirectoryExclusionReason::NotWorker);
        node.model_eligible = false;
    }
}

fn retain_last_snapshot(writer: &ModelDirectoryWriter, node: &mut ModelDirectoryNode, now: u64) {
    let Some(snapshot) = writer.last_snapshot.get(&node.node_id).cloned() else {
        return;
    };
    let retained_schema = writer
        .last_schema
        .get(&node.node_id)
        .copied()
        .unwrap_or(NODE_MODEL_SNAPSHOT_SCHEMA_VERSION);
    let health = node.health;
    let reasons = node.unhealthy_reasons.clone();
    let exclusion = node.exclusion_reason;
    let observed_schema = node.observed_schema_version;
    let observed_generation = node.snapshot_generation;
    apply_snapshot(node, snapshot, retained_schema, now);
    node.health = health;
    node.unhealthy_reasons = reasons;
    node.exclusion_reason = exclusion;
    if observed_schema.is_some() {
        node.observed_schema_version = observed_schema;
    }
    if observed_generation.is_some() {
        node.snapshot_generation = observed_generation;
    }
    node.model_eligible = false;
}

fn exclude_node(
    node: &mut ModelDirectoryNode,
    reason: ModelDirectoryExclusionReason,
    health: ModelDirectoryHealth,
) {
    node.exclusion_reason = Some(reason);
    node.model_eligible = false;
    node.health = health;
    if reason.makes_node_unhealthy() || health != ModelDirectoryHealth::Healthy {
        let reason = reason.as_str().to_string();
        if !node.unhealthy_reasons.contains(&reason) {
            node.unhealthy_reasons.push(reason);
            node.unhealthy_reasons.sort();
        }
    }
}

fn fence_replica_generations(nodes: &mut [ModelDirectoryNode]) {
    let mut active = BTreeMap::<String, u64>::new();
    for replica in nodes
        .iter()
        .filter(|node| node.model_eligible)
        .flat_map(|node| node.replicas.iter())
        .filter(|replica| replica.state == DeploymentRuntimeState::Ready)
    {
        active
            .entry(replica.deployment.clone())
            .and_modify(|generation| *generation = (*generation).max(replica.deployment_generation))
            .or_insert(replica.deployment_generation);
    }
    for node in nodes.iter_mut().filter(|node| node.model_eligible) {
        let behind = node.replicas.iter().any(|replica| {
            replica.state == DeploymentRuntimeState::Ready
                && active
                    .get(&replica.deployment)
                    .is_some_and(|active| replica.deployment_generation < *active)
        });
        if behind {
            exclude_node(
                node,
                ModelDirectoryExclusionReason::BehindActiveGeneration,
                ModelDirectoryHealth::Degraded,
            );
        }
    }
}

fn build_replica_index(
    nodes: &[ModelDirectoryNode],
) -> BTreeMap<String, Vec<ModelDirectoryReplica>> {
    let mut index = BTreeMap::<String, Vec<ModelDirectoryReplica>>::new();
    for node in nodes.iter().filter(|node| node.model_eligible) {
        for replica in node
            .replicas
            .iter()
            .filter(|replica| replica.state == DeploymentRuntimeState::Ready)
        {
            index
                .entry(replica.deployment.clone())
                .or_default()
                .push(ModelDirectoryReplica {
                    node_id: node.node_id.clone(),
                    deployment: replica.deployment.clone(),
                    deployment_generation: replica.deployment_generation,
                    model: replica.model.clone(),
                    variant: replica.variant.clone(),
                    endpoint: replica.endpoint.clone(),
                    state: replica.state,
                    active_requests: replica.active_requests,
                    queue_depth: replica.queue_depth,
                });
        }
    }
    for replicas in index.values_mut() {
        replicas.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    }
    index
}

fn summarize(
    nodes: &[ModelDirectoryNode],
    replicas: &BTreeMap<String, Vec<ModelDirectoryReplica>>,
    deployment_digest_mismatch: bool,
) -> ModelDirectorySummary {
    ModelDirectorySummary {
        total_nodes: nodes.len(),
        healthy_nodes: nodes
            .iter()
            .filter(|node| node.health == ModelDirectoryHealth::Healthy)
            .count(),
        degraded_nodes: nodes
            .iter()
            .filter(|node| node.health == ModelDirectoryHealth::Degraded)
            .count(),
        unhealthy_nodes: nodes
            .iter()
            .filter(|node| node.health == ModelDirectoryHealth::Unhealthy)
            .count(),
        eligible_workers: nodes.iter().filter(|node| node.model_eligible).count(),
        eligible_replicas: replicas.values().map(Vec::len).sum(),
        deployment_digest_mismatch,
    }
}

enum NormalizeError {
    Incompatible,
    Malformed,
}

fn normalize_snapshot(
    envelope: &DirectorySnapshotEnvelope,
) -> Result<NodeModelSnapshot, NormalizeError> {
    match envelope.schema_version {
        NODE_MODEL_SNAPSHOT_SCHEMA_VERSION => {
            let bytes =
                serde_json::to_vec(&envelope.payload).map_err(|_| NormalizeError::Malformed)?;
            NodeModelSnapshot::from_json(&bytes).map_err(|_| NormalizeError::Malformed)
        }
        0 => {
            let previous: NodeModelSnapshotV0 = serde_json::from_value(envelope.payload.clone())
                .map_err(|_| NormalizeError::Malformed)?;
            if previous.schema_version != 0 {
                return Err(NormalizeError::Malformed);
            }
            let normalized = NodeModelSnapshot {
                schema_version: NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
                node: previous.node,
                health: NodeHealthSnapshot {
                    state: NodeHealthState::Ready,
                    reason_codes: Vec::new(),
                },
                engines: previous.engines,
                devices: previous.devices,
                artifacts: previous.artifacts,
                replicas: previous.replicas,
                placement_weight: previous.placement_weight,
                active_deployment_digest: None,
                generation: previous.generation,
                published_at_unix_ms: previous.published_at_unix_ms,
                expires_at_unix_ms: previous.expires_at_unix_ms,
            };
            normalized
                .validate()
                .map_err(|_| NormalizeError::Malformed)?;
            Ok(normalized)
        }
        _ => Err(NormalizeError::Incompatible),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeModelSnapshotV0 {
    schema_version: u32,
    node: NodeIdentitySnapshot,
    engines: Vec<NodeEngineSnapshot>,
    devices: Vec<NodeDeviceSnapshot>,
    artifacts: Vec<NodeArtifactSnapshot>,
    replicas: Vec<NodeReplicaSnapshot>,
    placement_weight: u32,
    generation: u64,
    published_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}
