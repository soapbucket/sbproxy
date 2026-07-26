// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Gossip accelerator for config distribution: an authority announces the
//! revision it has just begun serving into typed cluster state, and a
//! subscriber that happens to be a mesh member pulls immediately instead of
//! waiting out its poll interval.
//!
//! # An accelerator, never a correctness requirement
//!
//! Polling already gets every subscriber to the authority's current revision
//! within one `poll_interval`, and that path works whether or not a node is
//! in anybody's gossip cluster. It has to: managed-service subscribers reach
//! the authority over the internet and are not mesh members at all. So
//! everything in this module is a shortcut on top of a mechanism that is
//! already complete, and a bug here can only slow propagation down. It
//! cannot make a node apply the wrong configuration, and it cannot make a
//! node apply nothing.
//!
//! Two consequences that shape the whole design:
//!
//! - A node with no mesh node gets no watcher, takes no extra code path, and
//!   is therefore untouched by anything here.
//! - The announcement is a hint about a number. The pull it triggers is the
//!   ordinary [`crate::config_subscriber::ConfigSubscriber::poll_once`]
//!   cycle, which fetches over HTTP and runs the full signature, schema,
//!   digest, expiry, declared-mode, anti-replay, merge, deny-list, and
//!   compile path. Nothing in a gossiped payload is ever adopted as
//!   configuration.
//!
//! # What travels
//!
//! [`crate::config_gossip::RevisionAnnouncement`]: a revision, a content
//! digest, and the publishing authority's id. Three scalars. Deliberately
//! not the config body, so the size of a fleet's configuration never becomes
//! the size of a gossip message. The digest is carried so an operator
//! reading cluster state can tell which content a revision refers to, and so
//! a same-revision content change is visible; the subscriber's own cursor is
//! what actually enforces both.
//!
//! # Why the read side polls
//!
//! [`sbproxy_mesh::ClusterHandle`] exposes typed state as a read, not as a
//! subscription, so the watcher reads the announcement every
//! [`crate::config_gossip::PROBE_INTERVAL`] while it waits out the poll
//! interval. That is still worth doing: the probe is a few hundred bytes
//! against the cluster's own hash-ring owner, usually this very process,
//! while the thing it replaces is an authenticated HTTPS round trip that can
//! carry megabytes of YAML.
//!
//! # Why the announcement expires
//!
//! It is published once per revision and never refreshed. Its whole job is
//! to compress the window immediately after a publish, which is the only
//! window in which it can help anyone; once every subscriber has polled, it
//! has nothing left to say. Leaving it readable forever would mean a dead
//! authority's last revision sits in cluster state indefinitely, described
//! as current, long after the authority that wrote it stopped existing. So
//! it carries [`crate::config_gossip::ANNOUNCEMENT_TTL`] and then goes away,
//! after which every subscriber is back on the poll interval, which is the
//! required path regardless.

use std::time::Duration;

use sbproxy_mesh::{ClusterHandle, ClusterNodeRole, ClusterStateRead, ClusterStateRecord};
use serde::{Deserialize, Serialize};

/// Typed cluster-state namespace the revision announcement lives under.
pub const ANNOUNCEMENT_NAMESPACE: &str = "config-authority";

/// Key inside [`crate::config_gossip::ANNOUNCEMENT_NAMESPACE`] holding the
/// current announcement.
///
/// One key per cluster, not one per authority: chained authorities are
/// rejected at config validation, so a cluster has at most one publisher and
/// a second one writing here would be a misconfiguration worth colliding
/// over rather than silently tolerating.
pub const ANNOUNCEMENT_KEY: &str = "current";

/// Payload schema version for [`RevisionAnnouncement`].
pub const ANNOUNCEMENT_SCHEMA_VERSION: u32 = 1;

/// How long an announcement stays readable after it is published.
///
/// Fifteen minutes. The announcement only ever helps in the window between a
/// publish and the next poll on each subscriber, so the TTL needs to cover
/// the default 30-second interval, and anything up to a few minutes, several
/// times over: that also covers a subscriber that restarts shortly after a
/// publish. A node deliberately configured to poll hourly has said it does
/// not want fast propagation, and it converges on its own schedule. Short
/// enough, meanwhile, that a dead authority's last revision is gone well
/// inside one on-call handover rather than describing itself as current for
/// days.
pub const ANNOUNCEMENT_TTL: Duration = Duration::from_secs(15 * 60);

/// How often a waiting subscriber re-reads the announcement.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// Longest accepted `content_digest` or `authority_id` in an announcement.
///
/// The envelope bound is a megabyte, which is the right bound for typed
/// state in general and far too generous for three scalars. A cluster member
/// publishing a 900 KiB "digest" is not something to reason about further
/// down.
const MAX_ANNOUNCEMENT_FIELD_LEN: usize = 256;

/// What an authority tells the cluster after a successful publish.
///
/// Never the config body. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionAnnouncement {
    /// Monotonic authority revision now being served.
    pub revision: u64,
    /// `sha256:<hex>` digest of the payload that revision carries.
    pub content_digest: String,
    /// Publishing authority's configured identifier.
    pub authority_id: String,
}

/// What one announcement attempt did.
///
/// The `result` label on `sbproxy_config_authority_announce_total` comes from
/// [`AnnounceOutcome::as_str`], so a new outcome cannot be added without
/// giving it a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceOutcome {
    /// Written into typed cluster state.
    Published,
    /// This node is not a mesh member, so there is nobody to tell. Not a
    /// failure: the great majority of authorities are single nodes serving
    /// subscribers over the internet.
    NotClustered,
    /// The write was refused or its owner was unreachable. Subscribers fall
    /// back to their poll interval, which is where they started.
    Failed,
}

impl AnnounceOutcome {
    /// Stable metric label. Never changes for a given variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::NotClustered => "not_clustered",
            Self::Failed => "failed",
        }
    }
}

/// What one read of the announcement means for a subscriber's cursor.
///
/// The `outcome` label on `sbproxy_config_bundle_gossip_total` comes from
/// [`GossipProbe::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipProbe {
    /// An announcement above the local cursor. Pull now.
    Hint,
    /// An announcement at or below the local cursor. No fetch: this node
    /// already holds that revision, or one past it.
    Stale,
    /// Nothing is announced, or the announcement passed its TTL.
    Absent,
    /// The announcement could not be read, or it did not validate. Treated
    /// exactly like `Absent` by the caller; counted separately so an
    /// operator can tell a quiet cluster from a broken one.
    Unreadable,
}

impl GossipProbe {
    /// Stable metric label. Never changes for a given variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hint => "hint",
            Self::Stale => "stale",
            Self::Absent => "absent",
            Self::Unreadable => "unreadable",
        }
    }

    /// Whether this probe should cut the poll interval short.
    #[must_use]
    pub const fn triggers_pull(self) -> bool {
        matches!(self, Self::Hint)
    }
}

/// Why a poll cycle ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleTrigger {
    /// The poll interval elapsed. The only trigger a non-mesh subscriber
    /// ever reports, and the one every subscriber falls back to.
    Interval,
    /// A cluster peer announced a revision this node does not hold.
    Gossip,
}

impl CycleTrigger {
    /// Stable log field. Never changes for a given variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interval => "interval",
            Self::Gossip => "gossip",
        }
    }
}

/// A mesh-member subscriber's read side of the announcement.
///
/// Constructing one is the whole gate: [`ConfigGossipWatcher::from_handle`]
/// returns `None` for a handle with no mesh node, and a subscriber without a
/// watcher runs precisely the code it ran before this module existed.
#[derive(Debug, Clone)]
pub struct ConfigGossipWatcher {
    handle: ClusterHandle,
    probe_interval: Duration,
}

impl ConfigGossipWatcher {
    /// Build a watcher over one cluster handle.
    ///
    /// `None` when the handle has no mesh node, which covers both a node
    /// with no `proxy.cluster` block at all and a node whose handle is the
    /// one-process local mode. Neither has peers to hear from.
    #[must_use]
    pub fn from_handle(handle: ClusterHandle) -> Option<Self> {
        // A non-mesh handle has no gossip substrate, so there is nothing to
        // watch. Returning None here is what makes a non-mesh subscriber fall
        // back to plain interval polling with no cluster code on its path.
        handle.mesh_node()?;
        Some(Self {
            handle,
            probe_interval: PROBE_INTERVAL,
        })
    }

    /// Watcher over the installed process cluster, when this node is a mesh
    /// member.
    #[must_use]
    pub fn process() -> Option<Self> {
        Self::from_handle(crate::cluster::current_cluster_handle()?)
    }

    /// Replace the probe cadence. Tests use it to keep a case short.
    #[must_use]
    pub fn with_probe_interval(mut self, interval: Duration) -> Self {
        self.probe_interval = interval;
        self
    }

    /// Read the announcement once and classify it against `cursor_revision`.
    ///
    /// Records `sbproxy_config_bundle_gossip_total{outcome}` exactly once per
    /// call, so the counter's sum is the number of probes made.
    pub async fn probe(&self, cursor_revision: u64) -> GossipProbe {
        let probe = self.read(cursor_revision).await;
        sbproxy_observe::metrics::record_config_bundle_gossip(probe.as_str());
        probe
    }

    /// Wait up to `interval` for an announcement above `cursor_revision`.
    ///
    /// Probes on the watcher's cadence and returns as soon as one of them is
    /// a [`GossipProbe::Hint`]. A probe never runs before the first sleep:
    /// the caller has just finished a poll cycle, so there is nothing an
    /// immediate read could tell it.
    pub async fn wait(&self, cursor_revision: u64, interval: Duration) -> CycleTrigger {
        let started = std::time::Instant::now();
        loop {
            let elapsed = started.elapsed();
            if elapsed >= interval {
                return CycleTrigger::Interval;
            }
            tokio::time::sleep((interval - elapsed).min(self.probe_interval)).await;
            if self.probe(cursor_revision).await.triggers_pull() {
                return CycleTrigger::Gossip;
            }
        }
    }

    async fn read(&self, cursor_revision: u64) -> GossipProbe {
        let read = self
            .handle
            .read_state::<RevisionAnnouncement>(
                ANNOUNCEMENT_NAMESPACE,
                ANNOUNCEMENT_KEY,
                ANNOUNCEMENT_SCHEMA_VERSION,
            )
            .await;
        let record = match read {
            ClusterStateRead::Present(record) => record,
            ClusterStateRead::Missing | ClusterStateRead::Expired { .. } => {
                return GossipProbe::Absent
            }
            other => {
                // Debug rather than warn: an owner that is briefly
                // unreachable during a membership change is ordinary, and
                // the consequence is one subscriber waiting out one
                // interval it would otherwise have skipped.
                tracing::debug!(
                    read = ?other,
                    "config revision announcement could not be read; falling back to the poll \
                     interval",
                );
                return GossipProbe::Unreadable;
            }
        };
        if let Err(reason) = validate(&record) {
            tracing::warn!(
                reason,
                publisher = %record.publisher_node_id,
                "refusing a config revision announcement; falling back to the poll interval",
            );
            return GossipProbe::Unreadable;
        }
        if record.payload.revision > cursor_revision {
            GossipProbe::Hint
        } else {
            GossipProbe::Stale
        }
    }
}

/// Screen one announcement before its revision is allowed to shorten a wait.
///
/// None of this protects configuration, which the pull path verifies on its
/// own account. It protects the poll interval: a member that announces
/// `u64::MAX` would otherwise have every subscriber in the cluster fetching
/// on the probe cadence forever, and the answer would be `304` every time.
fn validate(record: &ClusterStateRecord<RevisionAnnouncement>) -> Result<(), &'static str> {
    if record.payload.revision == 0 {
        return Err("announcement names revision zero, which no publication produces");
    }
    if record.generation != record.payload.revision {
        return Err("announcement generation does not match the revision it carries");
    }
    for field in [
        record.payload.content_digest.as_str(),
        record.payload.authority_id.as_str(),
    ] {
        if field.is_empty() || field.len() > MAX_ANNOUNCEMENT_FIELD_LEN {
            return Err("announcement identity field is empty or oversized");
        }
    }
    // Only enforceable where canonical mTLS gives the envelope enrolled
    // claims; a manual-PKI or shared-key cluster has none, and the same
    // check in `cluster::validate_enrolled_authority_publisher` is
    // conditional for the same reason.
    if record
        .authenticated_identity
        .as_ref()
        .is_some_and(|identity| {
            identity.node_id != record.publisher_node_id
                || !identity.roles.contains(&ClusterNodeRole::Authority)
        })
    {
        return Err("announcement publisher lacks its enrolled authority role");
    }
    Ok(())
}

/// Publish one announcement through `handle`.
///
/// Returns [`AnnounceOutcome::NotClustered`] without writing anything when
/// the handle has no mesh node: a local handle's typed state is visible to
/// this process and nobody else, so writing there would spend a generation
/// to tell ourselves something we already know.
///
/// Records `sbproxy_config_authority_announce_total{result}` exactly once per
/// call.
pub async fn announce_on(
    handle: &ClusterHandle,
    announcement: &RevisionAnnouncement,
) -> AnnounceOutcome {
    if handle.mesh_node().is_none() {
        return record_announce(AnnounceOutcome::NotClustered);
    }
    // The revision doubles as the generation, so cluster state fences an
    // out-of-order announcement the same way the deployment authority
    // fences an out-of-order bundle pointer. `validate` then refuses any
    // record where the two disagree.
    let outcome = match handle
        .publish_state(
            ANNOUNCEMENT_NAMESPACE,
            ANNOUNCEMENT_KEY,
            ANNOUNCEMENT_SCHEMA_VERSION,
            announcement.revision,
            ANNOUNCEMENT_TTL,
            announcement,
        )
        .await
    {
        Ok(()) => {
            tracing::debug!(
                revision = announcement.revision,
                authority_id = %announcement.authority_id,
                "announced a config revision to the cluster",
            );
            AnnounceOutcome::Published
        }
        Err(error) => {
            // Never propagated to the publish path. The revision is signed,
            // stored, and already being served; a fleet that hears about it
            // one poll interval later is the pre-existing behaviour, not an
            // incident.
            tracing::warn!(
                error = %error,
                revision = announcement.revision,
                "could not announce a config revision to the cluster; subscribers will pick it \
                 up on their next poll",
            );
            AnnounceOutcome::Failed
        }
    };
    record_announce(outcome)
}

/// Announce a revision through the installed process cluster.
///
/// Blocking, on the process cluster runtime rather than the caller's, because
/// the publish path this hangs off is synchronous and may itself be running
/// inside a runtime. Publishing happens when an operator asks for it, and the
/// call it follows has already compiled a whole configuration and constructed
/// a whole pipeline, so a bounded cluster write on the end of that is not the
/// expensive part.
pub fn announce_revision(
    authority_id: &str,
    revision: u64,
    content_digest: &str,
) -> AnnounceOutcome {
    let Some(handle) = crate::cluster::current_cluster_handle() else {
        return record_announce(AnnounceOutcome::NotClustered);
    };
    if handle.mesh_node().is_none() {
        return record_announce(AnnounceOutcome::NotClustered);
    }
    let announcement = RevisionAnnouncement {
        revision,
        content_digest: content_digest.to_string(),
        authority_id: authority_id.to_string(),
    };
    crate::cluster::block_on_cluster(async move { announce_on(&handle, &announcement).await })
}

/// Count one announcement attempt and hand the outcome back, so every exit
/// from the announce path records exactly once by construction.
fn record_announce(outcome: AnnounceOutcome) -> AnnounceOutcome {
    sbproxy_observe::metrics::record_config_authority_announce(outcome.as_str());
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        generation: u64,
        payload: RevisionAnnouncement,
    ) -> ClusterStateRecord<RevisionAnnouncement> {
        ClusterStateRecord {
            publisher_node_id: "authority-a".to_string(),
            schema_version: ANNOUNCEMENT_SCHEMA_VERSION,
            generation,
            published_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            authenticated_identity: None,
            payload,
        }
    }

    fn announcement(revision: u64) -> RevisionAnnouncement {
        RevisionAnnouncement {
            revision,
            content_digest: format!("sha256:{}", "a".repeat(64)),
            authority_id: "acme-prod".to_string(),
        }
    }

    #[test]
    fn every_label_is_the_documented_string() {
        assert_eq!(
            [
                AnnounceOutcome::Published,
                AnnounceOutcome::NotClustered,
                AnnounceOutcome::Failed,
            ]
            .map(AnnounceOutcome::as_str),
            ["published", "not_clustered", "failed"],
        );
        assert_eq!(
            [
                GossipProbe::Hint,
                GossipProbe::Stale,
                GossipProbe::Absent,
                GossipProbe::Unreadable,
            ]
            .map(GossipProbe::as_str),
            ["hint", "stale", "absent", "unreadable"],
        );
        assert_eq!(
            [CycleTrigger::Interval, CycleTrigger::Gossip].map(CycleTrigger::as_str),
            ["interval", "gossip"],
        );
    }

    #[test]
    fn only_a_hint_shortens_the_wait() {
        assert!(GossipProbe::Hint.triggers_pull());
        assert!(!GossipProbe::Stale.triggers_pull());
        assert!(!GossipProbe::Absent.triggers_pull());
        assert!(!GossipProbe::Unreadable.triggers_pull());
    }

    #[test]
    fn a_well_formed_announcement_validates() {
        assert_eq!(validate(&record(7, announcement(7))), Ok(()));
    }

    #[test]
    fn revision_zero_and_a_mismatched_generation_are_refused() {
        assert!(validate(&record(0, announcement(0))).is_err());
        assert!(validate(&record(8, announcement(7))).is_err());
    }

    #[test]
    fn empty_and_oversized_identity_fields_are_refused() {
        let mut empty = announcement(7);
        empty.content_digest = String::new();
        assert!(validate(&record(7, empty)).is_err());

        let mut huge = announcement(7);
        huge.authority_id = "a".repeat(MAX_ANNOUNCEMENT_FIELD_LEN + 1);
        assert!(validate(&record(7, huge)).is_err());
    }

    #[test]
    fn the_payload_carries_three_scalars_and_no_config_body() {
        let encoded = serde_json::to_value(announcement(7)).expect("encode announcement");
        let object = encoded.as_object().expect("announcement is a JSON object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["authority_id", "content_digest", "revision"]);
    }

    #[test]
    fn an_announcement_with_an_extra_field_is_refused() {
        // `deny_unknown_fields`, so a future publisher that starts stapling
        // the config body on gets refused here rather than having a
        // subscriber quietly ignore it.
        let smuggled = serde_json::json!({
            "revision": 7,
            "content_digest": "sha256:abc",
            "authority_id": "acme-prod",
            "config_yaml": "origins: {}\n",
        });
        assert!(serde_json::from_value::<RevisionAnnouncement>(smuggled).is_err());
    }

    #[test]
    fn the_ttl_is_bounded_and_not_forever() {
        assert!(ANNOUNCEMENT_TTL >= Duration::from_secs(60));
        assert!(ANNOUNCEMENT_TTL <= Duration::from_secs(60 * 60));
        assert!(PROBE_INTERVAL < ANNOUNCEMENT_TTL);
    }
}
