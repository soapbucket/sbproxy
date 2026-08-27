//! The facade the rest of the proxy holds: one value that owns the catalog,
//! the registration queue, and the observability every decision through them
//! produces.
//!
//! Keeping the counting and the event emission here rather than inside
//! [`crate::registration::RegistrationQueue`] means the queue stays a
//! testable state machine with no global registry or event bus behind it,
//! and there is exactly one place to read to find out what an operator can
//! see. The cost is that a caller reaching past this type into the queue
//! gets no metrics; nothing in this workspace does, and the queue is not
//! re-exported for that reason.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use sbproxy_platform::storage::{EphemeralKv, PersistentKv};

use crate::catalog::{Catalog, CatalogStore};
use crate::error::{RegistryError, Result};
use crate::feed::{verify_feed, verify_key_directory, BootstrapKeys};
use crate::metrics::{record_registry_op, set_registry_entries};
use crate::registration::{
    AgentMetadata, ApprovalState, RegistrationQueue, RegistrationSecrets, RegistrationView,
    RotatedSecret, TenantScope,
};

/// How the registry was configured.
#[derive(Debug, Clone)]
pub struct AgentRegistryOptions {
    /// File holding the signed catalog feed. Absent means the registry
    /// serves whatever the store last cached and refuses a refresh.
    pub feed_path: Option<PathBuf>,
    /// File holding the signed key directory.
    pub key_directory_path: Option<PathBuf>,
    /// Bootstrap public keys that vouch for the key directory.
    pub bootstrap_keys: BootstrapKeys,
    /// How far past its own `expires_at` a feed may still be applied.
    pub stale_grace: Duration,
    /// How long an identical resubmission is treated as a retry.
    pub duplicate_window: Duration,
    /// How long a rotated-away client secret keeps working.
    pub rotation_grace: Duration,
}

impl Default for AgentRegistryOptions {
    fn default() -> Self {
        Self {
            feed_path: None,
            key_directory_path: None,
            bootstrap_keys: BootstrapKeys::default(),
            stale_grace: Duration::zero(),
            duplicate_window: Duration::hours(1),
            rotation_grace: Duration::days(30),
        }
    }
}

/// What `GET /admin/agent-registry` answers with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RegistrySummary {
    /// The tenant these queue counts cover: a tenant name for a scoped
    /// operator, or `all` for a deployment-wide one. The catalog fields
    /// below are always deployment-wide, because the catalog is one signed
    /// feed for the whole proxy; a scoped operator sees its size here and
    /// is refused its contents.
    pub scope: String,
    /// Whether this operator may read the catalog listing and refresh the
    /// feed. False for a tenant-scoped operator, which is what the console
    /// hides those controls on.
    pub catalog_writable: bool,
    /// How many agents the live catalog names.
    pub catalog_entries: usize,
    /// When the publisher built the catalog in memory, if there is one.
    pub catalog_generated_at: Option<DateTime<Utc>>,
    /// When that catalog expires.
    pub catalog_expires_at: Option<DateTime<Utc>>,
    /// Whether the catalog in memory is past its expiry right now.
    pub catalog_expired: bool,
    /// Registrations awaiting a decision.
    pub pending: usize,
    /// Registrations an operator approved.
    pub approved: usize,
    /// Registrations an operator rejected.
    pub rejected: usize,
    /// Registrations an operator revoked.
    pub revoked: usize,
    /// Whether a feed and a key directory are configured, which is what
    /// separates "refresh found nothing" from "refresh cannot run".
    pub feed_configured: bool,
    /// How many bootstrap keys vouch for the key directory. Zero means no
    /// feed can ever verify.
    pub bootstrap_keys: usize,
}

/// The agent registry: a verified catalog and an owner-approval queue over
/// one shared embedded store.
pub struct AgentRegistry {
    catalog: CatalogStore,
    queue: RegistrationQueue,
    options: AgentRegistryOptions,
}

impl AgentRegistry {
    /// Build a registry over a durable store and an ephemeral dedup window.
    pub fn new(
        store: Arc<dyn PersistentKv>,
        dedup: Arc<dyn EphemeralKv>,
        options: AgentRegistryOptions,
    ) -> Result<Self> {
        let queue = RegistrationQueue::new(
            Arc::clone(&store),
            dedup,
            options.duplicate_window,
            options.rotation_grace,
        )?;
        Ok(Self {
            catalog: CatalogStore::new(store)?,
            queue,
            options,
        })
    }

    /// Load the last verified catalog and publish the opening gauge values.
    ///
    /// A registry that boots and publishes zero is distinguishable from one
    /// that was never configured, which is the whole reason the gauge
    /// exists. Call this once at startup, before anything reads.
    pub async fn boot(&self) -> Result<usize> {
        let restored = self.catalog.restore().await?;
        record_registry_op("boot", "applied");
        self.publish_gauges().await?;
        tracing::info!(
            restored_entries = restored,
            "agent registry restored its cached catalog"
        );
        Ok(restored)
    }

    /// The live catalog snapshot.
    pub fn catalog(&self) -> Arc<Catalog> {
        self.catalog.snapshot()
    }

    /// Re-read the configured feed and key directory, verify both, and swap
    /// the result in.
    ///
    /// Nothing is applied unless verification passes end to end, so a
    /// tampered or expired feed leaves the previous catalog exactly where it
    /// was. That is the fail-closed direction: an operator would rather
    /// serve yesterday's verified catalog than today's unverified one.
    pub async fn refresh(&self, now: DateTime<Utc>) -> Result<usize> {
        let outcome = self.refresh_inner(now).await;
        match &outcome {
            Ok(applied) => {
                record_registry_op("feed_refresh", "applied");
                tracing::info!(
                    entries = applied,
                    "agent registry applied a verified catalog feed"
                );
            }
            Err(error) => {
                record_registry_op("feed_refresh", error.outcome());
                // warn rather than error: the previous catalog is still
                // serving, so this is a degraded refresh rather than a fault.
                tracing::warn!(
                    reason = error.outcome(),
                    error = %error,
                    "agent registry refused a catalog feed; the previous catalog is still in effect"
                );
            }
        }
        if outcome.is_ok() {
            self.publish_gauges().await?;
        }
        outcome
    }

    async fn refresh_inner(&self, now: DateTime<Utc>) -> Result<usize> {
        let (Some(feed_path), Some(directory_path)) = (
            self.options.feed_path.as_ref(),
            self.options.key_directory_path.as_ref(),
        ) else {
            return Err(RegistryError::Invalid {
                field: "feed",
                detail: "no feed path and key directory path are configured".into(),
            });
        };
        let directory_bytes = std::fs::read(directory_path).map_err(|error| {
            RegistryError::Backend(format!(
                "could not read the key directory at {}: {error}",
                directory_path.display()
            ))
        })?;
        let directory = verify_key_directory(&directory_bytes, &self.options.bootstrap_keys)?;

        let feed_bytes = std::fs::read(feed_path).map_err(|error| {
            RegistryError::Backend(format!(
                "could not read the catalog feed at {}: {error}",
                feed_path.display()
            ))
        })?;
        let feed = verify_feed(&feed_bytes, &directory, now, self.options.stale_grace)?;
        self.catalog.apply(feed).await
    }

    /// Accept a submission into the queue.
    pub async fn register(
        &self,
        scope: &TenantScope,
        metadata: AgentMetadata,
        actor: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<(RegistrationSecrets, RegistrationView)> {
        let outcome = self.queue.register(scope, metadata, now).await;
        match &outcome {
            Ok((_, view)) => {
                record_registry_op("register", "applied");
                self.emit_decision(&view.agent_id, "submitted", view.state, actor);
            }
            Err(error) => record_registry_op("register", error.outcome()),
        }
        if outcome.is_ok() {
            self.publish_gauges().await?;
        }
        outcome
    }

    /// Approve a pending registration.
    pub async fn approve(
        &self,
        scope: &TenantScope,
        agent_id: &str,
        reason: Option<String>,
        decided_by: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<RegistrationView> {
        let actor = decided_by.clone();
        let outcome = self
            .queue
            .approve(scope, agent_id, reason, decided_by, now)
            .await;
        self.after_decision("approve", agent_id, actor, outcome)
            .await
    }

    /// Reject a pending registration, burning its slug.
    pub async fn reject(
        &self,
        scope: &TenantScope,
        agent_id: &str,
        reason: String,
        decided_by: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<RegistrationView> {
        let actor = decided_by.clone();
        let outcome = self
            .queue
            .reject(scope, agent_id, reason, decided_by, now)
            .await;
        self.after_decision("reject", agent_id, actor, outcome)
            .await
    }

    /// Revoke a registration, burning its slug.
    pub async fn revoke(
        &self,
        scope: &TenantScope,
        agent_id: &str,
        reason: Option<String>,
        decided_by: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<RegistrationView> {
        let actor = decided_by.clone();
        let outcome = self
            .queue
            .revoke(scope, agent_id, reason, decided_by, now)
            .await;
        self.after_decision("revoke", agent_id, actor, outcome)
            .await
    }

    /// Count, log, and publish one decision, whichever it was.
    ///
    /// The three decisions differ only in which queue method they call and
    /// what they are called; everything an operator sees afterwards is the
    /// same, so it is written once. A separate copy per decision is where a
    /// missing counter or a missing event comes from.
    async fn after_decision(
        &self,
        op: &'static str,
        agent_id: &str,
        decided_by: Option<String>,
        outcome: Result<RegistrationView>,
    ) -> Result<RegistrationView> {
        match &outcome {
            Ok(view) => {
                record_registry_op(op, "applied");
                self.emit_decision(&view.agent_id, op, view.state, decided_by.as_deref());
                tracing::info!(
                    agent_id = %view.agent_id,
                    decision = op,
                    state = view.state.as_str(),
                    "agent registration decided"
                );
            }
            Err(error) => {
                record_registry_op(op, error.outcome());
                tracing::warn!(
                    agent_id = %agent_id,
                    decision = op,
                    reason = error.outcome(),
                    "agent registration decision refused"
                );
            }
        }
        if outcome.is_ok() {
            self.publish_gauges().await?;
        }
        outcome
    }

    /// Rotate a registration's client secret, authenticated by its
    /// registration access token.
    pub async fn rotate_secret(
        &self,
        scope: &TenantScope,
        agent_id: &str,
        registration_access_token: &str,
        now: DateTime<Utc>,
    ) -> Result<RotatedSecret> {
        let outcome = self
            .queue
            .rotate_secret(scope, agent_id, registration_access_token, now)
            .await;
        match &outcome {
            Ok(_) => record_registry_op("rotate", "applied"),
            Err(error) => record_registry_op("rotate", error.outcome()),
        }
        outcome
    }

    /// Whether `presented` authenticates as this agent right now.
    pub async fn verify_client_secret(
        &self,
        scope: &TenantScope,
        agent_id: &str,
        presented: &str,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let outcome = self
            .queue
            .verify_client_secret(scope, agent_id, presented, now)
            .await;
        match &outcome {
            Ok(true) => record_registry_op("verify", "applied"),
            Ok(false) => record_registry_op("verify", "unauthorized"),
            Err(error) => record_registry_op("verify", error.outcome()),
        }
        outcome
    }

    /// Read one registration.
    pub async fn get(&self, scope: &TenantScope, agent_id: &str) -> Result<RegistrationView> {
        self.queue.get(scope, agent_id).await
    }

    /// List registrations, optionally filtered to one state.
    pub async fn list(
        &self,
        scope: &TenantScope,
        state: Option<ApprovalState>,
    ) -> Result<Vec<RegistrationView>> {
        self.queue.list(scope, state).await
    }

    /// The operator summary.
    pub async fn summary(
        &self,
        scope: &TenantScope,
        now: DateTime<Utc>,
    ) -> Result<RegistrySummary> {
        let catalog = self.catalog.snapshot();
        let counts = self.queue.counts(scope).await?;
        let count_of = |wanted: ApprovalState| {
            counts
                .iter()
                .find(|(state, _)| *state == wanted)
                .map(|(_, count)| *count)
                .unwrap_or(0)
        };
        Ok(RegistrySummary {
            scope: match scope {
                TenantScope::All => "all".to_string(),
                TenantScope::Only(tenant) => tenant.clone(),
            },
            catalog_writable: !scope.is_scoped(),
            catalog_entries: catalog.len(),
            catalog_generated_at: catalog.generated_at(),
            catalog_expires_at: catalog.expires_at(),
            catalog_expired: catalog.is_expired(now),
            pending: count_of(ApprovalState::Pending),
            approved: count_of(ApprovalState::Approved),
            rejected: count_of(ApprovalState::Rejected),
            revoked: count_of(ApprovalState::Revoked),
            feed_configured: self.options.feed_path.is_some()
                && self.options.key_directory_path.is_some(),
            bootstrap_keys: self.options.bootstrap_keys.len(),
        })
    }

    async fn publish_gauges(&self) -> Result<()> {
        set_registry_entries("catalog", self.catalog.snapshot().len() as i64);
        for (state, count) in self.queue.counts(&TenantScope::All).await? {
            let collection = match state {
                ApprovalState::Pending => "pending",
                ApprovalState::Approved => "approved",
                ApprovalState::Rejected => "rejected",
                ApprovalState::Revoked => "revoked",
            };
            set_registry_entries(collection, count as i64);
        }
        Ok(())
    }

    /// Publish the typed decision event.
    ///
    /// `publish_proxy_event` is fire-and-forget by design: an operator who
    /// configured no `events:` sink has said they do not want one, and an
    /// approval should not fail because a SIEM is unreachable. The durable
    /// record of the decision is the store, not the event.
    fn emit_decision(
        &self,
        agent_id: &str,
        decision: &str,
        state: ApprovalState,
        decided_by: Option<&str>,
    ) {
        let agent_id = agent_id.to_owned();
        let decision = decision.to_owned();
        let decided_by = decided_by.map(str::to_owned);
        sbproxy_observe::event_sink::publish_proxy_event(
            sbproxy_observe::EventType::AgentRegistrationDecided,
            move || {
                sbproxy_observe::events::AgentRegistrationDecidedData::new(
                    &agent_id,
                    &decision,
                    state.as_str(),
                    decided_by.as_deref(),
                )
                .into_proxy_event(String::new(), String::new())
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registration::{Purpose, RequestedScope};
    use sbproxy_platform::storage::{EmbeddedKvStore, MemoryKv};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("fixed instant")
    }

    fn temp_path() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(
            "{}/sbproxy_agent_service_test_{}_{}.redb",
            std::env::temp_dir().display(),
            std::process::id(),
            n
        )
    }

    fn registry(path: &str, options: AgentRegistryOptions) -> AgentRegistry {
        let store = EmbeddedKvStore::open(path, "agent_registry").expect("open store");
        AgentRegistry::new(
            Arc::new(store),
            Arc::new(MemoryKv::new("agent_registry")),
            options,
        )
        .expect("registry")
    }

    fn metadata() -> AgentMetadata {
        AgentMetadata {
            vendor: "Acme".into(),
            purpose: Purpose::Search,
            contact_url: "https://acme.example.com/bots".into(),
            expected_user_agents: vec!["AcmeBot/1.0".into()],
            expected_reverse_dns_suffixes: vec![],
            expected_keyids: vec![],
            requested_scopes: vec![RequestedScope::CrawlPublic],
        }
    }

    #[tokio::test]
    async fn the_summary_separates_never_configured_from_empty() {
        let path = temp_path();
        let registry = registry(&path, AgentRegistryOptions::default());
        registry.boot().await.expect("boot");

        let summary = registry
            .summary(&TenantScope::All, now())
            .await
            .expect("summary");
        assert_eq!(summary.catalog_entries, 0);
        assert!(!summary.feed_configured, "no feed path means no refresh");
        assert_eq!(summary.bootstrap_keys, 0);
        assert_eq!(summary.pending, 0);

        registry
            .register(&TenantScope::All, metadata(), None, now())
            .await
            .expect("register");
        let summary = registry
            .summary(&TenantScope::All, now())
            .await
            .expect("summary");
        assert_eq!(summary.pending, 1);
        assert_eq!(summary.approved, 0);

        std::fs::remove_file(&path).ok();
    }

    /// A refresh with nothing configured has to say so rather than
    /// reporting a successful zero-entry apply, which is what an operator
    /// would read as "the publisher sent an empty catalog".
    #[tokio::test]
    async fn a_refresh_with_no_feed_configured_is_refused_rather_than_reported_empty() {
        let path = temp_path();
        let registry = registry(&path, AgentRegistryOptions::default());
        assert!(matches!(
            registry.refresh(now()).await,
            Err(RegistryError::Invalid { field: "feed", .. })
        ));
        std::fs::remove_file(&path).ok();
    }

    /// The fail-closed direction, and the reason refresh is not "read the
    /// file, swap it in": a feed that does not verify must leave the
    /// previous catalog exactly where it was.
    #[tokio::test]
    async fn a_feed_that_does_not_verify_leaves_the_previous_catalog_in_place() {
        use crate::feed::test_support::{public_b64, sign_document};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let dir = std::env::temp_dir().join(format!(
            "sbproxy_agent_feed_test_{}_{}",
            std::process::id(),
            now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let feed_path = dir.join("feed.json");
        let directory_path = dir.join("keys.json");

        let bootstrap = SigningKey::generate(&mut OsRng);
        let feed_key = SigningKey::generate(&mut OsRng);
        std::fs::write(
            &directory_path,
            sign_document(
                serde_json::json!({
                    "format_version": 1,
                    "generated_at": now().to_rfc3339(),
                    "active": {"kid": "feed-1", "alg": "ed25519", "public_key": public_b64(&feed_key)},
                    "grace": [],
                    "revoked": [],
                }),
                "boot-1",
                &bootstrap,
            ),
        )
        .expect("write directory");

        let feed_body = |agent_id: &str| {
            serde_json::json!({
                "format_version": 1,
                "generated_at": now().to_rfc3339(),
                "expires_at": (now() + Duration::hours(24)).to_rfc3339(),
                "entries": [{
                    "agent_id": agent_id,
                    "vendor": "Acme",
                    "purpose": "search",
                    "expected_user_agents": ["AcmeBot/1.0"],
                    "reputation_score": 80,
                }],
                "signature": {"kid": "feed-1", "sig": ""},
            })
        };
        std::fs::write(
            &feed_path,
            sign_document(feed_body("acme-1"), "feed-1", &feed_key),
        )
        .expect("write feed");

        let path = temp_path();
        let options = AgentRegistryOptions {
            feed_path: Some(feed_path.clone()),
            key_directory_path: Some(directory_path),
            bootstrap_keys: BootstrapKeys::from_pairs([("boot-1", public_b64(&bootstrap))])
                .expect("bootstrap"),
            ..AgentRegistryOptions::default()
        };
        let registry = registry(&path, options);
        assert_eq!(registry.refresh(now()).await.expect("first refresh"), 1);
        assert!(registry.catalog().get("acme-1").is_some());

        // Now tamper with the feed after signing.
        let signed = sign_document(feed_body("acme-2"), "feed-1", &feed_key);
        let mut document: serde_json::Value = serde_json::from_slice(&signed).expect("parse");
        document["entries"][0]["reputation_score"] = serde_json::json!(1);
        std::fs::write(
            &feed_path,
            serde_json::to_vec(&document).expect("serialize"),
        )
        .expect("write tampered feed");

        assert!(matches!(
            registry.refresh(now()).await,
            Err(RegistryError::Signature(_))
        ));
        let catalog = registry.catalog();
        assert!(
            catalog.get("acme-1").is_some(),
            "the previously verified catalog must still be serving"
        );
        assert!(catalog.get("acme-2").is_none());

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir_all(&dir).ok();
    }
}
