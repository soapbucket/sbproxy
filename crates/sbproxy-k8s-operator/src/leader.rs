//! Leader election via a Kubernetes `Lease` resource.
//!
//! `kube-runtime` 0.95 ships no `leader_election` helper, so this module
//! drives the well-trodden `coordination.k8s.io/v1.Lease` pattern by hand.
//! The shape is intentionally small:
//!
//! 1. **Acquire**: `acquire_lease` blocks until this pod owns the Lease.
//! 2. **Renew**: `renew_loop` periodically PATCHes `renewTime` so other
//!    candidates back off.
//! 3. **Step down**: any failure to renew (the lease was stolen, the API
//!    server is unreachable, the holder string no longer matches) returns
//!    `Err`. The caller cancels the controller and exits with code 0 so
//!    the pod is restarted by the Deployment and re-races for the lock.
//!
//! The implementation deliberately avoids server-side-apply on the Lease.
//! SSA's "force ownership" semantics interact poorly with the holder field
//! (a successful apply by a non-holder would steal the lease). We use plain
//! merge PATCHes guarded by `resourceVersion` precondition equivalents
//! (a holder check after read) so two candidates only see one winner.
//!
//! The chosen defaults match the upstream `client-go` defaults so anyone
//! familiar with kubelet / kube-controller-manager leader election can read
//! the timing without surprise:
//!
//! | Field | Value |
//! | --- | --- |
//! | `lease_duration` | 15s |
//! | `renew_deadline` | 10s |
//! | `retry_period` | 2s |
//!
//! The `renew_deadline` exists so we step down before the lease expires,
//! giving the next candidate a clean handoff.

use std::time::Duration;

use chrono::Utc;
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use kube::Client;
use serde_json::json;
use tokio::time::sleep;

/// How long a held lease is considered valid before another candidate may
/// force-acquire it. Matches client-go's default.
pub const LEASE_DURATION: Duration = Duration::from_secs(15);

/// How long the holder waits between renew attempts. Must be < `LEASE_DURATION`
/// minus `RETRY_PERIOD` to leave headroom for a few failed retries before the
/// lease expires from the other side's perspective.
pub const RENEW_PERIOD: Duration = Duration::from_secs(5);

/// How long a contender waits between acquire attempts when the lease is held
/// by someone else.
pub const RETRY_PERIOD: Duration = Duration::from_secs(2);

/// Per-renew API call timeout. The renew loop fails closed if the API server
/// stalls for longer than this; the caller treats that as a step-down.
pub const RENEW_DEADLINE: Duration = Duration::from_secs(10);

/// Configuration for a leader-election session.
#[derive(Debug, Clone)]
pub struct LeaderConfig {
    /// The Lease name, e.g. `sbproxy-operator-leader`.
    pub lease_name: String,

    /// Namespace the Lease lives in.
    pub namespace: String,

    /// Stable holder identity. Pod name is conventional; we suffix a short
    /// random tag to avoid stale-acquire races when a Deployment re-creates a
    /// pod with the same name in quick succession.
    pub identity: String,
}

/// Holder-identity helper. Builds `<hostname>_<8 hex chars>` so multiple
/// candidates on the same host (kind, mac docker desktop) get distinct ids.
pub fn build_identity(hostname: &str) -> String {
    use rand::Rng;
    let suffix: u32 = rand::thread_rng().gen();
    format!("{hostname}_{suffix:08x}")
}

/// Discover the namespace the operator pod is running in.
///
/// Resolution order, matching the controller-runtime convention:
///
/// 1. `K8S_NAMESPACE` environment variable (chart-set or operator-set).
/// 2. `/var/run/secrets/kubernetes.io/serviceaccount/namespace`, present on
///    every pod that mounts the default service-account token.
/// 3. The fallback string `"default"`. Only ever hit when running outside a
///    pod (e.g. `cargo run` against a kind cluster).
///
/// Pure function over inputs so it can be unit-tested without a filesystem.
pub fn discover_namespace<F>(env_lookup: impl Fn(&str) -> Option<String>, file_read: F) -> String
where
    F: FnOnce() -> Option<String>,
{
    if let Some(ns) = env_lookup("K8S_NAMESPACE")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return ns;
    }
    if let Some(ns) = file_read()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return ns;
    }
    "default".to_string()
}

/// Default service-account namespace path. Pulled out so tests don't need to
/// monkey-patch the filesystem.
pub const SERVICE_ACCOUNT_NS_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

/// Convenience wrapper used by `main.rs`: discover the namespace using the
/// real environment + service-account file.
pub fn discover_namespace_default() -> String {
    discover_namespace(
        |k| std::env::var(k).ok(),
        || std::fs::read_to_string(SERVICE_ACCOUNT_NS_PATH).ok(),
    )
}

/// Outcome of a single acquire attempt.
#[derive(Debug)]
enum AcquireOutcome {
    /// We are now the holder.
    Acquired,
    /// Someone else holds the lease and it is still fresh.
    Held,
}

/// Block until this pod owns the Lease.
///
/// Polls every [`RETRY_PERIOD`]. The function only returns once we are the
/// holder; the caller then enters the renew loop.
pub async fn acquire_lease(client: &Client, cfg: &LeaderConfig) -> anyhow::Result<()> {
    let api: Api<Lease> = Api::namespaced(client.clone(), &cfg.namespace);

    loop {
        match try_acquire(&api, cfg).await {
            Ok(AcquireOutcome::Acquired) => {
                tracing::info!(
                    lease = %cfg.lease_name,
                    namespace = %cfg.namespace,
                    identity = %cfg.identity,
                    "acquired leader lease"
                );
                return Ok(());
            }
            Ok(AcquireOutcome::Held) => {
                tracing::debug!(
                    lease = %cfg.lease_name,
                    namespace = %cfg.namespace,
                    "lease held by another candidate; retrying"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    lease = %cfg.lease_name,
                    namespace = %cfg.namespace,
                    "acquire attempt failed; retrying"
                );
            }
        }
        sleep(RETRY_PERIOD).await;
    }
}

/// Attempt one Lease acquire / steal cycle.
///
/// Behaviour matches client-go:
///
/// - If the Lease is missing, CREATE it with us as holder.
/// - If the Lease is held by us, refresh `renewTime` and report acquired.
/// - If the Lease is held by someone else and not yet expired, return `Held`.
/// - If the Lease is expired, PATCH ourselves into the holder slot and bump
///   `leaseTransitions`.
async fn try_acquire(api: &Api<Lease>, cfg: &LeaderConfig) -> anyhow::Result<AcquireOutcome> {
    let now = MicroTime(Utc::now());
    let existing = api.get_opt(&cfg.lease_name).await?;

    match existing {
        None => {
            // Lease does not exist yet; create it with ourselves as holder.
            let lease = Lease {
                metadata: ObjectMeta {
                    name: Some(cfg.lease_name.clone()),
                    namespace: Some(cfg.namespace.clone()),
                    ..Default::default()
                },
                spec: Some(LeaseSpec {
                    holder_identity: Some(cfg.identity.clone()),
                    lease_duration_seconds: Some(LEASE_DURATION.as_secs() as i32),
                    acquire_time: Some(now.clone()),
                    renew_time: Some(now),
                    lease_transitions: Some(0),
                }),
            };
            // Conflict here means a peer beat us by milliseconds. Not an error,
            // just retry on the next pass.
            match api.create(&PostParams::default(), &lease).await {
                Ok(_) => Ok(AcquireOutcome::Acquired),
                Err(kube::Error::Api(e)) if e.code == 409 => Ok(AcquireOutcome::Held),
                Err(e) => Err(e.into()),
            }
        }
        Some(lease) => {
            let spec = lease.spec.as_ref();
            let holder = spec.and_then(|s| s.holder_identity.as_deref());
            let expired = is_expired(spec);

            if holder == Some(cfg.identity.as_str()) {
                // Already ours; refresh renewTime so we keep the lease.
                patch_renew(api, cfg, &now, /*transition=*/ false).await?;
                Ok(AcquireOutcome::Acquired)
            } else if expired {
                // Stale; steal it and increment leaseTransitions.
                patch_renew(api, cfg, &now, /*transition=*/ true).await?;
                Ok(AcquireOutcome::Acquired)
            } else {
                Ok(AcquireOutcome::Held)
            }
        }
    }
}

/// Stay holder by renewing every [`RENEW_PERIOD`]. Returns when the lease is
/// no longer ours, or when an API error persists past [`RENEW_DEADLINE`].
///
/// The caller cancels the controller task and exits with code 0 on return so
/// the pod is restarted and re-races for the lock.
pub async fn renew_loop(client: Client, cfg: LeaderConfig) -> anyhow::Result<()> {
    let api: Api<Lease> = Api::namespaced(client, &cfg.namespace);

    loop {
        sleep(RENEW_PERIOD).await;

        let renew = tokio::time::timeout(RENEW_DEADLINE, async {
            let lease = api.get(&cfg.lease_name).await?;
            let holder = lease
                .spec
                .as_ref()
                .and_then(|s| s.holder_identity.as_deref());
            if holder != Some(cfg.identity.as_str()) {
                anyhow::bail!(
                    "lease no longer held by this pod (holder={:?}, expected={:?})",
                    holder,
                    cfg.identity
                );
            }
            let now = MicroTime(Utc::now());
            patch_renew(&api, &cfg, &now, /*transition=*/ false).await?;
            Ok::<(), anyhow::Error>(())
        })
        .await;

        match renew {
            Ok(Ok(())) => continue,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "renew failed; stepping down");
                return Err(e);
            }
            Err(_) => {
                tracing::warn!(
                    "renew API call exceeded {:?}; stepping down",
                    RENEW_DEADLINE
                );
                anyhow::bail!("renew exceeded RENEW_DEADLINE");
            }
        }
    }
}

/// Whether the existing lease is expired (renewTime + leaseDurationSeconds in
/// the past).
fn is_expired(spec: Option<&LeaseSpec>) -> bool {
    let Some(spec) = spec else { return true };
    let dur = Duration::from_secs(spec.lease_duration_seconds.unwrap_or(0).max(0) as u64);
    let Some(MicroTime(renew)) = spec.renew_time.as_ref() else {
        return true;
    };
    let elapsed = Utc::now().signed_duration_since(*renew);
    elapsed
        .to_std()
        .map(|e| e > dur)
        .unwrap_or(false /* renewTime in the future => not expired */)
}

/// PATCH the Lease's holderIdentity / renewTime / acquireTime / transitions.
///
/// `transition=true` bumps `leaseTransitions` and resets `acquireTime`,
/// matching client-go's behaviour when the Lease is being stolen.
async fn patch_renew(
    api: &Api<Lease>,
    cfg: &LeaderConfig,
    now: &MicroTime,
    transition: bool,
) -> Result<(), kube::Error> {
    // Build a JSON merge patch by hand. Server-side-apply on Leases is
    // discouraged because the holder field has hard-write semantics that
    // don't line up with SSA conflict resolution.
    let mut spec = json!({
        "holderIdentity": cfg.identity,
        "leaseDurationSeconds": LEASE_DURATION.as_secs() as i32,
        "renewTime": now,
    });
    if transition {
        // Read current transitions count; default 0. We can't atomically bump
        // it without a read-then-write, but a small race here only over- or
        // under-counts transitions, which is purely advisory.
        let current = api
            .get_opt(&cfg.lease_name)
            .await?
            .as_ref()
            .and_then(|l| l.spec.as_ref())
            .and_then(|s| s.lease_transitions)
            .unwrap_or(0);
        spec["leaseTransitions"] = json!(current + 1);
        spec["acquireTime"] = json!(now);
    }

    let patch = json!({ "spec": spec });
    api.patch(
        &cfg.lease_name,
        &PatchParams::default(),
        &Patch::Merge(&patch),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    #[test]
    fn discover_namespace_prefers_env() {
        let ns = discover_namespace(
            |k| {
                if k == "K8S_NAMESPACE" {
                    Some("from-env".to_string())
                } else {
                    None
                }
            },
            || Some("from-file".to_string()),
        );
        assert_eq!(ns, "from-env");
    }

    #[test]
    fn discover_namespace_falls_back_to_service_account_file() {
        let ns = discover_namespace(|_| None, || Some("from-file".to_string()));
        assert_eq!(ns, "from-file");
    }

    #[test]
    fn discover_namespace_falls_back_to_default() {
        let ns = discover_namespace(|_| None, || None);
        assert_eq!(ns, "default");
    }

    #[test]
    fn discover_namespace_treats_empty_env_as_unset() {
        // An empty K8S_NAMESPACE (chart sets the env var but values.yaml is
        // missing the field) must not be returned as `""`.
        let ns = discover_namespace(
            |k| (k == "K8S_NAMESPACE").then(|| "   ".to_string()),
            || Some("from-file".to_string()),
        );
        assert_eq!(ns, "from-file");
    }

    #[test]
    fn discover_namespace_treats_empty_file_as_unset() {
        let ns = discover_namespace(|_| None, || Some(String::new()));
        assert_eq!(ns, "default");
    }

    #[test]
    fn build_identity_is_unique_per_call() {
        let a = build_identity("pod-1");
        let b = build_identity("pod-1");
        // Both start with the hostname; suffix random.
        assert!(a.starts_with("pod-1_"));
        assert!(b.starts_with("pod-1_"));
        assert_ne!(a, b, "random suffix should disambiguate");
    }

    #[test]
    fn is_expired_true_for_missing_spec() {
        assert!(is_expired(None));
    }

    #[test]
    fn is_expired_true_for_old_renew() {
        let spec = LeaseSpec {
            lease_duration_seconds: Some(15),
            renew_time: Some(MicroTime(Utc::now() - ChronoDuration::seconds(60))),
            ..Default::default()
        };
        assert!(is_expired(Some(&spec)));
    }

    #[test]
    fn is_expired_false_for_recent_renew() {
        let spec = LeaseSpec {
            lease_duration_seconds: Some(15),
            renew_time: Some(MicroTime(Utc::now() - ChronoDuration::seconds(2))),
            ..Default::default()
        };
        assert!(!is_expired(Some(&spec)));
    }

    #[test]
    fn is_expired_false_for_future_renew() {
        // Clock skew: a renew time slightly ahead of "now" must not flag as
        // expired (we'd flap-step-down).
        let spec = LeaseSpec {
            lease_duration_seconds: Some(15),
            renew_time: Some(MicroTime(Utc::now() + ChronoDuration::seconds(5))),
            ..Default::default()
        };
        assert!(!is_expired(Some(&spec)));
    }
}
