// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Timed refresh for Git-backed dynamic extension bundles.

use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use sbproxy_config::ExtensionBundlesConfig;
use sbproxy_plugin::{ExtensionInventorySnapshot, ExtensionRegistrationSource};

use crate::server::TryBundleRefreshOutcome;

const JITTER_FRACTION: f64 = 0.15;

/// Whether a complete candidate needed publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CandidateDecision<T> {
    /// The fingerprint moved and the apply closure completed.
    Applied(T),
    /// The verified Git commits match the generation already serving.
    NotModified,
}

/// Publish only when a candidate's verified source identity moved.
pub(crate) fn apply_if_changed<T>(
    current_fingerprint: &str,
    candidate_fingerprint: &str,
    apply: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<CandidateDecision<T>> {
    if current_fingerprint == candidate_fingerprint {
        return Ok(CandidateDecision::NotModified);
    }
    apply().map(CandidateDecision::Applied)
}

/// Result of one timer cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BundleRefreshCycle {
    Applied,
    NotModified,
    Failed,
    ReloadBusy,
}

impl BundleRefreshCycle {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "ok",
            Self::NotModified => "not_modified",
            Self::Failed => "failed",
            Self::ReloadBusy => "reload_busy",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BundleRefreshHealth {
    cycle: BundleRefreshCycle,
    consecutive_failures: u64,
}

static REFRESH_HEALTH: OnceLock<RwLock<Option<BundleRefreshHealth>>> = OnceLock::new();

fn refresh_health() -> &'static RwLock<Option<BundleRefreshHealth>> {
    REFRESH_HEALTH.get_or_init(|| RwLock::new(None))
}

fn record_health(cycle: BundleRefreshCycle, consecutive_failures: u64) {
    *refresh_health()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(BundleRefreshHealth {
        cycle,
        consecutive_failures,
    });
}

/// Clear timer health after any successful pipeline publication.
pub(crate) fn clear_health() {
    *refresh_health()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

/// Clone the serving inventory and add process-level refresh health to Git
/// bundle detail. The added text is static plus a counter, never an error or
/// credential value.
pub(crate) fn inventory_with_health(
    inventory: &ExtensionInventorySnapshot,
) -> ExtensionInventorySnapshot {
    let health = *refresh_health()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut inventory = inventory.clone();
    let Some(health) = health else {
        return inventory;
    };
    annotate_inventory(&mut inventory, health);
    inventory
}

fn annotate_inventory(inventory: &mut ExtensionInventorySnapshot, health: BundleRefreshHealth) {
    let failures = health.consecutive_failures;
    let refresh_detail = match health.cycle {
        BundleRefreshCycle::Applied => "refresh ok".to_string(),
        BundleRefreshCycle::NotModified => "refresh source unchanged".to_string(),
        // A busy cycle never reached the source, so it neither clears
        // the failure count nor adds to it. Reporting it as a clean
        // skip would hide the rejection that is still outstanding.
        BundleRefreshCycle::ReloadBusy if failures > 0 => format!(
            "refresh skipped because another reload was active; the last candidate that \
             reached the source was rejected and the last verified generation is still \
             serving ({failures} consecutive failure(s))"
        ),
        BundleRefreshCycle::ReloadBusy => {
            "refresh skipped because another reload was active".to_string()
        }
        BundleRefreshCycle::Failed => format!(
            "refresh candidate rejected; serving last verified generation ({failures} \
             consecutive failure(s))"
        ),
    };
    // A rejected candidate keeps the last verified generation serving,
    // so the bundle really did load and its lifecycle state stays
    // honest. The load status is then the only field that can say the
    // refresh pipeline stopped tracking its source, and without it a
    // proxy pinned to a stale generation reads exactly like a healthy
    // one: same green Load badge, same neutral detail line, one poll
    // after the last good one (WOR-2684).
    //
    // The gate is the counter rather than this cycle's outcome, because
    // only Applied and NotModified reset it. A ReloadBusy cycle leaves
    // it standing, so gating on `cycle == Failed` would hand the page a
    // green badge for one whole interval on any busy poll that follows
    // a rejection, with the source still untracked.
    let degraded = failures > 0;
    for bundle in &mut inventory.bundles {
        if bundle.source != ExtensionRegistrationSource::Git {
            continue;
        }
        let detail = match bundle.load.detail.as_deref() {
            Some(provenance) => format!("{refresh_detail}; {provenance}"),
            None => refresh_detail.clone(),
        };
        bundle.load.detail = Some(bound_detail(detail, 512));
        if degraded {
            bundle.load.status = "degraded".to_owned();
        }
    }
}

fn bound_detail(mut detail: String, maximum: usize) -> String {
    if detail.len() <= maximum {
        return detail;
    }
    let mut boundary = maximum;
    while !detail.is_char_boundary(boundary) {
        boundary -= 1;
    }
    detail.truncate(boundary);
    detail
}

/// One non-overlapping, jittered refresh loop for every configured Git bundle
/// source in the current candidate.
pub(crate) struct BundleRefreshPoller {
    config_path: String,
    interval: Duration,
    consecutive_failures: u64,
}

impl std::fmt::Debug for BundleRefreshPoller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BundleRefreshPoller")
            .field("config_path", &self.config_path)
            .field("interval", &self.interval)
            .field("consecutive_failures", &self.consecutive_failures)
            .finish()
    }
}

impl BundleRefreshPoller {
    /// Build one poller at the shortest positive configured interval.
    pub(crate) fn from_config(config_path: &str, config: &ExtensionBundlesConfig) -> Option<Self> {
        config.refresh_interval().map(|interval| Self {
            config_path: config_path.to_string(),
            interval,
            consecutive_failures: 0,
        })
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn interval(&self) -> Duration {
        self.interval
    }

    /// Fetch and validate one complete candidate, publishing only a changed
    /// generation. The lifecycle try-lock is the overlap guard.
    pub(crate) fn poll_once(&mut self) -> BundleRefreshCycle {
        let cycle = match crate::server::try_refresh_extension_bundles(&self.config_path) {
            Ok(TryBundleRefreshOutcome::Applied(outcome)) => {
                self.consecutive_failures = 0;
                if outcome.is_fully_applied() {
                    tracing::info!("extension bundle refresh applied");
                } else {
                    tracing::warn!(
                        degraded = %outcome,
                        "extension bundle refresh applied with stale subsystem state",
                    );
                }
                BundleRefreshCycle::Applied
            }
            Ok(TryBundleRefreshOutcome::NotModified) => {
                self.consecutive_failures = 0;
                BundleRefreshCycle::NotModified
            }
            Ok(TryBundleRefreshOutcome::Busy) => BundleRefreshCycle::ReloadBusy,
            Err(_) => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                tracing::error!(
                    consecutive_failures = self.consecutive_failures,
                    "extension bundle refresh candidate was rejected; continuing to serve the \
                     last verified generation",
                );
                BundleRefreshCycle::Failed
            }
        };
        tracing::debug!(
            result = cycle.as_str(),
            "extension bundle refresh cycle finished"
        );
        record_health(cycle, self.consecutive_failures);
        cycle
    }

    fn run(mut self) {
        tracing::info!(
            refresh_interval_secs = self.interval.as_secs(),
            "extension bundle refresh started",
        );
        std::thread::sleep(self.interval.mul_f64(rand::random::<f64>()));
        loop {
            self.poll_once();
            std::thread::sleep(jitter(self.interval));
        }
    }
}

fn jitter(interval: Duration) -> Duration {
    let factor = 1.0 - JITTER_FRACTION + rand::random::<f64>() * 2.0 * JITTER_FRACTION;
    interval.mul_f64(factor)
}

/// Start the process-owned refresh loop when any Git source enabled it.
pub(crate) fn spawn(poller: Option<BundleRefreshPoller>) {
    let Some(poller) = poller else {
        return;
    };
    std::thread::Builder::new()
        .name("sbproxy-extension-refresh".to_string())
        .spawn(move || poller.run())
        .map_err(|error| {
            tracing::error!(
                error = %error,
                "failed to spawn extension bundle refresh thread; timed refresh is disabled",
            );
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::time::Duration;

    use sbproxy_config::{BundleSourceConfig, ExtensionBundlesConfig};
    use sbproxy_plugin::{
        ExtensionBundleRecord, ExtensionInventoryScope, ExtensionInventorySummary,
        ExtensionLoadRecord, ExtensionRuntime, ExtensionScopeMode, ExtensionState,
        EXTENSION_INVENTORY_SCHEMA_VERSION,
    };

    use super::*;

    fn git_source(refresh_interval_secs: u64) -> BundleSourceConfig {
        BundleSourceConfig::Git {
            repo: "https://example.test/extensions.git".to_string(),
            revision: "signed-release".to_string(),
            path: "bundles".to_string(),
            credential: None,
            verify_signature: true,
            timeout_secs: 60,
            refresh_interval_secs,
        }
    }

    #[test]
    fn disabled_sources_do_not_start_a_refresh_poller() {
        let config = ExtensionBundlesConfig {
            bundles_dir: None,
            sources: vec![git_source(0)],
            grants: Default::default(),
        };

        assert!(BundleRefreshPoller::from_config("sb.yml", &config).is_none());
    }

    #[test]
    fn poller_uses_the_bounded_shortest_interval() {
        let config = ExtensionBundlesConfig {
            bundles_dir: None,
            sources: vec![git_source(300), git_source(45)],
            grants: Default::default(),
        };

        let poller = BundleRefreshPoller::from_config("sb.yml", &config)
            .expect("enabled source starts a poller");

        assert_eq!(poller.interval(), Duration::from_secs(45));
    }

    #[test]
    fn unchanged_source_skips_candidate_publication() {
        let applied = Cell::new(0);

        let outcome = apply_if_changed("commit-a", "commit-a", || {
            applied.set(applied.get() + 1);
            Ok::<_, anyhow::Error>(())
        })
        .expect("unchanged comparison succeeds");

        assert_eq!(outcome, CandidateDecision::NotModified);
        assert_eq!(applied.get(), 0);
    }

    #[test]
    fn changed_source_publishes_one_complete_candidate() {
        let applied = Cell::new(0);

        let outcome = apply_if_changed("commit-a", "commit-b", || {
            applied.set(applied.get() + 1);
            Ok::<_, anyhow::Error>("generation-b")
        })
        .expect("changed candidate applies");

        assert_eq!(outcome, CandidateDecision::Applied("generation-b"));
        assert_eq!(applied.get(), 1);
    }

    #[test]
    fn failed_candidate_keeps_the_last_green_generation() {
        let serving_generation = Cell::new("generation-a");

        let error = apply_if_changed("commit-a", "commit-b", || {
            Err::<(), _>(anyhow::anyhow!(
                "bundle.javascript: candidate export is invalid"
            ))
        })
        .expect_err("candidate validation fails");

        assert!(error.to_string().contains("candidate export is invalid"));
        assert_eq!(serving_generation.get(), "generation-a");
    }

    /// One serving Git bundle shaped the way the loader publishes it:
    /// `phase: candidate_load`, `status: ok`, and the redacted
    /// repo-reference-commit provenance as the whole detail.
    fn git_bundle_inventory() -> ExtensionInventorySnapshot {
        ExtensionInventorySnapshot {
            schema_version: EXTENSION_INVENTORY_SCHEMA_VERSION,
            scope: ExtensionInventoryScope {
                mode: ExtensionScopeMode::Running,
                proxy_version: "test".to_string(),
                config_revision: Some("config-a".to_string()),
            },
            summary: ExtensionInventorySummary::default(),
            bundles: vec![ExtensionBundleRecord {
                id: "private-bundle".to_string(),
                name: "private-bundle".to_string(),
                version: "1.0.0".to_string(),
                package: Some("entry.js".to_string()),
                source: ExtensionRegistrationSource::Git,
                runtime: ExtensionRuntime::Javascript,
                state: ExtensionState::Active,
                hook_ids: Vec::new(),
                load: ExtensionLoadRecord {
                    phase: "candidate_load".to_string(),
                    status: "ok".to_string(),
                    detail: Some(
                        "https://example.test/extensions.git at release-v1 (commit-a)".to_string(),
                    ),
                },
            }],
            hooks: Vec::new(),
            collisions: Vec::new(),
        }
    }

    #[test]
    fn failed_refresh_health_keeps_safe_last_green_provenance_in_inventory() {
        let mut inventory = git_bundle_inventory();

        annotate_inventory(
            &mut inventory,
            BundleRefreshHealth {
                cycle: BundleRefreshCycle::Failed,
                consecutive_failures: 3,
            },
        );

        let detail = inventory.bundles[0]
            .load
            .detail
            .as_deref()
            .expect("health detail");
        assert!(
            detail.contains("serving last verified generation"),
            "{detail}"
        );
        assert!(detail.contains("3 consecutive failure(s)"), "{detail}");
        assert!(
            detail.contains("https://example.test/extensions.git"),
            "{detail}"
        );
        assert_eq!(inventory.bundles[0].load.status, "degraded");
        assert!(detail.len() <= 512);
    }

    #[test]
    fn healthy_refresh_health_leaves_the_load_status_alone() {
        let mut inventory = git_bundle_inventory();

        annotate_inventory(
            &mut inventory,
            BundleRefreshHealth {
                cycle: BundleRefreshCycle::NotModified,
                consecutive_failures: 0,
            },
        );

        let detail = inventory.bundles[0]
            .load
            .detail
            .as_deref()
            .expect("health detail");
        assert!(detail.starts_with("refresh source unchanged"), "{detail}");
        assert_eq!(inventory.bundles[0].load.status, "ok");
        assert_eq!(inventory.bundles[0].state, ExtensionState::Active);
    }

    #[test]
    fn a_busy_cycle_after_a_rejection_keeps_reporting_degraded() {
        // ReloadBusy never reaches the source, so it neither clears the
        // failure count nor adds to it. Gating on the cycle alone would
        // hand the page a green badge for one whole refresh interval
        // while the source is still untracked (WOR-2684).
        let mut inventory = git_bundle_inventory();

        annotate_inventory(
            &mut inventory,
            BundleRefreshHealth {
                cycle: BundleRefreshCycle::ReloadBusy,
                consecutive_failures: 2,
            },
        );

        let detail = inventory.bundles[0]
            .load
            .detail
            .as_deref()
            .expect("health detail");
        assert!(detail.contains("another reload was active"), "{detail}");
        assert!(detail.contains("2 consecutive failure(s)"), "{detail}");
        assert_eq!(inventory.bundles[0].load.status, "degraded");
    }

    #[test]
    fn a_busy_cycle_with_no_outstanding_failure_stays_ok() {
        let mut inventory = git_bundle_inventory();

        annotate_inventory(
            &mut inventory,
            BundleRefreshHealth {
                cycle: BundleRefreshCycle::ReloadBusy,
                consecutive_failures: 0,
            },
        );

        let detail = inventory.bundles[0]
            .load
            .detail
            .as_deref()
            .expect("health detail");
        assert!(detail.contains("another reload was active"), "{detail}");
        assert!(!detail.contains("consecutive failure"), "{detail}");
        assert_eq!(inventory.bundles[0].load.status, "ok");
    }

    #[test]
    fn refresh_health_does_not_degrade_a_non_git_bundle() {
        let mut inventory = git_bundle_inventory();
        inventory.bundles[0].source = ExtensionRegistrationSource::Directory;

        annotate_inventory(
            &mut inventory,
            BundleRefreshHealth {
                cycle: BundleRefreshCycle::Failed,
                consecutive_failures: 7,
            },
        );

        assert_eq!(inventory.bundles[0].load.status, "ok");
    }
}
