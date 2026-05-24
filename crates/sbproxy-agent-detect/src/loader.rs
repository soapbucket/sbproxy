//! Hot-reload loader for ADRF rule packs.
//!
//! The hot path reads a single `arc_swap::ArcSwap<CompiledRulePack>`
//! per request, so reloading the file behind it does not require any
//! locking on the read side. An operator triggers a reload by editing
//! the rule-pack file and either calling [`RulePackLoader::reload`]
//! directly (the SIGHUP handler does this in the proxy binary) or
//! via the file-watch hook a runtime can wire in.
//!
//! Behaviour:
//!
//! - Bad reload (parse error, schema-version mismatch, regex compile
//!   failure) is fail-soft: the previous compiled pack stays loaded;
//!   the failure is recorded via the [`ReloadOutcome`] return + the
//!   per-outcome [`ReloadMetrics`] counters.
//! - Success records the [`CompiledRulePack`]'s rule count so the
//!   operator-facing dashboard can confirm the new pack landed.
//! - The loader does not own the file-watch loop; the runtime owns
//!   it (e.g. `notify::RecommendedWatcher` in the proxy binary).
//!   This module exposes the swap primitive only.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::rules::CompiledRulePack;

/// Outcome of a [`RulePackLoader::reload`] attempt.
#[derive(Debug, Clone)]
pub enum ReloadOutcome {
    /// Reload succeeded. The new pack is now the live pack;
    /// `rule_count` is the number of agent rules in it (operators use
    /// this to confirm the new pack is the size they expect).
    Loaded {
        /// Number of agent rules in the new pack.
        rule_count: usize,
    },
    /// The file path could not be read. The previous pack stays
    /// loaded.
    IoError(String),
    /// The file parsed but the rule pack was rejected. The previous
    /// pack stays loaded. `kind` is the same closed-set label
    /// [`RulePackError::kind`](crate::rules::RulePackError::kind)
    /// returns so dashboards can group by it.
    RejectedPack {
        /// Closed-set error kind: `yaml`, `version`, `bad_regex`,
        /// `duplicate_id`.
        kind: &'static str,
        /// Human-readable detail of the failure.
        detail: String,
    },
}

impl ReloadOutcome {
    /// Short label suitable for a metric counter. One of `loaded` /
    /// `io_error` / `rejected`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Loaded { .. } => "loaded",
            Self::IoError(_) => "io_error",
            Self::RejectedPack { .. } => "rejected",
        }
    }

    /// Whether the live pack was swapped. `IoError` and
    /// `RejectedPack` leave the live pack untouched and return
    /// `false`.
    pub fn updated(&self) -> bool {
        matches!(self, Self::Loaded { .. })
    }
}

/// Per-outcome reload counters. Stored on the loader so a runtime
/// can project them into the proxy's existing Prometheus surface
/// without the agent-detect crate taking a direct dep on
/// `prometheus`.
///
/// The corresponding Prometheus metric in the proxy binary is
/// `sbproxy_agent_detect_rulepack_reloads_total{outcome}` where
/// `outcome` is the label returned by [`ReloadOutcome::label`].
#[derive(Debug, Default)]
pub struct ReloadMetrics {
    loaded: AtomicU64,
    io_error: AtomicU64,
    rejected: AtomicU64,
}

impl ReloadMetrics {
    fn record(&self, outcome: &ReloadOutcome) {
        match outcome {
            ReloadOutcome::Loaded { .. } => {
                self.loaded.fetch_add(1, Ordering::Relaxed);
            }
            ReloadOutcome::IoError(_) => {
                self.io_error.fetch_add(1, Ordering::Relaxed);
            }
            ReloadOutcome::RejectedPack { .. } => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Snapshot the three counters. Returns
    /// `(loaded, io_error, rejected)`.
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.loaded.load(Ordering::Relaxed),
            self.io_error.load(Ordering::Relaxed),
            self.rejected.load(Ordering::Relaxed),
        )
    }
}

/// Hot-reload front-end for a [`CompiledRulePack`]. Wraps an
/// `ArcSwap` so the hot path stays lock-free.
pub struct RulePackLoader {
    inner: Arc<ArcSwap<CompiledRulePack>>,
    path: PathBuf,
    metrics: ReloadMetrics,
}

impl RulePackLoader {
    /// Build a loader for `path`. The initial load is eager: the
    /// constructor returns an error if the initial read or parse
    /// fails so a misconfigured proxy fails fast on startup rather
    /// than serving requests against an empty rule pack.
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path)?;
        let initial = CompiledRulePack::from_yaml(&bytes).map_err(|e| anyhow::anyhow!(e))?;
        Ok(Self {
            inner: Arc::new(ArcSwap::from_pointee(initial)),
            path,
            metrics: ReloadMetrics::default(),
        })
    }

    /// Build a loader from a pre-compiled pack and a watch path. The
    /// watch path is used by [`Self::reload`]; on construction the
    /// supplied pack is loaded as-is without reading the file. Useful
    /// for tests and for runtimes that want to feed the initial pack
    /// via a different source.
    pub fn from_pack<P: AsRef<Path>>(pack: CompiledRulePack, watch_path: P) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(pack)),
            path: watch_path.as_ref().to_path_buf(),
            metrics: ReloadMetrics::default(),
        }
    }

    /// Hot-path read. One atomic pointer load. Cheap enough to call
    /// per request.
    pub fn pack(&self) -> Arc<CompiledRulePack> {
        self.inner.load_full()
    }

    /// The file path the loader watches.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Per-outcome reload counters.
    pub fn metrics(&self) -> &ReloadMetrics {
        &self.metrics
    }

    /// Reload from the watched file. Fail-soft: a bad reload leaves
    /// the previous pack in place and returns the outcome describing
    /// the failure. Operators wire this to SIGHUP and to a file-watch
    /// notification.
    pub fn reload(&self) -> ReloadOutcome {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) => {
                let outcome = ReloadOutcome::IoError(format!("{}: {}", self.path.display(), e));
                self.metrics.record(&outcome);
                return outcome;
            }
        };
        match CompiledRulePack::from_yaml(&bytes) {
            Ok(new_pack) => {
                let rule_count = new_pack.len();
                self.inner.store(Arc::new(new_pack));
                let outcome = ReloadOutcome::Loaded { rule_count };
                self.metrics.record(&outcome);
                outcome
            }
            Err(e) => {
                let kind = e.kind();
                let detail = e.to_string();
                let outcome = ReloadOutcome::RejectedPack { kind, detail };
                self.metrics.record(&outcome);
                outcome
            }
        }
    }

    /// Replace the live pack with `next` without touching the watched
    /// file. Used by tests and by the runtime when a pre-built pack
    /// arrives over a different channel (e.g. a control-plane push).
    pub fn replace(&self, next: CompiledRulePack) -> ReloadOutcome {
        let rule_count = next.len();
        self.inner.store(Arc::new(next));
        let outcome = ReloadOutcome::Loaded { rule_count };
        self.metrics.record(&outcome);
        outcome
    }

    /// Replace the live pack with a freshly parsed YAML body. Useful
    /// for control-plane pushes that supply the YAML over a network
    /// channel rather than a file write.
    pub fn replace_from_yaml(&self, yaml: &str) -> ReloadOutcome {
        match CompiledRulePack::from_yaml_str(yaml) {
            Ok(p) => self.replace(p),
            Err(e) => {
                let outcome = ReloadOutcome::RejectedPack {
                    kind: e.kind(),
                    detail: e.to_string(),
                };
                self.metrics.record(&outcome);
                outcome
            }
        }
    }
}

/// Stable metric name the runtime is expected to expose against the
/// loader's outcome counters. Quoted here so the runtime layer and
/// the dashboards can share a single source of truth.
pub const RELOAD_METRIC_NAME: &str = "sbproxy_agent_detect_rulepack_reloads_total";

/// Closed set of outcome label values. Useful for the dashboard
/// pre-declaration that registers the metric with every label value
/// before any request arrives.
pub const RELOAD_OUTCOME_LABELS: &[&str] = &["loaded", "io_error", "rejected"];

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SAMPLE_PACK: &str = "version: 0\nagents:\n  - id: a\n    match: {}\n    provenance: unsigned-named\n    score: 50\n";

    fn write_pack(yaml: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(yaml.as_bytes()).expect("write");
        f
    }

    #[test]
    fn open_loads_the_initial_pack() {
        let file = write_pack(SAMPLE_PACK);
        let loader = RulePackLoader::open(file.path()).expect("open");
        assert_eq!(loader.pack().len(), 1);
        let (loaded, io_err, rej) = loader.metrics().snapshot();
        // open() does not count as a "reload" outcome; counters
        // start at zero.
        assert_eq!((loaded, io_err, rej), (0, 0, 0));
    }

    #[test]
    fn open_fails_loudly_on_bad_initial_pack() {
        let file = write_pack("version: 99\nagents: []\n");
        assert!(RulePackLoader::open(file.path()).is_err());
    }

    #[test]
    fn reload_swaps_the_live_pack_on_success() {
        let file = write_pack(SAMPLE_PACK);
        let loader = RulePackLoader::open(file.path()).unwrap();
        // Rewrite the file with a two-rule pack.
        let two = "version: 0\nagents:\n  - id: a\n    match: {}\n    provenance: unsigned-named\n    score: 50\n  - id: b\n    match: {}\n    provenance: unsigned-named\n    score: 51\n";
        std::fs::write(file.path(), two).unwrap();
        let outcome = loader.reload();
        match outcome {
            ReloadOutcome::Loaded { rule_count } => assert_eq!(rule_count, 2),
            other => panic!("expected Loaded, got {other:?}"),
        }
        assert_eq!(loader.pack().len(), 2);
        let (loaded, io_err, rej) = loader.metrics().snapshot();
        assert_eq!((loaded, io_err, rej), (1, 0, 0));
    }

    #[test]
    fn reload_keeps_old_pack_on_parse_failure() {
        let file = write_pack(SAMPLE_PACK);
        let loader = RulePackLoader::open(file.path()).unwrap();
        // Corrupt the file. The reload should reject the pack and
        // keep the previous one.
        std::fs::write(file.path(), "version: 0\nagents:\n  - unknown_key: foo\n").unwrap();
        let outcome = loader.reload();
        assert!(matches!(outcome, ReloadOutcome::RejectedPack { .. }));
        assert!(!outcome.updated());
        assert_eq!(loader.pack().len(), 1, "previous pack stays live");
        let (loaded, _, rej) = loader.metrics().snapshot();
        assert_eq!(loaded, 0);
        assert_eq!(rej, 1);
    }

    #[test]
    fn reload_io_error_keeps_old_pack() {
        let file = write_pack(SAMPLE_PACK);
        let loader = RulePackLoader::open(file.path()).unwrap();
        // Drop the file. The reload should report IoError and keep
        // the previous pack live.
        std::fs::remove_file(file.path()).unwrap();
        let outcome = loader.reload();
        assert!(matches!(outcome, ReloadOutcome::IoError(_)));
        assert_eq!(loader.pack().len(), 1);
        let (_, io_err, _) = loader.metrics().snapshot();
        assert_eq!(io_err, 1);
    }

    #[test]
    fn reload_version_mismatch_records_kind_label() {
        let file = write_pack(SAMPLE_PACK);
        let loader = RulePackLoader::open(file.path()).unwrap();
        std::fs::write(file.path(), "version: 99\nagents: []\n").unwrap();
        let outcome = loader.reload();
        match outcome {
            ReloadOutcome::RejectedPack { kind, .. } => assert_eq!(kind, "version"),
            other => panic!("expected RejectedPack, got {other:?}"),
        }
    }

    #[test]
    fn replace_from_yaml_swaps_without_touching_file() {
        let file = write_pack(SAMPLE_PACK);
        let loader = RulePackLoader::open(file.path()).unwrap();
        let outcome = loader.replace_from_yaml(
            "version: 0\nagents:\n  - id: a\n    match: {}\n    provenance: unsigned-named\n    score: 50\n  - id: b\n    match: {}\n    provenance: unsigned-named\n    score: 51\n  - id: c\n    match: {}\n    provenance: unsigned-named\n    score: 52\n",
        );
        assert!(matches!(outcome, ReloadOutcome::Loaded { rule_count: 3 }));
        assert_eq!(loader.pack().len(), 3);
    }

    #[test]
    fn metric_labels_are_a_closed_set() {
        // The runtime registers the metric with every outcome label
        // pre-declared; verify the label set the loader emits matches
        // the published constant.
        assert_eq!(RELOAD_OUTCOME_LABELS, &["loaded", "io_error", "rejected"]);
        assert_eq!(ReloadOutcome::Loaded { rule_count: 0 }.label(), "loaded");
        assert_eq!(ReloadOutcome::IoError("x".into()).label(), "io_error");
        assert_eq!(
            ReloadOutcome::RejectedPack {
                kind: "yaml",
                detail: "x".into()
            }
            .label(),
            "rejected"
        );
    }
}
