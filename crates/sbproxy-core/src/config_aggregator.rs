//! The aggregator: fetch every `origin_sources` entry, compose the
//! `origins:` map, and publish the result through the config authority
//! that already ships (WOR-2437, WOR-2438, WOR-2439, WOR-2440).
//!
//! # Why one aggregator and not every node
//!
//! Composition on every node costs four things this shape avoids. A
//! full `git clone --depth 1` per entry per interval per node, since
//! there is no cheap change check. N project teams each holding a
//! fleet-wide reload trigger against one global reload lock that returns
//! `Busy` rather than queueing. N clones held under that lock, because
//! `reload_from_resolved_yaml` deliberately re-resolves under it. And a
//! local cache that is authoritative at boot with no signature.
//!
//! So this is a compose step in front of a shipped endpoint, not a new
//! deployable. [`crate::config_authority::ConfigAuthority::publish`]
//! already runs `compile_config`, `CompiledPipeline::from_config_for_validation`
//! and `validate_model_runtime`, screens
//! [`sbproxy_config::AUTHORITY_DENIED_PATHS`], signs, stores and serves
//! with an ETag. Nodes keep the subscriber they already have.
//!
//! # Two failure classes, deliberately kept apart
//!
//! A single entry that will not fetch is not the same as a composed
//! document that will not compile. One unreachable repository must not
//! discard the other forty-nine entries' last-known-good; a document
//! that fails validation must never be published at all. So a fetch
//! failure falls back to that entry's last resolved document and is
//! reported by name, and a compose or validation failure aborts the
//! whole round.
//!
//! An entry that fails its **first** fetch has no last-known-good, and
//! there the round aborts too. Composing without it would publish a
//! document whose `origins:` silently lacks that project's hosts, which
//! is a service taken offline by a network blip.
//!
//! # Change detection
//!
//! [`sbproxy_config::source::poll_git_revision`] asks the remote which
//! commit a reference points at in one round trip with no working tree,
//! and a fetch only happens when that sha moved. Argo CD's repo-server
//! resolves an ambiguous revision the same way and keys its manifest
//! cache on the resolved sha, so an unchanged sha never reaches a clone.
//! Three reductions fall out: an entry pinned to a full sha is never
//! polled at all, two entries pinned to the same repository and revision
//! are one fetch, and a round where nothing moved composes nothing,
//! publishes nothing, and leaves every subscriber on its `304`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

use sbproxy_config::origin_profile::{
    resolve_origins_with, CompositionProvenance, DroppedDefault, OriginResolveError, ProfileBinding,
};
use sbproxy_config::source::{
    poll_git_revision, ConfigSourceError, FetchContext, GitTreeRequest, MaterializedGitTree,
};
use sbproxy_config::{ConfigFile, OriginSourceEntry, OriginSourcesConfig, MAX_CONFIG_YAML_BYTES};

/// Comment marker the offline path writes above its header block, and
/// the anchor a reader greps for.
const OFFLINE_HEADER_MARKER: &str = "# composed by sbproxy aggregate";

/// Why a composition or a publication could not happen.
///
/// No variant carries a config value or a credential. An entry
/// credential and a bound input are both secret-shaped, and every
/// repository this reports is credential-stripped by
/// [`sbproxy_config::redact_repo`] before it reaches a variant.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AggregateError {
    /// The runtime document does not parse as a config file.
    #[error("aggregate: the runtime document does not parse: {0}")]
    Parse(String),
    /// The runtime document declares no `origin_sources:` block.
    #[error(
        "aggregate: the document declares no `origin_sources:` block, so there is nothing to \
         compose. Add the block naming the project repositories and the hosts each one answers on"
    )]
    NoSources,
    /// One or more entries could not be resolved and have no previously
    /// resolved document to fall back on.
    #[error(
        "aggregate: {} entr{} could not be resolved and {} never resolved before, so composing \
         would publish an `origins:` map missing their hosts: {}",
        .entries.len(),
        if .entries.len() == 1 { "y" } else { "ies" },
        if .entries.len() == 1 { "has" } else { "have" },
        .details.join("; ")
    )]
    Unresolvable {
        /// The entry names, in `origin_sources` order.
        entries: Vec<String>,
        /// `<entry>: <reason>` per entry, in the same order.
        ///
        /// The names alone were not enough. "checkout could not be
        /// resolved" sends an operator to the network; the reason
        /// separates a repository that is down from a profile committed
        /// as a symlink, one past the read cap, and one that is there
        /// and is not UTF-8, and those are four different people's
        /// problems.
        details: Vec<String>,
    },
    /// The round's global deadline passed with entries outstanding.
    #[error(
        "aggregate: the {deadline_secs}s composition deadline passed with {} of {total} \
         entr{} still unresolved: {}. Raise `origin_sources.aggregator.deadline_secs`, lower \
         a slow entry's `timeout_secs`, or raise `concurrency`",
        .outstanding.len(),
        if *.total == 1 { "y" } else { "ies" },
        .outstanding.join(", ")
    )]
    Deadline {
        /// Entries that had not been attempted or had not finished.
        outstanding: Vec<String>,
        /// How many entries the round started with.
        total: usize,
        /// The deadline that passed, in seconds.
        deadline_secs: u64,
    },
    /// The composition itself was refused.
    #[error("aggregate: composition refused: {0}")]
    Compose(#[from] OriginResolveError),
    /// The composed document is past the size a bundle may carry.
    #[error(
        "aggregate: the composed document is {bytes} bytes, past the {limit}-byte \
         `MAX_CONFIG_YAML_BYTES` limit a signed bundle may carry. It materialized {origins} \
         origins from {entries} entries, at about {bytes_per_origin} bytes each; an origin is \
         materialized once per host, so a profile bound to ten hosts is ten origins"
    )]
    TooLarge {
        /// Size of the composed document.
        bytes: usize,
        /// The limit it passed.
        limit: usize,
        /// How many origins composed.
        origins: usize,
        /// How many entries produced them.
        entries: usize,
        /// Mean bytes per composed origin, which is the number to
        /// reason about a fleet's headroom with.
        bytes_per_origin: usize,
    },
    /// Reading or writing a file failed.
    #[error("aggregate: {0}")]
    Io(String),
    /// The authority refused the composed document.
    #[error("aggregate: the config authority refused the composed document: {0}")]
    Publish(String),
}

/// One project repository resolved for one composition.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct ResolvedEntry {
    /// The `origin_sources` entry name.
    pub entry: String,
    /// The repository, credential-stripped.
    pub repo: String,
    /// The revision the entry asked for, or `HEAD`.
    pub revision: String,
    /// The commit it resolved to.
    pub commit: String,
    /// Whether this round reused the previously resolved document
    /// because the fetch failed.
    pub from_cache: bool,
    /// Whether this round skipped the fetch because the remote sha had
    /// not moved.
    pub unchanged: bool,
}

/// One entry that would not resolve this round.
///
/// Present in a successful outcome, not only in an error: an entry
/// falling back to its last-known-good is a degraded success and the
/// operator has to be told which repository is unreachable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct EntryFailure {
    /// The `origin_sources` entry name.
    pub entry: String,
    /// The repository, credential-stripped.
    pub repo: String,
    /// Why it failed, credential-scrubbed by the source layer.
    pub reason: String,
    /// The commit that was reused instead, when there was one.
    pub reused_commit: Option<String>,
}

/// What one composition produced.
///
/// Two documents, deliberately, because the two consumers want
/// different things. [`Self::yaml`] is the whole runtime document with
/// its composition blocks replaced by the origins they produced, which
/// is what `--out` writes: a single node boots that file unmodified, so
/// it has to carry `proxy:`. [`Self::payload`] is the origins overlay
/// alone, which is what gets published: a bundle carrying `proxy:`
/// would be refused outright, and it would be wrong even if it were
/// not, because a subscriber's listeners, TLS and admin surface are not
/// the fleet's to set.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct CompositionOutcome {
    /// The composed runtime document, ready to write to a file.
    pub yaml: String,
    /// The overlay the config authority publishes: the composed and
    /// hand-written `origins:` map, plus `origin_defaults` when the
    /// runtime document carries one, and nothing else.
    pub payload: String,
    /// `sha256:<hex>` of [`Self::payload`], which is the change detector
    /// the publish gate compares.
    ///
    /// The payload rather than the whole document, so editing a node's
    /// own `proxy:` block in the aggregator's runtime file does not
    /// publish a revision that changes nothing for any subscriber.
    pub content_digest: String,
    /// Every entry that resolved, in `origin_sources` order.
    pub resolved: Vec<ResolvedEntry>,
    /// Every entry that did not, in `origin_sources` order.
    pub failed: Vec<EntryFailure>,
    /// Which layer set each leaf of each composed origin.
    pub provenance: BTreeMap<String, CompositionProvenance>,
    /// Every `origin_defaults` entry a project switched off.
    pub drops: Vec<DroppedDefault>,
    /// How many origins the composition materialized.
    pub origins: usize,
    /// How long the round took, fetches included.
    pub duration: Duration,
}

impl CompositionOutcome {
    /// The header comment the offline path writes above the document.
    ///
    /// Every source entry and its resolved sha, so a composed file that
    /// lands in a repository is traceable back to the four inputs that
    /// produced it without anyone having to reconstruct the round.
    #[must_use]
    pub fn header(&self) -> String {
        let mut out = String::new();
        out.push_str(OFFLINE_HEADER_MARKER);
        out.push('\n');
        out.push_str("# Do not edit: change the project profile or the runtime document that\n");
        out.push_str("# named it, then compose again.\n");
        for entry in &self.resolved {
            out.push_str(&format!(
                "#   {} {} {} {}\n",
                entry.entry, entry.repo, entry.revision, entry.commit
            ));
        }
        for failure in &self.failed {
            out.push_str(&format!(
                "#   {} {} UNRESOLVED this round ({})\n",
                failure.entry, failure.repo, failure.reason
            ));
        }
        out
    }

    /// The composed document with its provenance header.
    ///
    /// Private because the header and the body are always written
    /// together: [`Aggregator::write_composed`] and
    /// [`Aggregator::diff_against`] are the two things that need the
    /// pair, and a caller that assembled its own would be free to write
    /// a body with no header, which is the file nobody can trace.
    fn document_with_header(&self) -> String {
        format!("{}{}", self.header(), self.yaml)
    }
}

/// One entry's last successfully resolved profile.
#[derive(Debug, Clone)]
struct CachedProfile {
    document: String,
    commit: String,
}

/// A fetch the round has to perform, after deduplication.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FetchKey {
    repo: String,
    revision: Option<String>,
}

/// The aggregator's state between rounds.
///
/// Holds the runtime document, the fetch context, and the per-entry
/// last-known-good the failure policy needs. One process, one instance:
/// the whole point of composing in one place is that the caches and the
/// change detection are one thing rather than N.
pub struct Aggregator {
    runtime_yaml: String,
    sources: OriginSourcesConfig,
    config: ConfigFile,
    /// The runtime document's own `origins:` node, kept as authored.
    ///
    /// The typed `ConfigFile::origins` would round-trip through
    /// `RawOriginConfig`, which has no `skip_serializing_if` and would
    /// write all fifty-two fields per hand-written origin into the
    /// published payload. Keeping the authored node means a hand-written
    /// origin reaches the fleet exactly as somebody wrote it.
    hand_written_origins: serde_yaml::Value,
    /// Where the runtime document was read from, when it was read from
    /// a file. `None` for a document handed in as text.
    ///
    /// The in-process loop re-reads it every round. Without that, a
    /// SIGHUP or a config-watcher reload updates the node's own pipeline
    /// and `GET /admin/origin-composition`, while the aggregator keeps
    /// publishing from the document it read at boot, so the two halves
    /// of one admin response disagree and the operator's only signal is
    /// that nothing happened.
    config_path: Option<std::path::PathBuf>,
    fetch: FetchContext,
    cache: BTreeMap<String, CachedProfile>,
    /// Remote sha last observed per fetch key, which is what makes a
    /// poll cheap and a round with no movement free.
    observed: BTreeMap<FetchKey, String>,
    /// Fetch keys a poll saw move and no compose has read yet.
    ///
    /// The reason [`Aggregator::compose`] does not poll every group
    /// itself: the loop polls once per interval, and a compose that
    /// polled again would double the request rate against every project
    /// repository, which is the number the documentation quotes and the
    /// number whoever runs the git server budgets for.
    dirty: BTreeSet<FetchKey>,
    last_published_digest: Option<String>,
}

impl std::fmt::Debug for Aggregator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Aggregator")
            .field("entries", &self.sources.entries.len())
            .field("tier", &self.sources.tier.as_str())
            .field("cached", &self.cache.len())
            .finish_non_exhaustive()
    }
}

impl Aggregator {
    /// Build an aggregator from a runtime config document.
    ///
    /// # Errors
    ///
    /// Returns [`AggregateError::Parse`] when the document is not a
    /// config file and [`AggregateError::NoSources`] when it declares no
    /// `origin_sources:` block.
    pub fn from_document(runtime_yaml: &str) -> Result<Self, AggregateError> {
        Self::with_fetch_context(runtime_yaml, FetchContext::with_git_binary())
    }

    /// [`Self::from_document`] with the git surface supplied.
    ///
    /// The seam tests drive: a fixture cloner copies a directory instead
    /// of contacting a repository, and every other line of this module
    /// stays identical.
    ///
    /// # Errors
    ///
    /// As [`Self::from_document`].
    pub fn with_fetch_context(
        runtime_yaml: &str,
        fetch: FetchContext,
    ) -> Result<Self, AggregateError> {
        let (config, sources, hand_written_origins) = Self::parse(runtime_yaml)?;
        Ok(Self {
            runtime_yaml: runtime_yaml.to_string(),
            sources,
            config,
            hand_written_origins,
            config_path: None,
            fetch,
            cache: BTreeMap::new(),
            observed: BTreeMap::new(),
            dirty: BTreeSet::new(),
            last_published_digest: None,
        })
    }

    /// Build an aggregator from a document on disk, and remember where
    /// it came from so later rounds can re-read it.
    ///
    /// # Errors
    ///
    /// Returns [`AggregateError::Io`] when the file cannot be read, and
    /// otherwise as [`Self::from_document`].
    pub fn from_path(path: &std::path::Path, fetch: FetchContext) -> Result<Self, AggregateError> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| AggregateError::Io(format!("read '{}': {error}", path.display())))?;
        let mut aggregator = Self::with_fetch_context(&text, fetch)?;
        aggregator.config_path = Some(path.to_path_buf());
        Ok(aggregator)
    }

    /// The three parsed views of one runtime document.
    fn parse(
        runtime_yaml: &str,
    ) -> Result<(ConfigFile, OriginSourcesConfig, serde_yaml::Value), AggregateError> {
        let config: ConfigFile = serde_yaml::from_str(runtime_yaml)
            .map_err(|error| AggregateError::Parse(error.to_string()))?;
        let sources = config
            .origin_sources
            .clone()
            .ok_or(AggregateError::NoSources)?;
        let raw: serde_yaml::Value = serde_yaml::from_str(runtime_yaml)
            .map_err(|error| AggregateError::Parse(error.to_string()))?;
        let hand_written = raw
            .get("origins")
            .cloned()
            .unwrap_or(serde_yaml::Value::Null);
        Ok((config, sources, hand_written))
    }

    /// Re-read the runtime document, when it came from a file and its
    /// text has changed.
    ///
    /// Returns whether anything was swapped. The per-entry caches and
    /// the observed shas are keyed by entry name and by repository, not
    /// by position, so they survive an edit: an entry the operator did
    /// not touch keeps its last resolved profile and is not re-fetched
    /// just because a neighbour was added.
    ///
    /// A document that no longer parses, or that lost its
    /// `origin_sources` block, is a warning and a no-op rather than a
    /// stop. The aggregator keeps publishing from the last good document
    /// while the operator fixes the file, which is the same posture the
    /// node's own reload takes.
    ///
    /// Private: [`aggregation_loop`] is the only thing that should
    /// decide when a round starts, and a caller that refreshed out of
    /// band would compose from a document no poll had been taken
    /// against.
    fn refresh_document(&mut self) -> bool {
        let Some(path) = self.config_path.clone() else {
            return false;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return false;
        };
        if text == self.runtime_yaml {
            return false;
        }
        match Self::parse(&text) {
            Ok((config, sources, hand_written)) => {
                tracing::info!(
                    path = %path.display(),
                    entries = sources.entries.len(),
                    "aggregate: runtime document changed; composing from the new one",
                );
                self.runtime_yaml = text;
                self.config = config;
                self.sources = sources;
                self.hand_written_origins = hand_written;
                // Everything is re-examined against the new document,
                // rather than trusting a dirty set computed against the
                // old one.
                self.dirty.clear();
                true
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "aggregate: the runtime document changed but does not load; still composing \
                     from the last one that did",
                );
                false
            }
        }
    }

    /// Record a resolved credential for one repository, so a private
    /// entry can be fetched.
    #[must_use]
    pub fn with_credential(mut self, repo: impl Into<String>, credential: String) -> Self {
        self.fetch.credentials.insert(repo.into(), credential);
        self
    }

    /// Resolve every entry credential reference through the process
    /// secret resolver.
    ///
    /// Deliberately reuses
    /// [`crate::config_source::resolve_secret_reference`] rather than
    /// giving the aggregator a second secret authority, for the same
    /// reason the extension bundle loader does. The error names the
    /// entry and the credential-stripped repository and never the
    /// reference or the value, because a message naming the reference
    /// is a message naming which variable holds the token.
    ///
    /// # Errors
    ///
    /// Returns [`AggregateError::Io`] naming the entry whose credential
    /// did not resolve.
    pub fn resolve_credentials(&mut self) -> Result<(), AggregateError> {
        for entry in &self.sources.entries {
            let Some(reference) = entry.credential.as_deref() else {
                continue;
            };
            let resolved = crate::config_source::resolve_secret_reference(
                reference,
                "origin_sources.entries[].credential",
            )
            .map_err(|_| {
                AggregateError::Io(format!(
                    "the credential declared for entry `{}` ({}) could not be resolved",
                    entry.name,
                    sbproxy_config::redact_repo(&entry.repo)
                ))
            })?;
            self.fetch.credentials.insert(entry.repo.clone(), resolved);
        }
        Ok(())
    }

    /// The timings this document configured.
    #[must_use]
    pub fn timings(&self) -> &sbproxy_config::OriginAggregatorConfig {
        &self.sources.aggregator
    }

    /// The entries this document declares.
    #[must_use]
    pub fn entries(&self) -> &[OriginSourceEntry] {
        &self.sources.entries
    }

    /// Ask every entry whether its revision moved, with no working tree
    /// materialized.
    ///
    /// Returns the entry names whose sha differs from the one this
    /// aggregator last observed. An entry pinned to a full commit sha is
    /// answered from the pin itself and never reaches the network after
    /// its first round, because a sha cannot move. Two entries sharing a
    /// repository and revision are polled once.
    ///
    /// A poll that errors reports the entry as moved rather than as
    /// unchanged: an unreachable remote is not evidence that nothing
    /// happened, and the fetch that follows is where the failure gets
    /// its proper handling and its last-known-good fallback.
    ///
    /// The poll phase runs under the same bounded pool and the same
    /// round deadline as the fetch phase. Serially it was neither: ten
    /// entries pointing at a git host that has started blackholing
    /// connections cost ten times `timeout_secs` (default 60) in one
    /// cycle, so a `poll_interval_secs: 120` loop spends ten minutes
    /// inside `poll()`, the interval gate never gates anything again,
    /// and the documented thirty requests per hour per repository turns
    /// into a continuous poll storm against the healthy repositories
    /// while nothing composes at all.
    ///
    /// # Errors
    ///
    /// Never. Every per-entry failure is folded into "treat as moved".
    pub fn poll(&mut self) -> Vec<String> {
        let mut moved: Vec<String> = Vec::new();
        let mut dirty: BTreeSet<FetchKey> = BTreeSet::new();
        let keys: Vec<FetchKey> = {
            let mut seen: BTreeSet<FetchKey> = BTreeSet::new();
            self.sources
                .entries
                .iter()
                .map(fetch_key)
                .filter(|key| seen.insert(key.clone()))
                .collect()
        };
        let answered = poll_groups(
            &self.fetch,
            &self.sources.entries,
            &keys,
            self.sources.aggregator.concurrency.max(1),
            Instant::now() + Duration::from_secs(self.sources.aggregator.deadline_secs.max(1)),
        );
        for entry in &self.sources.entries {
            let key = fetch_key(entry);
            let sha = answered.get(&key).cloned().flatten();
            let changed = match sha.as_ref() {
                Some(sha) => self.observed.get(&key) != Some(sha),
                // The cloner could not answer cheaply, or the remote
                // refused. Either way the fetch is the only thing that
                // can settle it.
                None => true,
            };
            if changed {
                moved.push(entry.name.clone());
                dirty.insert(key);
            }
        }
        for (key, sha) in answered {
            if let Some(sha) = sha {
                self.observed.insert(key, sha);
            }
        }
        self.dirty.extend(dirty);
        moved
    }

    /// Fetch what has moved, compose, and return the document.
    ///
    /// Nothing is published and nothing is written. The whole round's
    /// fetches share one deadline, and a fetch failure falls back to
    /// that entry's last successfully resolved document.
    ///
    /// What gets fetched is every group [`Self::poll`] saw move, plus
    /// every group holding an entry with no previously resolved
    /// document. It deliberately does **not** poll every group itself:
    /// the loop already polls once per interval, and a compose that
    /// polled again would double the request rate against every project
    /// repository. A caller that wants a fresh read calls
    /// [`Self::poll`] first, which is what the loop does. A one-shot
    /// invocation in a fresh process needs no poll at all, because
    /// nothing is cached and every group is therefore fetched.
    ///
    /// # Errors
    ///
    /// Returns [`AggregateError::Deadline`] when the round ran out of
    /// budget, [`AggregateError::Unresolvable`] when an entry failed
    /// with no last-known-good, [`AggregateError::Compose`] when the
    /// composition itself was refused, and [`AggregateError::TooLarge`]
    /// when the result is past what a bundle may carry.
    pub fn compose(&mut self) -> Result<CompositionOutcome, AggregateError> {
        let started = Instant::now();
        let deadline_secs = self.sources.aggregator.deadline_secs;
        let deadline = started + Duration::from_secs(deadline_secs);
        let concurrency = self.sources.aggregator.concurrency.max(1);

        // Deduplicate before fetching. Two entries pinned to the same
        // repository and revision are the same tree, and cloning it
        // twice is a second network round trip for a byte-identical
        // answer.
        let mut groups: BTreeMap<FetchKey, Vec<usize>> = BTreeMap::new();
        for (index, entry) in self.sources.entries.iter().enumerate() {
            groups.entry(fetch_key(entry)).or_default().push(index);
        }
        let mut needed: Vec<(FetchKey, Vec<usize>)> = Vec::new();
        let mut unchanged: BTreeSet<usize> = BTreeSet::new();
        let mut polled: BTreeMap<FetchKey, String> = BTreeMap::new();
        for (key, indices) in groups {
            let cached_all = indices.iter().all(|index| {
                self.sources
                    .entries
                    .get(*index)
                    .is_some_and(|entry| self.cache.contains_key(&entry.name))
            });
            if cached_all && !self.dirty.contains(&key) {
                unchanged.extend(indices.iter().copied());
                continue;
            }
            // About to fetch this group anyway, so one cheap poll here
            // is free relative to the clone, and it is what the next
            // poll compares against. Deliberately taken *before* the
            // fetch: a push landing between the two then makes the next
            // round re-fetch, which is the safe direction. Taken after,
            // this would record a sha newer than the tree that was read
            // and the change would be missed entirely.
            if let Some(entry) = indices
                .first()
                .and_then(|index| self.sources.entries.get(*index))
            {
                if let Some(sha) = poll_one(&self.fetch, entry) {
                    polled.insert(key.clone(), sha);
                }
            }
            needed.push((key, indices));
        }

        let fetched = fetch_groups(
            &self.fetch,
            &self.sources.entries,
            &needed,
            concurrency,
            deadline,
        );

        // The deadline is a property of the round, not of an entry, so
        // it is reported once and names every entry that did not finish
        // rather than the first one that ran out.
        let outstanding: Vec<String> = needed
            .iter()
            .filter(|(key, _)| !fetched.contains_key(key))
            .flat_map(|(_, indices)| {
                indices
                    .iter()
                    .filter_map(|index| self.sources.entries.get(*index))
                    .map(|entry| entry.name.clone())
            })
            .collect();
        if !outstanding.is_empty() && Instant::now() >= deadline {
            // Same reason as the `Unresolvable` path below: an operator
            // alerting on `failed > 0` has to see the outstanding
            // entries here, not the previous round's zeroes. `resolved`
            // and `unchanged` are the entries that really did finish,
            // which for a deadline is usually few and sometimes none.
            let finished: Vec<ResolvedEntry> = self
                .sources
                .entries
                .iter()
                .enumerate()
                .filter(|(index, entry)| {
                    unchanged.contains(index) || fetched.contains_key(&fetch_key(entry))
                })
                .map(|(index, entry)| ResolvedEntry {
                    entry: entry.name.clone(),
                    repo: sbproxy_config::redact_repo(&entry.repo),
                    revision: entry.revision.clone().unwrap_or_else(|| "HEAD".to_string()),
                    commit: String::new(),
                    from_cache: false,
                    unchanged: unchanged.contains(&index),
                })
                .collect();
            let timed_out: Vec<EntryFailure> = outstanding
                .iter()
                .map(|name| EntryFailure {
                    entry: name.clone(),
                    repo: String::new(),
                    reason: "the round's deadline passed before this repository was read"
                        .to_string(),
                    reused_commit: None,
                })
                .collect();
            write_entry_gauges(&finished, &timed_out);
            return Err(AggregateError::Deadline {
                outstanding,
                total: self.sources.entries.len(),
                deadline_secs,
            });
        }

        let mut resolved: Vec<ResolvedEntry> = Vec::new();
        let mut failed: Vec<EntryFailure> = Vec::new();
        let mut unresolvable: Vec<String> = Vec::new();
        let mut documents: BTreeMap<String, (String, String)> = BTreeMap::new();
        for (index, entry) in self.sources.entries.iter().enumerate() {
            let key = fetch_key(entry);
            let repo = sbproxy_config::redact_repo(&entry.repo);
            let revision = entry.revision.clone().unwrap_or_else(|| "HEAD".to_string());
            if unchanged.contains(&index) {
                if let Some(cached) = self.cache.get(&entry.name) {
                    documents.insert(
                        entry.name.clone(),
                        (cached.document.clone(), cached.commit.clone()),
                    );
                    resolved.push(ResolvedEntry {
                        entry: entry.name.clone(),
                        repo,
                        revision,
                        commit: cached.commit.clone(),
                        from_cache: false,
                        unchanged: true,
                    });
                    continue;
                }
            }
            match fetched.get(&key) {
                Some(Ok(tree)) => match tree.documents.get(&entry.path) {
                    Some(document) => {
                        documents
                            .insert(entry.name.clone(), (document.clone(), tree.commit.clone()));
                        self.cache.insert(
                            entry.name.clone(),
                            CachedProfile {
                                document: document.clone(),
                                commit: tree.commit.clone(),
                            },
                        );
                        // The polled sha rather than the checkout's
                        // commit, because those are the same value only
                        // for a branch. `ls_remote` peels an annotated
                        // tag, but a cloner that could not answer
                        // cheaply left nothing here, and then the
                        // commit is the honest fallback.
                        let observed = polled
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| tree.commit.clone());
                        self.observed.insert(key.clone(), observed);
                        self.dirty.remove(&key);
                        resolved.push(ResolvedEntry {
                            entry: entry.name.clone(),
                            repo,
                            revision,
                            commit: tree.commit.clone(),
                            from_cache: false,
                            unchanged: false,
                        });
                    }
                    None => {
                        // A path the checkout did not yield is the
                        // entry's fault rather than the network's, so it
                        // is not eligible for the last-known-good
                        // fallback: the previous document would keep a
                        // fleet running on a profile the repository no
                        // longer ships. The reason comes from the read
                        // guard, so "missing", "is a symlink", "is not
                        // UTF-8" and "is past the size cap" stay
                        // distinguishable.
                        unresolvable.push(entry.name.clone());
                        failed.push(EntryFailure {
                            entry: entry.name.clone(),
                            repo,
                            reason: tree.refusals.get(&entry.path).cloned().unwrap_or_else(|| {
                                format!(
                                    "`{}` produced no document at the resolved revision",
                                    entry.path
                                )
                            }),
                            reused_commit: None,
                        });
                    }
                },
                Some(Err(_)) | None => {
                    let reason = reason_or_deadline(fetched.get(&key));
                    match self.cache.get(&entry.name) {
                        Some(cached) => {
                            documents.insert(
                                entry.name.clone(),
                                (cached.document.clone(), cached.commit.clone()),
                            );
                            resolved.push(ResolvedEntry {
                                entry: entry.name.clone(),
                                repo: repo.clone(),
                                revision,
                                commit: cached.commit.clone(),
                                from_cache: true,
                                unchanged: false,
                            });
                            failed.push(EntryFailure {
                                entry: entry.name.clone(),
                                repo,
                                reason,
                                reused_commit: Some(cached.commit.clone()),
                            });
                        }
                        None => {
                            unresolvable.push(entry.name.clone());
                            failed.push(EntryFailure {
                                entry: entry.name.clone(),
                                repo,
                                reason,
                                reused_commit: None,
                            });
                        }
                    }
                }
            }
        }
        // Written before the composition and before the abort below, so
        // the fetch picture is visible on every path. The gauge's own
        // doc and `docs/configuration.md` both promise "every outcome on
        // every round including the zeroes", and the two paths where
        // that used to be false are exactly the two an operator alerts
        // on: a partition that takes out every repository returned
        // `Unresolvable` with the gauges left showing the last good
        // round, which reads as evidence of absence.
        write_entry_gauges(&resolved, &failed);
        if !unresolvable.is_empty() {
            for failure in &failed {
                tracing::warn!(
                    entry = %failure.entry,
                    repo = %failure.repo,
                    reason = %failure.reason,
                    "aggregate: entry did not resolve",
                );
            }
            let details = failed
                .iter()
                .filter(|failure| unresolvable.contains(&failure.entry))
                .map(|failure| format!("{}: {}", failure.entry, failure.reason))
                .collect();
            return Err(AggregateError::Unresolvable {
                entries: unresolvable,
                details,
            });
        }

        let outcome = self.compose_documents(&documents, resolved, failed, started)?;
        sbproxy_observe::metrics::record_aggregate_compose_duration(outcome.duration.as_secs_f64());
        Ok(outcome)
    }

    /// Compose already-resolved documents into the runtime document.
    ///
    /// Split out from [`Self::compose`] so the composition half is
    /// reachable without a fetch: `sbproxy plan` renders provenance from
    /// documents on disk, and every merge-rule test drives this.
    ///
    /// # Errors
    ///
    /// Returns [`AggregateError::Compose`] and
    /// [`AggregateError::TooLarge`].
    fn compose_documents(
        &self,
        documents: &BTreeMap<String, (String, String)>,
        resolved: Vec<ResolvedEntry>,
        failed: Vec<EntryFailure>,
        started: Instant,
    ) -> Result<CompositionOutcome, AggregateError> {
        let hand_written: BTreeSet<String> = self.config.origins.keys().cloned().collect();
        let declares_bundles = self.config.extensions.declares_any_source();
        let bindings: Vec<ProfileBinding<'_>> = self
            .sources
            .entries
            .iter()
            .filter_map(|entry| {
                documents.get(&entry.name).map(|(document, commit)| {
                    ProfileBinding::new(entry, document.as_str()).with_commit(commit.as_str())
                })
            })
            .collect();
        let resolution = resolve_origins_with(
            self.config.origin_defaults.as_ref(),
            &bindings,
            &hand_written,
            declares_bundles,
        )?;
        let yaml = splice_origins(&self.runtime_yaml, &resolution.composed)?;
        let payload = composition_payload(
            &self.config,
            &self.hand_written_origins,
            &resolution.composed,
        )?;
        let origins = resolution.origins.len();
        // The payload rather than the whole document, because the limit
        // is the size a signed bundle may carry and the payload is what
        // gets signed. A node's own `proxy:` block never travels.
        if payload.len() > MAX_CONFIG_YAML_BYTES {
            return Err(AggregateError::TooLarge {
                bytes: payload.len(),
                limit: MAX_CONFIG_YAML_BYTES,
                origins,
                entries: self.sources.entries.len(),
                bytes_per_origin: payload.len() / origins.max(1),
            });
        }
        let content_digest = sbproxy_config::ConfigBundle::content_digest_of(&payload);
        Ok(CompositionOutcome {
            yaml,
            payload,
            content_digest,
            resolved,
            failed,
            provenance: resolution.provenance,
            drops: resolution.drops,
            origins,
            duration: started.elapsed(),
        })
    }

    /// Whether this composed document differs from the last one this
    /// aggregator published.
    ///
    /// Content digest rather than revision: two rounds that resolved
    /// different commits can compose byte-identical documents (a project
    /// merged a README), and publishing that is a full pipeline rebuild
    /// on every subscriber for no configuration change at all.
    #[must_use]
    fn would_change(&self, outcome: &CompositionOutcome) -> bool {
        self.last_published_digest.as_deref() != Some(outcome.content_digest.as_str())
    }

    /// Record that a composition was published, so the next identical
    /// one publishes nothing.
    /// Seed the change detector from a digest published earlier.
    ///
    /// Called at [`spawn`] with whatever the authority is already
    /// serving. Without it a restart republishes a byte-identical
    /// revision, and every published revision is a full pipeline rebuild
    /// on every subscriber, so a rolling restart of the aggregator would
    /// reload the entire fleet for no configuration change at all.
    pub fn seed_published_digest(&mut self, digest: impl Into<String>) {
        self.last_published_digest = Some(digest.into());
    }

    fn mark_published(&mut self, outcome: &CompositionOutcome) {
        self.last_published_digest = Some(outcome.content_digest.clone());
    }

    /// Write a composed document to a file, with its provenance header
    /// (WOR-2439).
    ///
    /// The written file is an ordinary config document: it boots
    /// normally, reloads normally, and needs none of the runtime
    /// machinery. That is the single-node and self-host path, and it is
    /// also what a CI job wants when it would rather review the composed
    /// output before it ships.
    ///
    /// Written through a temporary file and renamed, so a resolve
    /// failure or a full disk cannot leave a half-composed document
    /// where a node would boot from it.
    ///
    /// # Errors
    ///
    /// Returns [`AggregateError::Io`] when the file cannot be written.
    pub fn write_composed(outcome: &CompositionOutcome, path: &Path) -> Result<(), AggregateError> {
        let body = outcome.document_with_header();
        let temporary = path.with_extension("sbproxy-aggregate-tmp");
        std::fs::write(&temporary, body.as_bytes()).map_err(|error| {
            AggregateError::Io(format!("write '{}': {error}", temporary.display()))
        })?;
        std::fs::rename(&temporary, path).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            AggregateError::Io(format!("rename into '{}': {error}", path.display()))
        })?;
        Ok(())
    }

    /// What `--out` would change against a file that is already there.
    ///
    /// Returns `None` when the file does not exist, an empty vector when
    /// the bytes are identical, and otherwise the differing lines. The
    /// header is compared along with the body, because a composed file
    /// whose only difference is a resolved sha is still a different
    /// composition and a CI diff that hid that would hide the
    /// interesting half.
    ///
    /// The changed decision is `existing != proposed` on the whole text,
    /// never on the diff being non-empty. Those are not the same
    /// question: a set-difference diff reports nothing for two documents
    /// with the same lines in a different order, which is exactly what
    /// swapping two services' `hosts:` between entries produces, and a
    /// `--dry-run` that answered "already holds this composition" there
    /// would defeat the acceptance line that a CI diff is meaningful.
    ///
    /// # Errors
    ///
    /// Returns [`AggregateError::Io`] when the existing file cannot be
    /// read.
    pub fn diff_against(
        outcome: &CompositionOutcome,
        path: &Path,
    ) -> Result<Option<Vec<String>>, AggregateError> {
        if !path.exists() {
            return Ok(None);
        }
        let existing = std::fs::read_to_string(path)
            .map_err(|error| AggregateError::Io(format!("read '{}': {error}", path.display())))?;
        let proposed = outcome.document_with_header();
        if existing == proposed {
            return Ok(Some(Vec::new()));
        }
        Ok(Some(line_diff(&existing, &proposed)))
    }
}

/// The fetch identity of one entry: the repository and the revision.
///
/// Not the path. Two entries reading different files out of one tree at
/// one revision are one fetch, and that is exactly the shape a monorepo
/// deploying several services takes.
fn fetch_key(entry: &OriginSourceEntry) -> FetchKey {
    FetchKey {
        repo: entry.repo.clone(),
        revision: entry.revision.clone(),
    }
}

/// One materialized tree's contents, keyed by the paths the entries in
/// its group asked for.
#[derive(Debug, Clone)]
struct FetchedTree {
    commit: String,
    documents: BTreeMap<String, String>,
    /// Why a path the group asked for produced no document.
    ///
    /// Kept alongside the successes so the entry's refusal names the
    /// real reason. "Not in the repository at the resolved revision" is
    /// the wrong answer for a file that is there and is a symlink, or is
    /// there and is not UTF-8, or is there and is a gigabyte, and each
    /// of those sends an operator somewhere different.
    refusals: BTreeMap<String, String>,
}

/// Ask one repository which commit its revision points at.
///
/// `None` means "could not answer cheaply", which the callers turn into
/// "assume it moved". A full commit sha answers itself without a round
/// trip, so a pinned entry is polled exactly once, in the round that
/// first records it.
fn poll_one(fetch: &FetchContext, entry: &OriginSourceEntry) -> Option<String> {
    poll_one_bounded(fetch, entry, Duration::from_secs(entry.timeout_secs.max(1)))
}

/// [`poll_one`] with the round's remaining budget clamping the entry's
/// own timeout, so one blackholing host cannot hold a poll cycle open
/// past the round it belongs to.
fn poll_one_bounded(
    fetch: &FetchContext,
    entry: &OriginSourceEntry,
    remaining: Duration,
) -> Option<String> {
    if let Some(revision) = entry.revision.as_deref() {
        if sbproxy_config::source::is_full_commit_sha(revision) {
            // A sha cannot move, so once it has been recorded there is
            // nothing left to ask anybody. Before that first record the
            // pin is still its own answer, which is what makes the
            // round-two poll count zero rather than one.
            return Some(revision.to_ascii_lowercase());
        }
    }
    let request = GitTreeRequest {
        repo: &entry.repo,
        revision: entry.revision.as_deref(),
        credential: entry.credential.as_deref(),
        verify_signature: entry.verify_signature,
        timeout: Duration::from_secs(entry.timeout_secs.max(1)).min(remaining),
        fetch_context: fetch,
    };
    match poll_git_revision(&request) {
        Ok(sha) => sha,
        Err(error) => {
            tracing::debug!(
                entry = %entry.name,
                repo = %sbproxy_config::redact_repo(&entry.repo),
                %error,
                "aggregate: cheap revision poll failed; the fetch will settle it",
            );
            None
        }
    }
}

/// Ask every distinct repository which commit its revision points at,
/// under the same bounded pool and round deadline the fetch phase uses.
///
/// A group whose poll did not get a turn before the deadline is absent
/// from the map, which the caller reads as "could not answer cheaply"
/// and therefore as moved. That is the safe direction: an unanswered
/// poll costs one fetch, and a poll wrongly reported unchanged costs a
/// stale fleet.
fn poll_groups(
    fetch: &FetchContext,
    entries: &[OriginSourceEntry],
    keys: &[FetchKey],
    concurrency: usize,
    deadline: Instant,
) -> BTreeMap<FetchKey, Option<String>> {
    use std::sync::Mutex;

    let queue = Mutex::new(keys.iter().collect::<std::collections::VecDeque<_>>());
    let answers: Mutex<BTreeMap<FetchKey, Option<String>>> = Mutex::new(BTreeMap::new());
    let workers = concurrency.min(keys.len().max(1));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let Some(key) = queue.lock().ok().and_then(|mut queue| queue.pop_front()) else {
                    return;
                };
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return;
                }
                let Some(entry) = entries.iter().find(|entry| &fetch_key(entry) == key) else {
                    continue;
                };
                let answer = poll_one_bounded(fetch, entry, remaining);
                if let Ok(mut answers) = answers.lock() {
                    answers.insert(key.clone(), answer);
                }
            });
        }
    });
    answers.into_inner().unwrap_or_default()
}

/// Fetch every needed group under a bounded pool and a global deadline.
///
/// The pool is bounded because serial resolution with per-entry timeouts
/// lets fifty entries hold one compose open for fifty times one timeout,
/// and unbounded concurrency turns a fleet's composition into a
/// thundering herd against one git server.
///
/// The deadline is enforced two ways, both of which matter. A worker
/// that reaches the front of the queue after the deadline does not start
/// its fetch at all, and a fetch that does start is given
/// `min(entry timeout, remaining budget)` so it cannot run past the
/// round. A group that never started is simply absent from the returned
/// map, which is how the caller names what was outstanding.
fn fetch_groups(
    fetch: &FetchContext,
    entries: &[OriginSourceEntry],
    needed: &[(FetchKey, Vec<usize>)],
    concurrency: usize,
    deadline: Instant,
) -> BTreeMap<FetchKey, Result<FetchedTree, String>> {
    use std::sync::Mutex;

    let queue = Mutex::new(needed.iter().collect::<std::collections::VecDeque<_>>());
    let results: Mutex<BTreeMap<FetchKey, Result<FetchedTree, String>>> =
        Mutex::new(BTreeMap::new());
    let workers = concurrency.min(needed.len().max(1));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let Some((key, indices)) =
                    queue.lock().ok().and_then(|mut queue| queue.pop_front())
                else {
                    return;
                };
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    // Deliberately not recorded as a failure: an entry
                    // that never got a turn is outstanding, not broken,
                    // and calling it broken would send an operator to
                    // look at a healthy repository.
                    return;
                }
                // `first()` rather than `indices[0]`: the invariant that
                // a group is non-empty is held by the construction in
                // `compose`, and an index that only the constructor
                // knows is safe is a panic waiting for the next caller.
                let Some(first) = indices.first().and_then(|index| entries.get(*index)) else {
                    continue;
                };
                let paths: BTreeSet<String> = indices
                    .iter()
                    .filter_map(|index| entries.get(*index))
                    .map(|entry| entry.path.clone())
                    .collect();
                let timeout = Duration::from_secs(first.timeout_secs.max(1)).min(remaining);
                let outcome = fetch_one(fetch, first, &paths, timeout);
                if let Ok(mut results) = results.lock() {
                    results.insert(key.clone(), outcome);
                }
            });
        }
    });
    results.into_inner().unwrap_or_default()
}

/// Materialize one repository and read every path its group asked for.
fn fetch_one(
    fetch: &FetchContext,
    entry: &OriginSourceEntry,
    paths: &BTreeSet<String>,
    timeout: Duration,
) -> Result<FetchedTree, String> {
    let request = GitTreeRequest {
        repo: &entry.repo,
        revision: entry.revision.as_deref(),
        credential: entry.credential.as_deref(),
        verify_signature: entry.verify_signature,
        timeout,
        fetch_context: fetch,
    };
    sbproxy_config::source::materialize_git_tree(
        request,
        |tree: MaterializedGitTree<'_>| -> Result<FetchedTree, ConfigSourceError> {
            let mut documents = BTreeMap::new();
            let mut refusals = BTreeMap::new();
            for path in paths {
                // Both halves of the trust boundary, in one guard. The
                // traversal check constrains the runtime document, which
                // is the platform's. The symlink refusal, the
                // resolve-and-compare and the size cap constrain the
                // checkout, which is the project's, and that is the half
                // the epic exists to distrust: `git clone` materializes
                // symlinks, so a project committing `sbproxy/origin.yaml`
                // as a link at the aggregator's own `/etc/sbproxy/sb.yml`
                // would otherwise be read with this process's rights.
                match sbproxy_config::source::read_file_within(
                    tree.root(),
                    path,
                    sbproxy_config::source::MAX_CHECKOUT_FILE_BYTES,
                    "origin_sources.entries[].path",
                ) {
                    Ok(text) => {
                        documents.insert(path.clone(), text);
                    }
                    Err(error) => {
                        refusals.insert(path.clone(), error.to_string());
                    }
                }
            }
            Ok(FetchedTree {
                commit: tree.revision().commit.clone(),
                documents,
                refusals,
            })
        },
    )
    .map_err(|error: ConfigSourceError| error.to_string())
}

/// The differing lines between two documents, bounded.
///
/// Common prefix and common suffix are trimmed and the differing middle
/// is printed, which is linear in the input and is the right answer for
/// two documents generated by the same composer: an edit shows as a
/// contiguous block, not as a scatter. The previous version asked
/// `after.contains(line)` per line, which is quadratic (about 10^10
/// comparisons on the 4 MiB document the size limit allows) and is a
/// *set* difference, so a reordering compared equal.
///
/// The output is capped. A diff nobody can read is not more useful than
/// a count, and this goes to a terminal.
fn line_diff(existing: &str, proposed: &str) -> Vec<String> {
    const MAX_DIFF_LINES: usize = 200;

    let before: Vec<&str> = existing.lines().collect();
    let after: Vec<&str> = proposed.lines().collect();
    let common_prefix = before
        .iter()
        .zip(after.iter())
        .take_while(|(left, right)| left == right)
        .count();
    let common_suffix = before[common_prefix..]
        .iter()
        .rev()
        .zip(after[common_prefix..].iter().rev())
        .take_while(|(left, right)| left == right)
        .count();
    let removed = &before[common_prefix..before.len() - common_suffix];
    let added = &after[common_prefix..after.len() - common_suffix];

    let mut lines: Vec<String> = Vec::new();
    let total = removed.len() + added.len();
    for line in removed {
        if lines.len() == MAX_DIFF_LINES {
            break;
        }
        lines.push(format!("- {line}"));
    }
    for line in added {
        if lines.len() == MAX_DIFF_LINES {
            break;
        }
        lines.push(format!("+ {line}"));
    }
    if total > lines.len() {
        lines.push(format!(
            "... and {} more changed line(s)",
            total - lines.len()
        ));
    }
    lines
}

/// Publish the three per-outcome entry gauges for one round.
///
/// One function rather than three calls at each of the three exits, so
/// a new exit cannot forget one of them and so the arithmetic that
/// splits `resolved` from `unchanged` cannot drift between paths.
fn write_entry_gauges(resolved: &[ResolvedEntry], failed: &[EntryFailure]) {
    let unchanged = resolved.iter().filter(|entry| entry.unchanged).count();
    let cached = resolved.iter().filter(|entry| entry.from_cache).count();
    sbproxy_observe::metrics::set_aggregate_entries(
        "resolved",
        i64::try_from(resolved.len().saturating_sub(unchanged + cached)).unwrap_or(i64::MAX),
    );
    sbproxy_observe::metrics::set_aggregate_entries(
        "unchanged",
        i64::try_from(unchanged).unwrap_or(i64::MAX),
    );
    sbproxy_observe::metrics::set_aggregate_entries(
        "failed",
        i64::try_from(failed.len()).unwrap_or(i64::MAX),
    );
}

/// The reason string for an entry whose group is absent or failed.
fn reason_or_deadline(outcome: Option<&Result<FetchedTree, String>>) -> String {
    match outcome {
        Some(Err(reason)) => reason.clone(),
        _ => "the round's deadline passed before this repository was read".to_string(),
    }
}

/// The overlay a config authority publishes: `origins:`, plus
/// `origin_defaults` when the runtime document carries one.
///
/// Built from scratch rather than by removing keys from the runtime
/// document, and that is the whole point. A payload assembled by
/// subtraction carries whatever nobody thought to subtract, and the
/// runtime document is full of things a fleet must never receive: this
/// is the node that runs the aggregator, so it necessarily declares
/// `proxy.config_authority`, and any entry with a `credential:` needs a
/// `proxy.secrets` backend in the same file to resolve it against. Both
/// are on [`sbproxy_config::AUTHORITY_DENIED_PATHS`], so a
/// subtract-two-keys payload is refused by the publish screen on every
/// real configuration, and a subtract-more-keys payload would be one
/// new denied path away from the same bug. Constructing the allowed set
/// makes the refusal unreachable by shape rather than by list.
///
/// `origin_defaults` rides along because it is deliberately **not** a
/// denied path: the platform raising a security floor across the fleet
/// is the one thing that channel exists for, and a subscriber's
/// `GET /admin/origin-composition` then reports the floor its composed
/// origins were actually built from. It is not re-applied anywhere on a
/// node, because nothing on a node composes.
///
/// Everything else a platform team wants to distribute goes through
/// `sbproxy config authority publish` with a payload it writes. This
/// verb composes origins.
///
/// # Errors
///
/// Returns [`AggregateError::Parse`] when the runtime document's root is
/// not a mapping or the result will not serialize.
fn composition_payload(
    config: &ConfigFile,
    hand_written: &serde_yaml::Value,
    origins: &BTreeMap<String, serde_yaml::Mapping>,
) -> Result<String, AggregateError> {
    let mut document = serde_yaml::Mapping::new();
    if let Some(defaults) = config.origin_defaults.as_ref() {
        document.insert(
            serde_yaml::Value::String("origin_defaults".to_string()),
            serde_yaml::Value::Mapping(defaults.clone()),
        );
    }
    let mut map = match hand_written {
        serde_yaml::Value::Mapping(existing) => existing.clone(),
        // A runtime document with no `origins:` at all, or one whose
        // `origins:` is not a mapping. The second is refused where it is
        // read; this arm keeps the payload well-formed either way.
        _ => serde_yaml::Mapping::new(),
    };
    for (host, origin) in origins {
        map.insert(
            serde_yaml::Value::String(host.clone()),
            serde_yaml::Value::Mapping(origin.clone()),
        );
    }
    document.insert(
        serde_yaml::Value::String("origins".to_string()),
        serde_yaml::Value::Mapping(map),
    );
    serde_yaml::to_string(&serde_yaml::Value::Mapping(document))
        .map_err(|error| AggregateError::Parse(error.to_string()))
}

/// Splice composed origins into the runtime document.
///
/// The **offline** half, and the one `--out` writes. Through text and
/// back rather than through the typed struct, because text is what a
/// node parses, so an origin that only survives in memory is caught
/// here rather than at a boot.
///
/// Both composition blocks are removed. `origin_sources` because a
/// composed output is not a source of further composition and
/// re-composing an output would be a loop; `origin_defaults` because the
/// floor is already folded into every composed origin and leaving it
/// would let a node re-apply it over hand-written origins the aggregator
/// never touched.
///
/// Nothing here is published. The published payload is
/// [`composition_payload`], which is built up rather than cut down.
///
/// # Errors
///
/// Returns [`AggregateError::Parse`] when the runtime document's root is
/// not a mapping or the result will not serialize.
fn splice_origins(
    runtime_yaml: &str,
    origins: &BTreeMap<String, serde_yaml::Mapping>,
) -> Result<String, AggregateError> {
    let mut document: serde_yaml::Value = serde_yaml::from_str(runtime_yaml)
        .map_err(|error| AggregateError::Parse(error.to_string()))?;
    let Some(map) = document.as_mapping_mut() else {
        return Err(AggregateError::Parse(
            "the runtime document's root is not a mapping".to_string(),
        ));
    };
    map.remove("origin_sources");
    map.remove("origin_defaults");
    let slot = map
        .entry(serde_yaml::Value::String("origins".to_string()))
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    let Some(existing) = slot.as_mapping_mut() else {
        return Err(AggregateError::Parse(
            "`origins:` in the runtime document is not a mapping".to_string(),
        ));
    };
    // A `BTreeMap` insertion order is the key order, so the composed
    // half is deterministic; the hand-written half keeps the order the
    // runtime document wrote it in. Both halves are stable across runs,
    // which is what makes a CI diff of `--out` meaningful.
    for (host, origin) in origins {
        existing.insert(
            serde_yaml::Value::String(host.clone()),
            serde_yaml::Value::Mapping(origin.clone()),
        );
    }
    serde_yaml::to_string(&document).map_err(|error| AggregateError::Parse(error.to_string()))
}

/// The coalescing window, as a decision rather than a sleep.
///
/// Separated from any clock so both halves are testable without waiting:
/// a burst inside the window composes once, and a stream of movement
/// still publishes at the ceiling. Argo CD reaches the same pair with
/// `--app-resync` and its self-heal timeout, where the resync is the
/// floor on how often a change is looked for and the timeout is the
/// floor on how often one is acted on.
#[derive(Debug, Clone)]
pub(crate) struct Coalescer {
    debounce: Duration,
    max_deferral: Duration,
    /// When the current window opened, which is what the ceiling is
    /// measured from. `None` means no movement is pending.
    window_opened: Option<Instant>,
    /// When movement was last seen, which is what the debounce is
    /// measured from.
    last_movement: Option<Instant>,
    pending: BTreeSet<String>,
}

/// What a coalescer says to do right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoalesceDecision {
    /// Nothing moved; do nothing.
    Idle,
    /// Movement is pending but the window is still open.
    Waiting {
        /// How long until the next decision could change, so a caller
        /// sleeps once rather than spinning.
        next_check: Duration,
    },
    /// Compose now, for these entries.
    Compose {
        /// Every entry that moved since the window opened.
        entries: Vec<String>,
        /// Whether the ceiling fired rather than the window closing.
        deferral_ceiling: bool,
    },
}

impl Coalescer {
    /// Build a coalescer from the configured timings.
    #[must_use]
    pub(crate) fn new(config: &sbproxy_config::OriginAggregatorConfig) -> Self {
        Self {
            debounce: Duration::from_secs(config.debounce_secs),
            max_deferral: Duration::from_secs(config.max_deferral_secs),
            window_opened: None,
            last_movement: None,
            pending: BTreeSet::new(),
        }
    }

    /// Record that these entries moved, at `now`.
    pub(crate) fn observe(&mut self, entries: &[String], now: Instant) {
        if entries.is_empty() {
            return;
        }
        if self.window_opened.is_none() {
            self.window_opened = Some(now);
        }
        self.last_movement = Some(now);
        self.pending.extend(entries.iter().cloned());
    }

    /// What to do at `now`.
    #[must_use]
    pub(crate) fn decide(&self, now: Instant) -> CoalesceDecision {
        let (Some(opened), Some(last)) = (self.window_opened, self.last_movement) else {
            return CoalesceDecision::Idle;
        };
        let ceiling_reached = now.duration_since(opened) >= self.max_deferral;
        if ceiling_reached {
            return CoalesceDecision::Compose {
                entries: self.pending.iter().cloned().collect(),
                deferral_ceiling: true,
            };
        }
        if now.duration_since(last) >= self.debounce {
            return CoalesceDecision::Compose {
                entries: self.pending.iter().cloned().collect(),
                deferral_ceiling: false,
            };
        }
        // The nearer of the two, so a caller that sleeps for this long
        // wakes exactly when one of them fires rather than after it.
        let until_debounce = self.debounce.saturating_sub(now.duration_since(last));
        let until_ceiling = self.max_deferral.saturating_sub(now.duration_since(opened));
        CoalesceDecision::Waiting {
            next_check: until_debounce.min(until_ceiling),
        }
    }

    /// Adopt new timings without closing the window that is open.
    ///
    /// The runtime document is re-read every cycle, so the two durations
    /// can change under a pending window. Rebuilding the coalescer
    /// instead would drop the pending entries, which is a lost publish
    /// rather than a retuned one.
    pub(crate) fn retune(&mut self, config: &sbproxy_config::OriginAggregatorConfig) {
        self.debounce = Duration::from_secs(config.debounce_secs);
        self.max_deferral = Duration::from_secs(config.max_deferral_secs);
    }

    /// How many entries are waiting on the current window.
    pub(crate) fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Clear the window after a compose.
    pub(crate) fn reset(&mut self) {
        self.window_opened = None;
        self.last_movement = None;
        self.pending.clear();
    }
}

// --- Publishing, rounds, and the background loop ---------------------

/// Where a composed document goes.
///
/// A trait because the two callers reach the same
/// [`crate::config_authority::ConfigAuthority::publish`] by different
/// routes. The in-process aggregator holds the authority directly; the
/// CLI posts to the admin route, which calls it on the other side. Both
/// therefore get `compile_config`, the pipeline construction, the
/// model-runtime check and the denied-path screen, which is the whole
/// reason composition publishes through the authority rather than
/// writing a file every node reads.
pub trait CompositionPublisher {
    /// Publish one composed document and report the revision it got.
    ///
    /// # Errors
    ///
    /// Returns the refusal as text. The caller turns it into
    /// [`AggregateError::Publish`]; the string is already the
    /// authority's own operator-facing message.
    fn publish(&self, config_yaml: &str) -> Result<u64, String>;
}

/// Publish straight into this process's config authority.
pub struct AuthorityPublisher {
    authority: std::sync::Arc<crate::config_authority::ConfigAuthority>,
    mode: sbproxy_config::BundleMode,
}

impl AuthorityPublisher {
    /// Wrap the authority this process installed.
    #[must_use]
    pub fn new(
        authority: std::sync::Arc<crate::config_authority::ConfigAuthority>,
        mode: sbproxy_config::BundleMode,
    ) -> Self {
        Self { authority, mode }
    }
}

impl CompositionPublisher for AuthorityPublisher {
    fn publish(&self, config_yaml: &str) -> Result<u64, String> {
        self.authority
            .publish(config_yaml, self.mode)
            .map(|outcome| outcome.revision)
            .map_err(|error| error.to_string())
    }
}

/// What one round decided.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RoundOutcome {
    /// The composition differed and went to the authority.
    Published {
        /// Revision the authority assigned.
        revision: u64,
        /// The composition that was published.
        outcome: CompositionOutcome,
    },
    /// The composition was byte-identical to the last published one, so
    /// nothing was published and no subscriber reloaded.
    Unchanged {
        /// The composition that was compared.
        outcome: CompositionOutcome,
    },
}

/// The last round's result, for the admin surface.
///
/// Held per process because there is one aggregator per process by
/// construction. A node that never aggregates leaves this empty and the
/// admin route says so rather than inventing a zero.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AggregationStatus {
    /// When the round finished, in unix milliseconds.
    pub at_unix_ms: u64,
    /// `published`, `unchanged`, or `refused`.
    pub decision: String,
    /// Revision the authority assigned, when one was.
    pub revision: Option<u64>,
    /// Digest of the composed document.
    pub content_digest: Option<String>,
    /// How long the round took.
    pub duration_ms: u64,
    /// How many origins composed.
    pub origins: usize,
    /// Every entry that resolved.
    pub resolved: Vec<ResolvedEntry>,
    /// Every entry that did not.
    pub failed: Vec<EntryFailure>,
    /// Every `origin_defaults` entry a project switched off.
    pub drops: Vec<DroppedDefault>,
    /// Which layer set each leaf, per composed host.
    pub provenance: BTreeMap<String, CompositionProvenance>,
    /// Why the round was refused, when it was.
    pub reason: Option<String>,
}

static LAST_ROUND: std::sync::OnceLock<arc_swap::ArcSwapOption<AggregationStatus>> =
    std::sync::OnceLock::new();

fn last_round_slot() -> &'static arc_swap::ArcSwapOption<AggregationStatus> {
    LAST_ROUND.get_or_init(arc_swap::ArcSwapOption::empty)
}

/// The last aggregation round this process ran, if it ran one.
#[must_use]
pub fn last_round() -> Option<std::sync::Arc<AggregationStatus>> {
    last_round_slot().load_full()
}

/// Record a round for the admin surface.
///
/// Private, so the only thing that can write this slot is a round that
/// really happened. A status somebody else could set is a status an
/// operator cannot trust.
fn record_status(status: AggregationStatus) {
    last_round_slot().store(Some(std::sync::Arc::new(status)));
}

impl Aggregator {
    /// Compose, decide whether to publish, and publish if so.
    ///
    /// The one seam both the CLI and the background loop go through, so
    /// the change-detection rule, the metrics and the admin status
    /// cannot differ between them.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::compose`] returns, and
    /// [`AggregateError::Publish`] when the authority refused the
    /// composed document. A refusal is recorded on the admin status and
    /// counted before it is returned, because the operator who has to
    /// fix it is reading one of those two surfaces.
    pub fn run_round(
        &mut self,
        publisher: &dyn CompositionPublisher,
    ) -> Result<RoundOutcome, AggregateError> {
        let composed = match self.compose() {
            Ok(composed) => composed,
            Err(error) => {
                sbproxy_observe::metrics::record_aggregate_round("refused");
                record_status(AggregationStatus {
                    at_unix_ms: now_unix_ms(),
                    decision: "refused".to_string(),
                    reason: Some(error.to_string()),
                    ..AggregationStatus::default()
                });
                return Err(error);
            }
        };
        self.publish_composed(composed, publisher)
    }

    /// Decide whether to publish a composition already in hand, and
    /// publish it if so.
    ///
    /// Split out from [`Self::run_round`] because the one-shot CLI has
    /// already composed by the time it decides to publish: it needs the
    /// outcome for `--explain`, for the failure warnings and for the
    /// JSON summary. Composing a second time inside `run_round` cost a
    /// second round of I/O and, worse, reported every entry as
    /// `unchanged` the second time through, so
    /// `sbproxy_aggregate_entries{outcome="resolved"}` read zero
    /// immediately after a publish that resolved every entry.
    ///
    /// # Errors
    ///
    /// Returns [`AggregateError::Publish`] when the authority refused
    /// the composed document. The refusal is recorded on the admin
    /// status and counted before it is returned, because the operator
    /// who has to fix it is reading one of those two surfaces.
    pub fn publish_composed(
        &mut self,
        composed: CompositionOutcome,
        publisher: &dyn CompositionPublisher,
    ) -> Result<RoundOutcome, AggregateError> {
        if !self.would_change(&composed) {
            sbproxy_observe::metrics::record_aggregate_round("unchanged");
            record_status(status_of(&composed, "unchanged", None, None));
            tracing::debug!(
                digest = %composed.content_digest,
                origins = composed.origins,
                "aggregate: composition unchanged; nothing published",
            );
            return Ok(RoundOutcome::Unchanged { outcome: composed });
        }
        // The payload, never the runtime document. A bundle carrying a
        // node's `proxy:` block is refused by the denied-path screen on
        // every real configuration, and would be wrong even if it were
        // not: a subscriber's listeners, TLS, admin surface and secrets
        // are not the fleet's to set.
        match publisher.publish(&composed.payload) {
            Ok(revision) => {
                self.mark_published(&composed);
                sbproxy_observe::metrics::record_aggregate_round("published");
                sbproxy_observe::metrics::set_aggregate_published_revision(
                    i64::try_from(revision).unwrap_or(i64::MAX),
                );
                record_status(status_of(&composed, "published", Some(revision), None));
                tracing::info!(
                    revision,
                    digest = %composed.content_digest,
                    origins = composed.origins,
                    entries = composed.resolved.len(),
                    failed = composed.failed.len(),
                    "aggregate: published a composed configuration",
                );
                Ok(RoundOutcome::Published {
                    revision,
                    outcome: composed,
                })
            }
            Err(reason) => {
                sbproxy_observe::metrics::record_aggregate_round("refused");
                record_status(status_of(&composed, "refused", None, Some(reason.clone())));
                Err(AggregateError::Publish(reason))
            }
        }
    }
}

/// Build an admin status from one composition.
fn status_of(
    outcome: &CompositionOutcome,
    decision: &str,
    revision: Option<u64>,
    reason: Option<String>,
) -> AggregationStatus {
    AggregationStatus {
        at_unix_ms: now_unix_ms(),
        decision: decision.to_string(),
        revision,
        content_digest: Some(outcome.content_digest.clone()),
        duration_ms: u64::try_from(outcome.duration.as_millis()).unwrap_or(u64::MAX),
        origins: outcome.origins,
        resolved: outcome.resolved.clone(),
        failed: outcome.failed.clone(),
        drops: outcome.drops.clone(),
        provenance: outcome.provenance.clone(),
        reason,
    }
}

/// Wall-clock milliseconds, or zero when the clock is before the epoch.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Start the in-process aggregation loop, when this node is the one that
/// should run it.
///
/// Two conditions, and both are load-bearing. The document has to
/// declare `origin_sources` entries, and this process has to hold a
/// config authority. A node with entries and no authority has nowhere to
/// publish to: its composed document would be a file, which is the
/// offline path `sbproxy aggregate --out` owns and not something to do
/// behind an operator's back. Saying so in a log line rather than
/// silently doing nothing is the difference between a misconfiguration
/// an operator can see and a fleet that quietly never composes.
///
/// # Errors
///
/// Returns an error when the loop thread cannot be spawned. Everything
/// after that is per-round and is logged rather than returned, because a
/// single unreachable repository must not stop a proxy from serving.
pub fn spawn(config_path: &str, mode: sbproxy_config::BundleMode) -> anyhow::Result<()> {
    // `from_path` rather than a read plus `with_fetch_context`, because
    // remembering where the document came from is what lets every round
    // re-read it. A SIGHUP or a config-watcher reload updates the node's
    // own pipeline and `GET /admin/origin-composition`; an aggregator
    // frozen at boot would keep publishing the boot-time document, so
    // the two halves of one admin response would disagree and the
    // operator's only signal would be that nothing happened.
    let mut aggregator = match Aggregator::from_path(
        std::path::Path::new(config_path),
        FetchContext::with_git_binary(),
    ) {
        Ok(aggregator) => aggregator,
        Err(AggregateError::NoSources) => return Ok(()),
        Err(AggregateError::Io(reason)) => {
            tracing::debug!(%reason, "aggregate: no readable config document; not aggregating");
            return Ok(());
        }
        Err(error) => {
            tracing::warn!(%error, "aggregate: not aggregating on this node");
            return Ok(());
        }
    };
    if aggregator.entries().is_empty() {
        return Ok(());
    }
    let Some(authority) = crate::config_authority::current_authority() else {
        tracing::warn!(
            entries = aggregator.entries().len(),
            "aggregate: this document declares origin_sources entries but this node publishes no \
             config authority, so nothing composes here. Run the aggregator on the authority \
             node, or compose to a file with `sbproxy aggregate --out`",
        );
        return Ok(());
    };
    if let Err(error) = aggregator.resolve_credentials() {
        tracing::error!(%error, "aggregate: entry credentials did not resolve; not aggregating");
        return Ok(());
    }
    // Seed the change detector from what this authority is already
    // serving, so a restart does not republish a byte-identical payload
    // and rebuild every subscriber's pipeline for nothing.
    if let Some(digest) = authority.current_content_digest() {
        aggregator.seed_published_digest(digest);
    }
    let publisher = AuthorityPublisher::new(authority, mode);
    std::thread::Builder::new()
        .name("sbproxy-aggregate".to_string())
        .spawn(move || {
            aggregation_loop(&mut aggregator, &publisher, None);
        })
        .map_err(|error| anyhow::anyhow!("spawn the aggregation thread: {error}"))?;
    tracing::info!("aggregate: composition loop started");
    Ok(())
}

/// Poll, coalesce, compose and publish until `polls` cycles have run.
///
/// `polls: None` runs until the process ends. The bound counts **poll
/// cycles**, not compositions, and that is the only shape a bound can
/// honestly take: a fleet where nothing moves composes nothing, so a
/// bound counting compositions would never be reached and the loop would
/// never return. A test and a cron-shaped invocation both want "look
/// this many times", which is what this is.
///
/// The timings are re-read from the aggregator each cycle rather than
/// captured once, because the runtime document is re-read each cycle
/// too: an operator who lowers `poll_interval_secs` and reloads expects
/// the next cycle to use it.
pub fn aggregation_loop(
    aggregator: &mut Aggregator,
    publisher: &dyn CompositionPublisher,
    polls: Option<u32>,
) {
    let mut coalescer = Coalescer::new(aggregator.timings());
    let mut next_poll = Instant::now();
    let mut polled = 0_u32;
    let compose = |aggregator: &mut Aggregator,
                   coalescer: &mut Coalescer,
                   entries: usize,
                   deferral_ceiling: bool| {
        coalescer.reset();
        tracing::info!(
            entries,
            deferral_ceiling,
            "aggregate: composing for the entries that moved",
        );
        if let Err(error) = aggregator.run_round(publisher) {
            tracing::error!(%error, "aggregate: round failed");
        }
    };
    loop {
        let now = Instant::now();
        if now >= next_poll {
            if polls.is_some_and(|limit| polled >= limit) {
                // Drain a window that is still open before returning.
                // With `debounce_secs > poll_interval_secs` the last
                // window is never closed by a `decide`, so a bounded run
                // would otherwise observe movement and then exit without
                // composing for it, which is the silent no-op a
                // cron-shaped invocation would never notice.
                let pending = coalescer.pending_count();
                if pending > 0 {
                    compose(aggregator, &mut coalescer, pending, false);
                }
                return;
            }
            // Before the poll, so an entry added to the document this
            // cycle is polled this cycle rather than next.
            aggregator.refresh_document();
            coalescer.retune(aggregator.timings());
            let moved = aggregator.poll();
            polled = polled.saturating_add(1);
            coalescer.observe(&moved, now);
            // Bound rather than chained so the config-reader registry
            // can see an unambiguous read of the field: the scanner
            // looks for a plain access on a value of the config type,
            // and the whole point of that gate is that a documented key
            // nothing reads cannot ship.
            let poll_interval = {
                let timings: &sbproxy_config::OriginAggregatorConfig = aggregator.timings();
                Duration::from_secs(timings.poll_interval_secs.max(1))
            };
            next_poll = now + poll_interval;
        }
        match coalescer.decide(Instant::now()) {
            CoalesceDecision::Compose {
                entries,
                deferral_ceiling,
            } => {
                compose(aggregator, &mut coalescer, entries.len(), deferral_ceiling);
            }
            CoalesceDecision::Waiting { next_check } => {
                let until_poll = next_poll.saturating_duration_since(Instant::now());
                std::thread::sleep(next_check.min(until_poll).max(Duration::from_millis(10)));
            }
            CoalesceDecision::Idle => {
                if polls.is_some_and(|limit| polled >= limit) {
                    return;
                }
                std::thread::sleep(
                    next_poll
                        .saturating_duration_since(Instant::now())
                        .max(Duration::from_millis(10)),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Coalescer` built from the defaults an operator would get.
    fn timings(debounce: u64, ceiling: u64) -> sbproxy_config::OriginAggregatorConfig {
        sbproxy_config::OriginAggregatorConfig {
            poll_interval_secs: 1,
            debounce_secs: debounce,
            max_deferral_secs: ceiling,
            concurrency: 1,
            deadline_secs: 30,
        }
    }

    /// Three teams merging inside the same minute is one composed
    /// document and one published revision, not three fleet reloads.
    ///
    /// In this file rather than in `tests/config_aggregator.rs` because
    /// the coalescer is `pub(crate)`: its only production caller is
    /// [`aggregation_loop`], and an item a test has to reach for is not
    /// a reason to widen a crate's public surface.
    #[test]
    fn a_burst_inside_the_debounce_window_composes_once() {
        let mut coalescer = Coalescer::new(&timings(30, 300));
        let start = Instant::now();
        coalescer.observe(&["svc0".to_string()], start);
        assert!(matches!(
            coalescer.decide(start + Duration::from_secs(1)),
            CoalesceDecision::Waiting { .. }
        ));
        coalescer.observe(&["svc1".to_string()], start + Duration::from_secs(2));
        coalescer.observe(&["svc2".to_string()], start + Duration::from_secs(4));
        assert!(
            matches!(
                coalescer.decide(start + Duration::from_secs(20)),
                CoalesceDecision::Waiting { .. }
            ),
            "the window is still open twenty seconds in, because the last movement was at four"
        );

        let CoalesceDecision::Compose {
            entries,
            deferral_ceiling,
        } = coalescer.decide(start + Duration::from_secs(35))
        else {
            panic!("the window closes into exactly one compose");
        };
        assert!(
            !deferral_ceiling,
            "the window closed rather than the ceiling firing"
        );
        assert_eq!(entries, vec!["svc0", "svc1", "svc2"], "all three, once");

        coalescer.reset();
        assert!(matches!(
            coalescer.decide(start + Duration::from_secs(40)),
            CoalesceDecision::Idle
        ));
    }

    /// A continuously-changing entry still publishes.
    #[test]
    fn the_deferral_ceiling_fires_for_a_continuously_changing_entry() {
        let mut coalescer = Coalescer::new(&timings(10, 25));
        let start = Instant::now();
        // Movement every five seconds resets the debounce forever, so
        // without a ceiling this never composes at all.
        let mut at = start;
        for _ in 0..10 {
            coalescer.observe(&["churn".to_string()], at);
            at += Duration::from_secs(5);
            if let CoalesceDecision::Compose {
                deferral_ceiling, ..
            } = coalescer.decide(at)
            {
                assert!(
                    deferral_ceiling,
                    "the debounce never closed, so the ceiling is what fired"
                );
                assert!(
                    at.duration_since(start) >= Duration::from_secs(25),
                    "and it fired no earlier than the ceiling"
                );
                return;
            }
        }
        panic!("the ceiling never fired, so a continuously-changing entry would never publish");
    }

    /// A zero debounce composes on the first decision after movement,
    /// which is what an operator who wants no coalescing at all gets.
    #[test]
    fn a_zero_debounce_composes_immediately() {
        let mut coalescer = Coalescer::new(&timings(0, 120));
        let now = Instant::now();
        assert!(matches!(coalescer.decide(now), CoalesceDecision::Idle));
        coalescer.observe(&["svc".to_string()], now);
        assert!(matches!(
            coalescer.decide(now),
            CoalesceDecision::Compose {
                deferral_ceiling: false,
                ..
            }
        ));
    }
}
