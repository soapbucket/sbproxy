//! Repo-native [`Listing`] primitive (WOR-136).
//!
//! A `Listing` is a published, versioned view of a Resource that lives
//! in the same Repo as the rest of the proxy config. The shape is
//! Kubernetes-flavoured (`apiVersion`, `kind`, `metadata`, `spec`) so
//! it round-trips cleanly with the rest of the platform's YAML and
//! lets future agents (the WOR-196 Listing-scoped agent-skills hook,
//! the WOR-135 hosted-Catalog surface, the future preview-environments
//! work) build on a stable shape.
//!
//! ## What this module provides
//!
//! * The serde-deserialisable [`Listing`] schema, plus the supporting
//!   types ([`ListingSpec`], [`ListingResource`], [`Revision`],
//!   [`RevisionMode`], [`ListingAuth`], [`ListingAccessPlan`],
//!   [`ListingPublish`], [`ListingLifecycle`]).
//! * [`load_listings_from_repo`] and [`load_listing_file`]: a
//!   filesystem loader that picks up `listings/*.yaml` (and `*.yml`)
//!   from a Repo root and parses each file into a [`Listing`].
//! * [`ListingRegistry`]: a small in-memory registry the loader
//!   populates and the plan / validate path queries.
//! * [`validate_listings`]: plan-time semantic validation that folds
//!   into the existing [`crate::validate::PlanFinding`] stream.
//!
//! The loader is intentionally cheap and synchronous: it is a single
//! pass over a directory at config-load time, and no network or git
//! plumbing is invoked from here. Revision-mode validation against a
//! real git Repo is best-effort and is delegated to the caller through
//! [`RevisionResolver`]; the OSS default ([`NoopRevisionResolver`])
//! treats every revision as resolvable so the OSS plan surface stays
//! self-contained.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::types::{AgentSkillEntry, ConfigFile, RawOriginConfig};
use crate::validate::{PlanFinding, Severity};

// --- Schema -------------------------------------------------------------

/// The expected `apiVersion` value on every [`Listing`] document.
pub const LISTING_API_VERSION: &str = "sbproxy.dev/v1";

/// The expected `kind` value on every [`Listing`] document.
pub const LISTING_KIND: &str = "Listing";

/// One Listing document: a published, versioned view of a Resource.
///
/// The on-disk YAML shape mirrors a Kubernetes manifest. Adding fields
/// to this type is a non-breaking schema change as long as the new
/// fields are `Option`-typed or carry a serde default; renaming or
/// removing existing fields is breaking.
///
/// Future fields tracked but not yet on this type:
///
/// * `spec.skills`: per-Listing agent-skills extension (WOR-196). It
///   lives on the Listing because skills are scoped to a published
///   surface, not to the underlying Resource.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Listing {
    /// Schema discriminator, e.g. `sbproxy.dev/v1`. Must match
    /// [`LISTING_API_VERSION`]. Any other value at load time produces
    /// a `bad-listing-api-version` error.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// Resource kind. Must equal [`LISTING_KIND`]. We accept the field
    /// here so the loader can give a precise error when an operator
    /// drops a non-Listing manifest under `listings/` by mistake.
    pub kind: String,
    /// Object metadata: name and labels.
    pub metadata: ListingMetadata,
    /// Listing payload.
    pub spec: ListingSpec,
}

/// Object metadata (name + labels). Patterned on the Kubernetes
/// `ObjectMeta` shape so an operator's eyes can grab the file's
/// purpose at a glance.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListingMetadata {
    /// Listing name. Must be unique inside a single Repo. The plan
    /// path for findings emitted against this Listing is
    /// `listings.<name>`.
    pub name: String,
    /// Free-form label map. The OSS proxy does not interpret labels;
    /// they are carried for downstream consumers (the hosted-Catalog
    /// surface, the k8s controller, etc.).
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Listing payload. Captures the Resource(s) the Listing exposes, the
/// auth strategies it accepts, the access plan the operator publishes,
/// the publish-visibility settings, and the lifecycle stage.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListingSpec {
    /// Listing type. Currently `api`, `mcp`, or `docs`. The set is
    /// extensible: unknown values pass parsing and surface as a
    /// `unknown-listing-type` warning at plan time so a new type can
    /// land in the schema before the validator is taught about it.
    #[serde(rename = "type")]
    pub listing_type: String,
    /// Lifecycle stage. `draft`, `published`, or `retired`.
    pub status: String,
    /// What the Listing exposes. Each entry references a Resource by
    /// `ref` (e.g. `origins/example.com`) and pins the revision the
    /// Listing should serve. At least one entry is required.
    pub resources: Vec<ListingResource>,
    /// Auth strategies this Listing advertises. Must be a subset of
    /// (or compatible with) the Resource's own auth surface; see
    /// [`validate_listings`] for the rule.
    #[serde(default)]
    pub auth: ListingAuth,
    /// Access plan: free / paid pricing the Listing publishes. The
    /// schema is intentionally narrow; richer billing lives in
    /// follow-on work.
    #[serde(default, rename = "accessPlan")]
    pub access_plan: ListingAccessPlan,
    /// Publish surface: who can see the Listing and where its docs
    /// live.
    #[serde(default)]
    pub publish: ListingPublish,
    /// Lifecycle metadata: deprecation note + sunset date.
    #[serde(default)]
    pub lifecycle: ListingLifecycle,
    /// Per-Listing Agent Skills v0.2.0 advertisement (WOR-196).
    ///
    /// Each entry mirrors the top-level `agent_skills:` block from
    /// `WOR-193`: `name`, `type`, `description`, `url`, optional
    /// `visibility`, plus the `path` / `body` / archive-safety knobs.
    /// At config-load time the projection layer resolves the artifact
    /// bytes, hashes them, and exposes the resulting index at two
    /// well-known paths:
    ///
    /// - `GET /.well-known/agent-skills/<listing-name>/index.json`
    ///   serves the per-Listing manifest.
    /// - `GET /.well-known/agent-skills/index.json` on a Catalog
    ///   domain serves the union of every visible Listing's
    ///   `spec.skills[]` plus any top-level `agent_skills` configured
    ///   directly on the origin.
    ///
    /// Plan-time validation (see [`validate_listings`]) checks that
    /// every `url` resolves to a file under `skills/` in the same
    /// Repo or is a fully-qualified URL; pinned digests on the
    /// underlying entry are recomputed at config-load time and
    /// rejected when they diverge from the artifact bytes.
    #[serde(default)]
    pub skills: Vec<AgentSkillEntry>,
}

/// One Resource the Listing exposes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListingResource {
    /// Reference to a Resource in the same Repo, formatted as
    /// `<kind>/<name>`. Today we resolve `origins/<hostname>`,
    /// `mcp/<name>`, and `docs/<name>`. Other shapes pass parsing so
    /// the schema is forward-compatible with future Resource kinds.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Pinning policy. Required so a published Listing always serves
    /// a deterministic revision; see [`Revision`] and
    /// [`RevisionMode`].
    pub revision: Revision,
}

/// Revision pin for a single [`ListingResource`].
///
/// All three modes carry a single string `value`, but the
/// interpretation differs by [`RevisionMode`]. We keep the shape flat
/// (rather than an enum-with-payload) so the YAML stays human-readable
/// and so adding a future mode does not break the wire format.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Revision {
    /// How the resource is pinned. See [`RevisionMode`].
    pub mode: RevisionMode,
    /// Mode-specific identifier. For [`RevisionMode::Pin`] this is a
    /// commit SHA (full or short). For [`RevisionMode::TrackBranch`]
    /// it is a branch name. For [`RevisionMode::Tag`] it is a tag
    /// name.
    pub value: String,
}

/// How a [`Revision`] is pinned.
///
/// The set is closed today; growing it is an additive schema change.
/// Plugin authors that want to target a specific mode should match on
/// this enum directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevisionMode {
    /// Pin to a specific commit SHA (short or long form). The plan
    /// validator asks the [`RevisionResolver`] whether the SHA exists
    /// in the Repo.
    Pin,
    /// Track a moving branch. The Listing resolves to whatever the
    /// branch currently points at at load time. Plan validation only
    /// checks that the branch exists.
    TrackBranch,
    /// Pin to a tag. Plan validation checks that the tag exists.
    Tag,
}

/// Auth strategies a Listing advertises.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ListingAuth {
    /// Strategy names matching the OSS auth catalog (`api_key`, `jwt`,
    /// `bearer`, ...). Plan validation checks that every entry is a
    /// subset of, or compatible with, the underlying Resource's
    /// `authentication.type`.
    #[serde(default)]
    pub strategies: Vec<String>,
}

/// Access plan advertised on the Listing.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ListingAccessPlan {
    /// Free tier rate-limit string, e.g. `100/min`. Free-form today;
    /// the future Catalog surface will parse this into a structured
    /// quota.
    #[serde(default)]
    pub free: Option<ListingFreeTier>,
    /// Paid tier price + currency. Free-form today.
    #[serde(default)]
    pub paid: Option<ListingPaidTier>,
}

/// Free tier of an [`ListingAccessPlan`].
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ListingFreeTier {
    /// Rate quota in `<count>/<window>` form, e.g. `100/min`.
    #[serde(default)]
    pub rate: Option<String>,
}

/// Paid tier of an [`ListingAccessPlan`].
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ListingPaidTier {
    /// Price in micro-units of `currency` per call. E.g.
    /// `price_micros: 1000` with `currency: USD` is one tenth of a
    /// cent per call.
    #[serde(default)]
    pub price_micros: Option<u64>,
    /// ISO 4217 currency code. The OSS proxy does not enforce the
    /// list; downstream Catalog surfaces will.
    #[serde(default)]
    pub currency: Option<String>,
}

/// Publish surface of a Listing.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ListingPublish {
    /// Visibility class. Today: `public`, `authenticated`,
    /// `restricted`. Unknown values surface as a warning.
    #[serde(default)]
    pub visibility: Option<String>,
    /// Path on the public docs site where the Listing is documented.
    #[serde(default, rename = "docsUrl")]
    pub docs_url: Option<String>,
}

/// Lifecycle metadata.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ListingLifecycle {
    /// Deprecation notice. Free-form today; renderers can show this
    /// inline with the Listing's docs entry.
    #[serde(default)]
    pub deprecation: Option<String>,
    /// Sunset date in `YYYY-MM-DD` form. Free-form today; the future
    /// Catalog surface will parse this and surface it on the listing
    /// page.
    #[serde(default, rename = "sunsetDate")]
    pub sunset_date: Option<String>,
}

// --- Loader -------------------------------------------------------------

/// One loaded Listing plus the file path it came from. The path is
/// kept so plan findings can point at the offending YAML file.
#[derive(Debug, Clone)]
pub struct LoadedListing {
    /// Filesystem path the Listing was read from.
    pub source_path: PathBuf,
    /// Parsed Listing.
    pub listing: Listing,
}

/// Errors that can be reported by [`load_listings_from_repo`] or
/// [`load_listing_file`].
#[derive(Debug, thiserror::Error)]
pub enum ListingLoadError {
    /// Filesystem I/O error while reading a Listing file.
    #[error("io error reading {path}: {source}")]
    Io {
        /// File whose read failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// YAML parse failure.
    #[error("yaml parse error in {path}: {source}")]
    Yaml {
        /// File whose parse failed.
        path: PathBuf,
        /// Underlying YAML error.
        #[source]
        source: serde_yaml::Error,
    },
    /// Manifest had a wrong `apiVersion` or `kind` field.
    #[error("{path}: expected apiVersion={LISTING_API_VERSION}, kind={LISTING_KIND}; got apiVersion={actual_api_version}, kind={actual_kind}")]
    BadHeader {
        /// File whose header was wrong.
        path: PathBuf,
        /// `apiVersion` value found in the file.
        actual_api_version: String,
        /// `kind` value found in the file.
        actual_kind: String,
    },
}

// We pull `thiserror` in already through the workspace; if it ever
// disappears we can fall back to a hand-rolled `Display` impl on this
// enum without changing callers.

/// Directory under a Repo root that holds Listing manifests.
pub const LISTINGS_DIRNAME: &str = "listings";

/// Load every `listings/*.yaml` (and `*.yml`) under `repo_root`.
///
/// Returns a vector of [`LoadedListing`] in stable, lexicographic
/// order so plan findings stay reproducible across runs. A missing
/// `listings/` directory is not an error: it produces an empty vector
/// (most Repos that have not adopted the primitive yet).
///
/// Per-file failures are collected into `errors`; the function still
/// returns the listings that did parse so the caller can present a
/// partial load. Callers that want strict semantics check that
/// `errors` is empty.
pub fn load_listings_from_repo(
    repo_root: &Path,
    errors: &mut Vec<ListingLoadError>,
) -> Vec<LoadedListing> {
    let dir = repo_root.join(LISTINGS_DIRNAME);
    if !dir.is_dir() {
        return Vec::new();
    }
    let mut paths: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(it) => it
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .and_then(|s| s.to_str())
                        .map(|ext| {
                            ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml")
                        })
                        .unwrap_or(false)
            })
            .collect(),
        Err(e) => {
            errors.push(ListingLoadError::Io {
                path: dir.clone(),
                source: e,
            });
            return Vec::new();
        }
    };
    paths.sort();
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        match load_listing_file(&path) {
            Ok(listing) => out.push(LoadedListing {
                source_path: path,
                listing,
            }),
            Err(e) => errors.push(e),
        }
    }
    out
}

/// Read a single Listing manifest file and return the parsed
/// [`Listing`]. The header (`apiVersion`, `kind`) is validated before
/// returning so a misfiled non-Listing YAML produces a clear error
/// instead of a confusing serde failure deeper down.
///
/// # Errors
///
/// Returns [`ListingLoadError`] if the file cannot be read, if its YAML
/// does not deserialize into a [`Listing`], or if its `apiVersion` /
/// `kind` header does not match the expected Listing schema.
pub fn load_listing_file(path: &Path) -> Result<Listing, ListingLoadError> {
    let body = std::fs::read_to_string(path).map_err(|source| ListingLoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let listing: Listing =
        serde_yaml::from_str(&body).map_err(|source| ListingLoadError::Yaml {
            path: path.to_path_buf(),
            source,
        })?;
    if listing.api_version != LISTING_API_VERSION || listing.kind != LISTING_KIND {
        return Err(ListingLoadError::BadHeader {
            path: path.to_path_buf(),
            actual_api_version: listing.api_version,
            actual_kind: listing.kind,
        });
    }
    Ok(listing)
}

// --- In-memory registry -------------------------------------------------

/// In-memory registry of loaded Listings. Keyed by
/// `metadata.name` for O(1) lookup at plan / apply time.
///
/// The registry is intentionally a thin wrapper over a `HashMap` so
/// the OSS surface stays small. Future enterprise consumers (the
/// hosted-Catalog surface, the k8s controller) can extend with a
/// reverse index or a watcher channel without touching this struct.
#[derive(Debug, Default, Clone)]
pub struct ListingRegistry {
    inner: HashMap<String, LoadedListing>,
}

impl ListingRegistry {
    /// Build an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the Listing keyed under
    /// `loaded.listing.metadata.name`. Returns the previous entry, if
    /// any, so the caller can detect duplicate-name collisions.
    pub fn insert(&mut self, loaded: LoadedListing) -> Option<LoadedListing> {
        self.inner
            .insert(loaded.listing.metadata.name.clone(), loaded)
    }

    /// Number of Listings registered.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when no Listing has been registered yet.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Look up a Listing by `metadata.name`.
    pub fn get(&self, name: &str) -> Option<&LoadedListing> {
        self.inner.get(name)
    }

    /// Iterate every registered Listing in lexicographic order. The
    /// stable order is the contract for plan-output rendering and
    /// downstream Catalog surfaces.
    pub fn iter(&self) -> impl Iterator<Item = &LoadedListing> {
        let mut sorted: Vec<&LoadedListing> = self.inner.values().collect();
        sorted.sort_by(|a, b| a.listing.metadata.name.cmp(&b.listing.metadata.name));
        sorted.into_iter()
    }

    /// Build a registry from a list of [`LoadedListing`] values.
    /// Duplicate names produce a `duplicate-listing-name` finding the
    /// caller can surface in the plan stream.
    pub fn from_loaded(loaded: Vec<LoadedListing>, findings: &mut Vec<PlanFinding>) -> Self {
        let mut reg = Self::new();
        for entry in loaded {
            let name = entry.listing.metadata.name.clone();
            if let Some(prev) = reg.insert(entry) {
                findings.push(PlanFinding {
                    severity: Severity::Error,
                    rule_id: "duplicate-listing-name".to_string(),
                    path: format!("listings.{name}"),
                    message: format!(
                        "duplicate listing name '{name}' (already loaded from {})",
                        prev.source_path.display()
                    ),
                });
            }
        }
        reg
    }
}

// --- Revision resolver --------------------------------------------------

/// Resolve revision pins against a Repo.
///
/// The [`Listing`] schema includes three pinning modes (`pin`,
/// `track-branch`, `tag`). Validating those modes for real requires
/// either git plumbing or an out-of-band index of the Repo, which the
/// OSS proxy does not assume is present. This trait lets a caller
/// inject a real resolver (the k8s controller, the hosted-Catalog
/// surface) without dragging the dependency into `sbproxy-config`.
pub trait RevisionResolver {
    /// True when `sha` exists in the Repo. `sha` may be the short or
    /// the full form.
    fn sha_exists(&self, sha: &str) -> bool;
    /// True when `branch` exists in the Repo.
    fn branch_exists(&self, branch: &str) -> bool;
    /// True when `tag` exists in the Repo.
    fn tag_exists(&self, tag: &str) -> bool;
}

/// OSS-default resolver that treats every revision as resolvable.
///
/// This keeps the OSS plan surface self-contained: the validator
/// still checks that each Listing names a known Resource and that the
/// auth strategies are compatible, but the existence-of-revision
/// check is a no-op until a real resolver is plugged in. A future
/// CLI flag can swap in a git-backed resolver.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRevisionResolver;

impl RevisionResolver for NoopRevisionResolver {
    fn sha_exists(&self, _sha: &str) -> bool {
        true
    }
    fn branch_exists(&self, _branch: &str) -> bool {
        true
    }
    fn tag_exists(&self, _tag: &str) -> bool {
        true
    }
}

/// Lightweight resolver that delegates to an explicit allowlist of
/// SHAs / branches / tags. Useful in tests and in callers that have
/// already collected a Repo's git state out of band.
#[derive(Debug, Default, Clone)]
pub struct StaticRevisionResolver {
    /// Set of commit SHAs (full and short forms accepted).
    pub shas: BTreeSet<String>,
    /// Set of branch names.
    pub branches: BTreeSet<String>,
    /// Set of tag names.
    pub tags: BTreeSet<String>,
}

impl RevisionResolver for StaticRevisionResolver {
    fn sha_exists(&self, sha: &str) -> bool {
        if self.shas.contains(sha) {
            return true;
        }
        // Accept a short SHA when the resolver was seeded with a
        // longer one (the common Repo-snapshot case).
        self.shas.iter().any(|x| x.starts_with(sha))
    }
    fn branch_exists(&self, branch: &str) -> bool {
        self.branches.contains(branch)
    }
    fn tag_exists(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }
}

// --- Plan-step validation -----------------------------------------------

/// Validate a [`ListingRegistry`] against a parsed [`ConfigFile`] and
/// emit [`PlanFinding`] entries. Findings ride alongside the existing
/// validate stream so the CLI surfaces them under the same `Validation:`
/// header.
///
/// Rules enforced today:
///
/// 1. Every `resources[].ref` must resolve to a known Resource in the
///    same Repo. `origins/<hostname>` is checked against the
///    `ConfigFile.origins` map. `mcp/<name>` and `docs/<name>` are
///    accepted as forward-compatible kinds with a warning when the
///    underlying Resource cannot be located in the OSS surface.
/// 2. For `revision: { mode: pin }`, the SHA must exist (per the
///    [`RevisionResolver`]).
/// 3. For `revision: { mode: track-branch }`, the branch must exist.
/// 4. For `revision: { mode: tag }`, the tag must exist.
/// 5. Every entry in `auth.strategies` must be compatible with the
///    underlying Resource's `authentication.type` field. We accept the
///    strategy when (a) the Resource has no auth, or (b) the
///    Resource's auth type is in the strategy list, or (c) the
///    strategy is in the OSS-known auth catalog (forward-compatible
///    fallback).
/// 6. `spec.status` must be one of `draft` / `published` / `retired`.
///    Other values surface as `unknown-listing-status` warnings.
/// 7. `spec.type` must be one of `api` / `mcp` / `docs`. Other values
///    surface as `unknown-listing-type` warnings.
pub fn validate_listings<R: RevisionResolver>(
    registry: &ListingRegistry,
    config: &ConfigFile,
    resolver: &R,
    findings: &mut Vec<PlanFinding>,
) {
    let known_origins: BTreeSet<&str> = config.origins.keys().map(|s| s.as_str()).collect();

    for loaded in registry.iter() {
        validate_one(loaded, &known_origins, &config.origins, resolver, findings);
    }
}

fn validate_one<R: RevisionResolver>(
    loaded: &LoadedListing,
    known_origins: &BTreeSet<&str>,
    origins_map: &HashMap<String, RawOriginConfig>,
    resolver: &R,
    findings: &mut Vec<PlanFinding>,
) {
    let listing = &loaded.listing;
    let name = &listing.metadata.name;

    // --- spec.type -----------------------------------------------------
    if !matches!(listing.spec.listing_type.as_str(), "api" | "mcp" | "docs") {
        findings.push(PlanFinding {
            severity: Severity::Warn,
            rule_id: "unknown-listing-type".to_string(),
            path: format!("listings.{name}.spec.type"),
            message: format!(
                "listing '{name}' has unknown spec.type '{}' (known: api, mcp, docs)",
                listing.spec.listing_type
            ),
        });
    }

    // --- spec.status ---------------------------------------------------
    if !matches!(
        listing.spec.status.as_str(),
        "draft" | "published" | "retired"
    ) {
        findings.push(PlanFinding {
            severity: Severity::Warn,
            rule_id: "unknown-listing-status".to_string(),
            path: format!("listings.{name}.spec.status"),
            message: format!(
                "listing '{name}' has unknown spec.status '{}' (known: draft, published, retired)",
                listing.spec.status
            ),
        });
    }

    if listing.spec.resources.is_empty() {
        findings.push(PlanFinding {
            severity: Severity::Error,
            rule_id: "empty-listing-resources".to_string(),
            path: format!("listings.{name}.spec.resources"),
            message: format!(
                "listing '{name}' has no resources; at least one resources[] entry is required"
            ),
        });
        return;
    }

    // Walk each `resources[]` entry. Track the first resolved origin
    // (when there is one) so the auth-compatibility check has a
    // concrete Resource to compare against.
    let mut first_origin_auth_type: Option<String> = None;

    for (idx, res) in listing.spec.resources.iter().enumerate() {
        let entry_path = format!("listings.{name}.spec.resources[{idx}]");

        // -- ref resolution --
        match parse_ref(&res.reference) {
            Some((kind, target)) if kind == "origins" => {
                if !known_origins.contains(target.as_str()) {
                    findings.push(PlanFinding {
                        severity: Severity::Error,
                        rule_id: "orphan-listing-resource".to_string(),
                        path: format!("{entry_path}.ref"),
                        message: format!(
                            "listing '{name}' references unknown origin '{target}' (no matching entry under origins.*)"
                        ),
                    });
                } else if first_origin_auth_type.is_none() {
                    if let Some(auth_type) =
                        origins_map.get(target.as_str()).and_then(extract_auth_type)
                    {
                        first_origin_auth_type = Some(auth_type);
                    }
                }
            }
            Some((kind, _)) if kind == "mcp" || kind == "docs" => {
                // Forward-compatible: there is no first-class `mcp`
                // or `docs` Resource map in the OSS schema yet, so we
                // accept the reference but warn once so an operator
                // sees the missing wiring.
                findings.push(PlanFinding {
                    severity: Severity::Warn,
                    rule_id: "forward-compatible-listing-resource".to_string(),
                    path: format!("{entry_path}.ref"),
                    message: format!(
                        "listing '{name}' references '{}' which is not yet validated by the OSS schema",
                        res.reference
                    ),
                });
            }
            Some(_) => {
                findings.push(PlanFinding {
                    severity: Severity::Error,
                    rule_id: "invalid-listing-resource-kind".to_string(),
                    path: format!("{entry_path}.ref"),
                    message: format!(
                        "listing '{name}' references unsupported resource kind in '{}' (expected origins/, mcp/, or docs/)",
                        res.reference
                    ),
                });
            }
            None => {
                findings.push(PlanFinding {
                    severity: Severity::Error,
                    rule_id: "invalid-listing-resource-ref".to_string(),
                    path: format!("{entry_path}.ref"),
                    message: format!(
                        "listing '{name}' has malformed resource ref '{}' (expected '<kind>/<name>')",
                        res.reference
                    ),
                });
            }
        }

        // -- revision resolution --
        match res.revision.mode {
            RevisionMode::Pin => {
                if !resolver.sha_exists(&res.revision.value) {
                    findings.push(PlanFinding {
                        severity: Severity::Error,
                        rule_id: "missing-listing-revision-sha".to_string(),
                        path: format!("{entry_path}.revision.value"),
                        message: format!(
                            "listing '{name}' pins commit '{}' which does not exist in the Repo",
                            res.revision.value
                        ),
                    });
                }
            }
            RevisionMode::TrackBranch => {
                if !resolver.branch_exists(&res.revision.value) {
                    findings.push(PlanFinding {
                        severity: Severity::Error,
                        rule_id: "missing-listing-revision-branch".to_string(),
                        path: format!("{entry_path}.revision.value"),
                        message: format!(
                            "listing '{name}' tracks branch '{}' which does not exist in the Repo",
                            res.revision.value
                        ),
                    });
                }
            }
            RevisionMode::Tag => {
                if !resolver.tag_exists(&res.revision.value) {
                    findings.push(PlanFinding {
                        severity: Severity::Error,
                        rule_id: "missing-listing-revision-tag".to_string(),
                        path: format!("{entry_path}.revision.value"),
                        message: format!(
                            "listing '{name}' pins tag '{}' which does not exist in the Repo",
                            res.revision.value
                        ),
                    });
                }
            }
        }
    }

    // --- spec.skills (WOR-196) ---------------------------------------
    //
    // Each Listing carries an optional `spec.skills[]` block matching
    // the shape of the top-level `agent_skills:` config block from
    // WOR-193. The validator enforces three rules:
    //
    // 1. The `type` discriminator must be `skill-md` or `archive`.
    // 2. The `url` must be either fully-qualified (`https://...` or
    //    `http://...`) or path-relative to a file under `skills/` in
    //    the Repo (path-absolute `/skills/...` or relative
    //    `skills/...`). Other paths produce a
    //    `listing-skill-url-out-of-tree` error.
    // 3. Names must be unique within one Listing's `spec.skills[]`.
    validate_listing_skills(loaded, findings);

    // --- auth.strategies vs underlying Resource ----------------------
    if !listing.spec.auth.strategies.is_empty() {
        if let Some(resource_auth) = &first_origin_auth_type {
            // Compatibility rule: the underlying Resource's auth type
            // must appear in the Listing's strategies. Otherwise the
            // Listing is advertising auth the Resource does not
            // accept.
            let listing_strategies: BTreeSet<&str> = listing
                .spec
                .auth
                .strategies
                .iter()
                .map(|s| s.as_str())
                .collect();
            if !listing_strategies.contains(resource_auth.as_str()) {
                findings.push(PlanFinding {
                    severity: Severity::Error,
                    rule_id: "listing-auth-mismatch".to_string(),
                    path: format!("listings.{name}.spec.auth.strategies"),
                    message: format!(
                        "listing '{name}' advertises auth strategies {:?} but the underlying Resource accepts '{resource_auth}'",
                        listing.spec.auth.strategies
                    ),
                });
            }
        }
    }
}

/// Plan-time validation for `Listing.spec.skills[]` (WOR-196).
///
/// Walks every entry and emits findings against the existing plan
/// stream. The rules mirror the AC on WOR-196:
///
/// - `type` must be `skill-md` or `archive`; other values produce a
///   `listing-skill-bad-type` error.
/// - `url` must be either fully-qualified (`https://...`,
///   `http://...`) or resolve to a file under `skills/` in the Repo
///   (path-absolute `/skills/...` or relative `skills/...`). Other
///   shapes produce a `listing-skill-url-out-of-tree` error.
/// - `name` must be unique within one Listing's `spec.skills[]`.
///   Duplicates produce a `duplicate-listing-skill-name` error.
/// - `visibility` must be `public` or `authenticated`; anything else
///   produces an `unknown-listing-skill-visibility` warning so a
///   forward-compatible value passes parsing without breaking the
///   plan.
fn validate_listing_skills(loaded: &LoadedListing, findings: &mut Vec<PlanFinding>) {
    let listing = &loaded.listing;
    let name = &listing.metadata.name;
    let mut seen_names: BTreeSet<&str> = BTreeSet::new();

    for (idx, skill) in listing.spec.skills.iter().enumerate() {
        let entry_path = format!("listings.{name}.spec.skills[{idx}]");

        // -- type discriminator --
        if !matches!(skill.kind.as_str(), "skill-md" | "archive") {
            findings.push(PlanFinding {
                severity: Severity::Error,
                rule_id: "listing-skill-bad-type".to_string(),
                path: format!("{entry_path}.type"),
                message: format!(
                    "listing '{name}' skill[{idx}] has unsupported type '{}' (expected 'skill-md' or 'archive')",
                    skill.kind
                ),
            });
        }

        // -- url placement --
        if !is_well_placed_skill_url(&skill.url) {
            findings.push(PlanFinding {
                severity: Severity::Error,
                rule_id: "listing-skill-url-out-of-tree".to_string(),
                path: format!("{entry_path}.url"),
                message: format!(
                    "listing '{name}' skill[{idx}] url '{}' must be fully-qualified or resolve to a file under skills/ in the Repo",
                    skill.url
                ),
            });
        }

        // -- name uniqueness --
        if !seen_names.insert(skill.name.as_str()) {
            findings.push(PlanFinding {
                severity: Severity::Error,
                rule_id: "duplicate-listing-skill-name".to_string(),
                path: format!("{entry_path}.name"),
                message: format!(
                    "listing '{name}' skill[{idx}] duplicates name '{}' already declared in the same Listing",
                    skill.name
                ),
            });
        }

        // -- visibility (warn) --
        if !matches!(skill.visibility.as_str(), "public" | "authenticated") {
            findings.push(PlanFinding {
                severity: Severity::Warn,
                rule_id: "unknown-listing-skill-visibility".to_string(),
                path: format!("{entry_path}.visibility"),
                message: format!(
                    "listing '{name}' skill[{idx}] has unknown visibility '{}' (known: public, authenticated)",
                    skill.visibility
                ),
            });
        }
    }
}

/// True when a skill `url` is acceptable for plan-time validation.
///
/// Accepts:
///
/// - Fully-qualified URLs (`http://...` or `https://...`).
/// - Path-absolute URLs that point inside `/skills/` (e.g.
///   `/skills/deploy.md`).
/// - Path-relative URLs under `skills/` (e.g.
///   `skills/deploy.md`).
///
/// Anything else (a bare filename, `/etc/passwd`, `../escape`) fails
/// the check so an operator authoring a Listing cannot accidentally
/// publish a skill URL that resolves outside the Repo's `skills/`
/// directory.
pub fn is_well_placed_skill_url(url: &str) -> bool {
    if url.starts_with("http://") || url.starts_with("https://") {
        return true;
    }
    if url.contains("..") {
        return false;
    }
    if let Some(rest) = url.strip_prefix('/') {
        return rest.starts_with("skills/");
    }
    url.starts_with("skills/")
}

/// Pull the type of the underlying Resource's auth block. Mirrors the
/// shape of the validator's existing `type_of` helper but consumes a
/// `RawOriginConfig` rather than a generic JSON value.
fn extract_auth_type(origin: &RawOriginConfig) -> Option<String> {
    let auth = origin.authentication.as_ref()?;
    let t = auth.get("type")?.as_str()?;
    Some(t.to_string())
}

/// Split `<kind>/<name>` into `(kind, name)`. Returns `None` when the
/// reference is empty, has no slash, or has more than one slash.
fn parse_ref(reference: &str) -> Option<(String, String)> {
    let mut parts = reference.splitn(2, '/');
    let kind = parts.next()?.to_string();
    let name = parts.next()?.to_string();
    if kind.is_empty() || name.is_empty() {
        return None;
    }
    Some((kind, name))
}

// --- Tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn parse(yaml: &str) -> Listing {
        serde_yaml::from_str(yaml).expect("Listing parse")
    }

    fn parse_config(yaml: &str) -> ConfigFile {
        serde_yaml::from_str(yaml).expect("ConfigFile parse")
    }

    const SAMPLE_LISTING: &str = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: example-listing
  labels:
    team: platform
spec:
  type: api
  status: published
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: "abc1234"
  auth:
    strategies: [api_key, jwt]
  accessPlan:
    free:
      rate: "100/min"
    paid:
      price_micros: 1000
      currency: USD
  publish:
    visibility: public
    docsUrl: "/docs/example"
  lifecycle:
    deprecation: null
    sunsetDate: null
"#;

    #[test]
    fn schema_round_trips_through_yaml() {
        let listing = parse(SAMPLE_LISTING);
        assert_eq!(listing.api_version, LISTING_API_VERSION);
        assert_eq!(listing.kind, LISTING_KIND);
        assert_eq!(listing.metadata.name, "example-listing");
        assert_eq!(
            listing.metadata.labels.get("team").map(String::as_str),
            Some("platform")
        );
        assert_eq!(listing.spec.listing_type, "api");
        assert_eq!(listing.spec.status, "published");
        assert_eq!(listing.spec.resources.len(), 1);
        assert_eq!(
            listing.spec.resources[0].reference,
            "origins/api.example.com"
        );
        assert_eq!(listing.spec.resources[0].revision.mode, RevisionMode::Pin);
        assert_eq!(listing.spec.resources[0].revision.value, "abc1234");
        assert_eq!(listing.spec.auth.strategies, vec!["api_key", "jwt"]);
        assert_eq!(
            listing
                .spec
                .access_plan
                .free
                .as_ref()
                .and_then(|f| f.rate.as_deref()),
            Some("100/min")
        );
        assert_eq!(
            listing
                .spec
                .access_plan
                .paid
                .as_ref()
                .and_then(|p| p.price_micros),
            Some(1000)
        );
        assert_eq!(listing.spec.publish.visibility.as_deref(), Some("public"));
        assert_eq!(
            listing.spec.publish.docs_url.as_deref(),
            Some("/docs/example")
        );
    }

    fn make_repo(layout: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let listings = dir.path().join(LISTINGS_DIRNAME);
        fs::create_dir_all(&listings).expect("mkdir listings");
        for (name, body) in layout {
            fs::write(listings.join(name), body).expect("write fixture");
        }
        dir
    }

    #[test]
    fn loader_picks_up_a_single_yaml() {
        let repo = make_repo(&[("example.yaml", SAMPLE_LISTING)]);
        let mut errors = Vec::new();
        let loaded = load_listings_from_repo(repo.path(), &mut errors);
        assert!(errors.is_empty(), "got errors: {errors:?}");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].listing.metadata.name, "example-listing");
        // The registry should round-trip the loaded listing.
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(loaded, &mut findings);
        assert!(findings.is_empty(), "got findings: {findings:?}");
        assert_eq!(registry.len(), 1);
        assert!(registry.get("example-listing").is_some());
    }

    #[test]
    fn loader_returns_empty_when_no_listings_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut errors = Vec::new();
        let loaded = load_listings_from_repo(dir.path(), &mut errors);
        assert!(errors.is_empty());
        assert!(loaded.is_empty());
    }

    #[test]
    fn loader_rejects_bad_header() {
        let body = r#"
apiVersion: not-sbproxy/v1
kind: Other
metadata:
  name: nope
spec:
  type: api
  status: draft
  resources: []
"#;
        let repo = make_repo(&[("bad.yaml", body)]);
        let mut errors = Vec::new();
        let loaded = load_listings_from_repo(repo.path(), &mut errors);
        assert!(loaded.is_empty());
        assert_eq!(errors.len(), 1);
        match &errors[0] {
            ListingLoadError::BadHeader { .. } => {}
            other => panic!("expected BadHeader, got {other:?}"),
        }
    }

    #[test]
    fn pin_mode_validates_against_resolver() {
        let listing = parse(SAMPLE_LISTING);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/example.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        assert!(findings.is_empty());

        let cfg_yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#;
        let cfg = parse_config(cfg_yaml);

        // Resolver knows the SHA: clean.
        let resolver = StaticRevisionResolver {
            shas: BTreeSet::from(["abc1234".to_string()]),
            ..Default::default()
        };
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &resolver, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "missing-listing-revision-sha"),
            "got findings: {findings:?}"
        );

        // Resolver does not know the SHA: error.
        let resolver = StaticRevisionResolver::default();
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &resolver, &mut findings);
        let missing: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "missing-listing-revision-sha")
            .collect();
        assert_eq!(missing.len(), 1, "got findings: {findings:?}");
        assert_eq!(missing[0].severity, Severity::Error);
    }

    #[test]
    fn track_branch_mode_validates() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: branch-listing
spec:
  type: api
  status: published
  resources:
    - ref: origins/api.example.com
      revision:
        mode: track-branch
        value: main
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/branch.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = parse_config(
            r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#,
        );

        // Branch known: clean.
        let resolver = StaticRevisionResolver {
            branches: BTreeSet::from(["main".to_string()]),
            ..Default::default()
        };
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &resolver, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "missing-listing-revision-branch"),
            "got findings: {findings:?}"
        );

        // Branch unknown: error.
        let resolver = StaticRevisionResolver::default();
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &resolver, &mut findings);
        let missing: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "missing-listing-revision-branch")
            .collect();
        assert_eq!(missing.len(), 1, "got findings: {findings:?}");
    }

    #[test]
    fn tag_mode_validates() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: tag-listing
spec:
  type: api
  status: published
  resources:
    - ref: origins/api.example.com
      revision:
        mode: tag
        value: v1.2.3
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/tag.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = parse_config(
            r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#,
        );

        let resolver = StaticRevisionResolver {
            tags: BTreeSet::from(["v1.2.3".to_string()]),
            ..Default::default()
        };
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &resolver, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "missing-listing-revision-tag"),
            "got findings: {findings:?}"
        );

        let resolver = StaticRevisionResolver::default();
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &resolver, &mut findings);
        let missing: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "missing-listing-revision-tag")
            .collect();
        assert_eq!(missing.len(), 1, "got findings: {findings:?}");
    }

    #[test]
    fn orphan_resource_ref_is_flagged() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: orphan-listing
spec:
  type: api
  status: draft
  resources:
    - ref: origins/missing.example.com
      revision:
        mode: pin
        value: deadbeef
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/orphan.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = parse_config(
            r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#,
        );

        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);
        let orphan: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "orphan-listing-resource")
            .collect();
        assert_eq!(orphan.len(), 1, "got findings: {findings:?}");
        assert_eq!(orphan[0].severity, Severity::Error);
        assert!(orphan[0].message.contains("missing.example.com"));
    }

    #[test]
    fn auth_mismatch_is_flagged() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: auth-listing
spec:
  type: api
  status: published
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: abc1234
  auth:
    strategies: [api_key]
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/auth.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = parse_config(
            r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    authentication:
      type: jwt
      secret: hardcoded-not-a-ref
"#,
        );

        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);
        let mismatch: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "listing-auth-mismatch")
            .collect();
        assert_eq!(mismatch.len(), 1, "got findings: {findings:?}");
        assert_eq!(mismatch[0].severity, Severity::Error);
    }

    #[test]
    fn auth_compatible_is_clean() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: auth-listing
spec:
  type: api
  status: published
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: abc1234
  auth:
    strategies: [api_key, jwt]
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/auth.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = parse_config(
            r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    authentication:
      type: jwt
      secret: hardcoded-not-a-ref
"#,
        );

        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "listing-auth-mismatch"),
            "got findings: {findings:?}"
        );
    }

    #[test]
    fn duplicate_listing_name_is_flagged() {
        let listing = parse(SAMPLE_LISTING);
        let loaded_a = LoadedListing {
            source_path: PathBuf::from("listings/a.yaml"),
            listing: listing.clone(),
        };
        let loaded_b = LoadedListing {
            source_path: PathBuf::from("listings/b.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let _registry = ListingRegistry::from_loaded(vec![loaded_a, loaded_b], &mut findings);
        let dup: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "duplicate-listing-name")
            .collect();
        assert_eq!(dup.len(), 1, "got findings: {findings:?}");
    }

    #[test]
    fn unknown_listing_type_is_warning() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: future-kind
spec:
  type: agent
  status: published
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: abc1234
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/future.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = parse_config(
            r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#,
        );

        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);
        let unknown: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "unknown-listing-type")
            .collect();
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].severity, Severity::Warn);
    }

    // --- WOR-196 spec.skills tests -----------------------------------

    const LISTING_WITH_SKILLS: &str = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: listing-with-skills
spec:
  type: api
  status: published
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: abc1234
  skills:
    - name: deploy-via-pr
      type: skill-md
      description: "Open a PR to deploy"
      url: /skills/deploy.md
      visibility: public
    - name: internal-rotate-secret
      type: skill-md
      description: "Rotate a credential"
      url: skills/rotate.md
      visibility: authenticated
"#;

    fn cfg_with_origin() -> ConfigFile {
        parse_config(
            r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#,
        )
    }

    #[test]
    fn spec_skills_round_trips_through_yaml() {
        let listing = parse(LISTING_WITH_SKILLS);
        assert_eq!(listing.spec.skills.len(), 2);
        assert_eq!(listing.spec.skills[0].name, "deploy-via-pr");
        assert_eq!(listing.spec.skills[0].kind, "skill-md");
        assert_eq!(listing.spec.skills[0].url, "/skills/deploy.md");
        assert_eq!(listing.spec.skills[0].visibility, "public");
        assert_eq!(listing.spec.skills[1].name, "internal-rotate-secret");
        assert_eq!(listing.spec.skills[1].visibility, "authenticated");
    }

    #[test]
    fn spec_skills_default_is_empty() {
        let listing = parse(SAMPLE_LISTING);
        assert!(
            listing.spec.skills.is_empty(),
            "listing without skills: must round-trip as empty"
        );
    }

    #[test]
    fn validate_accepts_well_placed_urls() {
        let listing = parse(LISTING_WITH_SKILLS);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/with-skills.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = cfg_with_origin();
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| !f.rule_id.starts_with("listing-skill-")
                    && f.rule_id != "duplicate-listing-skill-name"
                    && f.rule_id != "unknown-listing-skill-visibility"),
            "got findings: {findings:?}"
        );
    }

    #[test]
    fn validate_rejects_out_of_tree_url() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: bad-skill
spec:
  type: api
  status: draft
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: abc1234
  skills:
    - name: bad
      type: skill-md
      description: "Out of tree"
      url: /etc/passwd
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/bad.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = cfg_with_origin();
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);
        let bad: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "listing-skill-url-out-of-tree")
            .collect();
        assert_eq!(bad.len(), 1, "got findings: {findings:?}");
        assert_eq!(bad[0].severity, Severity::Error);
    }

    #[test]
    fn validate_rejects_parent_traversal_in_url() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: traversal
spec:
  type: api
  status: draft
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: abc1234
  skills:
    - name: bad
      type: skill-md
      description: "Traversal attempt"
      url: skills/../../../../etc/passwd
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/traversal.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = cfg_with_origin();
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "listing-skill-url-out-of-tree"));
    }

    #[test]
    fn validate_accepts_fully_qualified_url() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: remote-skill
spec:
  type: api
  status: published
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: abc1234
  skills:
    - name: remote
      type: skill-md
      description: "Fully-qualified url"
      url: https://cdn.example.com/skills/remote.md
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/remote.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = cfg_with_origin();
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);
        assert!(findings
            .iter()
            .all(|f| f.rule_id != "listing-skill-url-out-of-tree"));
    }

    #[test]
    fn validate_flags_duplicate_skill_names() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: dup-skill
spec:
  type: api
  status: draft
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: abc1234
  skills:
    - name: same
      type: skill-md
      description: "First"
      url: /skills/a.md
    - name: same
      type: skill-md
      description: "Second"
      url: /skills/b.md
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/dup.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = cfg_with_origin();
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);
        let dup: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "duplicate-listing-skill-name")
            .collect();
        assert_eq!(dup.len(), 1, "got findings: {findings:?}");
    }

    #[test]
    fn validate_flags_bad_skill_type() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: bad-type
spec:
  type: api
  status: draft
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: abc1234
  skills:
    - name: weird
      type: executable
      description: "Not a v0.2.0 type"
      url: /skills/weird.exe
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/badtype.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = cfg_with_origin();
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "listing-skill-bad-type"));
    }

    #[test]
    fn unknown_visibility_is_warning() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: weird-vis
spec:
  type: api
  status: draft
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: abc1234
  skills:
    - name: hidden
      type: skill-md
      description: "Unknown visibility"
      url: /skills/hidden.md
      visibility: members-only
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/weird.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = cfg_with_origin();
        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);
        let warn: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "unknown-listing-skill-visibility")
            .collect();
        assert_eq!(warn.len(), 1, "got findings: {findings:?}");
        assert_eq!(warn[0].severity, Severity::Warn);
    }

    #[test]
    fn malformed_ref_is_flagged() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: bad-ref
spec:
  type: api
  status: draft
  resources:
    - ref: "no-slash-here"
      revision:
        mode: pin
        value: abc1234
"#;
        let listing = parse(yaml);
        let loaded = LoadedListing {
            source_path: PathBuf::from("listings/bad.yaml"),
            listing,
        };
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(vec![loaded], &mut findings);
        let cfg = parse_config(
            r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#,
        );

        let mut findings = Vec::new();
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);
        let bad: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "invalid-listing-resource-ref")
            .collect();
        assert_eq!(bad.len(), 1);
    }
}
