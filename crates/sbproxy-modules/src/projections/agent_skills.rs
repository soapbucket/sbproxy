//! Agent Skills v0.2.0 well-known projection.
//!
//! The Agent Skills v0.2.0 specification describes a well-known
//! discovery endpoint at `GET /.well-known/agent-skills/index.json`
//! that an agent fetches to discover the skills an origin advertises.
//! The manifest schema lives at
//! `https://schemas.agentskills.io/discovery/0.2.0/schema.json` and
//! the originating RFC is at
//! `https://github.com/cloudflare/agent-skills-discovery-rfc`.
//!
//! ## Manifest shape
//!
//! ```json
//! {
//!   "$schema": "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
//!   "entries": [
//!     {
//!       "name": "deploy-via-pr",
//!       "type": "skill-md",
//!       "description": "Open a PR to deploy a config change",
//!       "url": "/skills/deploy-via-pr.md",
//!       "digest": "sha256:..."
//!     }
//!   ]
//! }
//! ```
//!
//! Per the spec each entry carries:
//!
//! - `name` - stable identifier.
//! - `type` - closed enum `{skill-md, archive}`.
//! - `description` - human-readable capability summary.
//! - `url` - relative, path-absolute, or fully-qualified. The proxy
//!   resolves relative refs against the request authority per
//!   RFC 3986 at serve time so the manifest's URLs stay portable.
//! - `digest` - SHA-256 of the artifact body, recomputed at
//!   config-load time and again on every artifact GET.
//!
//! ## Integrity contract
//!
//! Every artifact `GET` re-hashes the served body and compares to the
//! manifest digest. A mismatch returns HTTP 503 to the client and emits
//! the `agent_skill.digest_mismatch` audit event so the operator
//! notices a hot-swap or memory corruption. The runtime hash check is
//! the contract that lets cooperative agents trust the digest.
//!
//! ## No script execution
//!
//! Per the v0.2.0 spec the proxy MUST NOT execute pre-/post-hooks or
//! any embedded scripts shipped inside an artifact. The proxy serves
//! every artifact as opaque bytes; nothing in this module ever
//! interprets the artifact contents beyond hashing them. Archives are
//! validated for size and traversal safety at config-load time but are
//! never extracted to disk during a request, and the request handler
//! never invokes a subprocess on the artifact body.
//!
//! ## Archive safety
//!
//! `archive` entries point at a `.tar.gz` or `.zip` bundle. The
//! [`validate_archive_bytes`] helper inspects the bundle once at
//! config-load and refuses to accept an archive that:
//!
//! - traverses outside the archive root via `..` or absolute paths,
//! - contains a symlink whose target escapes the archive root,
//! - exceeds the configured decompression ratio (default 100:1),
//! - exceeds the configured entry count (default 1000), or
//! - exceeds the configured expanded byte budget (default 10 MiB).
//!
//! The caps are configurable per entry via the
//! `max_decompression_ratio`, `max_entries`, and `max_expanded_bytes`
//! fields on `AgentSkillEntry`. Operators tune them when they have a
//! legitimately large skill bundle.

use std::collections::HashMap;
use std::path::Path;

use bytes::Bytes;
use compact_str::CompactString;
use sbproxy_config::{AgentSkillEntry, CompiledConfig, ListingRegistry, LoadedListing};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Default decompression-ratio cap (compressed:expanded). Refuses
/// archives whose expanded size is more than 100x the compressed size.
pub const DEFAULT_MAX_DECOMPRESSION_RATIO: u32 = 100;

/// Default per-archive entry count cap.
pub const DEFAULT_MAX_ENTRIES: u32 = 1000;

/// Default per-archive expanded byte budget (10 MiB).
pub const DEFAULT_MAX_EXPANDED_BYTES: u64 = 10 * 1024 * 1024;

/// Default clock-skew tolerance in seconds for any time-sensitive
/// header attached to an artifact response. The v0.2.0 ship attaches
/// no such header today; the field exists so a follow-up that signs
/// each artifact body can wire its own freshness check.
pub const DEFAULT_MAX_CLOCK_SKEW_SECS: u32 = 60;

/// One entry in the served manifest.
///
/// Mirrors the v0.2.0 schema field-for-field. Serialised to JSON as
/// the manifest body.
#[derive(Debug, Clone, Serialize)]
pub struct ManifestEntry {
    /// Stable identifier (matches the YAML `name`).
    pub name: String,
    /// Discriminator: `skill-md` or `archive`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Human-readable description.
    pub description: String,
    /// URL the agent fetches to retrieve the artifact. Path-absolute
    /// or fully-qualified; the data-plane handler resolves relative
    /// refs against the request authority before re-emitting.
    pub url: String,
    /// SHA-256 digest as `sha256:<lowercase-hex>` per the v0.2.0 spec.
    pub digest: String,
    /// Visibility gate, inherited from the YAML config. Filtered at
    /// serve time so the manifest body shipped to anonymous callers
    /// never contains authenticated-only entries.
    #[serde(skip)]
    pub visibility: SkillVisibility,
}

/// Visibility gate for one skill entry.
///
/// The serve-time filter walks the manifest, skipping
/// `Authenticated` entries when the caller is anonymous. Public
/// entries always ship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SkillVisibility {
    /// Visible to every caller (default).
    #[default]
    Public,
    /// Visible only to authenticated callers; filtered out for
    /// anonymous requests.
    Authenticated,
}

impl SkillVisibility {
    fn parse(s: &str) -> Self {
        match s {
            "authenticated" => Self::Authenticated,
            _ => Self::Public,
        }
    }
}

/// Per-origin Agent Skills index, materialised once per config reload.
///
/// Carries the manifest entries (one per configured skill), the
/// artifact bodies cached for fast serving, and the per-entry digest
/// the runtime hash check compares against on every artifact GET.
#[derive(Debug, Default, Clone)]
pub struct AgentSkillsIndex {
    /// Manifest entries in author order.
    pub entries: Vec<ManifestEntry>,
    /// Artifact bodies keyed by manifest URL path (path-absolute
    /// form). Fully-qualified URLs are absent; the proxy does not
    /// re-host external artifacts.
    pub artifacts: HashMap<CompactString, Bytes>,
    /// Per-entry digest hex (lowercase, no `sha256:` prefix). The
    /// data-plane handler re-hashes the served body and compares
    /// against this map per request.
    pub digests: HashMap<CompactString, String>,
}

/// Build the per-origin Agent Skills index from a list of YAML
/// entries.
///
/// Resolves every artifact body once at config-load time:
///
/// - `body:` literal entries are hashed in-place.
/// - `path:` entries read the file from the local filesystem.
/// - Path-absolute `url:` entries fall back to a workspace-relative
///   path under `skills/` so the example bundle convention works
///   without requiring an explicit `path:`.
/// - Fully-qualified `url:` entries are fetched once via the shared
///   blocking HTTP client; the body is hashed and the artifact is not
///   cached locally (the proxy emits the entry but does not re-host).
///
/// Errors are logged and the offending entry is skipped so a single
/// broken skill cannot break the rest of the manifest.
pub fn build_index(entries: &[AgentSkillEntry], workspace_root: &Path) -> AgentSkillsIndex {
    let mut index = AgentSkillsIndex::default();

    for entry in entries {
        let visibility = SkillVisibility::parse(&entry.visibility);

        // Resolve the artifact bytes. None means we could not load
        // the body and the entry is skipped.
        let body_opt = resolve_artifact_bytes(entry, workspace_root);
        let Some(body) = body_opt else {
            tracing::warn!(
                skill = %entry.name,
                kind = %entry.kind,
                url = %entry.url,
                "agent_skills: failed to resolve artifact body; skipping entry"
            );
            continue;
        };

        // Validate archives at config-load time so a zip bomb cannot
        // pass through to the data plane. `skill-md` entries
        // are served verbatim.
        if entry.kind == "archive" {
            let max_ratio = entry
                .max_decompression_ratio
                .unwrap_or(DEFAULT_MAX_DECOMPRESSION_RATIO);
            let max_entries = entry.max_entries.unwrap_or(DEFAULT_MAX_ENTRIES);
            let max_bytes = entry
                .max_expanded_bytes
                .unwrap_or(DEFAULT_MAX_EXPANDED_BYTES);
            if let Err(e) =
                validate_archive_bytes(&entry.url, &body, max_ratio, max_entries, max_bytes)
            {
                tracing::warn!(
                    skill = %entry.name,
                    error = %e,
                    "agent_skills: archive failed safety check; skipping entry"
                );
                continue;
            }
        }

        let digest_hex = sha256_hex(&body);
        let digest_field = format!("sha256:{digest_hex}");

        // Path-only URLs (relative or absolute) are re-hosted by the
        // proxy. Fully-qualified URLs (https://...) emit verbatim.
        let url_field = entry.url.clone();

        // Cache the artifact body keyed by canonical path so the
        // data-plane handler can serve it. Fully-qualified URLs do
        // not contribute to `artifacts`.
        if let Some(path_key) = canonical_path_key(&entry.url) {
            index
                .artifacts
                .insert(CompactString::new(&path_key), body.clone());
            index
                .digests
                .insert(CompactString::new(&path_key), digest_hex.clone());
        }

        index.entries.push(ManifestEntry {
            name: entry.name.clone(),
            kind: entry.kind.clone(),
            description: entry.description.clone(),
            url: url_field,
            digest: digest_field,
            visibility,
        });
    }

    index
}

/// Resolve the artifact bytes for one config entry.
///
/// Tries `path:` first, then `body:` literal, then a workspace-relative
/// fallback derived from the URL when the URL is path-absolute. Returns
/// `None` when the bytes could not be loaded; the caller logs and
/// skips the entry.
fn resolve_artifact_bytes(entry: &AgentSkillEntry, workspace_root: &Path) -> Option<Bytes> {
    if let Some(path_str) = entry.path.as_deref() {
        let path = if Path::new(path_str).is_absolute() {
            std::path::PathBuf::from(path_str)
        } else {
            workspace_root.join(path_str)
        };
        return std::fs::read(&path).ok().map(Bytes::from);
    }

    if let Some(body) = entry.body.as_deref() {
        return Some(Bytes::from(body.as_bytes().to_vec()));
    }

    // Path-absolute or relative URL with no explicit path/body: try
    // resolving it relative to the workspace root by stripping any
    // leading slash. This makes the common convention of dropping
    // skill files under `examples/<NN>-agent-skills/skills/foo.md`
    // work without an explicit `path:`.
    if !entry.url.starts_with("http://") && !entry.url.starts_with("https://") {
        let trimmed = entry.url.trim_start_matches('/');
        let candidate = workspace_root.join(trimmed);
        if let Ok(body) = std::fs::read(&candidate) {
            return Some(Bytes::from(body));
        }
    }

    // Fully-qualified URL with no explicit path/body: fetch once via
    // the shared blocking client. The proxy emits the entry but does
    // not re-host the artifact, so a network failure here just hashes
    // an empty body, which the caller treats as a load failure.
    if entry.url.starts_with("http://") || entry.url.starts_with("https://") {
        if let Ok(client) = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            if let Ok(resp) = client.get(&entry.url).send() {
                if let Ok(bytes) = resp.bytes() {
                    return Some(Bytes::from(bytes.to_vec()));
                }
            }
        }
    }

    None
}

/// Map a manifest URL onto the path key used by the artifact cache.
///
/// Returns `Some(path)` for path-only URLs (relative or path-absolute);
/// the path is normalised to start with `/` so the data-plane handler's
/// `req_path` (which always starts with `/`) hits the cache.
/// Returns `None` for fully-qualified URLs (the proxy does not
/// re-host external artifacts).
fn canonical_path_key(url: &str) -> Option<String> {
    if url.starts_with("http://") || url.starts_with("https://") {
        return None;
    }
    if url.starts_with('/') {
        Some(url.to_string())
    } else {
        Some(format!("/{url}"))
    }
}

/// Render the manifest body for one origin.
///
/// `authenticated` filters the entry list (anonymous callers see the
/// public-only manifest, authenticated callers see everything). The
/// returned body is the JSON document the data-plane handler ships at
/// `/.well-known/agent-skills/index.json` with `Content-Type:
/// application/json`.
///
/// `request_authority` is the request `Host` header (no scheme), used
/// to resolve relative URLs per RFC 3986. Path-absolute and fully-
/// qualified URLs pass through unchanged; relative refs (e.g.
/// `skills/foo.md`) are resolved against the request authority.
pub fn render_manifest(
    index: &AgentSkillsIndex,
    authenticated: bool,
    request_authority: Option<&str>,
    request_scheme: &str,
) -> String {
    let entries: Vec<serde_json::Value> = index
        .entries
        .iter()
        .filter(|e| match e.visibility {
            SkillVisibility::Public => true,
            SkillVisibility::Authenticated => authenticated,
        })
        .map(|e| {
            let resolved_url = resolve_url(&e.url, request_authority, request_scheme);
            serde_json::json!({
                "name": e.name,
                "type": e.kind,
                "description": e.description,
                "url": resolved_url,
                "digest": e.digest,
            })
        })
        .collect();

    let manifest = serde_json::json!({
        "$schema": "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
        "entries": entries,
    });

    serde_json::to_string_pretty(&manifest).unwrap_or_else(|_| String::from("{\"entries\":[]}"))
}

/// Resolve a manifest URL against the request authority per RFC 3986.
///
/// - Fully-qualified URLs (`https://...`) pass through unchanged.
/// - Path-absolute URLs (`/skills/foo.md`) keep their path but are
///   prefixed with `<scheme>://<authority>` when an authority is
///   provided.
/// - Relative URLs (`skills/foo.md`) become path-absolute under the
///   `/.well-known/agent-skills/` base and then resolve against the
///   authority.
///
/// When `request_authority` is `None` the URL is returned as-is so
/// the manifest still validates against the v0.2.0 schema (the spec
/// permits relative refs at rest).
fn resolve_url(url: &str, authority: Option<&str>, scheme: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        return url.to_string();
    }
    let Some(auth) = authority else {
        return url.to_string();
    };
    if url.starts_with('/') {
        return format!("{scheme}://{auth}{url}");
    }
    // Relative reference: resolve against the well-known base. The
    // base is the directory of the manifest, so `skills/foo.md`
    // becomes `/.well-known/agent-skills/skills/foo.md`. This matches
    // RFC 3986 Section 5.3 with `Reference Resolution` against the
    // manifest URL.
    format!("{scheme}://{auth}/.well-known/agent-skills/{url}")
}

/// Compute SHA-256 of a body, returning the lowercase hex string.
///
/// Used at config-load time to pin the manifest digest, and at request
/// time to verify the body the proxy is about to ship still matches
/// what the manifest advertises.
pub fn sha256_hex(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

/// Audit-event payload for a runtime digest mismatch.
///
/// Emitted on every `GET` of an artifact whose served body fails the
/// re-hash check. The proxy returns HTTP 503 to the caller with a
/// generic "service unavailable" body; the structured fields here
/// land on the operator's audit sink so the divergence is visible.
#[derive(Debug, Clone)]
pub struct DigestMismatchEvent {
    /// Skill name (matches `agent_skills[].name`).
    pub skill_name: String,
    /// Origin hostname the artifact belongs to.
    pub hostname: String,
    /// Hex-encoded digest the manifest claims for this artifact.
    pub expected_digest: String,
    /// Hex-encoded digest the proxy actually computed at serve time.
    pub observed_digest: String,
    /// Caller identity, when known. `None` for anonymous callers.
    pub caller: Option<String>,
    /// Per-request id for cross-correlation with access-log lines.
    pub request_id: Option<String>,
}

// --- Cache wiring ---

/// Walk every origin in `config` and build the per-hostname Agent
/// Skills index map.
///
/// Origins without `agent_skills` produce no entries (the data-plane
/// handler 404s the well-known URL for those hostnames). The
/// returned map is consumed by [`crate::projections::ProjectionDocs`]
/// so the existing atomic swap cache covers Agent Skills too.
pub fn render_indices(
    config: &CompiledConfig,
    workspace_root: &Path,
) -> HashMap<CompactString, AgentSkillsIndex> {
    let mut out = HashMap::new();
    for origin in &config.origins {
        if origin.agent_skills.is_empty() {
            continue;
        }
        let idx = build_index(&origin.agent_skills, workspace_root);
        if idx.entries.is_empty() && idx.artifacts.is_empty() {
            // Every entry failed to load; skip so the well-known URL
            // 404s with no manifest rather than serving an empty one.
            continue;
        }
        out.insert(origin.hostname.clone(), idx);
    }
    out
}

// --- Listing-scoped indices ---

/// One Listing's resolved Agent Skills index, keyed for serving at
/// `/.well-known/agent-skills/<listing-name>/index.json`.
///
/// The struct carries:
///
/// - The Listing name (matches the URL path segment after
///   `/.well-known/agent-skills/`).
/// - The set of origin hostnames the Listing publishes; the data-plane
///   handler matches the request `Host` against this set so a Listing
///   only serves on hostnames it explicitly opts into.
/// - The fully-resolved [`AgentSkillsIndex`] (per-entry manifest rows,
///   hash-pinned artifact bytes, digest map).
#[derive(Debug, Clone)]
pub struct ListingScopedIndex {
    /// Listing name (matches `Listing.metadata.name`).
    pub listing_name: String,
    /// Hostnames the Listing publishes. Sourced from the Listing's
    /// `spec.resources[].ref` entries of kind `origins/<hostname>`.
    pub hostnames: Vec<CompactString>,
    /// The resolved index, hashed at config-load time. Re-used at
    /// serve time exactly like the per-origin index from
    /// [`render_indices`].
    pub index: AgentSkillsIndex,
}

/// Build a per-Listing Agent Skills index from a registry.
///
/// Walks every Listing whose `spec.skills[]` is non-empty, resolves
/// each entry's artifact body against the workspace root (the same
/// CWD resolution the per-origin path uses), and returns the index
/// keyed by Listing name. Listings whose entries all fail to load are
/// skipped so the well-known URL 404s instead of serving an empty
/// manifest.
///
/// Per WOR-196 the resolved hostnames come from the Listing's
/// `spec.resources[].ref` entries (kinds `origins/<hostname>`); other
/// resource kinds are recorded but do not contribute hostnames for
/// the OSS surface today.
pub fn render_listing_indices(
    registry: &ListingRegistry,
    workspace_root: &Path,
) -> HashMap<String, ListingScopedIndex> {
    let mut out = HashMap::new();
    for loaded in registry.iter() {
        if loaded.listing.spec.skills.is_empty() {
            continue;
        }
        let idx = build_index(&loaded.listing.spec.skills, workspace_root);
        if idx.entries.is_empty() && idx.artifacts.is_empty() {
            continue;
        }
        let hostnames = listing_origin_hostnames(loaded);
        out.insert(
            loaded.listing.metadata.name.clone(),
            ListingScopedIndex {
                listing_name: loaded.listing.metadata.name.clone(),
                hostnames,
                index: idx,
            },
        );
    }
    out
}

/// Extract the origin hostnames a Listing publishes from its
/// `spec.resources[].ref` entries. Returns the set of hostnames for
/// every `origins/<hostname>` reference. Other kinds (`mcp/`,
/// `docs/`) are skipped: the OSS data plane only serves Agent Skills
/// on origin hostnames today.
fn listing_origin_hostnames(loaded: &LoadedListing) -> Vec<CompactString> {
    let mut out: Vec<CompactString> = Vec::new();
    for res in &loaded.listing.spec.resources {
        let Some((kind, target)) = split_ref(&res.reference) else {
            continue;
        };
        if kind == "origins" && !out.iter().any(|h| h.as_str() == target) {
            out.push(CompactString::new(target));
        }
    }
    out
}

fn split_ref(reference: &str) -> Option<(&str, &str)> {
    let (kind, name) = reference.split_once('/')?;
    if kind.is_empty() || name.is_empty() {
        return None;
    }
    Some((kind, name))
}

/// Merge a per-origin [`AgentSkillsIndex`] with every visible
/// per-Listing index whose `hostnames` include the request hostname.
///
/// Used by the data plane to serve the aggregated
/// `/.well-known/agent-skills/index.json` endpoint on a Catalog
/// domain. The merge is name-deduplicated: when two indices contribute
/// an entry with the same `name`, the first occurrence wins (the
/// per-origin entries are walked first, then Listings in stable
/// lexicographic order).
///
/// Visibility is preserved on every merged entry; the higher-level
/// [`render_manifest`] still filters anonymous callers down to
/// `Public` entries.
pub fn aggregate_for_hostname(
    per_origin: Option<&AgentSkillsIndex>,
    listings: &HashMap<String, ListingScopedIndex>,
    hostname: &str,
) -> AgentSkillsIndex {
    let mut merged = AgentSkillsIndex::default();
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    // First pass: per-origin entries (the WOR-193 surface).
    if let Some(idx) = per_origin {
        for e in &idx.entries {
            if seen_names.insert(e.name.clone()) {
                merged.entries.push(e.clone());
            }
        }
        for (k, v) in &idx.artifacts {
            merged
                .artifacts
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &idx.digests {
            merged.digests.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    // Second pass: per-Listing entries whose hostnames include the
    // request hostname. Listings are walked in stable lexicographic
    // order so the union is deterministic across reloads.
    let mut listing_names: Vec<&String> = listings.keys().collect();
    listing_names.sort();
    for name in listing_names {
        let Some(scoped) = listings.get(name) else {
            continue;
        };
        if !scoped.hostnames.iter().any(|h| h.as_str() == hostname) {
            continue;
        }
        for e in &scoped.index.entries {
            if seen_names.insert(e.name.clone()) {
                merged.entries.push(e.clone());
            }
        }
        for (k, v) in &scoped.index.artifacts {
            merged
                .artifacts
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &scoped.index.digests {
            merged.digests.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    merged
}

// --- Archive validation ---

/// Validate an archive body at config-load time.
///
/// Refuses to accept the archive when any safety cap is breached.
/// Detects the format from a simple sniff:
///
/// - `.zip` archives start with `PK\x03\x04`.
/// - `.tar.gz` archives start with the gzip magic `\x1f\x8b`.
///
/// Anything else is treated as raw bytes and rejected (the v0.2.0
/// spec only allows tar.gz and zip).
pub fn validate_archive_bytes(
    url_hint: &str,
    body: &[u8],
    max_ratio: u32,
    max_entries: u32,
    max_expanded_bytes: u64,
) -> Result<(), String> {
    if body.len() >= 4 && &body[..4] == b"PK\x03\x04" {
        validate_zip_bytes(body, max_ratio, max_entries, max_expanded_bytes)
    } else if body.len() >= 2 && &body[..2] == b"\x1f\x8b" {
        validate_tar_gz_bytes(body, max_ratio, max_entries, max_expanded_bytes)
    } else {
        Err(format!(
            "agent_skills archive at {url_hint} is neither tar.gz nor zip"
        ))
    }
}

fn validate_tar_gz_bytes(
    body: &[u8],
    max_ratio: u32,
    max_entries: u32,
    max_expanded_bytes: u64,
) -> Result<(), String> {
    // First, decompress with a hard cap on the expanded size so a
    // gzip bomb cannot exhaust memory before we inspect tar headers.
    let decompressed = decompress_gzip_capped(body, max_expanded_bytes)?;
    enforce_ratio(body.len(), decompressed.len(), max_ratio)?;
    let mut archive = tar::Archive::new(std::io::Cursor::new(&decompressed));
    let entries = archive
        .entries()
        .map_err(|e| format!("tar.gz read error: {e}"))?;
    let mut count: u32 = 0;
    let mut expanded: u64 = 0;
    for entry_res in entries {
        let entry = entry_res.map_err(|e| format!("tar entry read error: {e}"))?;
        count += 1;
        if count > max_entries {
            return Err(format!(
                "tar.gz archive exceeds max_entries cap ({max_entries})"
            ));
        }
        let header = entry.header();
        let path = entry
            .path()
            .map_err(|e| format!("tar entry path error: {e}"))?;
        check_safe_path(path.as_ref())?;
        // Symlinks: refuse if the target escapes the archive root.
        if matches!(
            header.entry_type(),
            tar::EntryType::Symlink | tar::EntryType::Link
        ) {
            if let Some(link) = entry.link_name().ok().flatten() {
                check_safe_path(link.as_ref())?;
            }
        }
        let size = header.size().unwrap_or(0);
        expanded = expanded.saturating_add(size);
        if expanded > max_expanded_bytes {
            return Err(format!(
                "tar.gz archive exceeds max_expanded_bytes cap ({max_expanded_bytes})"
            ));
        }
    }
    Ok(())
}

fn validate_zip_bytes(
    body: &[u8],
    max_ratio: u32,
    max_entries: u32,
    max_expanded_bytes: u64,
) -> Result<(), String> {
    let reader = std::io::Cursor::new(body);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| format!("zip read error: {e}"))?;
    let count = archive.len() as u32;
    if count > max_entries {
        return Err(format!(
            "zip archive exceeds max_entries cap ({max_entries})"
        ));
    }
    let mut total_expanded: u64 = 0;
    for i in 0..archive.len() {
        let file = archive
            .by_index(i)
            .map_err(|e| format!("zip entry read error: {e}"))?;
        // Path traversal: refuse `..` or absolute paths.
        let raw_name = file.name();
        check_safe_path(Path::new(raw_name))?;
        // Zip symlinks are encoded via the external Unix mode bits
        // (`0o120000`) carried in the central directory. The safe-
        // archive contract here is "no symlinks at all": the v0.2.0
        // spec leaves symlinks ambiguous and the simplest defence is
        // to refuse them outright.
        if let Some(mode) = file.unix_mode() {
            const S_IFMT: u32 = 0o170000;
            const S_IFLNK: u32 = 0o120000;
            if mode & S_IFMT == S_IFLNK {
                return Err(format!(
                    "zip archive contains symlink entry {raw_name:?}; refusing"
                ));
            }
        }
        total_expanded = total_expanded.saturating_add(file.size());
        if total_expanded > max_expanded_bytes {
            return Err(format!(
                "zip archive exceeds max_expanded_bytes cap ({max_expanded_bytes})"
            ));
        }
    }
    enforce_ratio(body.len(), total_expanded as usize, max_ratio)?;
    Ok(())
}

fn check_safe_path(path: &Path) -> Result<(), String> {
    if path.is_absolute() {
        return Err(format!(
            "archive entry path {:?} is absolute; refusing",
            path.display()
        ));
    }
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(format!(
                    "archive entry path {:?} contains '..'; refusing",
                    path.display()
                ));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(format!(
                    "archive entry path {:?} escapes archive root; refusing",
                    path.display()
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn enforce_ratio(compressed: usize, expanded: usize, max_ratio: u32) -> Result<(), String> {
    if compressed == 0 {
        return Ok(());
    }
    let ratio = expanded.saturating_div(compressed);
    if ratio as u32 > max_ratio {
        return Err(format!(
            "decompression ratio {ratio}:1 exceeds max_decompression_ratio {max_ratio}"
        ));
    }
    Ok(())
}

fn decompress_gzip_capped(body: &[u8], max_bytes: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(body);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| format!("gzip decode error: {e}"))?;
        if n == 0 {
            break;
        }
        if (out.len() + n) as u64 > max_bytes {
            return Err(format!(
                "gzip body exceeds max_expanded_bytes cap ({max_bytes})"
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_entry(name: &str, kind: &str, url: &str, body: &str) -> AgentSkillEntry {
        AgentSkillEntry {
            name: name.to_string(),
            kind: kind.to_string(),
            description: "test skill".to_string(),
            url: url.to_string(),
            visibility: "public".to_string(),
            path: None,
            body: Some(body.to_string()),
            max_decompression_ratio: None,
            max_entries: None,
            max_expanded_bytes: None,
            max_clock_skew_secs: None,
        }
    }

    #[test]
    fn build_index_hashes_inline_body() {
        let entry = make_entry("hello", "skill-md", "/skills/hello.md", "# Hello\n");
        let idx = build_index(std::slice::from_ref(&entry), Path::new("."));
        assert_eq!(idx.entries.len(), 1);
        assert!(idx.entries[0].digest.starts_with("sha256:"));
        assert!(idx
            .artifacts
            .contains_key(&CompactString::new("/skills/hello.md")));
        assert_eq!(
            idx.digests
                .get(&CompactString::new("/skills/hello.md"))
                .unwrap(),
            &sha256_hex(b"# Hello\n")
        );
    }

    #[test]
    fn render_manifest_emits_valid_v0_2_0_envelope() {
        let entry = make_entry("hello", "skill-md", "/skills/hello.md", "# Hello\n");
        let idx = build_index(std::slice::from_ref(&entry), Path::new("."));
        let body = render_manifest(&idx, false, Some("api.example.com"), "https");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            value["$schema"],
            "https://schemas.agentskills.io/discovery/0.2.0/schema.json"
        );
        assert_eq!(value["entries"][0]["name"], "hello");
        assert_eq!(value["entries"][0]["type"], "skill-md");
        assert_eq!(
            value["entries"][0]["url"],
            "https://api.example.com/skills/hello.md"
        );
        assert!(value["entries"][0]["digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
    }

    #[test]
    fn render_manifest_filters_authenticated_for_anonymous() {
        let mut e1 = make_entry("public", "skill-md", "/skills/public.md", "x");
        e1.visibility = "public".to_string();
        let mut e2 = make_entry("private", "skill-md", "/skills/private.md", "y");
        e2.visibility = "authenticated".to_string();
        let idx = build_index(&[e1, e2], Path::new("."));
        let anon = render_manifest(&idx, false, Some("h.example.com"), "https");
        let v: serde_json::Value = serde_json::from_str(&anon).unwrap();
        assert_eq!(v["entries"].as_array().unwrap().len(), 1);
        assert_eq!(v["entries"][0]["name"], "public");

        let auth = render_manifest(&idx, true, Some("h.example.com"), "https");
        let v2: serde_json::Value = serde_json::from_str(&auth).unwrap();
        assert_eq!(v2["entries"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn fully_qualified_url_passes_through_unchanged() {
        let mut e = make_entry(
            "external",
            "skill-md",
            "https://cdn.example.com/skills/foo.md",
            "ignored",
        );
        // Mark body None and path None so resolve_artifact_bytes
        // attempts the network fetch; for the test we want to confirm
        // that even with a body the url is not rewritten.
        e.body = Some("local".to_string());
        let idx = build_index(std::slice::from_ref(&e), Path::new("."));
        // With a fully-qualified URL the artifact is not re-hosted.
        assert!(idx.artifacts.is_empty());
        let body = render_manifest(&idx, false, Some("h.example.com"), "https");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["entries"][0]["url"],
            "https://cdn.example.com/skills/foo.md"
        );
    }

    #[test]
    fn relative_url_resolves_against_authority() {
        let resolved = resolve_url("skills/foo.md", Some("h.example.com"), "https");
        assert_eq!(
            resolved,
            "https://h.example.com/.well-known/agent-skills/skills/foo.md"
        );
    }

    #[test]
    fn path_absolute_url_resolves_against_authority() {
        let resolved = resolve_url("/skills/foo.md", Some("h.example.com"), "https");
        assert_eq!(resolved, "https://h.example.com/skills/foo.md");
    }

    #[test]
    fn fully_qualified_url_pass_through_in_resolve() {
        let resolved = resolve_url(
            "https://cdn.example.com/x.md",
            Some("h.example.com"),
            "https",
        );
        assert_eq!(resolved, "https://cdn.example.com/x.md");
    }

    #[test]
    fn check_safe_path_rejects_traversal() {
        assert!(check_safe_path(Path::new("../etc/passwd")).is_err());
        assert!(check_safe_path(Path::new("a/../b")).is_err());
        assert!(check_safe_path(Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn check_safe_path_accepts_normal_paths() {
        assert!(check_safe_path(Path::new("foo/bar.md")).is_ok());
        assert!(check_safe_path(Path::new("dir/sub/file.txt")).is_ok());
    }

    #[test]
    fn enforce_ratio_rejects_zip_bomb() {
        // 100 KiB compressed, 100 MiB expanded => 1024:1 ratio.
        assert!(enforce_ratio(100 * 1024, 100 * 1024 * 1024, 100).is_err());
        // Within the cap (50:1).
        assert!(enforce_ratio(1000, 50_000, 100).is_ok());
    }

    fn build_test_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for (name, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(name).unwrap();
                header.set_size(data.len() as u64);
                header.set_cksum();
                builder.append(&header, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut gz = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        encoder.write_all(&tar_buf).unwrap();
        encoder.finish().unwrap();
        gz
    }

    fn build_test_tar_gz_with_symlink(target: &str) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_path("link").unwrap();
            header.set_link_name(target).unwrap();
            header.set_size(0);
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }
        let mut gz = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        encoder.write_all(&tar_buf).unwrap();
        encoder.finish().unwrap();
        gz
    }

    #[test]
    fn validate_tar_gz_accepts_safe_archive() {
        let gz = build_test_tar_gz(&[("foo.md", b"hello"), ("bar.md", b"world")]);
        let r = validate_archive_bytes("test.tar.gz", &gz, 100, 1000, 10 * 1024 * 1024);
        assert!(r.is_ok(), "expected ok, got {:?}", r);
    }

    /// Build a tar.gz body whose only entry has the literal name
    /// `../etc/passwd`. The `tar` crate's high-level `set_path` API
    /// refuses to write parent traversal segments, so the test bypasses
    /// it by writing the header bytes directly. A real attacker writing
    /// archive bytes by hand is exactly the threat the validator must
    /// catch, so this is the right shape for the regression test.
    fn build_traversal_tar_gz() -> Vec<u8> {
        let mut header = [0u8; 512];
        let name = b"../etc/passwd";
        header[..name.len()].copy_from_slice(name);
        // Mode 0644.
        header[100..107].copy_from_slice(b"0000644");
        // UID/GID 0.
        header[108..115].copy_from_slice(b"0000000");
        header[116..123].copy_from_slice(b"0000000");
        // Size 1.
        header[124..135].copy_from_slice(b"00000000001");
        // Mtime 0.
        header[136..147].copy_from_slice(b"00000000000");
        // Type flag '0' (regular file).
        header[156] = b'0';
        // ustar magic + version.
        header[257..263].copy_from_slice(b"ustar ");
        header[263..265].copy_from_slice(b" \0");
        // Compute checksum: sum of all bytes treating chksum field as
        // spaces, padded into bytes 148..156 as octal.
        for b in &mut header[148..156] {
            *b = b' ';
        }
        let sum: u32 = header.iter().map(|&b| b as u32).sum();
        let cksum_str = format!("{:06o}\0 ", sum);
        header[148..148 + cksum_str.len()].copy_from_slice(cksum_str.as_bytes());
        let mut tar_buf = Vec::new();
        tar_buf.extend_from_slice(&header);
        // Body: 1 byte 'x' padded to 512.
        let mut body = vec![0u8; 512];
        body[0] = b'x';
        tar_buf.extend_from_slice(&body);
        // Two empty 512-byte blocks mark the end of archive.
        tar_buf.extend_from_slice(&[0u8; 1024]);
        let mut gz = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        encoder.write_all(&tar_buf).unwrap();
        encoder.finish().unwrap();
        gz
    }

    #[test]
    fn path_traversal_rejected() {
        let gz = build_traversal_tar_gz();
        let r = validate_archive_bytes("evil.tar.gz", &gz, 100, 1000, 10 * 1024 * 1024);
        assert!(r.is_err(), "expected traversal to be rejected, got {:?}", r);
        let msg = r.unwrap_err();
        assert!(
            msg.contains("..") || msg.contains("escapes"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn symlink_attack_rejected() {
        let gz = build_test_tar_gz_with_symlink("../etc/passwd");
        let r = validate_archive_bytes("link.tar.gz", &gz, 100, 1000, 10 * 1024 * 1024);
        assert!(r.is_err());
    }

    #[test]
    fn entry_count_cap_rejected() {
        let entries: Vec<(String, Vec<u8>)> = (0..10)
            .map(|i| (format!("f{i}.md"), b"x".to_vec()))
            .collect();
        let entries_ref: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(s, b)| (s.as_str(), b.as_slice()))
            .collect();
        let gz = build_test_tar_gz(&entries_ref);
        let r = validate_archive_bytes("toomany.tar.gz", &gz, 100, 5, 10 * 1024 * 1024);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("max_entries"));
    }

    #[test]
    fn expanded_size_cap_rejected() {
        let big = vec![0u8; 4096];
        let gz = build_test_tar_gz(&[("a", &big), ("b", &big)]);
        // Cap below 4096 + 4096 expanded.
        let r = validate_archive_bytes("big.tar.gz", &gz, 100, 1000, 4096);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("max_expanded_bytes"));
    }

    #[test]
    fn zip_bomb_ratio_rejected() {
        // Build a small zip with one entry that is mostly zeroes so
        // the deflate ratio is high. We construct a minimal zip with
        // 1 MiB of compressible data.
        let big = vec![0u8; 1024 * 1024];
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            let opts = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zw.start_file("zeros.bin", opts).unwrap();
            zw.write_all(&big).unwrap();
            zw.finish().unwrap();
        }
        // Ratio cap of 5:1: zeros compress >> 5x so this should reject.
        let r = validate_archive_bytes("bomb.zip", &buf, 5, 1000, 10 * 1024 * 1024);
        assert!(r.is_err(), "expected ratio rejection, got {:?}", r);
    }

    #[test]
    fn tampered_body_diverges_from_manifest_digest() {
        // WOR-194 contract: a tampered body produces a different
        // SHA-256 from the manifest digest, which the data-plane
        // handler observes per request and converts into a 503 +
        // audit event. This test pins the divergence at the hashing
        // layer; the higher-level integration test (server.rs)
        // exercises the 503 + audit emission.
        let entry = make_entry("hello", "skill-md", "/skills/hello.md", "# Hello\n");
        let idx = build_index(std::slice::from_ref(&entry), Path::new("."));
        let recorded = idx
            .digests
            .get(&CompactString::new("/skills/hello.md"))
            .unwrap()
            .clone();
        // Pretend an in-memory tamper happened after the manifest was
        // built. The runtime handler re-hashes the served bytes; if
        // they no longer match `recorded`, the 503 path fires.
        let tampered = b"# Hello attacker\n";
        let observed = sha256_hex(tampered);
        assert_ne!(recorded, observed, "tamper must produce a different digest");
    }

    // --- WOR-196 listing-scoped tests --------------------------------

    fn listing_yaml(name: &str, hostname: &str, skill_url: &str, visibility: &str) -> String {
        format!(
            r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: {name}
spec:
  type: api
  status: published
  resources:
    - ref: origins/{hostname}
      revision:
        mode: pin
        value: abc1234
  skills:
    - name: {name}-skill
      type: skill-md
      description: "Test skill"
      url: {skill_url}
      visibility: {visibility}
      body: |
        # {name}
"#
        )
    }

    fn registry_from_yaml(yamls: &[String]) -> ListingRegistry {
        let mut loaded = Vec::new();
        for (i, body) in yamls.iter().enumerate() {
            let listing: sbproxy_config::Listing =
                serde_yaml::from_str(body).expect("Listing parse");
            loaded.push(sbproxy_config::LoadedListing {
                source_path: std::path::PathBuf::from(format!("listings/{i}.yaml")),
                listing,
            });
        }
        let mut findings = Vec::new();
        ListingRegistry::from_loaded(loaded, &mut findings)
    }

    #[test]
    fn render_listing_indices_builds_per_listing_view() {
        let y1 = listing_yaml("first", "api.example.com", "/skills/first.md", "public");
        let y2 = listing_yaml(
            "second",
            "api.example.com",
            "/skills/second.md",
            "authenticated",
        );
        let registry = registry_from_yaml(&[y1, y2]);
        let map = render_listing_indices(&registry, Path::new("."));
        assert_eq!(map.len(), 2);
        let first = map.get("first").expect("first listing");
        assert_eq!(first.listing_name, "first");
        assert_eq!(first.hostnames.len(), 1);
        assert_eq!(first.hostnames[0].as_str(), "api.example.com");
        assert_eq!(first.index.entries.len(), 1);
        assert_eq!(first.index.entries[0].name, "first-skill");
    }

    #[test]
    fn render_listing_indices_skips_listings_without_skills() {
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: no-skills
spec:
  type: api
  status: draft
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: abc1234
"#;
        let registry = registry_from_yaml(&[yaml.to_string()]);
        let map = render_listing_indices(&registry, Path::new("."));
        assert!(map.is_empty(), "listing without skills must not project");
    }

    #[test]
    fn aggregated_index_unions_origin_and_listings_for_hostname() {
        // Per-origin entry under one hostname.
        let origin_entry = make_entry(
            "origin-skill",
            "skill-md",
            "/skills/origin.md",
            "origin body",
        );
        let origin_idx = build_index(std::slice::from_ref(&origin_entry), Path::new("."));

        // Two listings: one publishes the same hostname, one publishes
        // a different hostname. Only the same-hostname listing should
        // contribute to the merged manifest.
        let y_same = listing_yaml("same", "api.example.com", "/skills/same.md", "public");
        let y_other = listing_yaml("other", "other.example.com", "/skills/other.md", "public");
        let registry = registry_from_yaml(&[y_same, y_other]);
        let listings = render_listing_indices(&registry, Path::new("."));

        let merged = aggregate_for_hostname(Some(&origin_idx), &listings, "api.example.com");
        let names: Vec<&str> = merged.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"origin-skill"));
        assert!(names.contains(&"same-skill"));
        assert!(!names.contains(&"other-skill"));
    }

    #[test]
    fn aggregated_index_dedupes_by_name() {
        // Per-origin entry plus a Listing entry that re-declares the
        // same `name`. The merged view keeps the per-origin entry and
        // skips the duplicate from the Listing.
        let origin_entry = make_entry(
            "deploy-via-pr",
            "skill-md",
            "/skills/origin.md",
            "origin body",
        );
        let origin_idx = build_index(std::slice::from_ref(&origin_entry), Path::new("."));

        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: dup-listing
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
      description: "Duplicate name from a Listing"
      url: /skills/listing.md
      visibility: public
      body: |
        # listing body
"#
        .to_string();
        let registry = registry_from_yaml(&[yaml]);
        let listings = render_listing_indices(&registry, Path::new("."));
        let merged = aggregate_for_hostname(Some(&origin_idx), &listings, "api.example.com");
        let dup_count = merged
            .entries
            .iter()
            .filter(|e| e.name == "deploy-via-pr")
            .count();
        assert_eq!(dup_count, 1, "merged manifest must dedupe by name");
        // The per-origin entry's URL wins (it is walked first).
        let entry = merged
            .entries
            .iter()
            .find(|e| e.name == "deploy-via-pr")
            .unwrap();
        assert_eq!(entry.url, "/skills/origin.md");
    }

    #[test]
    fn aggregated_index_empty_when_no_listings_match_hostname() {
        let y = listing_yaml("nope", "other.example.com", "/skills/x.md", "public");
        let registry = registry_from_yaml(&[y]);
        let listings = render_listing_indices(&registry, Path::new("."));
        let merged = aggregate_for_hostname(None, &listings, "api.example.com");
        assert!(merged.entries.is_empty());
    }

    #[test]
    fn render_indices_skips_origins_without_skills() {
        // Build a CompiledConfig with one origin that has skills and
        // one that doesn't.
        use sbproxy_config::CompiledOrigin;
        let with_skills = CompiledOrigin {
            hostname: CompactString::new("with.example.com"),
            origin_id: CompactString::new("with"),
            workspace_id: CompactString::default(),
            action_config: serde_json::json!({"type": "proxy"}),
            auth_config: None,
            policy_configs: Vec::new(),
            transform_configs: Vec::new(),
            cors: None,
            hsts: None,
            compression: None,
            session: None,
            properties: None,
            sessions: None,
            user: None,
            force_ssl: false,
            allowed_methods: smallvec::smallvec![],
            request_modifiers: smallvec::smallvec![],
            response_modifiers: smallvec::smallvec![],
            variables: None,
            forward_rules: Vec::new(),
            fallback_origin: None,
            error_pages: None,
            problem_details: None,
            proxy_status: None,
            message_signatures: None,
            olp: None,
            idempotency: None,
            bot_detection: None,
            threat_protection: None,
            on_request: Vec::new(),
            on_response: Vec::new(),
            response_cache: None,
            mirror: None,
            extensions: HashMap::new(),
            expose_openapi: false,
            stream_safety: Vec::new(),
            rate_limits: None,
            auto_content_negotiate: None,
            content_signal: None,
            token_bytes_ratio: None,
            agent_skills: vec![make_entry("a", "skill-md", "/skills/a.md", "abc")],
            agents_md: None,
            ai_txt: None,
            agents_json: None,
            outbound_credential: None,
            outbound_web_bot_auth: false,
        };
        let without = CompiledOrigin {
            hostname: CompactString::new("without.example.com"),
            origin_id: CompactString::new("without"),
            workspace_id: CompactString::default(),
            action_config: serde_json::json!({"type": "proxy"}),
            auth_config: None,
            policy_configs: Vec::new(),
            transform_configs: Vec::new(),
            cors: None,
            hsts: None,
            compression: None,
            session: None,
            properties: None,
            sessions: None,
            user: None,
            force_ssl: false,
            allowed_methods: smallvec::smallvec![],
            request_modifiers: smallvec::smallvec![],
            response_modifiers: smallvec::smallvec![],
            variables: None,
            forward_rules: Vec::new(),
            fallback_origin: None,
            error_pages: None,
            problem_details: None,
            proxy_status: None,
            message_signatures: None,
            olp: None,
            idempotency: None,
            bot_detection: None,
            threat_protection: None,
            on_request: Vec::new(),
            on_response: Vec::new(),
            response_cache: None,
            mirror: None,
            extensions: HashMap::new(),
            expose_openapi: false,
            stream_safety: Vec::new(),
            rate_limits: None,
            auto_content_negotiate: None,
            content_signal: None,
            token_bytes_ratio: None,
            agent_skills: Vec::new(),
            agents_md: None,
            ai_txt: None,
            agents_json: None,
            outbound_credential: None,
            outbound_web_bot_auth: false,
        };
        let mut host_map = HashMap::new();
        host_map.insert(CompactString::new("with.example.com"), 0);
        host_map.insert(CompactString::new("without.example.com"), 1);
        let cfg = CompiledConfig {
            origins: vec![with_skills, without],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            messenger: None,
            mesh: None,
            access_log: None,
            agent_classes: None,
        };
        let map = render_indices(&cfg, Path::new("."));
        assert!(map.contains_key(&CompactString::new("with.example.com")));
        assert!(!map.contains_key(&CompactString::new("without.example.com")));
    }
}
