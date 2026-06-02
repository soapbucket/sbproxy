//! Policy-graph projections.
//!
//! The four projections are:
//!
//! - `robots.txt` per IETF draft-koster-rep-ai
//! - `llms.txt` and `llms-full.txt` per the Anthropic / Mistral
//!   convention
//! - `/licenses.xml` per RSL 1.0
//! - `/.well-known/tdmrep.json` per W3C TDMRep
//!
//! Adds a fifth sibling:
//!
//! - `/.well-known/agent-skills/index.json` per the Agent Skills v0.2.0
//!   discovery RFC (`https://github.com/cloudflare/agent-skills-discovery-rfc`).
//!   Manifest schema:
//!   `https://schemas.agentskills.io/discovery/0.2.0/schema.json`.
//!
//! All five are derived from the same compiled-policy graph
//! (`CompiledConfig`); they share an in-memory cache so the data plane
//! pays one atomic load and one hash-map lookup per request. Cache
//! refresh runs once per config reload, atomically.
//!
//! ## Crate placement
//!
//! The substrate (cache + render entrypoint) lives in `sbproxy-modules`
//! rather than `sbproxy-core` to avoid a circular-dep risk:
//! `sbproxy-modules` already depends on
//! `sbproxy-config` and `sbproxy-platform`, so projections walk
//! `CompiledConfig` without a back-edge into `sbproxy-core`. The
//! `sbproxy-core::reload` path drives the install via a small
//! `sbproxy-modules::projections::install_projections` call after
//! `load_pipeline`. The hot-path serving lives in
//! `sbproxy-core::server` which is already a downstream consumer of
//! `sbproxy-modules`.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use bytes::Bytes;
use compact_str::CompactString;
use sbproxy_config::{CompiledConfig, ListingRegistry};
use sbproxy_plugin::{current_admin_audit_emitter, ProjectionRefreshEvent};

use crate::policy::ai_crawl::ContentSignals;
use sha2::{Digest, Sha256};

/// RSL 1.0 `<payment type>` enum (the closed set of values the spec
/// allows). An operator-declared `payment.type:` outside this set falls
/// back to the derived crawl/free terms.
const VALID_PAYMENT_TYPES: &[&str] = &[
    "free",
    "purchase",
    "subscription",
    "training",
    "crawl",
    "use",
    "attribution",
];

/// WOR-808 PR5: inject `<link rel="license" href="<href>">` into the
/// `<head>` of an HTML document so HTML consumers can discover the
/// RSL `/licenses.xml` projection inline.
///
/// Pure helper, no I/O. Returns the original bytes verbatim when:
///
/// - The body already contains a `rel="license"` link (case-insensitive),
///   so a second pass through the proxy is a no-op.
/// - No `<head>` tag is found, so the body is a fragment / non-HTML the
///   proxy should not rewrite.
///
/// Otherwise inserts the tag immediately after the `<head>` open tag,
/// preserving any attributes on `<head>` itself. Match is
/// case-insensitive (HTML accepts `<HEAD>` / `<Head>` etc.).
pub fn inject_license_link(body: &[u8], href: &str) -> Vec<u8> {
    // Cheap early-out for the no-op cases. The substring check uses
    // a lower-cased copy of just the first 8 KiB so we don't pay an
    // O(n) lowercase on a multi-megabyte body for a header-only
    // search.
    let scan_window = body.len().min(8192);
    let head_window = String::from_utf8_lossy(&body[..scan_window]).to_ascii_lowercase();
    if head_window.contains("rel=\"license\"") || head_window.contains("rel='license'") {
        return body.to_vec();
    }
    let head_open = match find_head_open(&head_window) {
        Some(span) => span,
        None => return body.to_vec(),
    };
    let tag = format!("<link rel=\"license\" href=\"{href}\">");
    let mut out = Vec::with_capacity(body.len() + tag.len());
    out.extend_from_slice(&body[..head_open]);
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&body[head_open..]);
    out
}

/// Locate the byte offset just after the `<head ...>` open tag in a
/// lowercase ASCII window. Returns `None` when no `<head>` open tag is
/// present or the tag is unclosed.
fn find_head_open(lower_window: &str) -> Option<usize> {
    let start = lower_window.find("<head")?;
    let after = start + "<head".len();
    // The byte at `after` is either `>` (no attributes) or whitespace
    // (attributes follow). A tag like `<header` would also match the
    // `<head` prefix; reject by requiring the next byte to be one of
    // `>`, space, tab, newline, slash. This is the same disambiguation
    // every browser parser uses.
    let next = lower_window.as_bytes().get(after)?;
    if !matches!(*next, b'>' | b' ' | b'\t' | b'\n' | b'\r' | b'/') {
        return None;
    }
    // Walk forward to the closing `>` of the open tag.
    let close = after + lower_window[after..].find('>')?;
    Some(close + 1)
}

/// Format hint for [`inject_license_link_xml`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedFormat {
    /// RSS 2.0 (root element `<rss>`; the license link slots inside
    /// the first `<channel>` per RSL 1.0's feed-discovery convention).
    Rss,
    /// Atom 1.0 (root element `<feed>`; license link slots immediately
    /// inside the `<feed>` open tag).
    Atom,
}

/// WOR-808 PR6: inject `<link rel="license" href="<href>"/>` into the
/// `<channel>` (RSS) or `<feed>` (Atom) root of a syndication feed so
/// feed readers and feed-consuming scrapers discover the RSL
/// `/licenses.xml` projection alongside the HTTP `Link` header and the
/// HTML `<head>` injection.
///
/// Returns the original bytes verbatim when:
///
/// - The feed already contains a `rel="license"` link (case-insensitive
///   attribute name).
/// - The expected container open tag (`<channel>` / `<feed>`) is missing,
///   so the document is not the declared format (an empty body, an
///   error envelope, or a feed format we don't recognise).
///
/// Otherwise inserts the self-closing XML link immediately after the
/// container's open tag, preserving any attributes on the container.
pub fn inject_license_link_xml(body: &[u8], href: &str, format: FeedFormat) -> Vec<u8> {
    let scan_window = body.len().min(8192);
    let head_window = String::from_utf8_lossy(&body[..scan_window]).to_ascii_lowercase();
    if head_window.contains("rel=\"license\"") || head_window.contains("rel='license'") {
        return body.to_vec();
    }
    let container = match format {
        FeedFormat::Rss => "<channel",
        FeedFormat::Atom => "<feed",
    };
    let open = match find_container_open(&head_window, container) {
        Some(span) => span,
        None => return body.to_vec(),
    };
    let tag = format!("<link rel=\"license\" href=\"{href}\"/>");
    let mut out = Vec::with_capacity(body.len() + tag.len());
    out.extend_from_slice(&body[..open]);
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&body[open..]);
    out
}

/// Locate the byte offset just after a named XML container open tag
/// (`<channel ...>` or `<feed ...>`) in a lowercase ASCII window.
/// Returns `None` when no such open tag is present, or when no
/// occurrence's next byte is one of `>`, whitespace, or `/` (the same
/// disambiguation `find_head_open` uses, in case a sibling tag shares
/// the prefix). Skips false matches and continues searching.
fn find_container_open(lower_window: &str, prefix: &str) -> Option<usize> {
    let mut search_from = 0;
    loop {
        let rel = lower_window[search_from..].find(prefix)?;
        let start = search_from + rel;
        let after = start + prefix.len();
        let next = lower_window.as_bytes().get(after)?;
        if matches!(*next, b'>' | b' ' | b'\t' | b'\n' | b'\r' | b'/') {
            let close = after + lower_window[after..].find('>')?;
            return Some(close + 1);
        }
        search_from = after;
    }
}

/// Classify a `content-type` header value as one of the supported
/// syndication feed formats, or `None` when it is neither. Strips
/// parameters (`; charset=utf-8`) and matches case-insensitively so
/// `Application/RSS+XML` and `application/rss+xml` both resolve.
pub fn classify_feed_content_type(content_type: &str) -> Option<FeedFormat> {
    let main = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match main.as_str() {
        "application/rss+xml" => Some(FeedFormat::Rss),
        "application/atom+xml" => Some(FeedFormat::Atom),
        _ => None,
    }
}

/// Read the operator-declared `payment:` block on an `ai_crawl_control`
/// entry and turn it into [`licenses::PaymentTerms`]. Returns `None` when
/// the block is absent or the declared `type` is not in the RSL 1.0
/// enum, so the caller can fall through to the derived terms.
///
/// WOR-944: `standard:` (the URL of a reuse framework for attribution
/// payments, typically a CC-BY variant) is read here too; the
/// renderer slots it inside `<payment>` as a `<standard>` child.
fn operator_declared_payment(ai_crawl: &serde_json::Value) -> Option<licenses::PaymentTerms> {
    let decl = ai_crawl.get("payment").and_then(|v| v.as_object())?;
    let ptype = decl.get("type").and_then(|v| v.as_str())?;
    if !VALID_PAYMENT_TYPES.contains(&ptype) {
        return None;
    }
    Some(licenses::PaymentTerms {
        payment_type: ptype.to_string(),
        amount: decl.get("amount").and_then(|v| v.as_f64()),
        currency: decl
            .get("currency")
            .and_then(|v| v.as_str())
            .map(String::from),
        standard: decl
            .get("standard")
            .and_then(|v| v.as_str())
            .map(String::from),
    })
}

/// WOR-944: read the operator-declared `rsl_vocab:` block on an
/// `ai_crawl_control` entry and turn it into [`licenses::RslVocab`].
/// Missing block, missing sub-block, or empty token lists all map to
/// the default (silent tier), which the renderer omits cleanly.
fn operator_declared_rsl_vocab(ai_crawl: &serde_json::Value) -> licenses::RslVocab {
    let Some(block) = ai_crawl.get("rsl_vocab").and_then(|v| v.as_object()) else {
        return licenses::RslVocab::default();
    };
    fn read_tier(value: Option<&serde_json::Value>) -> licenses::TokenTier {
        let Some(obj) = value.and_then(|v| v.as_object()) else {
            return licenses::TokenTier::default();
        };
        fn read_list(v: Option<&serde_json::Value>) -> Vec<String> {
            v.and_then(|x| x.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        }
        licenses::TokenTier {
            permit: read_list(obj.get("permit")),
            prohibit: read_list(obj.get("prohibit")),
        }
    }
    licenses::RslVocab {
        user: read_tier(block.get("user")),
        geo: read_tier(block.get("geo")),
    }
}

/// WOR-808: read the operator-declared `license_tiers:` block on an
/// `ai_crawl_control` entry and turn it into a list of
/// [`licenses::LicenseTier`]. Each tier carries its own
/// payment + signals; the same `payment.standard` URL slot used by
/// the single-tier path applies (an attribution payment can still
/// point at a reuse framework). An absent block or an empty array
/// returns the empty vec; the caller falls through to single-tier
/// rendering then.
///
/// The key is deliberately `license_tiers:` (not `tiers:`) to avoid
/// collision with the pre-existing `ai_crawl_control.tiers` block,
/// which carries per-agent pricing for the pay-per-crawl flow.
///
/// Recognised tier shape:
///
/// ```yaml
/// license_tiers:
///   - name: summarize
///     payment: { type: crawl, amount: 0.002, currency: USD }
///     signals: { search: true, ai_input: true }
///   - name: full-display
///     payment: { type: crawl, amount: 0.01, currency: USD }
///     signals: { search: true, ai_input: true, ai_train: false }
/// ```
fn operator_declared_license_tiers(ai_crawl: &serde_json::Value) -> Vec<licenses::LicenseTier> {
    let Some(arr) = ai_crawl.get("license_tiers").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let Some(name) = entry.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        // Payment defaults to free when the tier omits the block.
        let payment = entry
            .get("payment")
            .and_then(|v| v.as_object())
            .map(|decl| {
                let ptype = decl
                    .get("type")
                    .and_then(|v| v.as_str())
                    .filter(|t| VALID_PAYMENT_TYPES.contains(t))
                    .unwrap_or("free");
                licenses::PaymentTerms {
                    payment_type: ptype.to_string(),
                    amount: decl.get("amount").and_then(|v| v.as_f64()),
                    currency: decl
                        .get("currency")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    standard: decl
                        .get("standard")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                }
            })
            .unwrap_or_else(licenses::PaymentTerms::free);
        let signals: ContentSignals = entry
            .get("signals")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        out.push(licenses::LicenseTier {
            name: name.to_string(),
            payment,
            signals,
        });
    }
    out
}

pub mod agent_skills;
pub mod agents_json;
pub mod licenses;
pub mod llms;
pub mod robots;
pub mod tdmrep;

/// Per-hostname projection bodies, plus the config-version stamp the
/// cache was built from.
///
/// The four `HashMap`s are keyed by the origin hostname (e.g.
/// `api.example.com`). Origins without an `ai_crawl_control` policy
/// produce no entries; data-plane handlers respond `404` for those
/// hostnames.
///
/// Bodies are stored as [`Bytes`] so cloning out of the cache is a
/// pointer copy, not a memcpy. Readers load the [`Arc`] via
/// [`current_projections`] and clone the body bytes into the response
/// buffer.
#[derive(Debug, Default, Clone)]
pub struct ProjectionDocs {
    /// Config version hash this snapshot was computed from. Used by
    /// the data-plane handler to detect stale hits (the hot path
    /// checks this against the live pipeline's version before
    /// serving).
    pub config_version: u64,
    /// Per-hostname `robots.txt` bodies.
    pub robots_txt: HashMap<CompactString, Bytes>,
    /// Per-hostname `llms.txt` bodies.
    pub llms_txt: HashMap<CompactString, Bytes>,
    /// Per-hostname `llms-full.txt` bodies.
    pub llms_full_txt: HashMap<CompactString, Bytes>,
    /// Per-hostname `/licenses.xml` bodies.
    pub licenses_xml: HashMap<CompactString, Bytes>,
    /// Per-hostname `/.well-known/tdmrep.json` bodies.
    pub tdmrep_json: HashMap<CompactString, Bytes>,
    /// Per-hostname `/AGENTS.md` bodies (WOR-809). Populated from the
    /// origin's `agents_md:` config, independently of
    /// `ai_crawl_control`. Origins without the field produce no entry
    /// and the data-plane handler 404s the path.
    pub agents_md: HashMap<CompactString, Bytes>,
    /// Per-hostname `/ai.txt` bodies (WOR-809). Populated from the
    /// origin's `ai_txt:` config, independently of `ai_crawl_control`.
    pub ai_txt: HashMap<CompactString, Bytes>,
    /// Per-hostname `/.well-known/agents.json` bodies (WOR-820).
    /// Populated from the origin's `agents_json:` config, independently
    /// of `ai_crawl_control`.
    pub agents_json: HashMap<CompactString, Bytes>,
    /// Per-hostname RSL URN of the form
    /// `urn:rsl:1.0:<hostname>:<config_version_hash>`. Stamped on
    /// `RequestContext.rsl_urn` by the request pipeline so downstream
    /// serialisers (the JSON envelope, agent-facing responses)
    /// can surface the URN without re-reading the projection body.
    pub rsl_urns: HashMap<CompactString, String>,
    /// Per-hostname `Content-Signal` value (or `None` when the origin
    /// asserts no signal). Surfaced to the response middleware so the
    /// proxy can stamp the optional `TDM-Reservation: 1` header per
    /// the TDMRep convention when an origin asserts no `Content-Signal`.
    pub content_signals: HashMap<CompactString, Option<CompactString>>,
    /// Per-hostname Agent Skills v0.2.0 index. Origins
    /// without `agent_skills:` produce no entries; the data-plane
    /// handler 404s the well-known URL for those hostnames.
    pub agent_skills: HashMap<CompactString, agent_skills::AgentSkillsIndex>,
    /// Per-Listing Agent Skills indices.
    ///
    /// Keyed by `Listing.metadata.name`. Each entry carries the set
    /// of origin hostnames the Listing publishes plus the resolved
    /// [`agent_skills::AgentSkillsIndex`] for that Listing's
    /// `spec.skills[]` block. The data-plane handler serves three
    /// surfaces from this map:
    ///
    /// - `GET /.well-known/agent-skills/<listing-name>/index.json`
    ///   serves one Listing's manifest (`ListingScopedIndex.index`).
    /// - `GET /.well-known/agent-skills/<listing-name>/<artifact>`
    ///   serves an individual skill body re-hosted by the proxy.
    /// - `GET /.well-known/agent-skills/index.json` returns the
    ///   merged manifest combining the per-origin entries (when
    ///   present) with every Listing whose `hostnames` include the
    ///   request hostname.
    pub agent_skills_listings: HashMap<String, agent_skills::ListingScopedIndex>,
}

/// Compute every projection body for every origin in `config`, with
/// no Listing-scoped overlay.
///
/// Equivalent to calling [`render_projections_with_listings`] with an
/// empty registry; existing callers that have not been threaded with
/// a `ListingRegistry` yet keep working unchanged.
pub fn render_projections(config: &CompiledConfig, config_version: u64) -> ProjectionDocs {
    render_projections_with_listings(config, &ListingRegistry::default(), config_version)
}

/// Compute every projection body for every origin in `config`,
/// folding the Listing-scoped agent-skills overlay into the
/// result.
///
/// Walks `config.origins`, filters for origins with an
/// `ai_crawl_control` policy entry in `policy_configs`, extracts the
/// pricing tiers and the `Content-Signal` value (read from the
/// origin's `extensions["content_signal"]` slot), and renders the
/// four documents.
///
/// Origins without `ai_crawl_control` produce no entries; readers
/// treat the absence as a 404.
///
/// The Listing-scoped overlay populates
/// [`ProjectionDocs::agent_skills_listings`]; each Listing's
/// `spec.skills[]` block resolves the same way the top-level
/// `agent_skills:` block does (`build_index` walks the entries,
/// hashes artifact bodies against the workspace root, and caches the
/// result). The aggregated `/.well-known/agent-skills/index.json` on
/// a request hostname is computed at serve time by walking the
/// per-origin entry (if any) and merging in every Listing whose
/// `hostnames` include the request authority.
pub fn render_projections_with_listings(
    config: &CompiledConfig,
    listings: &ListingRegistry,
    config_version: u64,
) -> ProjectionDocs {
    let mut docs = ProjectionDocs {
        config_version,
        ..ProjectionDocs::default()
    };

    // WOR-193: Agent Skills index. Walk every origin with `agent_skills:`
    // configured, resolve artifact bytes, hash them, and stash the
    // result on the projection cache. Workspace root defaults to the
    // current working directory; operators that author `path:` fields
    // in their YAML get filesystem reads relative to where the proxy
    // was started, matching the convention the other projection
    // modules use for any local-file resolution.
    let workspace_root = std::env::current_dir().unwrap_or_else(|_| ".".into());
    docs.agent_skills = agent_skills::render_indices(config, &workspace_root);

    // WOR-196: per-Listing agent-skills overlay. Each Listing in the
    // registry contributes a `ListingScopedIndex` keyed by its
    // `metadata.name`; the data-plane handler serves it at
    // `/.well-known/agent-skills/<listing-name>/index.json` plus the
    // re-hosted artifact bodies, and the aggregated
    // `/.well-known/agent-skills/index.json` on a Catalog domain
    // unions every Listing's entries with the per-origin entries
    // computed above.
    docs.agent_skills_listings = agent_skills::render_listing_indices(listings, &workspace_root);

    // WOR-809: AGENTS.md + ai.txt agent-web emission. These are served
    // verbatim from per-origin config and, unlike the pricing-derived
    // projections below, do not require an `ai_crawl_control` policy,
    // so they are populated here outside the per-origin gate (the same
    // placement as the agent-skills index above).
    for origin in &config.origins {
        if let Some(body) = &origin.agents_md {
            docs.agents_md
                .insert(origin.hostname.clone(), Bytes::from(body.clone()));
        }
        if let Some(body) = &origin.ai_txt {
            docs.ai_txt
                .insert(origin.hostname.clone(), Bytes::from(body.clone()));
        }
        if let Some(cfg) = &origin.agents_json {
            let body = agents_json::render(origin.hostname.as_str(), cfg);
            docs.agents_json
                .insert(origin.hostname.clone(), Bytes::from(body));
        }
    }

    for origin in &config.origins {
        // --- Discover the ai_crawl_control entry, if any ---
        //
        // `policy_configs` is a JSON array; each entry has a `type`
        // discriminator. Wave 4 only inspects the first
        // ai_crawl_control entry: the schema does not allow more than
        // one per origin (the compiler rejects duplicates), but we
        // read defensively by matching the type tag.
        let ai_crawl = origin.policy_configs.iter().find(|v| {
            v.get("type")
                .and_then(|t| t.as_str())
                .map(|s| s == "ai_crawl_control")
                .unwrap_or(false)
        });
        let Some(ai_crawl) = ai_crawl else {
            continue;
        };

        // --- Content-Signal extraction ---
        //
        // Wave 4 / G4.5: the validated `content_signal` field on
        // `CompiledOrigin` is the source of truth. Earlier waves read
        // from `extensions["content_signal"]` while the field was
        // pending; that path is retained as a fallback so older
        // configs that still set the value via the extensions map
        // continue to project correctly. Absent value -> default-deny
        // per A4.1's RSL / TDMRep mapping tables.
        let content_signal = origin.content_signal.map(CompactString::new).or_else(|| {
            origin
                .extensions
                .get("content_signal")
                .and_then(|v| v.as_str())
                .map(CompactString::new)
        });

        let hostname = origin.hostname.clone();

        // --- robots.txt ---
        let robots = robots::render(hostname.as_str(), ai_crawl, config_version);
        docs.robots_txt
            .insert(hostname.clone(), Bytes::from(robots));

        // --- llms.txt + llms-full.txt ---
        let (llms, llms_full) = llms::render(hostname.as_str(), ai_crawl, config_version);
        docs.llms_txt.insert(hostname.clone(), Bytes::from(llms));
        docs.llms_full_txt
            .insert(hostname.clone(), Bytes::from(llms_full));

        // --- licenses.xml ---
        //
        // WOR-804: when the `ai_crawl_control` policy declares
        // structured Content Signals, the same set drives both the
        // robots.txt directive and the RSL document so they cannot
        // contradict. Otherwise fall back to the legacy single
        // `content_signal` value (byte-identical to prior output).
        let content_signals: ContentSignals = ai_crawl
            .get("content_signals")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        // WOR-808: RSL `<payment>` terms. An operator-declared `payment:`
        // block on `ai_crawl_control` wins (validated against the RSL 1.0
        // enum). Otherwise derive from pay-per-crawl: a per-crawl price
        // maps to `type="crawl"` with the configured amount + currency;
        // an unpriced origin is `type="free"`.
        let payment = operator_declared_payment(ai_crawl).unwrap_or_else(|| {
            match ai_crawl.get("price").and_then(|v| v.as_f64()) {
                Some(p) if p > 0.0 => licenses::PaymentTerms {
                    payment_type: "crawl".to_string(),
                    amount: Some(p),
                    currency: Some(
                        ai_crawl
                            .get("currency")
                            .and_then(|v| v.as_str())
                            .unwrap_or("USD")
                            .to_string(),
                    ),
                    standard: None,
                },
                _ => licenses::PaymentTerms::free(),
            }
        });
        // WOR-944: read the tier-1 user / geo vocab. Default (no
        // declaration) is silent for both tiers so unchanged
        // configs produce the same `<permits type="usage">`-only
        // shape that the renamed `render_signals` emits.
        let rsl_vocab = operator_declared_rsl_vocab(ai_crawl);
        // WOR-808: when the operator declares `tiers:` on this
        // origin, the projection emits one `<license>` per tier
        // (TollBit summarize vs full-display, etc). Each tier gets
        // its own `<payment>` so a marketplace can buy the cheap
        // tier for snippet generation and the expensive tier for
        // full-page reuse. Falls through to the single-tier path
        // when no `tiers:` is declared.
        let license_tiers = operator_declared_license_tiers(ai_crawl);
        let (xml, urn) = if !license_tiers.is_empty() {
            licenses::render_tiered(
                hostname.as_str(),
                &license_tiers,
                &rsl_vocab,
                config_version,
            )
        } else if content_signals.is_empty() {
            licenses::render(
                hostname.as_str(),
                content_signal.as_deref(),
                Some(&payment),
                config_version,
            )
        } else {
            licenses::render_signals_with_vocab(
                hostname.as_str(),
                &content_signals,
                Some(&payment),
                &rsl_vocab,
                config_version,
            )
        };
        docs.licenses_xml.insert(hostname.clone(), Bytes::from(xml));
        docs.rsl_urns.insert(hostname.clone(), urn);

        // --- tdmrep.json ---
        let tdm = tdmrep::render(hostname.as_str(), ai_crawl, content_signal.as_deref());
        docs.tdmrep_json.insert(hostname.clone(), Bytes::from(tdm));

        // --- content-signal map for the response middleware ---
        docs.content_signals.insert(hostname, content_signal);
    }

    docs
}

// --- ArcSwap cache ---

static PROJECTIONS: OnceLock<ArcSwap<ProjectionDocs>> = OnceLock::new();

fn projections_store() -> &'static ArcSwap<ProjectionDocs> {
    PROJECTIONS.get_or_init(|| ArcSwap::from_pointee(ProjectionDocs::default()))
}

/// Atomically replace the projection cache with the freshly rendered
/// documents.
///
/// Called by `sbproxy-core::reload` after every successful
/// `load_pipeline`. The store is lock-free for readers; writers pay
/// one `ArcSwap::store` per reload.
///
/// Also emits one `ProjectionRefreshEvent` per `(hostname,
/// projection_kind)` pair through the
/// [`sbproxy_plugin::AdminAuditEmitter`] so registered audit sinks
/// capture an `AdminAuditEvent` § "Audit trail".
/// When no emitter is registered the calls are no-ops.
pub fn install_projections(docs: ProjectionDocs) {
    // Snapshot for audit emission before installing; cloning is cheap
    // (Bytes + small HashMaps).
    let emit_snapshot = docs.clone();
    projections_store().store(Arc::new(docs));

    // --- Audit emission per (hostname, projection_kind) ---
    let emitter = current_admin_audit_emitter();
    let cv = emit_snapshot.config_version;
    emit_for_kind(emitter.as_ref(), &emit_snapshot.robots_txt, "robots", cv);
    emit_for_kind(emitter.as_ref(), &emit_snapshot.llms_txt, "llms", cv);
    emit_for_kind(
        emitter.as_ref(),
        &emit_snapshot.llms_full_txt,
        "llms-full",
        cv,
    );
    emit_for_kind(
        emitter.as_ref(),
        &emit_snapshot.licenses_xml,
        "licenses",
        cv,
    );
    emit_for_kind(emitter.as_ref(), &emit_snapshot.tdmrep_json, "tdmrep", cv);
    emit_for_kind(emitter.as_ref(), &emit_snapshot.agents_md, "agents-md", cv);
    emit_for_kind(emitter.as_ref(), &emit_snapshot.ai_txt, "ai-txt", cv);
    emit_for_kind(
        emitter.as_ref(),
        &emit_snapshot.agents_json,
        "agents-json",
        cv,
    );

    // WOR-193: emit one ProjectionRefreshEvent per (hostname, agent_skill)
    // pair so audit sinks see a stable record of the manifest digests
    // that were live for this config version. Each entry's `doc_hash`
    // is the SHA-256 of the artifact body the manifest pinned, so a
    // verifier can check the served bytes match the audit row.
    for (hostname, idx) in &emit_snapshot.agent_skills {
        for entry in &idx.entries {
            // Strip the `sha256:` prefix the manifest carries to match
            // the existing audit-event hex contract.
            let hex_only = entry
                .digest
                .strip_prefix("sha256:")
                .unwrap_or(&entry.digest);
            emitter.record_projection_refresh(ProjectionRefreshEvent {
                hostname: hostname.to_string(),
                projection_kind: format!("agent-skill:{}", entry.name),
                config_version: cv,
                doc_hash: hex_only.to_string(),
                byte_len: idx
                    .artifacts
                    .get(&CompactString::new(canonical_path_from_url(&entry.url)))
                    .map(|b| b.len())
                    .unwrap_or(0),
            });
        }
    }

    // WOR-196: emit one ProjectionRefreshEvent per (listing, skill)
    // pair so audit sinks record the manifest digests for the
    // Listing-scoped surface too. The `projection_kind` is namespaced
    // as `listing-agent-skill:<listing>:<skill>` so an operator can
    // distinguish the two surfaces in the audit log.
    for (listing_name, scoped) in &emit_snapshot.agent_skills_listings {
        for entry in &scoped.index.entries {
            let hex_only = entry
                .digest
                .strip_prefix("sha256:")
                .unwrap_or(&entry.digest);
            // Emit one row per hostname the Listing publishes so the
            // audit log shows which origin a verifier can hit to
            // re-fetch the artifact.
            for hostname in &scoped.hostnames {
                emitter.record_projection_refresh(ProjectionRefreshEvent {
                    hostname: hostname.to_string(),
                    projection_kind: format!("listing-agent-skill:{listing_name}:{}", entry.name),
                    config_version: cv,
                    doc_hash: hex_only.to_string(),
                    byte_len: scoped
                        .index
                        .artifacts
                        .get(&CompactString::new(canonical_path_from_url(&entry.url)))
                        .map(|b| b.len())
                        .unwrap_or(0),
                });
            }
        }
    }
}

/// Strip the URL down to the canonical path key used by the artifact
/// cache, mirroring the crate-private `canonical_path_key` helper in
/// `agent_skills`. Used by the audit emitter to look up byte-lengths
/// for fully-qualified URLs (which return an empty path key here).
fn canonical_path_from_url(url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        return String::new();
    }
    if url.starts_with('/') {
        url.to_string()
    } else {
        format!("/{url}")
    }
}

fn emit_for_kind(
    emitter: &dyn sbproxy_plugin::AdminAuditEmitter,
    map: &HashMap<CompactString, Bytes>,
    kind: &'static str,
    config_version: u64,
) {
    for (hostname, body) in map {
        emitter.record_projection_refresh(ProjectionRefreshEvent {
            hostname: hostname.to_string(),
            projection_kind: kind.to_string(),
            config_version,
            doc_hash: sha256_hex(body),
            byte_len: body.len(),
        });
    }
}

fn sha256_hex(body: &Bytes) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body.as_ref());
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Borrow the current projection cache.
///
/// Returns an `Arc` so callers can hold it across `await` points
/// without blocking the reload writer. Readers pay one atomic load
/// per request (plus one HashMap lookup by hostname); no allocations
/// on the hot path.
pub fn current_projections() -> Arc<ProjectionDocs> {
    projections_store().load_full()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config_with_origin(hostname: &str, ai_crawl: serde_json::Value) -> CompiledConfig {
        let mut host_map = HashMap::new();
        host_map.insert(CompactString::new(hostname), 0);
        CompiledConfig {
            origins: vec![sbproxy_config::CompiledOrigin {
                hostname: CompactString::new(hostname),
                origin_id: CompactString::new(hostname),
                workspace_id: CompactString::default(),
                tenant_id: compact_str::CompactString::const_new("__default__"),
                action_config: serde_json::json!({"type": "proxy", "url": "http://127.0.0.1:9000"}),
                auth_config: None,
                policy_configs: vec![ai_crawl],
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
                web_bot_auth_publish: None,
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
                observability: None,
            }],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            messenger: None,
            mesh: None,
            access_log: None,
            agent_classes: None,
        }
    }

    #[test]
    fn render_skips_origins_without_ai_crawl() {
        let mut cfg = config_with_origin(
            "without.example.com",
            serde_json::json!({"type": "rate_limit", "max": 100}),
        );
        // Replace the policy configs with a non-ai_crawl entry.
        cfg.origins[0].policy_configs = vec![serde_json::json!({"type": "rate_limit"})];
        let docs = render_projections(&cfg, 1);
        assert!(docs.robots_txt.is_empty());
        assert!(docs.llms_txt.is_empty());
        assert!(docs.licenses_xml.is_empty());
        assert!(docs.tdmrep_json.is_empty());
    }

    #[test]
    fn render_emits_one_entry_per_origin_with_ai_crawl() {
        let cfg = config_with_origin(
            "shop.example.com",
            serde_json::json!({
                "type": "ai_crawl_control",
                "price": 0.001,
                "currency": "USD",
            }),
        );
        let docs = render_projections(&cfg, 7);
        assert_eq!(docs.config_version, 7);
        assert!(docs.robots_txt.contains_key("shop.example.com"));
        assert!(docs.llms_txt.contains_key("shop.example.com"));
        assert!(docs.llms_full_txt.contains_key("shop.example.com"));
        assert!(docs.licenses_xml.contains_key("shop.example.com"));
        assert!(docs.tdmrep_json.contains_key("shop.example.com"));
        assert!(docs.rsl_urns.contains_key("shop.example.com"));
    }

    #[test]
    fn operator_declared_payment_overrides_derived() {
        // Origin sets price (-> derived "crawl") but explicitly declares
        // `payment: training`; the operator declaration wins.
        let cfg = config_with_origin(
            "h.example.com",
            serde_json::json!({
                "type": "ai_crawl_control",
                "price": 0.001,
                "currency": "USD",
                "payment": { "type": "training" }
            }),
        );
        let docs = render_projections(&cfg, 1);
        let xml = std::str::from_utf8(
            docs.licenses_xml
                .get("h.example.com")
                .expect("licenses.xml present"),
        )
        .unwrap();
        assert!(
            xml.contains(r#"<payment type="training" />"#),
            "operator-declared payment.type wins; got:\n{xml}"
        );
        // The derived "crawl" must not appear.
        assert!(
            !xml.contains(r#"type="crawl""#),
            "derived crawl payment must not appear when operator overrides; got:\n{xml}"
        );
    }

    #[test]
    fn operator_declared_payment_emits_amount_and_currency() {
        let cfg = config_with_origin(
            "h.example.com",
            serde_json::json!({
                "type": "ai_crawl_control",
                "payment": { "type": "subscription", "amount": 9.99, "currency": "EUR" }
            }),
        );
        let docs = render_projections(&cfg, 1);
        let xml = std::str::from_utf8(docs.licenses_xml.get("h.example.com").unwrap()).unwrap();
        assert!(
            xml.contains(r#"<payment type="subscription" amount="9.99" currency="EUR" />"#),
            "got:\n{xml}"
        );
    }

    #[test]
    fn unknown_payment_type_falls_back_to_derived() {
        let cfg = config_with_origin(
            "h.example.com",
            serde_json::json!({
                "type": "ai_crawl_control",
                "price": 0.001,
                "currency": "USD",
                "payment": { "type": "totally-not-rsl" }
            }),
        );
        let docs = render_projections(&cfg, 1);
        let xml = std::str::from_utf8(docs.licenses_xml.get("h.example.com").unwrap()).unwrap();
        // Invalid operator type is dropped; derived crawl wins.
        assert!(
            xml.contains(r#"type="crawl""#),
            "fallback to derived; got:\n{xml}"
        );
        assert!(!xml.contains("totally-not-rsl"));
    }

    #[test]
    fn install_and_current_round_trip() {
        let mut docs = ProjectionDocs {
            config_version: 99,
            ..ProjectionDocs::default()
        };
        docs.robots_txt.insert(
            CompactString::new("a.example.com"),
            Bytes::from("User-agent: *\nDisallow:\n"),
        );
        install_projections(docs);
        let live = current_projections();
        assert_eq!(live.config_version, 99);
        assert!(live.robots_txt.contains_key("a.example.com"));
    }

    #[test]
    fn render_projections_with_listings_populates_listing_map() {
        // Compile a minimal config with no agent_skills at the
        // top-level, then add a Listing that carries `spec.skills[]`.
        // The Listing's index should land in
        // `docs.agent_skills_listings` keyed by `metadata.name`.
        let cfg = config_with_origin("api.example.com", serde_json::json!({"type": "rate_limit"}));
        let yaml = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: scoped-listing
spec:
  type: api
  status: published
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin
        value: abc1234
  skills:
    - name: hello
      type: skill-md
      description: "Hello skill"
      url: /skills/hello.md
      visibility: public
      body: |
        # Hello
"#;
        let listing: sbproxy_config::Listing = serde_yaml::from_str(yaml).unwrap();
        let mut findings = Vec::new();
        let registry = ListingRegistry::from_loaded(
            vec![sbproxy_config::LoadedListing {
                source_path: std::path::PathBuf::from("listings/scoped.yaml"),
                listing,
            }],
            &mut findings,
        );
        let docs = render_projections_with_listings(&cfg, &registry, 42);
        let scoped = docs
            .agent_skills_listings
            .get("scoped-listing")
            .expect("listing-scoped index missing");
        assert_eq!(scoped.listing_name, "scoped-listing");
        assert_eq!(scoped.hostnames.len(), 1);
        assert_eq!(scoped.hostnames[0].as_str(), "api.example.com");
        assert_eq!(scoped.index.entries.len(), 1);
        assert_eq!(scoped.index.entries[0].name, "hello");
    }

    #[test]
    fn render_projections_empty_registry_keeps_listing_map_empty() {
        let cfg = config_with_origin("api.example.com", serde_json::json!({"type": "rate_limit"}));
        let docs = render_projections(&cfg, 1);
        assert!(docs.agent_skills_listings.is_empty());
    }

    // --- WOR-808 PR5: inject_license_link ---

    #[test]
    fn inject_license_link_inserts_after_head_open() {
        let body = b"<html><head><title>x</title></head><body>hi</body></html>";
        let out = inject_license_link(body, "/licenses.xml");
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("<head><link rel=\"license\" href=\"/licenses.xml\"><title>"));
    }

    #[test]
    fn inject_license_link_handles_head_with_attributes() {
        let body = b"<html><HEAD lang=\"en\"><title>x</title></HEAD></html>";
        let out = inject_license_link(body, "/licenses.xml");
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("<HEAD lang=\"en\"><link rel=\"license\" href=\"/licenses.xml\">"),
            "preserve original head attrs + casing; got: {s}"
        );
    }

    #[test]
    fn inject_license_link_skips_when_license_already_present() {
        let body = b"<html><head><link REL=\"License\" href=\"/old.xml\"></head></html>";
        let out = inject_license_link(body, "/licenses.xml");
        // Match is case-insensitive, so an existing link suppresses
        // the injection regardless of attribute casing.
        assert_eq!(out, body.to_vec());
    }

    #[test]
    fn inject_license_link_skips_when_no_head_tag() {
        let body = b"<html><body>fragment</body></html>";
        let out = inject_license_link(body, "/licenses.xml");
        assert_eq!(out, body.to_vec());
    }

    #[test]
    fn inject_license_link_does_not_match_header_tag() {
        // `<header>` shares the `<head` prefix; the disambiguation
        // must reject it so we don't insert the link tag at top-level
        // content.
        let body = b"<html><body><header>nav</header></body></html>";
        let out = inject_license_link(body, "/licenses.xml");
        assert_eq!(out, body.to_vec());
    }

    #[test]
    fn inject_license_link_handles_self_closing_head_attr_quirk() {
        // Some templating engines emit `<head/>` followed by content;
        // the open-tag span ends at the `>` regardless, so injection
        // still slots correctly after the head open.
        let body = b"<head/><body>x</body>";
        let out = inject_license_link(body, "/x.xml");
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.starts_with("<head/><link rel=\"license\" href=\"/x.xml\">"),
            "got: {s}"
        );
    }

    // --- WOR-808 PR6: inject_license_link_xml + classify_feed_content_type ---

    #[test]
    fn classify_feed_content_type_resolves_rss_and_atom() {
        assert_eq!(
            classify_feed_content_type("application/rss+xml"),
            Some(FeedFormat::Rss)
        );
        assert_eq!(
            classify_feed_content_type("application/atom+xml"),
            Some(FeedFormat::Atom)
        );
        // Case-insensitive on the main type.
        assert_eq!(
            classify_feed_content_type("Application/RSS+XML"),
            Some(FeedFormat::Rss)
        );
        // Strips parameters.
        assert_eq!(
            classify_feed_content_type("application/atom+xml; charset=utf-8"),
            Some(FeedFormat::Atom)
        );
        // Non-feed types pass through as None.
        assert_eq!(classify_feed_content_type("text/html"), None);
        assert_eq!(classify_feed_content_type("application/xml"), None);
        assert_eq!(classify_feed_content_type(""), None);
    }

    #[test]
    fn inject_license_link_xml_rss_inserts_after_channel_open() {
        let body = b"<?xml version=\"1.0\"?><rss version=\"2.0\"><channel><title>x</title></channel></rss>";
        let out = inject_license_link_xml(body, "/licenses.xml", FeedFormat::Rss);
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("<channel><link rel=\"license\" href=\"/licenses.xml\"/><title>"),
            "got: {s}"
        );
    }

    #[test]
    fn inject_license_link_xml_atom_inserts_after_feed_open() {
        let body =
            b"<?xml version=\"1.0\"?><feed xmlns=\"http://www.w3.org/2005/Atom\"><title>x</title></feed>";
        let out = inject_license_link_xml(body, "/licenses.xml", FeedFormat::Atom);
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains(
                "<feed xmlns=\"http://www.w3.org/2005/Atom\"><link rel=\"license\" href=\"/licenses.xml\"/><title>"
            ),
            "got: {s}"
        );
    }

    #[test]
    fn inject_license_link_xml_idempotent_on_existing_license() {
        let body =
            b"<rss><channel><link rel=\"license\" href=\"/old.xml\"/><title>x</title></channel></rss>";
        let out = inject_license_link_xml(body, "/licenses.xml", FeedFormat::Rss);
        assert_eq!(out, body.to_vec());
    }

    #[test]
    fn inject_license_link_xml_skips_when_root_missing() {
        // Atom format but body has no <feed>; injection is a no-op.
        let body = b"<rss><channel><title>x</title></channel></rss>";
        let out = inject_license_link_xml(body, "/licenses.xml", FeedFormat::Atom);
        assert_eq!(out, body.to_vec());
    }

    #[test]
    fn find_container_open_skips_false_prefix_match() {
        // `<channels>` shares the `<channel` prefix; the search must
        // skip it and find the real `<channel>` later in the doc.
        let lower = "<rss><channels-list/><channel><title>";
        let pos = find_container_open(lower, "<channel").expect("found");
        // The real `<channel>` open ends at the second `>`; the slice
        // up to `pos` must include `<channel>`.
        assert!(
            &lower[..pos].ends_with("<channel>"),
            "got prefix: {}",
            &lower[..pos]
        );
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        let body = Bytes::from_static(b"abc");
        // Standard SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex(&body),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
