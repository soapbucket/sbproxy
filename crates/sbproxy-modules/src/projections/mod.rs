//! Wave 4 / G4.5..G4.10 wire: policy-graph projections.
//!
//! See `docs/adr-policy-graph-projections.md` (A4.1) for the full
//! contract. The four projections are:
//!
//! - `robots.txt` (G4.5) per IETF draft-koster-rep-ai
//! - `llms.txt` and `llms-full.txt` (G4.6) per the Anthropic / Mistral
//!   convention
//! - `/licenses.xml` (G4.7) per RSL 1.0
//! - `/.well-known/tdmrep.json` (G4.8) per W3C TDMRep
//!
//! All four are derived from the same compiled-policy graph
//! (`CompiledConfig`); they share an in-memory cache so the data plane
//! pays one atomic load and one hash-map lookup per request. Cache
//! refresh runs once per config reload, atomically.
//!
//! ## Crate placement (A4.1 open question 1)
//!
//! The substrate (cache + render entrypoint) lives in `sbproxy-modules`
//! rather than `sbproxy-core` to avoid the circular-dep risk A4.1's
//! open question 1 flagged: `sbproxy-modules` already depends on
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
use sbproxy_config::CompiledConfig;
use sbproxy_plugin::{current_admin_audit_emitter, ProjectionRefreshEvent};
use sha2::{Digest, Sha256};

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
    /// Per-hostname `robots.txt` bodies (G4.5).
    pub robots_txt: HashMap<CompactString, Bytes>,
    /// Per-hostname `llms.txt` bodies (G4.6).
    pub llms_txt: HashMap<CompactString, Bytes>,
    /// Per-hostname `llms-full.txt` bodies (G4.6).
    pub llms_full_txt: HashMap<CompactString, Bytes>,
    /// Per-hostname `/licenses.xml` bodies (G4.7).
    pub licenses_xml: HashMap<CompactString, Bytes>,
    /// Per-hostname `/.well-known/tdmrep.json` bodies (G4.8).
    pub tdmrep_json: HashMap<CompactString, Bytes>,
    /// Per-hostname RSL URN of the form
    /// `urn:rsl:1.0:<hostname>:<config_version_hash>`. Stamped on
    /// `RequestContext.rsl_urn` by the request pipeline so downstream
    /// serialisers (the A4.2 JSON envelope, agent-facing responses)
    /// can surface the URN without re-reading the projection body.
    pub rsl_urns: HashMap<CompactString, String>,
    /// Per-hostname `Content-Signal` value (or `None` when the origin
    /// asserts no signal). Surfaced to the response middleware so the
    /// proxy can stamp the optional `TDM-Reservation: 1` header per
    /// A4.1 § "TDMRep" when an origin asserts no `Content-Signal`.
    pub content_signals: HashMap<CompactString, Option<CompactString>>,
}

/// Compute all four projection bodies for every origin in `config`.
///
/// Walks `config.origins`, filters for origins with an
/// `ai_crawl_control` policy entry in `policy_configs`, extracts the
/// pricing tiers and the `Content-Signal` value (read from the
/// origin's `extensions["content_signal"]` slot per A4.1's open
/// question 1.5 / G4.2 hand-off), and renders the four documents.
///
/// Origins without `ai_crawl_control` produce no entries; readers
/// treat the absence as a 404.
pub fn render_projections(config: &CompiledConfig, config_version: u64) -> ProjectionDocs {
    let mut docs = ProjectionDocs {
        config_version,
        ..ProjectionDocs::default()
    };

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

        // --- robots.txt (G4.5) ---
        let robots = robots::render(hostname.as_str(), ai_crawl, config_version);
        docs.robots_txt
            .insert(hostname.clone(), Bytes::from(robots));

        // --- llms.txt + llms-full.txt (G4.6) ---
        let (llms, llms_full) = llms::render(hostname.as_str(), ai_crawl, config_version);
        docs.llms_txt.insert(hostname.clone(), Bytes::from(llms));
        docs.llms_full_txt
            .insert(hostname.clone(), Bytes::from(llms_full));

        // --- licenses.xml (G4.7) ---
        let (xml, urn) =
            licenses::render(hostname.as_str(), content_signal.as_deref(), config_version);
        docs.licenses_xml.insert(hostname.clone(), Bytes::from(xml));
        docs.rsl_urns.insert(hostname.clone(), urn);

        // --- tdmrep.json (G4.8) ---
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
/// capture an `AdminAuditEvent` per A1.7 / A4.1 § "Audit trail".
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
/// without blocking the reload writer. Per A4.1 the readers pay one
/// atomic load per request (plus one HashMap lookup by hostname); no
/// allocations on the hot path.
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
    fn sha256_hex_matches_known_vector() {
        let body = Bytes::from_static(b"abc");
        // Standard SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex(&body),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
