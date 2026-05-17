//! Agent fingerprinting and detection library (WOR-499 Module 1.1).
//!
//! The proxy needs a single typed answer to "is this an agent, and which
//! one?" that downstream policies, audit, and scripting can branch on
//! without re-deriving the answer from the underlying TLS / HTTP /
//! payload signals each time. This crate ships that answer:
//! [`AgentDetection`] carries a 0-100 score, an optional named id, a
//! provenance enum, a confidence number, and the list of signals the
//! scorer consulted. The rest of the proxy reads the struct off the
//! request context.
//!
//! This is the first slice (WOR-584): the crate skeleton + the public
//! shapes + the [`AgentScorer`] trait + a default scorer that returns
//! [`AgentProvenance::UnsignedAnonymous`] with a score of 0. The signal
//! extractor types ([`TlsSignals`], [`HttpSignals`], [`PayloadSignals`])
//! are intentionally placeholder shells so later slices can fill them
//! in without changing the public API surface that downstream code
//! starts taking dependencies on.
//!
//! Later slices:
//!
//! - **WOR-585**: ADRF YAML rule-pack format + parser + Claude Code /
//!   Cursor / Codex CLI / Copilot / Junie fixtures.
//! - **WOR-586**: surface JA4 / JA4H / JA4S from `sbproxy-tls` plus
//!   ALPN + SNI capture on [`TlsSignals`].
//! - **WOR-587**: HTTP signal extractors (header order hash, vendor
//!   header presence, User-Agent bucketing, cookie persistence).
//! - **WOR-588**: hot-reload of rule packs via `ArcSwap` + SIGHUP.
//! - **WOR-589**: expose `request.agent.*` on the CEL / Lua / JS /
//!   WASM scripting surfaces.
//! - **WOR-590**: JA4T (TCP fingerprint) + JA4X (cert-chain fingerprint).
//! - **WOR-591**: payload-shaped signals (filesystem-path leakage,
//!   stack-trace shape, embedding-burst heuristic).
//! - **WOR-592**: ONNX CatBoost scorer + Prometheus metrics.

use serde::{Deserialize, Serialize};

pub mod http_extractors;
pub mod loader;
pub mod payload_extractors;
pub mod rules;

pub use http_extractors::{
    extract_http_signals, header_order_hash, user_agent_bucket, vendor_headers, UserAgentBucket,
};
pub use loader::{
    ReloadMetrics, ReloadOutcome, RulePackLoader, RELOAD_METRIC_NAME, RELOAD_OUTCOME_LABELS,
};
pub use payload_extractors::{
    count_unique_filesystem_paths, extract_payload_signals, is_stack_trace_shaped,
};
pub use rules::{AgentRule, MatchSpec, RulePack, RulePackError};

// --- Public detection shape -------------------------------------------------

/// Outcome the scorer produces for a single request.
///
/// Field semantics are normative; downstream policy code and audit
/// events read these directly. The shape is stable across the slice
/// landings; later slices populate richer values for `signals_used`
/// without changing the surface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentDetection {
    /// Probability the traffic is agent-origin, scaled 0-100. The
    /// scorer is responsible for clamping into range; consumers can
    /// rely on `score <= 100`.
    pub score: u8,
    /// Named agent identifier when the rule pack matched. `None` for
    /// unsigned-anonymous traffic.
    pub agent_id: Option<String>,
    /// Identity provenance tier (signed vs unsigned-named vs
    /// unsigned-anonymous). Distinct from the score because a
    /// signed-but-low-score request is a different operator decision
    /// than an unsigned-named request scored high.
    pub provenance: AgentProvenance,
    /// Confidence the scorer attaches to the produced result. Range
    /// `0.0..=1.0`. Independent of `score`: a high score with low
    /// confidence is the model saying "looks agenty but I am not
    /// sure".
    pub confidence: f32,
    /// Signals the scorer actually consulted. Audit log uses this to
    /// reconstruct the why behind a decision; rule-pack authors use
    /// it to find which extractors are populated for their cohort.
    pub signals_used: Vec<String>,
}

impl AgentDetection {
    /// Build the empty, unscored detection. Used when no scorer is
    /// configured or the scorer short-circuits (e.g. internal health
    /// checks).
    pub fn unscored() -> Self {
        Self {
            score: 0,
            agent_id: None,
            provenance: AgentProvenance::UnsignedAnonymous,
            confidence: 0.0,
            signals_used: Vec::new(),
        }
    }
}

/// Identity provenance tier. Ordered loosely from strongest to
/// weakest signal: `Signed` means the request carries a verified
/// Web Bot Auth / KYA / TAP signature; `UnsignedNamed` means the rule
/// pack matched a named agent without a signature; `UnsignedAnonymous`
/// is the catch-all for traffic that does not match a rule and is
/// not signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentProvenance {
    /// Carries a verified signature (WBA / KYA / TAP / similar).
    Signed,
    /// Rule pack matched a named agent without a signature.
    UnsignedNamed,
    /// Not matched and not signed. Default for unrecognised traffic.
    UnsignedAnonymous,
}

impl AgentProvenance {
    /// Stable string identifier for metric labels and scripting
    /// exposure. Matches the kebab-case serde discriminant.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::UnsignedNamed => "unsigned-named",
            Self::UnsignedAnonymous => "unsigned-anonymous",
        }
    }
}

// --- Signal shapes ----------------------------------------------------------

/// Bag of signal extractor outputs the scorer reads. Each layer is
/// optional because later slices wire them in incrementally and the
/// scorer must produce a sensible default in the meantime.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Signals {
    /// TLS-layer signals (JA4, JA4H, JA4S, JA4T, JA4X, ALPN, SNI).
    /// Populated by WOR-586 (and WOR-590 for JA4T / JA4X).
    pub tls: Option<TlsSignals>,
    /// HTTP-layer signals (header order hash, vendor-header presence,
    /// User-Agent bucket, cookie persistence). Populated by WOR-587.
    pub http: Option<HttpSignals>,
    /// Payload-shaped signals (filesystem-path leakage, stack-trace
    /// shape, embedding-burst heuristic). Populated by WOR-591.
    pub payload: Option<PayloadSignals>,
}

/// TLS-layer signals. Slice 2 (WOR-585) seeded the minimal field set;
/// slice 3 (WOR-586) mirrors the full `sbproxy_tls::fingerprint::TlsFingerprint`
/// shape: JA4 (ClientHello), JA4H (request), JA4S (ServerHello)
/// fingerprints plus ALPN list and SNI hostname. Slice 7 (WOR-590)
/// will add JA4T + JA4X.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TlsSignals {
    /// JA4 ClientHello fingerprint string (FoxIO format).
    pub ja4: Option<String>,
    /// JA4H HTTP request fingerprint. Populated mid-pipeline once the
    /// request headers are visible.
    pub ja4h: Option<String>,
    /// JA4S TLS ServerHello fingerprint from the proxy's outbound
    /// session. `None` for inbound-only captures.
    pub ja4s: Option<String>,
    /// SNI host_name the client requested, lowercased. `None` when
    /// the extension was absent.
    pub sni: Option<String>,
    /// Full ALPN protocol-id list in wire order, GREASE filtered.
    /// Empty when the extension was absent.
    pub alpn: Vec<String>,
    /// Whether the ClientHello advertised a post-quantum hybrid key
    /// share (WOR-501). True for browsers that have rolled out
    /// X25519MLKEM768 (Chrome / Edge default in 2026); false for
    /// stock SDK HTTP stacks, which do not negotiate MLKEM. The
    /// scorer uses the *absence* of this signal on a request whose
    /// User-Agent claims a real browser as a high-confidence
    /// non-browser tell.
    pub pq_tls_present: bool,
}

impl From<&sbproxy_tls::fingerprint::TlsFingerprint> for TlsSignals {
    /// Lossless projection of the TLS-layer fingerprint onto the
    /// agent-detect signal type. Callers attach a `TlsFingerprint` at
    /// handshake time per the existing layering; downstream agent-
    /// detect scoring reads only this projection so it does not need
    /// to know about the `trustworthy` CIDR classification or the
    /// JA3 hash (neither of which the rule-pack matcher consults).
    fn from(fp: &sbproxy_tls::fingerprint::TlsFingerprint) -> Self {
        Self {
            ja4: fp.ja4.clone(),
            ja4h: fp.ja4h.clone(),
            ja4s: fp.ja4s.clone(),
            sni: fp.sni.clone(),
            alpn: fp.alpn.clone(),
            pq_tls_present: fp.pq_tls_present,
        }
    }
}

/// HTTP-layer signals consumed by the rule-pack matcher and the
/// future ML scorer. Slice 2 (WOR-585) seeded the matcher fields
/// (`user_agent`, `headers_present`); slice 4 (WOR-587) extends the
/// shape with the order-sensitive + vendor-aware extractors the
/// scoring layer needs.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HttpSignals {
    /// Raw `User-Agent` header value, when present.
    pub user_agent: Option<String>,
    /// Lowercased header names the request carried, in arrival
    /// order. Used by the rule-pack matcher's `header_present`
    /// predicate and by the order-sensitive
    /// [`header_order_hash`] extractor.
    pub headers_present: Vec<String>,
    /// SHA-256 hex (lowercase, 64 chars) of the concatenated
    /// `\n`-delimited lowercased header-name list, computed in
    /// arrival order. Stable across requests with identical header
    /// order; differs on any reorder. Empty when no headers were
    /// captured (so a stream of zero-header requests does not all
    /// collide on the SHA-256 of the empty string).
    pub header_order_hash: String,
    /// Lowercased vendor-aware header names detected on the request.
    /// Recognised names (slice 4): `x-stainless-*` family (OpenAI
    /// Stainless SDKs and downstream consumers like Anthropic's
    /// Claude Code CLI), `anthropic-version`, `openai-beta`.
    pub vendor_headers: Vec<String>,
    /// Coarse User-Agent classification computed by
    /// [`user_agent_bucket`]. `None` when no `User-Agent` header was
    /// captured.
    pub user_agent_bucket: Option<UserAgentBucket>,
    /// Whether the request carried a `Cookie` header. Crude proxy
    /// for "this client persists state across requests", which is
    /// rare for stateless agent / SDK traffic and ubiquitous for
    /// real browsers.
    pub cookie_persistence: bool,
}

/// Payload-shaped signals lifted from the request body. Slice 8
/// (WOR-591) introduces the three fields the scorer reads against
/// today. See [`crate::payload_extractors`] for the pure-function
/// extractors that build this struct from a body slice.
///
/// The signal set is intentionally PII-safe: filesystem-path
/// leakage is reported as a count (never the path text), and the
/// stack-trace detector returns a boolean. Operators can ship the
/// full struct to metrics and audit without a redactor in the path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PayloadSignals {
    /// Number of unique absolute filesystem paths the body leaks.
    /// Matches the three OS home-directory shapes (macOS, Linux,
    /// Windows). Surfaces the count only; the path text is never
    /// retained on this struct so the signal is safe to log.
    pub filesystem_paths_leaked: u32,
    /// True when the body contains a recognised runtime stack
    /// trace (Python, Node, Go panic, Java). Useful for the agent
    /// scorer because human-driven traffic almost never POSTs a
    /// raw traceback to a model endpoint, but agent retry loops
    /// commonly forward the runtime error verbatim.
    pub stack_trace_shaped: bool,
    /// Reserved for the session-window embedding-burst heuristic.
    /// A per-request body cannot determine session-level rate, so
    /// this slice hard-wires the value to `false`; a follow-up
    /// will wire session state (request count + embedding-payload
    /// ratio over a sliding window) and flip the field on when
    /// the burst threshold is crossed.
    pub embedding_burst: bool,
}

// --- Scorer trait -----------------------------------------------------------

/// Compute an [`AgentDetection`] from the [`Signals`] bag.
///
/// The trait is `Send + Sync` so the scorer can live in an `Arc` and be
/// shared across the proxy's worker threads. Implementations should
/// avoid blocking IO inside `score`; long-running setup (model load,
/// rule-pack parse) belongs in a separate constructor.
pub trait AgentScorer: Send + Sync {
    /// Score a request's signal bag.
    fn score(&self, signals: &Signals) -> AgentDetection;
}

/// Default scorer used when no other scorer is registered. Returns the
/// neutral [`AgentDetection::unscored`] result so the field is always
/// present on the request context without forcing every config to wire
/// a real scorer.
///
/// The presence of `signals` is recorded in `signals_used` so a
/// downstream consumer can tell whether the extractors ran even on
/// this no-op scoring path.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultScorer;

impl AgentScorer for DefaultScorer {
    fn score(&self, signals: &Signals) -> AgentDetection {
        let mut signals_used = Vec::new();
        if signals.tls.is_some() {
            signals_used.push("tls".to_string());
        }
        if signals.http.is_some() {
            signals_used.push("http".to_string());
        }
        if signals.payload.is_some() {
            signals_used.push("payload".to_string());
        }
        AgentDetection {
            score: 0,
            agent_id: None,
            provenance: AgentProvenance::UnsignedAnonymous,
            confidence: 0.0,
            signals_used,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unscored_is_neutral() {
        let d = AgentDetection::unscored();
        assert_eq!(d.score, 0);
        assert!(d.agent_id.is_none());
        assert_eq!(d.provenance, AgentProvenance::UnsignedAnonymous);
        assert_eq!(d.confidence, 0.0);
        assert!(d.signals_used.is_empty());
    }

    #[test]
    fn provenance_as_str_is_kebab_case() {
        assert_eq!(AgentProvenance::Signed.as_str(), "signed");
        assert_eq!(AgentProvenance::UnsignedNamed.as_str(), "unsigned-named");
        assert_eq!(
            AgentProvenance::UnsignedAnonymous.as_str(),
            "unsigned-anonymous",
        );
    }

    #[test]
    fn provenance_serde_matches_as_str() {
        // serde rename_all = "kebab-case" must agree with the manual
        // `as_str()`. If anyone touches one without the other the
        // metric label and the audit JSON will drift.
        for p in [
            AgentProvenance::Signed,
            AgentProvenance::UnsignedNamed,
            AgentProvenance::UnsignedAnonymous,
        ] {
            let json = serde_json::to_value(p).unwrap();
            assert_eq!(json.as_str().unwrap(), p.as_str());
        }
    }

    #[test]
    fn default_scorer_records_no_signals_on_empty_bag() {
        let s: Box<dyn AgentScorer> = Box::new(DefaultScorer);
        let d = s.score(&Signals::default());
        assert_eq!(d.score, 0);
        assert!(d.signals_used.is_empty());
        assert_eq!(d.provenance, AgentProvenance::UnsignedAnonymous);
    }

    #[test]
    fn default_scorer_records_present_layers_in_signals_used() {
        let signals = Signals {
            tls: Some(TlsSignals::default()),
            http: Some(HttpSignals::default()),
            payload: None,
        };
        let d = DefaultScorer.score(&signals);
        assert_eq!(d.signals_used, vec!["tls".to_string(), "http".to_string()]);
    }

    #[test]
    fn default_scorer_is_trait_object_safe() {
        // Compile-time-only check that AgentScorer remains object-safe;
        // later slices need a `Box<dyn AgentScorer>` shape on the
        // request context.
        fn _accept(_: &dyn AgentScorer) {}
        _accept(&DefaultScorer);
    }

    // --- WOR-586: From<&TlsFingerprint> for TlsSignals ---

    #[test]
    fn from_empty_tls_fingerprint_yields_default_signals() {
        let fp = sbproxy_tls::fingerprint::TlsFingerprint::empty();
        let signals: TlsSignals = (&fp).into();
        assert!(signals.ja4.is_none());
        assert!(signals.ja4h.is_none());
        assert!(signals.ja4s.is_none());
        assert!(signals.sni.is_none());
        assert!(signals.alpn.is_empty());
    }

    #[test]
    fn from_populated_tls_fingerprint_mirrors_every_field() {
        let fp = sbproxy_tls::fingerprint::TlsFingerprint {
            ja3: Some("ignored".into()),
            ja4: Some("t13d1516h2_8daaf6152771".into()),
            ja4h: Some("ge11nn030000_d4ce69e9c2f0".into()),
            ja4s: Some("t1302h2_2e6abc78c2d7".into()),
            sni: Some("api.example.test".into()),
            alpn: vec!["h2".into(), "http/1.1".into()],
            pq_tls_present: true,
            trustworthy: true,
        };
        let signals: TlsSignals = (&fp).into();
        assert_eq!(signals.ja4.as_deref(), Some("t13d1516h2_8daaf6152771"));
        assert_eq!(signals.ja4h.as_deref(), Some("ge11nn030000_d4ce69e9c2f0"));
        assert_eq!(signals.ja4s.as_deref(), Some("t1302h2_2e6abc78c2d7"));
        assert_eq!(signals.sni.as_deref(), Some("api.example.test"));
        assert_eq!(signals.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert!(signals.pq_tls_present);
    }
}
