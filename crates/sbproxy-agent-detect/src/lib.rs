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

/// Placeholder TLS signal shell. The fields land in WOR-586 + WOR-590;
/// the unit struct keeps the type name reachable from the rest of the
/// proxy now so later slices can fill it in without churning callers.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TlsSignals {
    // Reserved for WOR-586 / WOR-590. Fields intentionally omitted in
    // the slice-1 skeleton; adding them later is backward-compatible
    // because the struct is `Default` and not constructed by name in
    // tests today.
    #[doc(hidden)]
    pub _reserved: (),
}

/// Placeholder HTTP signal shell. Fields land in WOR-587.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HttpSignals {
    #[doc(hidden)]
    pub _reserved: (),
}

/// Placeholder payload signal shell. Fields land in WOR-591.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PayloadSignals {
    #[doc(hidden)]
    pub _reserved: (),
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
}
