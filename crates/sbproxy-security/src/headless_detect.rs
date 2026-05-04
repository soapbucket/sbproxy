//! Headless-browser detection via TLS fingerprint matching.
//!
//! Wave 5 / G5.4. See `docs/adr-tls-fingerprint-pipeline.md`.
//!
//! # What this module does
//!
//! Reads a request's JA4 fingerprint (captured by
//! `sbproxy-tls::parse_client_hello` at handshake time) and compares
//! it against the vendored TLS-fingerprint catalogue
//! (`crates/sbproxy-classifiers/data/tls-fingerprints.json`). On a
//! match, it returns [`HeadlessSignal::Detected`] with the library
//! name (`puppeteer`, `playwright`, ...) and a confidence score.
//!
//! # Trustworthy gating
//!
//! Per A5.1, when the request's TLS fingerprint is NOT trustworthy
//! (e.g. arrived via Cloudflare, where the proxy sees the CDN's TLS
//! library, not the agent's), the detector still records the signal
//! but halves the confidence and caps it at 0.5. This makes the
//! signal advisory rather than load-bearing for hard policy
//! decisions made by trustworthy=false traffic.
//!
//! # Agent classes added
//!
//! The Wave 5 catalog update ships three new entries that the G1.4
//! resolver chain emits when this detector matches:
//!
//! - `headless-browser` (generic fallthrough)
//! - `headless-puppeteer`
//! - `headless-playwright`
//!
//! See `crates/sbproxy-classifiers/data/agent_classes_default.yaml`.

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

// --- Public types ---

/// Verdict produced by the headless detector. This crate keeps its
/// own copy of the verdict type (mirrored in
/// `sbproxy-core::context::HeadlessSignal`) so security policies can
/// reason about the signal without pulling the proxy core into the
/// dep graph.
#[derive(Debug, Clone, PartialEq)]
pub enum HeadlessSignal {
    /// Detector ran and matched a known headless library.
    Detected {
        /// Library name (`puppeteer`, `playwright`, ...). Stable
        /// across releases; safe for metric labels.
        library: String,
        /// Confidence in `[0.0, 1.0]`. Halved (capped at 0.5) when
        /// `trustworthy = false` per A5.1.
        confidence: f32,
    },
    /// Detector ran and did NOT match any known headless library.
    NotDetected,
}

// --- Catalog loader ---

/// One entry in the vendored TLS-fingerprint catalogue.
///
/// Mirrors the JSON schema documented in A5.1 §"Reference fingerprint
/// catalogue". Every field defaults to empty so partial entries (e.g.
/// agents with no published JA4 yet) parse without error.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsFingerprintEntry {
    /// Catalog `agent_class` id (kebab-case, matches
    /// `agent_classes_default.yaml`).
    pub agent_class: String,
    #[serde(default)]
    /// Known JA3 fingerprints for this agent class (32-char hex).
    pub ja3: Vec<String>,
    #[serde(default)]
    /// Known JA4 fingerprints for this agent class (FoxIO format).
    pub ja4: Vec<String>,
    #[serde(default)]
    /// Known JA4H fingerprints for this agent class.
    pub ja4h: Vec<String>,
    #[serde(default)]
    /// Free-form notes (sources, dates).
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct CatalogFile {
    #[allow(dead_code)]
    version: u32,
    #[allow(dead_code)]
    updated_at: Option<String>,
    entries: Vec<TlsFingerprintEntry>,
}

/// Loaded TLS-fingerprint catalogue with prebuilt JA4 -> entry index
/// for O(1) detector lookups.
///
/// Built once at startup (or on SIGHUP reload) from the vendored
/// JSON file. The proxy holds it behind an `Arc` so the
/// detector hot path borrows without cloning.
#[derive(Debug, Clone)]
pub struct TlsFingerprintCatalog {
    entries: Vec<TlsFingerprintEntry>,
    /// Reverse index: `ja4` value -> `entries` index. Empty JA4
    /// fields are not indexed.
    by_ja4: HashMap<String, usize>,
}

/// Embedded default catalogue. Consumed at startup; operators can
/// override via the `tls_fingerprint.catalog_path` config or replace
/// at build time.
pub const DEFAULT_TLS_FINGERPRINT_JSON: &str =
    include_str!("../../sbproxy-classifiers/data/tls-fingerprints.json");

impl TlsFingerprintCatalog {
    /// Parse a catalogue from raw JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        let file: CatalogFile =
            serde_json::from_str(json).context("failed to parse tls-fingerprints.json")?;
        Self::from_entries(file.entries)
    }

    /// Build a catalogue from a parsed entry list. Validates that
    /// each `agent_class` is non-empty and that JA4 values do not
    /// collide across agent classes.
    pub fn from_entries(entries: Vec<TlsFingerprintEntry>) -> Result<Self> {
        let mut by_ja4 = HashMap::new();
        for (idx, entry) in entries.iter().enumerate() {
            if entry.agent_class.is_empty() {
                anyhow::bail!("tls-fingerprint catalog entry at index {idx} has empty agent_class");
            }
            for ja4 in &entry.ja4 {
                if let Some(prev) = by_ja4.insert(ja4.clone(), idx) {
                    let prev_class = &entries[prev].agent_class;
                    let cur_class = &entry.agent_class;
                    if prev_class != cur_class {
                        // Collisions across agent classes are noisy
                        // but not fatal; the latest entry wins. Log so
                        // operators notice when a feed update
                        // overlaps two libraries.
                        tracing::warn!(
                            ja4 = %ja4,
                            previous = %prev_class,
                            current = %cur_class,
                            "JA4 fingerprint collision; later entry wins"
                        );
                    }
                }
            }
        }
        Ok(Self { entries, by_ja4 })
    }

    /// Build the embedded default catalogue.
    pub fn default_embedded() -> Result<Self> {
        Self::from_json(DEFAULT_TLS_FINGERPRINT_JSON)
    }

    /// Number of entries in the catalogue.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the catalogue has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up the agent class for a given JA4 fingerprint.
    /// Returns `None` if no entry has the JA4 in its `ja4` list.
    pub fn lookup_ja4(&self, ja4: &str) -> Option<&TlsFingerprintEntry> {
        self.by_ja4.get(ja4).map(|idx| &self.entries[*idx])
    }

    /// CEL helper: return `true` when `ja4` is associated with
    /// `agent_class_id` in the catalogue. When the catalogue has no
    /// entry for `agent_class_id`, returns `true` (conservative; do
    /// not penalise uncatalogued agents). Per A5.1.
    pub fn matches(&self, ja4: &str, agent_class_id: &str) -> bool {
        // Find the entry for this agent_class.
        let entry = self
            .entries
            .iter()
            .find(|e| e.agent_class == agent_class_id);
        let entry = match entry {
            Some(e) => e,
            None => return true, // uncatalogued -> conservative true
        };
        if entry.ja4.is_empty() {
            // Catalogued but no JA4 published yet -> conservative true.
            return true;
        }
        entry.ja4.iter().any(|known| known == ja4)
    }
}

// --- Detector ---

/// Run the headless-browser detector against a JA4 fingerprint.
///
/// Returns:
///
/// - [`HeadlessSignal::Detected`] when `ja4` matches a catalogue
///   entry whose `agent_class` starts with `headless-`. Confidence
///   is set from the entry's library tier (currently fixed at
///   `0.95` for known matches per A5.1) and halved (capped at 0.5)
///   when `trustworthy = false`.
/// - [`HeadlessSignal::NotDetected`] when `ja4` is `None` or no
///   match is found.
///
/// Library names come from the entry's `agent_class` with the
/// `headless-` prefix stripped (e.g. `headless-puppeteer` ->
/// `puppeteer`). Generic `headless-browser` matches return
/// `library = "browser"`.
pub fn detect(
    catalog: &TlsFingerprintCatalog,
    ja4: Option<&str>,
    trustworthy: bool,
) -> HeadlessSignal {
    let ja4 = match ja4 {
        Some(s) if !s.is_empty() => s,
        _ => return HeadlessSignal::NotDetected,
    };

    let entry = match catalog.lookup_ja4(ja4) {
        Some(e) => e,
        None => return HeadlessSignal::NotDetected,
    };

    if !entry.agent_class.starts_with("headless-") {
        // Catalog hit but not a headless library (e.g. GPTBot).
        // The headless detector intentionally does not report on
        // these; the bot-auth and UA-spoof detectors own that
        // decision path.
        return HeadlessSignal::NotDetected;
    }

    let library = entry
        .agent_class
        .strip_prefix("headless-")
        .unwrap_or("browser")
        .to_string();
    // Library tiers: 0.95 baseline for known headless matches per
    // the ADR worked example; halved + capped at 0.5 when not
    // trustworthy.
    let baseline = 0.95_f32;
    let confidence = if trustworthy {
        baseline
    } else {
        (baseline * 0.5).min(0.5)
    };
    HeadlessSignal::Detected {
        library,
        confidence,
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn test_catalog() -> TlsFingerprintCatalog {
        let entries = vec![
            TlsFingerprintEntry {
                agent_class: "headless-puppeteer".to_string(),
                ja3: vec![],
                ja4: vec!["t13d1516h2_8daaf6152771".to_string()],
                ja4h: vec![],
                notes: None,
            },
            TlsFingerprintEntry {
                agent_class: "headless-playwright".to_string(),
                ja3: vec![],
                ja4: vec!["t13d1517h2_aaaaaaaaaaaa".to_string()],
                ja4h: vec![],
                notes: None,
            },
            TlsFingerprintEntry {
                agent_class: "openai-gptbot".to_string(),
                ja3: vec![],
                ja4: vec!["t13d1715h2_5b57614c22b0_3d5424432f57".to_string()],
                ja4h: vec![],
                notes: None,
            },
        ];
        TlsFingerprintCatalog::from_entries(entries).unwrap()
    }

    #[test]
    fn embedded_catalog_parses() {
        let cat = TlsFingerprintCatalog::default_embedded().unwrap();
        assert!(cat.len() >= 4, "embedded catalogue has the seed entries");
        assert!(!cat.is_empty());
    }

    #[test]
    fn detects_puppeteer_when_trustworthy() {
        let cat = test_catalog();
        let r = detect(&cat, Some("t13d1516h2_8daaf6152771"), true);
        match r {
            HeadlessSignal::Detected {
                library,
                confidence,
            } => {
                assert_eq!(library, "puppeteer");
                assert!(
                    (confidence - 0.95).abs() < f32::EPSILON,
                    "trustworthy=true keeps the 0.95 baseline, got {confidence}"
                );
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }

    #[test]
    fn halves_confidence_when_not_trustworthy() {
        let cat = test_catalog();
        let r = detect(&cat, Some("t13d1516h2_8daaf6152771"), false);
        match r {
            HeadlessSignal::Detected { confidence, .. } => {
                assert!(
                    confidence <= 0.5,
                    "trustworthy=false caps confidence at 0.5, got {confidence}"
                );
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }

    #[test]
    fn returns_not_detected_for_unknown_ja4() {
        let cat = test_catalog();
        let r = detect(&cat, Some("t13d9999h2_xxxxxxxxxxxx"), true);
        assert_eq!(r, HeadlessSignal::NotDetected);
    }

    #[test]
    fn returns_not_detected_for_missing_ja4() {
        let cat = test_catalog();
        assert_eq!(detect(&cat, None, true), HeadlessSignal::NotDetected);
        assert_eq!(detect(&cat, Some(""), true), HeadlessSignal::NotDetected);
    }

    #[test]
    fn ignores_non_headless_catalog_entries() {
        // GPTBot is in the catalog but its agent_class does not
        // start with `headless-`; the headless detector must not
        // flag it.
        let cat = test_catalog();
        let r = detect(&cat, Some("t13d1715h2_5b57614c22b0_3d5424432f57"), true);
        assert_eq!(r, HeadlessSignal::NotDetected);
    }

    #[test]
    fn matches_helper_returns_true_for_uncatalogued_class() {
        // Per A5.1: `tls_fingerprint_matches` returns true when the
        // catalogue has no entry for the given class. This avoids
        // penalising uncatalogued agents.
        let cat = test_catalog();
        assert!(cat.matches("anything", "made-up-class"));
    }

    #[test]
    fn matches_helper_returns_true_when_class_has_no_ja4_entries() {
        // `anthropic-claudebot` ships in the embedded catalogue with
        // an empty ja4 array; matches() must conservatively return
        // true.
        let cat = TlsFingerprintCatalog::default_embedded().unwrap();
        assert!(cat.matches("any-ja4", "anthropic-claudebot"));
    }

    #[test]
    fn matches_helper_returns_false_for_class_with_known_but_different_ja4() {
        let cat = test_catalog();
        assert!(!cat.matches("not-the-real-ja4", "headless-puppeteer"));
        assert!(cat.matches("t13d1516h2_8daaf6152771", "headless-puppeteer"));
    }

    #[test]
    fn lookup_ja4_returns_correct_entry() {
        let cat = test_catalog();
        let e = cat
            .lookup_ja4("t13d1516h2_8daaf6152771")
            .expect("known JA4 must map to entry");
        assert_eq!(e.agent_class, "headless-puppeteer");
        assert!(cat.lookup_ja4("nope").is_none());
    }

    #[test]
    fn from_json_parses_embedded_schema() {
        let json = r#"{
            "version": 1,
            "updated_at": "2026-05-01T00:00:00Z",
            "entries": [
                {
                    "agent_class": "headless-puppeteer",
                    "ja4": ["t13d1516h2_8daaf6152771"]
                }
            ]
        }"#;
        let cat = TlsFingerprintCatalog::from_json(json).unwrap();
        assert_eq!(cat.len(), 1);
        let r = detect(&cat, Some("t13d1516h2_8daaf6152771"), true);
        assert!(matches!(r, HeadlessSignal::Detected { .. }));
    }

    #[test]
    fn empty_agent_class_is_rejected() {
        let entries = vec![TlsFingerprintEntry {
            agent_class: "".to_string(),
            ja3: vec![],
            ja4: vec![],
            ja4h: vec![],
            notes: None,
        }];
        let err = TlsFingerprintCatalog::from_entries(entries).unwrap_err();
        assert!(err.to_string().contains("empty agent_class"));
    }

    #[test]
    fn confidence_floor_is_zero_or_above() {
        // Sanity: confidence stays in the documented range.
        let cat = test_catalog();
        let r = detect(&cat, Some("t13d1516h2_8daaf6152771"), false);
        if let HeadlessSignal::Detected { confidence, .. } = r {
            assert!((0.0..=1.0).contains(&confidence));
        }
    }
}
