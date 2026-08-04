//! Headless-browser detection via TLS fingerprint matching.
//!
//! # What this module does
//!
//! Reads a request's JA4 fingerprint (captured by
//! `sbproxy-tls::parse_client_hello` at handshake time) and compares
//! it against a TLS-fingerprint catalogue. On a match, it returns
//! [`HeadlessSignal::Detected`] with the library name (`puppeteer`,
//! `playwright`, ...) and a confidence score.
//!
//! # The catalogue ships empty
//!
//! `crates/sbproxy-classifiers/data/tls-fingerprints.json` names the
//! agent classes and carries no fingerprints. A JA4 value is a
//! measurement of one specific client build, and the published
//! collections of those measurements carry their own license terms, so a
//! populated default meant redistributing licensed third-party data
//! inside an Apache-2.0 binary (WOR-2296).
//!
//! An absent or empty class answers `true`, the conservative direction,
//! so a stock build never contradicts a client on fingerprint grounds.
//! Operators supply measured values with
//! `proxy.extensions.tls_fingerprint.catalog_file`, which replaces the
//! embedded catalogue wholesale rather than merging into it. See
//! `docs/headless-detection.md` for how to capture one.
//!
//! # Trustworthy gating
//!
//! When the request's TLS fingerprint is NOT trustworthy
//! (e.g. arrived via Cloudflare, where the proxy sees the CDN's TLS
//! library, not the agent's), the detector still records the signal
//! but halves the confidence and caps it at 0.5. This makes the
//! signal advisory rather than load-bearing for hard policy
//! decisions made by trustworthy=false traffic.
//!
//! # Agent classes
//!
//! These are the classes the resolver chain emits when this detector
//! matches, given a catalogue that names them:
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
        /// `trustworthy = false`.
        confidence: f32,
    },
    /// Detector ran and did NOT match any known headless library.
    NotDetected,
}

// --- Catalog loader ---

/// One entry in a TLS-fingerprint catalogue.
///
/// Mirrors the JSON schema for the reference fingerprint catalogue.
/// Every field defaults to empty so partial entries (e.g.
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
/// Built once at startup (or on SIGHUP reload) from the embedded
/// default or an operator's `catalog_file`. The proxy holds it behind an `Arc` so the
/// detector hot path borrows without cloning.
#[derive(Debug, Clone)]
pub struct TlsFingerprintCatalog {
    entries: Vec<TlsFingerprintEntry>,
    /// Reverse index: `ja4` value -> `entries` index. Empty JA4
    /// fields are not indexed.
    by_ja4: HashMap<String, usize>,
}

/// Embedded default catalogue. It names the agent classes and carries
/// **no fingerprints**: see the file's own `notes` and WOR-2296 for why
/// a populated default was removed. Operators supply their own with
/// `proxy.extensions.tls_fingerprint.catalog_file`, which replaces this
/// wholesale rather than merging into it.
pub(crate) const DEFAULT_TLS_FINGERPRINT_JSON: &str =
    include_str!("../../sbproxy-classifiers/data/tls-fingerprints.json");

impl TlsFingerprintCatalog {
    /// Parse a catalogue from raw JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        let file: CatalogFile =
            serde_json::from_str(json).context("failed to parse tls-fingerprints.json")?;
        Self::from_entries(file.entries)
    }

    /// Read a catalogue from an operator-supplied file.
    ///
    /// The error names the path, because the alternative is a boot log
    /// that says a catalogue failed to parse without saying which of the
    /// embedded default and the operator's file it meant.
    pub fn from_path(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path).with_context(|| {
            format!(
                "failed to read TLS fingerprint catalogue {}",
                path.display()
            )
        })?;
        Self::from_json(&json).with_context(|| {
            format!(
                "failed to parse TLS fingerprint catalogue {}",
                path.display()
            )
        })
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
    pub(crate) fn lookup_ja4(&self, ja4: &str) -> Option<&TlsFingerprintEntry> {
        self.by_ja4.get(ja4).map(|idx| &self.entries[*idx])
    }

    /// CEL helper: return `true` when `ja4` is associated with
    /// `agent_class_id` in the catalogue. When the catalogue has no
    /// entry for `agent_class_id`, returns `true` (conservative; do
    /// not penalise uncatalogued agents).
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
///   `0.95` for known matches) and halved (capped at 0.5)
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

    /// The embedded catalogue must carry no fingerprints.
    ///
    /// This is the guard on WOR-2296 rather than a test of behavior. The
    /// file used to ship JA4 values copied from a third-party
    /// fingerprint database, under a license that reserved the
    /// commercial redistribution our Apache-2.0 grant hands out. Nothing
    /// about a populated catalogue looks wrong in review, which is how
    /// it survived: the fix only holds if re-adding a value fails the
    /// build and makes someone say where it came from.
    ///
    /// Measured your own? It belongs in an operator `catalog_file`, or
    /// in a fixture next to the test that needs it, not here.
    #[test]
    fn the_embedded_catalogue_ships_no_fingerprints() {
        let file: CatalogFile =
            serde_json::from_str(DEFAULT_TLS_FINGERPRINT_JSON).expect("embedded catalogue parses");
        assert!(
            !file.entries.is_empty(),
            "the embedded catalogue still names the agent classes; only the \
             fingerprints are removed"
        );
        for entry in &file.entries {
            assert!(
                entry.ja3.is_empty() && entry.ja4.is_empty() && entry.ja4h.is_empty(),
                "agent class `{}` carries embedded fingerprints. A JA3/JA4/JA4H \
                 value is a measurement of one client build and the published \
                 collections of them are separately licensed, so the shipped \
                 default stays empty (WOR-2296). Put measured values in an \
                 operator catalog_file.",
                entry.agent_class
            );
        }
    }

    #[test]
    fn from_path_reads_an_operator_catalogue_and_matches_against_it() {
        let path = std::env::temp_dir().join(format!(
            "sbproxy-tls-fingerprints-{}-{}.json",
            std::process::id(),
            line!()
        ));
        std::fs::write(
            &path,
            r#"{
                "version": 2,
                "updated_at": "2026-08-04T00:00:00Z",
                "entries": [
                    {
                        "agent_class": "headless-puppeteer",
                        "ja4": ["t13d1517h2_aaaaaaaaaaaa_aaaaaaaaaaaa"]
                    }
                ]
            }"#,
        )
        .expect("write catalogue");

        let cat = TlsFingerprintCatalog::from_path(&path).expect("load catalogue");
        assert_eq!(cat.len(), 1);
        // The operator's file is the whole catalogue, not a layer over
        // the embedded one: a class the embedded file names is unknown
        // here because this file does not name it.
        assert!(cat
            .lookup_ja4("t13d1517h2_aaaaaaaaaaaa_aaaaaaaaaaaa")
            .is_some());
        assert!(cat.lookup_ja4("t13d1516h2_8daaf6152771").is_none());

        let _ = std::fs::remove_file(&path);
    }

    /// A boot log that says a catalogue failed to load without saying
    /// which file it meant sends the operator to the wrong place.
    #[test]
    fn from_path_error_names_the_file() {
        let path = std::env::temp_dir().join("sbproxy-tls-fingerprints-does-not-exist.json");
        let err = TlsFingerprintCatalog::from_path(&path).expect_err("missing file must error");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("sbproxy-tls-fingerprints-does-not-exist.json"),
            "error must name the path, got: {rendered}"
        );
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
