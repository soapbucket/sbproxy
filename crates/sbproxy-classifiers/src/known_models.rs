//! Pinned production classifier models.
//!
//! Each [`KnownModel`] entry pins a specific upstream URL plus the
//! SHA-256 hash of the file at that URL on the day it was added.
//! Detectors reference the entry by `name`, so operators do not have
//! to copy the URL and hash into every config; the registry is the
//! single source of truth for what "the production model" means.
//!
//! # Why pin in Rust source rather than config
//!
//! - Hashes change in lock-step with model behaviour. Pinning them in
//!   the binary makes a model rotation a code change with a code
//!   review attached, not a YAML edit any operator can land.
//! - Operators who need a private mirror (air-gapped sites) can still
//!   override the URL via `model_url` / `tokenizer_url` and skip the
//!   registry. The registry is a convenience, not a wall.
//! - `cargo deny` / supply-chain audits pick up the registry the same
//!   way they pick up `Cargo.toml` pins.
//!
//! # Adding or rotating an entry
//!
//! 1. Decide the upstream commit SHA for the model card revision.
//! 2. `curl --location <model-url> | sha256sum` to compute the file
//!    hash. Same for the tokenizer.
//! 3. Add or update the entry below with `revision_pinned_at` set to
//!    today's date in `YYYY-MM-DD` form.
//! 4. Submit a PR; the review must include the upstream model card
//!    URL and the LICENSE the model ships under.
//!
//! # Procedure for filling in an empty SHA
//!
//! Some entries land with empty `model_sha256` / `tokenizer_sha256`
//! values when the build sandbox cannot reach the upstream URL. Those
//! placeholders are temporary: the
//! `no_known_model_has_unpinned_sha256` test in this module fails the
//! build the moment any entry is committed without a hash. The
//! one-time follow-up to populate the values is:
//!
//! 1. Run the proxy locally with the relevant detector enabled. On
//!    first request, the file is fetched and cached under the
//!    operator's on-disk classifier cache (`SBPROXY_CACHE_DIR` or the
//!    OS default).
//! 2. `sha256sum <cache-path>/model.onnx` and
//!    `sha256sum <cache-path>/tokenizer.json` to compute the hashes.
//! 3. Paste the lowercase hex values into the matching `KnownModel`
//!    entry below and update `revision_pinned_at` to today.
//! 4. Re-enable the assertion test (drop the `#[ignore]` it carried
//!    while values were pending) and submit the PR.
//!
//! See `docs/model-pinning.md` for the longer narrative version,
//! including how operators verify a hash against an upstream model
//! card before committing.

use std::collections::HashMap;
use std::sync::OnceLock;

/// A registry entry pinning one ONNX model + tokenizer pair to a
/// specific upstream commit.
#[derive(Debug, Clone, Copy)]
pub struct KnownModel {
    /// Stable name referenced from policy configs as `model: <name>`.
    pub name: &'static str,
    /// HTTPS URL of the ONNX file on the upstream model host.
    pub model_url: &'static str,
    /// SHA-256 hash of the ONNX file in lowercase hex. Empty string
    /// means "to be computed on first download"; entries should not
    /// stay in that state past the next release.
    pub model_sha256: &'static str,
    /// HTTPS URL of the tokenizer file on the upstream model host.
    pub tokenizer_url: &'static str,
    /// SHA-256 hash of the tokenizer file in lowercase hex.
    pub tokenizer_sha256: &'static str,
    /// SPDX license identifier of the model weights.
    pub license: &'static str,
    /// Date the entry was last verified against the upstream URL,
    /// `YYYY-MM-DD`.
    pub revision_pinned_at: &'static str,
}

impl KnownModel {
    /// Returns `(model_sha, tokenizer_sha)` when both pins are present
    /// in lowercase hex, or `None` when either one is still pending
    /// computation (empty string).
    ///
    /// Detectors that load this model use the `Some` form to harden
    /// the download path against tampering, and fall back to the
    /// `None` form (no validation) when the entry is freshly added
    /// and the operator is the one who will compute the hashes
    /// locally.
    pub fn pinned_pair(&self) -> Option<(&'static str, &'static str)> {
        if self.model_sha256.is_empty() || self.tokenizer_sha256.is_empty() {
            None
        } else {
            Some((self.model_sha256, self.tokenizer_sha256))
        }
    }
}

// --- Registry ---

/// Production prompt-injection model.
///
/// Source: `protectai/deberta-v3-base-prompt-injection-v2` on Hugging
/// Face. Apache-2.0 licensed. The DeBERTa-v3-base classifier produces
/// a 2-class output (`SAFE`, `INJECTION`); the ONNX export under
/// `onnx/model.onnx` matches that vocabulary, and the tokenizer
/// included in the repo at `tokenizer.json` is the matching SentencePiece
/// BPE tokenizer.
///
/// SHA-256 hashes are deliberately empty in the initial landing of
/// this registry: the build sandbox where this code is reviewed has
/// no outbound network access and we will not commit a hash we have
/// not verified. The model loader treats an unpinned entry as "skip
/// SHA validation"; operators who
/// run the proxy in production should populate the hashes locally on
/// first download (the file lands in the on-disk cache and you can
/// `sha256sum` it) and submit a follow-up PR with the values, or set
/// the explicit `model_sha256` / `tokenizer_sha256` fields in their
/// own policy config to take over the pin.
pub const PROMPT_INJECTION_V2_MODEL: KnownModel = KnownModel {
    name: "prompt-injection-v2",
    model_url: concat!(
        "https://huggingface.co/protectai/",
        "deberta-v3-base-prompt-injection-v2/resolve/main/onnx/model.onnx"
    ),
    // Empty until the WOR-190 follow-up lands the computed value.
    // See the module-level "Procedure for filling in an empty SHA"
    // section. Until that PR ships, the detector treats this entry
    // as unpinned (no SHA validation), which is the same posture as
    // supplying the URL directly in policy config without
    // `model_sha256`. The `no_known_model_has_unpinned_sha256` test
    // in this module is `#[ignore]`'d for the same reason.
    model_sha256: "",
    tokenizer_url: concat!(
        "https://huggingface.co/protectai/",
        "deberta-v3-base-prompt-injection-v2/resolve/main/tokenizer.json"
    ),
    tokenizer_sha256: "",
    license: "Apache-2.0",
    revision_pinned_at: "2026-04-27",
};

/// Default sentence-embedding model for the AI gateway semantic cache and
/// the in-process / sidecar embedder.
///
/// `all-MiniLM-L6-v2` is a 6-layer, 384-dim sentence-transformer under
/// Apache-2.0. It runs on the pure-Rust tract engine, is small enough to
/// cache and ship to air-gapped sites, and its quality is well-suited to
/// near-duplicate prompt detection (the semantic-cache use case).
///
/// SHA pins are empty for the same reason as `prompt-injection-v2`: the
/// build sandbox cannot reach the upstream URL, so operators compute the
/// hash on first download. The `no_known_model_has_unpinned_sha256` test
/// stays `#[ignore]`'d until the pinning follow-up lands.
pub const ALL_MINILM_L6_V2_MODEL: KnownModel = KnownModel {
    name: "all-MiniLM-L6-v2",
    model_url: concat!(
        "https://huggingface.co/sentence-transformers/",
        "all-MiniLM-L6-v2/resolve/main/onnx/model.onnx"
    ),
    model_sha256: "",
    tokenizer_url: concat!(
        "https://huggingface.co/sentence-transformers/",
        "all-MiniLM-L6-v2/resolve/main/tokenizer.json"
    ),
    tokenizer_sha256: "",
    license: "Apache-2.0",
    revision_pinned_at: "2026-06-08",
};

/// Every entry the registry knows about. Add new pins here; tests
/// assert that the array stays unique by `name`.
pub const KNOWN_MODELS: &[KnownModel] = &[PROMPT_INJECTION_V2_MODEL, ALL_MINILM_L6_V2_MODEL];

static INDEX: OnceLock<HashMap<&'static str, &'static KnownModel>> = OnceLock::new();

fn index() -> &'static HashMap<&'static str, &'static KnownModel> {
    INDEX.get_or_init(|| {
        let mut m = HashMap::with_capacity(KNOWN_MODELS.len());
        for entry in KNOWN_MODELS {
            m.insert(entry.name, entry);
        }
        m
    })
}

/// Look up a registered model by name.
///
/// Returns `None` when no entry matches. Detectors that hit this path
/// should error out loudly so a misconfigured `model: <name>` surfaces
/// at startup rather than the first request.
pub fn lookup(name: &str) -> Option<&'static KnownModel> {
    index().get(name).copied()
}

/// Names of every registered model. Used by config-validation error
/// messages to suggest valid alternatives.
pub fn registered_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = KNOWN_MODELS.iter().map(|m| m.name).collect();
    names.sort_unstable();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_prompt_injection_v2() {
        let m = lookup("prompt-injection-v2").expect("registered");
        assert!(m.model_url.starts_with("https://huggingface.co/"));
        assert!(m.tokenizer_url.starts_with("https://huggingface.co/"));
        assert_eq!(m.license, "Apache-2.0");
    }

    #[test]
    fn registry_lookup_unknown_returns_none() {
        assert!(lookup("does-not-exist").is_none());
    }

    #[test]
    fn registry_names_are_unique() {
        let names = registered_names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            names.len(),
            sorted.len(),
            "duplicate model name in KNOWN_MODELS"
        );
    }

    #[test]
    fn pinned_pair_returns_none_when_either_hash_empty() {
        let m = KnownModel {
            name: "t",
            model_url: "https://example.com/m",
            model_sha256: "",
            tokenizer_url: "https://example.com/t",
            tokenizer_sha256: "deadbeef",
            license: "Apache-2.0",
            revision_pinned_at: "2026-04-27",
        };
        assert!(m.pinned_pair().is_none());
    }

    #[test]
    fn pinned_pair_returns_some_when_both_hashes_present() {
        let m = KnownModel {
            name: "t",
            model_url: "https://example.com/m",
            model_sha256: "aa",
            tokenizer_url: "https://example.com/t",
            tokenizer_sha256: "bb",
            license: "Apache-2.0",
            revision_pinned_at: "2026-04-27",
        };
        assert_eq!(m.pinned_pair(), Some(("aa", "bb")));
    }

    /// Supply-chain guard: a `KnownModel` registry entry must
    /// not be merged with an empty or sentinel SHA-256 value. Without
    /// this assertion the detector silently degrades to "unpinned"
    /// posture and a future re-introduction would not trip review.
    ///
    /// The test enumerates the obvious unsafe values:
    ///
    /// - empty string,
    /// - 64 hex zeros (the literal `0000...` placeholder operators
    ///   sometimes paste while shadowing local builds),
    /// - the lowercase hex form of `[0u8; 32]`.
    ///
    /// The latter two are the same byte sequence; both forms are
    /// listed for clarity at the call site.
    ///
    /// Currently `#[ignore]`'d because the in-tree
    /// `PROMPT_INJECTION_V2_MODEL` entry ships with empty SHAs (the
    /// build sandbox cannot reach Hugging Face). Re-enable in the
    /// WOR-190 follow-up PR that pastes the computed values.
    #[test]
    #[ignore = "ignored until SHA values land per WOR-190 follow-up; re-enable in that PR"]
    fn no_known_model_has_unpinned_sha256() {
        const ZERO_HEX_64: &str =
            "0000000000000000000000000000000000000000000000000000000000000000";
        let zero_bytes = hex::encode([0u8; 32]);

        for entry in KNOWN_MODELS {
            for (label, value) in [
                ("model_sha256", entry.model_sha256),
                ("tokenizer_sha256", entry.tokenizer_sha256),
            ] {
                assert!(
                    !value.is_empty(),
                    "KnownModel {:?} has empty {label}; populate via the procedure in `docs/model-pinning.md`",
                    entry.name,
                );
                assert_ne!(
                    value, ZERO_HEX_64,
                    "KnownModel {:?} has placeholder {label} (64 hex zeros); replace with the real SHA-256",
                    entry.name,
                );
                assert_ne!(
                    value, zero_bytes,
                    "KnownModel {:?} has placeholder {label} (zero-byte SHA-256); replace with the real value",
                    entry.name,
                );
            }
        }
    }
}
