//! HTTP-layer signal extractors.
//!
//! The signals here are pure functions over header tuples. They do
//! not touch the network or any shared state; the proxy hook that
//! intercepts the request passes header pairs in and the extractors
//! return a [`HttpSignals`] field set.
//!
//! Extractors:
//!
//! - [`header_order_hash`] - SHA-256 of the lowercased header-name
//!   list in arrival order. Stable across requests with identical
//!   order; differs on any reorder. Useful as a coarse client
//!   fingerprint because real-world stacks pin a deterministic
//!   header order that differs between SDKs and browsers.
//! - [`vendor_headers`] - presence detection for the `x-stainless-*`
//!   family, `anthropic-version`, and `openai-beta`. Returns the
//!   matched header names in stable lexicographic order so the
//!   metric label set stays small and reproducible.
//! - [`user_agent_bucket`] - coarse classification of the
//!   `User-Agent` string into [`UserAgentBucket`]. Distinct from the
//!   rule-pack matcher's regex-based named-agent identification;
//!   this is the "what category of client is this even" question.
//! - [`extract_http_signals`] - composes the above into an
//!   [`HttpSignals`].

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::HttpSignals;

/// Coarse User-Agent category. Distinct from the rule-pack matcher's
/// named-agent identification: a request can be `Sdk(Python)` and
/// `claude-code-cli` at the same time because Claude Code CLI is
/// built on the OpenAI Stainless SDK family. Operators use the
/// bucket for broad-category rate limits; the named match for
/// per-vendor policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UserAgentBucket {
    /// Real browser (Chrome, Firefox, Safari, Edge). Detected via
    /// the canonical `Mozilla/5.0` prefix the four ship today.
    Browser,
    /// Python SDK (`openai-python`, `anthropic-python`, the
    /// Stainless families, `python-requests`, `httpx`).
    SdkPython,
    /// Node / browser-shaped JS SDK (`node-fetch`, `axios`, the
    /// `@anthropic-ai/sdk`, the OpenAI JS SDK).
    SdkNode,
    /// Go SDK (`Go-http-client`, the vendor Go SDKs).
    SdkGo,
    /// Operator-facing CLI tool (`curl`, `wget`, `httpie`). Distinct
    /// from CLI-shaped agents like Claude Code or Codex CLI; those
    /// are matched by the rule-pack matcher, not the bucket.
    CliTool,
    /// Headless browser shape (Puppeteer, Playwright, Headless
    /// Chrome). The bucket is coarse; high-fidelity detection is
    /// the JA4 + named-agent layer's job.
    Headless,
    /// Any other shape the extractor recognises but cannot classify.
    Other,
}

impl UserAgentBucket {
    /// Stable string identifier for metric labels and scripting
    /// exposure.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::SdkPython => "sdk-python",
            Self::SdkNode => "sdk-node",
            Self::SdkGo => "sdk-go",
            Self::CliTool => "cli-tool",
            Self::Headless => "headless",
            Self::Other => "other",
        }
    }
}

/// Vendor header names the slice-4 extractor recognises. Match is
/// case-insensitive against the lowercased header-name list. The
/// `x-stainless` family is a prefix match (Stainless SDKs emit a
/// family of `x-stainless-arch`, `x-stainless-os`, etc.).
const VENDOR_PREFIXES: &[&str] = &["x-stainless-"];
const VENDOR_EXACT: &[&str] = &["anthropic-version", "openai-beta"];

/// SHA-256 hex (lowercase, 64 chars) of the lowercased header-name
/// list in arrival order. Returns an empty string when `names` is
/// empty so a header-less request does not all collide on the
/// SHA-256 of the empty string.
pub fn header_order_hash<I, S>(names: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut hasher = Sha256::new();
    let mut any = false;
    for (i, name) in names.into_iter().enumerate() {
        any = true;
        if i > 0 {
            hasher.update(b"\n");
        }
        // Hash the lowercased name. HTTP header names are case-
        // insensitive on the wire but real-world clients send a
        // canonical case; lowercasing gives us a hash that is stable
        // across the few clients that flip the case.
        let lowered = name.as_ref().to_ascii_lowercase();
        hasher.update(lowered.as_bytes());
    }
    if !any {
        return String::new();
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Detect vendor-specific headers on the request. Returns the
/// matched lowercased header names sorted lexicographically so the
/// downstream metric label set is reproducible.
pub fn vendor_headers<I, S>(names: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut hits: Vec<String> = Vec::new();
    for name in names {
        let lowered = name.as_ref().to_ascii_lowercase();
        if VENDOR_EXACT.contains(&lowered.as_str()) {
            hits.push(lowered);
            continue;
        }
        if VENDOR_PREFIXES
            .iter()
            .any(|prefix| lowered.starts_with(*prefix))
        {
            hits.push(lowered);
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

/// Classify the `User-Agent` string into a [`UserAgentBucket`]. The
/// classifier is a small ordered match: more specific signatures
/// come first so an `OpenAI/Python` UA gets `SdkPython` rather than
/// falling through to `Other`.
pub fn user_agent_bucket(ua: Option<&str>) -> Option<UserAgentBucket> {
    let ua = ua?;
    let lowered = ua.to_ascii_lowercase();

    // Headless first: a real-browser Mozilla prefix plus a
    // HeadlessChrome / Puppeteer marker should bucket as headless,
    // not Browser.
    if lowered.contains("headlesschrome")
        || lowered.contains("puppeteer")
        || lowered.contains("playwright")
    {
        return Some(UserAgentBucket::Headless);
    }

    // Python SDKs.
    if lowered.starts_with("openai/python")
        || lowered.starts_with("anthropic/python")
        || lowered.starts_with("python-requests/")
        || lowered.starts_with("python-httpx/")
        || lowered.starts_with("python/")
        || lowered.starts_with("aiohttp/")
    {
        return Some(UserAgentBucket::SdkPython);
    }

    // Node / JS SDKs.
    if lowered.starts_with("node-fetch")
        || lowered.starts_with("axios/")
        || lowered.starts_with("undici")
        || lowered.starts_with("openai/node")
        || lowered.starts_with("@anthropic-ai/sdk")
    {
        return Some(UserAgentBucket::SdkNode);
    }

    // Go SDKs and stdlib.
    if lowered.starts_with("go-http-client/")
        || lowered.starts_with("openai-go/")
        || lowered.starts_with("anthropic-go/")
    {
        return Some(UserAgentBucket::SdkGo);
    }

    // Operator CLIs (distinct from CLI-shaped *agents* like Claude
    // Code; those are matched by the rule pack).
    if lowered.starts_with("curl/")
        || lowered.starts_with("wget/")
        || lowered.starts_with("httpie/")
    {
        return Some(UserAgentBucket::CliTool);
    }

    // Real browsers. The match is loose because the canonical
    // shape is `Mozilla/5.0 ...` plus a vendor token; the bucket
    // here only cares about the surface category. Higher-fidelity
    // detection lives in the rule-pack matcher and the JA4 layer.
    if lowered.starts_with("mozilla/5.0") {
        return Some(UserAgentBucket::Browser);
    }

    Some(UserAgentBucket::Other)
}

/// Compose the full [`HttpSignals`] from request headers and a
/// pre-computed cookie-persistence flag. Headers are read once.
///
/// `headers` is an iterator of `(name, value)` pairs in arrival
/// order. The extractor lowercases each name into
/// [`HttpSignals::headers_present`] for the rule-pack matcher and
/// feeds the same name list into [`header_order_hash`].
///
/// `cookie_persistence` is supplied by the caller because the
/// presence of a `Cookie` header is implicit in `headers` and the
/// caller may have already filtered or extracted it.
pub fn extract_http_signals<'a, I>(headers: I, cookie_persistence: bool) -> HttpSignals
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut header_names: Vec<String> = Vec::new();
    let mut user_agent: Option<String> = None;
    for (name, value) in headers {
        let lowered = name.to_ascii_lowercase();
        if user_agent.is_none() && lowered == "user-agent" {
            user_agent = Some(value.to_string());
        }
        header_names.push(lowered);
    }

    let header_order_hash = header_order_hash(header_names.iter());
    let vendor_headers = vendor_headers(header_names.iter());
    let user_agent_bucket = user_agent_bucket(user_agent.as_deref());

    HttpSignals {
        user_agent,
        headers_present: header_names,
        header_order_hash,
        vendor_headers,
        user_agent_bucket,
        cookie_persistence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_order_hash_is_stable_for_identical_order() {
        let a = header_order_hash(["Host", "User-Agent", "Accept"]);
        let b = header_order_hash(["host", "user-agent", "accept"]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn header_order_hash_differs_on_reorder() {
        let a = header_order_hash(["Host", "User-Agent", "Accept"]);
        let b = header_order_hash(["User-Agent", "Host", "Accept"]);
        assert_ne!(a, b);
    }

    #[test]
    fn header_order_hash_of_empty_list_is_empty_string() {
        // Empty header list short-circuits to the empty string so
        // an empty-header request does not collide on the SHA-256
        // of the empty input.
        let h: Vec<&str> = Vec::new();
        assert_eq!(header_order_hash(h), "");
    }

    #[test]
    fn vendor_headers_detects_x_stainless_family() {
        let hits = vendor_headers([
            "Host",
            "X-Stainless-Arch",
            "X-Stainless-OS",
            "Content-Type",
            "X-Stainless-Lang",
        ]);
        assert_eq!(
            hits,
            vec![
                "x-stainless-arch".to_string(),
                "x-stainless-lang".to_string(),
                "x-stainless-os".to_string(),
            ]
        );
    }

    #[test]
    fn vendor_headers_detects_anthropic_and_openai_beta() {
        let hits = vendor_headers(["Anthropic-Version", "openai-beta", "Authorization"]);
        assert_eq!(
            hits,
            vec!["anthropic-version".to_string(), "openai-beta".to_string()],
        );
    }

    #[test]
    fn vendor_headers_dedupes_repeated_matches() {
        let hits = vendor_headers(["x-stainless-arch", "X-STAINLESS-ARCH", "anthropic-version"]);
        assert_eq!(
            hits,
            vec![
                "anthropic-version".to_string(),
                "x-stainless-arch".to_string(),
            ]
        );
    }

    #[test]
    fn vendor_headers_empty_when_no_known_headers() {
        let hits = vendor_headers(["Host", "Accept", "User-Agent"]);
        assert!(hits.is_empty());
    }

    #[test]
    fn ua_bucket_browser() {
        // Canonical Chrome 2026 UA prefix.
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
        assert_eq!(user_agent_bucket(Some(ua)), Some(UserAgentBucket::Browser));
    }

    #[test]
    fn ua_bucket_headless_outranks_browser() {
        // A Mozilla/5.0 prefix plus HeadlessChrome marker should
        // bucket as Headless, not Browser. The browser shape's
        // `Mozilla/5.0` prefix is a superset; the more-specific
        // headless detection wins.
        let ua = "Mozilla/5.0 (Linux; HeadlessChrome/126.0.0.0)";
        assert_eq!(user_agent_bucket(Some(ua)), Some(UserAgentBucket::Headless));
    }

    #[test]
    fn ua_bucket_python_sdks() {
        for ua in [
            "OpenAI/Python 1.2.3",
            "anthropic/python 0.30.0",
            "python-requests/2.31.0",
            "python-httpx/0.27.0",
        ] {
            assert_eq!(
                user_agent_bucket(Some(ua)),
                Some(UserAgentBucket::SdkPython),
                "UA {ua} should bucket as SdkPython",
            );
        }
    }

    #[test]
    fn ua_bucket_node_sdks() {
        for ua in [
            "node-fetch/3.3.2",
            "axios/1.6.0",
            "OpenAI/node 4.0.0",
            "@anthropic-ai/sdk 0.20.0",
        ] {
            assert_eq!(
                user_agent_bucket(Some(ua)),
                Some(UserAgentBucket::SdkNode),
                "UA {ua} should bucket as SdkNode",
            );
        }
    }

    #[test]
    fn ua_bucket_go_sdks() {
        assert_eq!(
            user_agent_bucket(Some("Go-http-client/1.1")),
            Some(UserAgentBucket::SdkGo),
        );
        assert_eq!(
            user_agent_bucket(Some("openai-go/0.1.0")),
            Some(UserAgentBucket::SdkGo),
        );
    }

    #[test]
    fn ua_bucket_cli_tools() {
        for ua in ["curl/8.0.0", "wget/1.20", "HTTPie/3.2.0"] {
            assert_eq!(
                user_agent_bucket(Some(ua)),
                Some(UserAgentBucket::CliTool),
                "UA {ua} should bucket as CliTool",
            );
        }
    }

    #[test]
    fn ua_bucket_unknown_falls_through_to_other() {
        assert_eq!(
            user_agent_bucket(Some("MysteryClient/0.0.1")),
            Some(UserAgentBucket::Other),
        );
    }

    #[test]
    fn ua_bucket_none_when_no_header() {
        assert!(user_agent_bucket(None).is_none());
    }

    #[test]
    fn ua_bucket_serde_kebab_case() {
        let json = serde_json::to_value(UserAgentBucket::SdkPython).unwrap();
        assert_eq!(json.as_str().unwrap(), "sdk-python");
        let parsed: UserAgentBucket = serde_json::from_str("\"cli-tool\"").unwrap();
        assert_eq!(parsed, UserAgentBucket::CliTool);
    }

    #[test]
    fn extract_full_signals_round_trip() {
        let headers: [(&str, &str); 4] = [
            ("Host", "api.example.test"),
            ("User-Agent", "Mozilla/5.0 (Windows NT 10.0)"),
            ("X-Stainless-Arch", "x64"),
            ("anthropic-version", "2026-05-15"),
        ];
        let signals = extract_http_signals(headers.iter().copied(), true);
        assert_eq!(
            signals.user_agent.as_deref(),
            Some("Mozilla/5.0 (Windows NT 10.0)"),
        );
        assert_eq!(
            signals.headers_present,
            vec![
                "host".to_string(),
                "user-agent".to_string(),
                "x-stainless-arch".to_string(),
                "anthropic-version".to_string(),
            ],
        );
        assert_eq!(signals.header_order_hash.len(), 64);
        assert_eq!(
            signals.vendor_headers,
            vec![
                "anthropic-version".to_string(),
                "x-stainless-arch".to_string(),
            ],
        );
        assert_eq!(signals.user_agent_bucket, Some(UserAgentBucket::Browser),);
        assert!(signals.cookie_persistence);
    }

    #[test]
    fn extract_signals_with_no_user_agent_yields_none_bucket() {
        let signals = extract_http_signals([("Host", "x.test")], false);
        assert!(signals.user_agent.is_none());
        assert!(signals.user_agent_bucket.is_none());
        assert!(!signals.cookie_persistence);
    }
}
