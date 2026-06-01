//! WOR-817: deterministic headless / stealth-browser indicator
//! heuristics.
//!
//! The existing TLS / JA4 lane (WOR-592) catches scrapers whose
//! TLS fingerprint diverges from a real browser's. Stealth tooling
//! (Puppeteer-stealth, Playwright with the stealth plugin, Selenium
//! with undetected-chromedriver) ships matching JA4 vectors out of
//! the box, so the TLS layer is no longer sufficient on its own. This
//! module ships the application-level companion: a set of cheap,
//! header-only heuristics that surface when a request claims to be a
//! recent Chrome / Firefox / Safari but its HTTP shape contradicts
//! that claim.
//!
//! Self-hostable on purpose. Akamai Content Protector pairs this
//! signal class with a proprietary ML score; the heuristics here are
//! the half SBproxy can ship without a model. The ML half stays an
//! integration boundary.
//!
//! # Indicator catalogue
//!
//! Every indicator is a deterministic boolean lifted from
//! [`HttpSignals`] (the existing extractor surface, WOR-587).
//! Operators read the bag through CEL via `request.agent.headless_*`
//! once the verdict is stamped on the request context.
//!
//! * `automation_marker_in_user_agent` - the UA carries one of the
//!   well-known automation strings (`HeadlessChrome`, `PhantomJS`,
//!   `Puppeteer`, `Playwright`, `Selenium`). Vanilla automation
//!   leaves the marker; stealth wrappers strip it.
//! * `claims_chrome_without_client_hints` - the UA includes the
//!   Chrome vendor token but the request omits the entire `sec-ch-ua`
//!   client-hint family. Real Chrome 89+ sends `Sec-Ch-Ua`,
//!   `Sec-Ch-Ua-Mobile`, and `Sec-Ch-Ua-Platform` on every
//!   navigation; a request that lacks all three with a Chrome UA is
//!   a strong stealth indicator.
//! * `claims_chrome_without_sec_fetch` - the UA includes the Chrome
//!   vendor token but no `Sec-Fetch-*` header is present. Fetch
//!   metadata (RFC 9534-equivalent draft) is mandatory on Chrome 76+;
//!   absence on a Chrome-claiming request is anomalous.
//! * `accept_language_missing` - no `Accept-Language` header at all.
//!   Real browsers always set one; many headless defaults skip it
//!   unless the runner explicitly stamps it.
//! * `accept_encoding_anomalous` - the `Accept-Encoding` value does
//!   not match the canonical browser order (`gzip, deflate, br` or
//!   `gzip, deflate, br, zstd` on modern browsers). Subtle but
//!   common stealth wrappers do not reorder it correctly.
//!
//! # Score
//!
//! Each indicator contributes an integer weight to the 0-100 score
//! returned from [`score_headless`]. The weights are tuned to make
//! the score thresholdable as:
//!
//! | Score   | Interpretation                          |
//! |---------|-----------------------------------------|
//! | 0-19    | indistinguishable from a real browser   |
//! | 20-49   | one or two stealth hints; low confidence|
//! | 50-79   | several hints; high confidence headless |
//! | 80-100  | obvious automation; vanilla headless    |
//!
//! The weights are deliberately conservative: an operator that wants
//! to block at `score >= 50` should also pair it with the JA4 score
//! and CAPTCHA fallback so the rare real-browser false positive
//! (TLS-MITM developer machine, custom ELinks build) gets a recovery
//! path.
//!
//! # Scope
//!
//! This module is the deterministic, request-side half. Two other
//! layers compose on top in follow-ups (out of scope for WOR-817):
//!
//! * **JS-execution challenge**: serve a script that posts a token
//!   back on first navigation; absence of the token on subsequent
//!   requests is a stronger signal than any header heuristic.
//! * **Session-window consistency**: header-order hash drift across
//!   the same session is a strong stealth indicator; needs the
//!   session-tracking surface to land.

use crate::HttpSignals;

/// Per-indicator results lifted from a single request's
/// [`HttpSignals`]. Stable shape so a downstream CEL view can render
/// the bag verbatim under `request.agent.headless_indicators`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeadlessIndicators {
    /// The `User-Agent` carries one of the well-known automation
    /// markers (`HeadlessChrome`, `PhantomJS`, `Puppeteer`,
    /// `Playwright`, `Selenium`, `WebDriver`).
    pub automation_marker_in_user_agent: bool,
    /// The `User-Agent` includes the Chrome vendor token but the
    /// request omits every `Sec-Ch-Ua*` client hint.
    pub claims_chrome_without_client_hints: bool,
    /// The `User-Agent` includes the Chrome vendor token but no
    /// `Sec-Fetch-*` fetch-metadata header is present.
    pub claims_chrome_without_sec_fetch: bool,
    /// The request omitted the `Accept-Language` header entirely.
    pub accept_language_missing: bool,
    /// The `Accept-Encoding` value does not match any canonical
    /// browser order (`gzip, deflate, br` or
    /// `gzip, deflate, br, zstd`). Absent header does not trip this
    /// indicator (it trips `accept_language_missing` only when the
    /// language header is the missing one).
    pub accept_encoding_anomalous: bool,
}

impl HeadlessIndicators {
    /// Number of indicators that fired. Useful for downstream
    /// metric labels.
    pub fn count(&self) -> u32 {
        u32::from(self.automation_marker_in_user_agent)
            + u32::from(self.claims_chrome_without_client_hints)
            + u32::from(self.claims_chrome_without_sec_fetch)
            + u32::from(self.accept_language_missing)
            + u32::from(self.accept_encoding_anomalous)
    }

    /// Render the indicator names that fired as a stable, sorted
    /// list. Renders verbatim into the CEL view under
    /// `request.agent.headless_indicators`.
    pub fn names(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.automation_marker_in_user_agent {
            out.push("automation_marker_in_user_agent");
        }
        if self.claims_chrome_without_client_hints {
            out.push("claims_chrome_without_client_hints");
        }
        if self.claims_chrome_without_sec_fetch {
            out.push("claims_chrome_without_sec_fetch");
        }
        if self.accept_language_missing {
            out.push("accept_language_missing");
        }
        if self.accept_encoding_anomalous {
            out.push("accept_encoding_anomalous");
        }
        out
    }
}

/// Canonical automation markers the heuristic scans for in the
/// `User-Agent` value. Each entry is matched case-insensitively as a
/// substring; vanilla automation tooling leaves at least one of
/// these on every request.
const AUTOMATION_MARKERS: &[&str] = &[
    "headlesschrome",
    "phantomjs",
    "puppeteer",
    "playwright",
    "selenium",
    "webdriver",
    "slimerjs",
];

/// Canonical browser shapes for `Accept-Encoding`. A request that
/// claims to be Chrome / Firefox / Safari but sends a different
/// value is suspicious. Lower-case comparison; whitespace
/// normalised on the caller's side because the existing
/// extractor preserves the original spacing.
const CANONICAL_ACCEPT_ENCODINGS: &[&str] = &[
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
];

/// Extract the [`HeadlessIndicators`] bag from a slice of headers
/// pre-parsed by the caller. Each indicator is a pure function of
/// the headers plus the [`HttpSignals::user_agent`] field.
///
/// The caller already owns [`HttpSignals`]; pass it here rather
/// than re-iterating headers so the cost is bounded.
pub fn extract_headless_indicators<'a, I>(http: &HttpSignals, headers: I) -> HeadlessIndicators
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let ua_lc = http
        .user_agent
        .as_deref()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    // Walk the headers once and remember every value we care about.
    let mut accept_language: Option<String> = None;
    let mut accept_encoding: Option<String> = None;
    let mut has_sec_ch_ua = false;
    let mut has_sec_ch_ua_mobile = false;
    let mut has_sec_ch_ua_platform = false;
    let mut has_sec_fetch = false;
    for (name, value) in headers {
        let lc = name.to_ascii_lowercase();
        match lc.as_str() {
            "accept-language" => accept_language = Some(value.to_string()),
            "accept-encoding" => accept_encoding = Some(value.to_string()),
            "sec-ch-ua" => has_sec_ch_ua = true,
            "sec-ch-ua-mobile" => has_sec_ch_ua_mobile = true,
            "sec-ch-ua-platform" => has_sec_ch_ua_platform = true,
            _ => {
                if lc.starts_with("sec-fetch-") {
                    has_sec_fetch = true;
                }
            }
        }
    }

    let automation_marker_in_user_agent = AUTOMATION_MARKERS.iter().any(|m| ua_lc.contains(m));

    let chrome_claim = ua_lc.contains("chrome/") || ua_lc.contains("chromium/");
    let claims_chrome_without_client_hints =
        chrome_claim && !has_sec_ch_ua && !has_sec_ch_ua_mobile && !has_sec_ch_ua_platform;
    let claims_chrome_without_sec_fetch = chrome_claim && !has_sec_fetch;

    let accept_language_missing = accept_language.is_none();

    let accept_encoding_anomalous = match accept_encoding.as_deref() {
        Some(v) => {
            // Trim each token's whitespace so a single-space vs
            // comma-separated reordering does not false-positive.
            let normalised = v
                .split(',')
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
                .join(", ")
                .to_ascii_lowercase();
            !CANONICAL_ACCEPT_ENCODINGS.iter().any(|c| normalised == *c)
        }
        // Absent header is reported by `accept_language_missing`
        // only; the encoding heuristic explicitly does not fire on
        // absence so the count is bounded.
        None => false,
    };

    HeadlessIndicators {
        automation_marker_in_user_agent,
        claims_chrome_without_client_hints,
        claims_chrome_without_sec_fetch,
        accept_language_missing,
        accept_encoding_anomalous,
    }
}

/// Compute the 0-100 headless score from a populated indicator bag.
///
/// Weights:
///
/// * `automation_marker_in_user_agent`: 60 (vanilla headless gives
///   itself away immediately)
/// * `claims_chrome_without_client_hints`: 25
/// * `claims_chrome_without_sec_fetch`: 25
/// * `accept_language_missing`: 15
/// * `accept_encoding_anomalous`: 10
///
/// Multiple weak indicators add up; the score saturates at 100 so
/// downstream consumers can use it as a probability surrogate.
pub fn score_headless(ind: &HeadlessIndicators) -> u8 {
    let mut s: u32 = 0;
    if ind.automation_marker_in_user_agent {
        s += 60;
    }
    if ind.claims_chrome_without_client_hints {
        s += 25;
    }
    if ind.claims_chrome_without_sec_fetch {
        s += 25;
    }
    if ind.accept_language_missing {
        s += 15;
    }
    if ind.accept_encoding_anomalous {
        s += 10;
    }
    s.min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_extractors::extract_http_signals;

    fn http(headers: &[(&str, &str)]) -> HttpSignals {
        extract_http_signals(headers.iter().copied(), false)
    }

    /// Headers a real Chrome 120 navigation carries. Used as the
    /// false-positive floor.
    const REAL_CHROME_NAVIGATION: &[(&str, &str)] = &[
        ("host", "example.com"),
        ("connection", "keep-alive"),
        ("sec-ch-ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\""),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", "\"macOS\""),
        ("upgrade-insecure-requests", "1"),
        ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
        ("sec-fetch-site", "none"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-user", "?1"),
        ("sec-fetch-dest", "document"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("accept-language", "en-US,en;q=0.9"),
    ];

    /// Vanilla `puppeteer-core` navigation. Vanilla means NO stealth
    /// plugin; the UA leaks the HeadlessChrome marker.
    const VANILLA_HEADLESS_CHROME: &[(&str, &str)] = &[
        ("host", "example.com"),
        ("upgrade-insecure-requests", "1"),
        ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36"),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-language", "en-US"),
    ];

    /// Puppeteer-stealth navigation: the marker is stripped from
    /// the UA but the Sec-Ch-Ua family is still missing because the
    /// stealth plugin only patches `navigator.webdriver` on the JS
    /// side; the network shape stays headless.
    const STEALTH_HEADLESS_CHROME: &[(&str, &str)] = &[
        ("host", "example.com"),
        ("upgrade-insecure-requests", "1"),
        ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-language", "en-US"),
    ];

    #[test]
    fn real_chrome_navigation_is_not_flagged() {
        let h = http(REAL_CHROME_NAVIGATION);
        let ind = extract_headless_indicators(&h, REAL_CHROME_NAVIGATION.iter().copied());
        assert_eq!(ind.count(), 0, "indicators fired: {:?}", ind.names());
        assert_eq!(score_headless(&ind), 0);
    }

    #[test]
    fn vanilla_headless_is_obviously_flagged() {
        let h = http(VANILLA_HEADLESS_CHROME);
        let ind = extract_headless_indicators(&h, VANILLA_HEADLESS_CHROME.iter().copied());
        assert!(ind.automation_marker_in_user_agent);
        // The Sec-Ch-Ua + Sec-Fetch families are absent because the
        // UA leak already disqualifies the request; no need to
        // patch them on this path.
        assert!(ind.claims_chrome_without_client_hints);
        assert!(ind.claims_chrome_without_sec_fetch);
        let score = score_headless(&ind);
        // 60 + 25 + 25 = 110 -> clamped to 100. Obvious headless
        // saturates the score.
        assert_eq!(score, 100);
    }

    #[test]
    fn stealth_headless_is_flagged_without_automation_marker() {
        let h = http(STEALTH_HEADLESS_CHROME);
        let ind = extract_headless_indicators(&h, STEALTH_HEADLESS_CHROME.iter().copied());
        // The marker indicator is the one stealth wrappers patch
        // and must not fire.
        assert!(!ind.automation_marker_in_user_agent);
        // The Sec-Ch-Ua + Sec-Fetch shape gives away the headless
        // origin even with the marker stripped.
        assert!(ind.claims_chrome_without_client_hints);
        assert!(ind.claims_chrome_without_sec_fetch);
        let score = score_headless(&ind);
        // 25 + 25 = 50; above the "high confidence headless"
        // threshold but below the saturate-on-marker score.
        assert!(
            (50..80).contains(&score),
            "stealth score landed at {score}; expected the high-confidence band"
        );
    }

    #[test]
    fn names_are_stable_and_lowercase() {
        let h = http(VANILLA_HEADLESS_CHROME);
        let ind = extract_headless_indicators(&h, VANILLA_HEADLESS_CHROME.iter().copied());
        let names = ind.names();
        // Field-declaration order, so downstream consumers can rely
        // on a stable list shape. Accept-Encoding on the vanilla
        // fixture is `gzip, deflate, br` which IS canonical, so
        // that indicator stays off.
        assert_eq!(
            names,
            vec![
                "automation_marker_in_user_agent",
                "claims_chrome_without_client_hints",
                "claims_chrome_without_sec_fetch",
            ]
        );
    }

    #[test]
    fn non_chrome_browser_does_not_fire_chrome_only_indicators() {
        // Firefox 120 navigation - Sec-Ch-Ua family is Chrome-only
        // by design (the Client Hints API is a Chrome surface), so
        // the absence must NOT fire the Chrome-only indicators on a
        // Firefox-claiming UA.
        let firefox: &[(&str, &str)] = &[
            ("host", "example.com"),
            ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0"),
            ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("accept-language", "en-US,en;q=0.5"),
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("upgrade-insecure-requests", "1"),
        ];
        let h = http(firefox);
        let ind = extract_headless_indicators(&h, firefox.iter().copied());
        assert!(!ind.claims_chrome_without_client_hints);
        assert!(!ind.claims_chrome_without_sec_fetch);
        assert!(!ind.automation_marker_in_user_agent);
        assert!(!ind.accept_language_missing);
        assert!(!ind.accept_encoding_anomalous);
        assert_eq!(ind.count(), 0);
    }

    #[test]
    fn empty_request_no_user_agent_does_not_panic() {
        let no_ua: &[(&str, &str)] = &[("host", "example.com")];
        let h = http(no_ua);
        let ind = extract_headless_indicators(&h, no_ua.iter().copied());
        // No UA -> no Chrome claim -> Chrome-only indicators stay
        // off; Accept-Language is missing which is expected for the
        // bare-host case.
        assert!(!ind.claims_chrome_without_client_hints);
        assert!(!ind.claims_chrome_without_sec_fetch);
        assert!(!ind.automation_marker_in_user_agent);
        assert!(ind.accept_language_missing);
    }

    #[test]
    fn accept_encoding_canonical_forms_are_not_flagged() {
        for canon in CANONICAL_ACCEPT_ENCODINGS {
            let headers: Vec<(&str, &str)> = vec![
                ("host", "example.com"),
                ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
                ("sec-ch-ua", "\"Chromium\";v=\"120\""),
                ("sec-ch-ua-mobile", "?0"),
                ("sec-ch-ua-platform", "\"macOS\""),
                ("sec-fetch-site", "none"),
                ("accept-language", "en-US"),
                ("accept-encoding", canon),
            ];
            let h = http(&headers);
            let ind = extract_headless_indicators(&h, headers.iter().copied());
            assert!(
                !ind.accept_encoding_anomalous,
                "canonical Accept-Encoding {canon:?} should not flag"
            );
        }
    }

    #[test]
    fn accept_encoding_curl_default_is_flagged() {
        // curl's default `Accept-Encoding` is `*/*` or absent; the
        // common curl + UA-spoof attack sets a Chrome UA but leaves
        // the encoding header as a single token. Verify the
        // anomaly trips.
        let curl_spoof: &[(&str, &str)] = &[
            ("host", "example.com"),
            ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
            ("sec-ch-ua", "\"Chromium\";v=\"120\""),
            ("sec-ch-ua-mobile", "?0"),
            ("sec-ch-ua-platform", "\"macOS\""),
            ("sec-fetch-site", "none"),
            ("accept-language", "en-US"),
            ("accept-encoding", "*"),
        ];
        let h = http(curl_spoof);
        let ind = extract_headless_indicators(&h, curl_spoof.iter().copied());
        assert!(ind.accept_encoding_anomalous);
        assert!(!ind.automation_marker_in_user_agent);
    }
}
