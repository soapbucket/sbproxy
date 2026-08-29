//! User-Agent parsing: browser / OS / device-type extraction plus a
//! headless-automation-library signal.
//!
//! ## Scope note: no bundled regex catalog
//!
//! An earlier design embedded a ~44 KB gzipped copy of the
//! `ua-parser`/`uap-core` regex catalog as a stepping stone toward a
//! future regex-driven engine, while the runtime parser it shipped
//! next to stayed the lightweight string-matching implementation
//! below (the catalog had no caller). This module ships only the
//! wired implementation: a bundled-but-unread data file is exactly
//! the "declared without a typed channel" shape this codebase
//! removes rather than carries forward (see `enricher/mod.rs`'s
//! module docs). Swapping to a regex-driven engine, if ever needed,
//! is a separate change that can add its own catalog when it has a
//! caller.
//!
//! ## Headless-library signal
//!
//! [`ParsedUserAgent::headless_library`] is a second, independent
//! headless-automation signal alongside the JA4-based TLS
//! fingerprint detector
//! (`sbproxy_security::headless_detect`/`RequestContext::headless_signal`).
//! It matches User-Agent tokens several common automation drivers
//! set by default (`HeadlessChrome`, Selenium's `webdriver`
//! parameter equivalents show up in the UA on some Selenium Manager
//! builds, PhantomJS's own UA string). Library name strings are
//! shared with the JA4 detector's vocabulary
//! (`"puppeteer"`, `"playwright"`, `"selenium"`, `"phantomjs"`,
//! `"headless_chrome"`) so a downstream consumer that reconciles both
//! signals compares like with like.

use serde::{Deserialize, Serialize};

/// Configuration for the `user_agent_parser` policy.
#[derive(Debug, Clone, Deserialize)]
pub struct UserAgentPolicy {
    /// Header name to stamp with the serialized parsed UA JSON on the
    /// upstream request. Defaults to `"x-parsed-ua"`.
    #[serde(default = "default_inject_header")]
    pub inject_header: String,
    /// Whether to stamp `inject_header` onto the upstream request at
    /// all. `true` by default; set `false` to populate
    /// `RequestContextView` / `RequestContext::parsed_user_agent` for
    /// hook consumers without adding an upstream header.
    #[serde(default = "default_true")]
    pub inject: bool,
}

fn default_inject_header() -> String {
    "x-parsed-ua".to_string()
}

fn default_true() -> bool {
    true
}

impl UserAgentPolicy {
    /// Deserialize a `user_agent_parser` policy config block.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }
}

/// Structured representation of a parsed User-Agent string.
///
/// This is the producer's output shape:
/// [`crate::policy::Policy::UserAgent`]'s enforcer stamps
/// `headless_library()` onto
/// `sbproxy_plugin::RequestContextView::ua_headless_library`, and
/// (when `inject` is set) serializes the whole struct as JSON onto
/// the upstream request's `inject_header`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ParsedUserAgent {
    /// Browser name (e.g. "Chrome", "Firefox", "Safari").
    pub browser_name: String,
    /// Browser version string (e.g. "120.0.6099.109").
    pub browser_version: String,
    /// Operating system name (e.g. "Windows", "macOS", "Linux", "Android", "iOS").
    pub os_name: String,
    /// Operating system version string.
    pub os_version: String,
    /// Device category: "desktop", "mobile", "tablet", "bot", or "unknown".
    pub device_type: String,
    /// Headless-automation-library label (e.g. `"headless_chrome"`,
    /// `"selenium"`), when the raw UA string carried a known
    /// automation-driver token. See [`Self::headless_library`] for
    /// the detection rule. `None` for an ordinary browser UA or a
    /// non-headless bot (a search-engine crawler is `device_type ==
    /// "bot"` but not a headless *browser*, so this stays `None` for
    /// it).
    pub headless_library: Option<String>,
}

impl ParsedUserAgent {
    /// Parse a User-Agent string into structured components.
    ///
    /// Detection order:
    /// 1. Bots (checked first; many bots also include OS tokens)
    /// 2. Device category (tablet before mobile to catch iPad)
    /// 3. Browser (reverse specificity: Edge before Chrome, Chrome before Safari)
    /// 4. Operating system
    pub fn parse(ua: &str) -> Self {
        if ua.is_empty() {
            return Self {
                device_type: "unknown".to_string(),
                ..Default::default()
            };
        }

        let ua_lower = ua.to_ascii_lowercase();

        // --- Bot detection ---
        let is_bot = ua_lower.contains("bot")
            || ua_lower.contains("crawler")
            || ua_lower.contains("spider")
            || ua_lower.contains("slurp")
            || ua_lower.contains("facebookexternalhit")
            || ua_lower.contains("whatsapp")
            || ua_lower.contains("twitterbot")
            || ua_lower.contains("linkedinbot")
            || ua_lower.contains("applebot")
            || ua_lower.contains("archive.org_bot")
            || ua_lower.contains("curl/")
            || ua_lower.contains("python-requests")
            || ua_lower.contains("go-http-client")
            || ua_lower.contains("java/")
            || ua_lower.contains("wget/");

        if is_bot {
            return Self {
                device_type: "bot".to_string(),
                ..Default::default()
            };
        }

        // --- Device category ---
        let is_ipad = ua_lower.contains("ipad");
        let is_iphone = ua_lower.contains("iphone");
        let is_android = ua_lower.contains("android");
        let is_mobile_token = ua_lower.contains("mobile");

        // The middle Android+mobile clause is fully subsumed by the
        // trailing is_mobile_token, so any UA carrying the "Mobile" token
        // (iPhone, Android phone, Windows Phone, etc.) lands on "mobile".
        // iPhone is kept explicit because some iPhone UAs omit "Mobile".
        let device_type = if is_ipad || (is_android && !is_mobile_token) {
            "tablet"
        } else if is_iphone || is_mobile_token {
            "mobile"
        } else {
            "desktop"
        }
        .to_string();

        // --- Browser detection (most specific first) ---
        // Edge must come before Chrome; OPR/Opera before Chrome; Chrome before Safari.
        let (browser_name, browser_version) = detect_browser(ua, &ua_lower);

        // --- OS detection ---
        let (os_name, os_version) = detect_os(ua, &ua_lower);

        let headless_library = Self::headless_library(ua).map(str::to_string);

        Self {
            browser_name,
            browser_version,
            os_name,
            os_version,
            device_type,
            headless_library,
        }
    }

    /// Return a stable headless-automation-library label when the
    /// User-Agent string carries a known automation-driver token,
    /// `None` otherwise.
    ///
    /// Independent of `device_type == "bot"`: a search-engine crawler
    /// is a bot but not a headless *browser*, and this method leaves
    /// it `None`. It matches only tokens that browser-automation
    /// tooling adds to (or fails to change from) the underlying
    /// browser's own UA string.
    pub fn headless_library(ua: &str) -> Option<&'static str> {
        let ua_lower = ua.to_ascii_lowercase();
        // Order matters only where one token could shadow another;
        // none do today, so this list is unordered otherwise.
        const TOKENS: &[(&str, &str)] = &[
            ("headlesschrome", "headless_chrome"),
            ("phantomjs", "phantomjs"),
            ("puppeteer", "puppeteer"),
            ("playwright", "playwright"),
            // Selenium's own HTTP client UA, and some driver-injected
            // markers; real browser-driven Selenium sessions usually
            // leave the browser's UA untouched, so this catches only
            // the subset that self-identifies.
            ("selenium", "selenium"),
        ];
        TOKENS
            .iter()
            .find(|(token, _)| ua_lower.contains(token))
            .map(|(_, label)| *label)
    }
}

// --- Browser detection helper ---

fn detect_browser(ua: &str, ua_lower: &str) -> (String, String) {
    // Try patterns in order of specificity. Each pattern is (token, display name).
    let patterns: &[(&str, &str)] = &[
        ("edg/", "Edge"),
        ("edga/", "Edge"),
        ("edgios/", "Edge"),
        ("opr/", "Opera"),
        ("opera/", "Opera"),
        ("firefox/", "Firefox"),
        ("fxios/", "Firefox"),
        ("chrome/", "Chrome"),
        ("crios/", "Chrome"),
        ("safari/", "Safari"),
    ];

    for (token, name) in patterns {
        if let Some(version) = extract_version_after(ua, ua_lower, token) {
            return (name.to_string(), version);
        }
    }

    // Mobile Safari without a chrome/firefox token.
    if ua_lower.contains("mobile/") && ua_lower.contains("safari/") {
        if let Some(version) = extract_version_after(ua, ua_lower, "version/") {
            return ("Safari".to_string(), version);
        }
    }

    (String::new(), String::new())
}

// --- OS detection helper ---

fn detect_os(ua: &str, ua_lower: &str) -> (String, String) {
    if ua_lower.contains("iphone") || ua_lower.contains("ipad") || ua_lower.contains("ipod") {
        let version = extract_ios_version(ua_lower).unwrap_or_default();
        return ("iOS".to_string(), version);
    }
    if ua_lower.contains("android") {
        let version = extract_version_after(ua, ua_lower, "android ").unwrap_or_default();
        return ("Android".to_string(), version);
    }
    if ua_lower.contains("windows nt") {
        let version = extract_version_after(ua, ua_lower, "windows nt ").unwrap_or_default();
        let friendly = match version.as_str() {
            "10.0" => "10".to_string(),
            "6.3" => "8.1".to_string(),
            "6.2" => "8".to_string(),
            "6.1" => "7".to_string(),
            "6.0" => "Vista".to_string(),
            "5.1" | "5.2" => "XP".to_string(),
            other => other.to_string(),
        };
        return ("Windows".to_string(), friendly);
    }
    if ua_lower.contains("macintosh") || ua_lower.contains("mac os x") {
        let version = extract_version_after(ua, ua_lower, "mac os x ")
            .map(|v| v.replace('_', "."))
            .unwrap_or_default();
        return ("macOS".to_string(), version);
    }
    if ua_lower.contains("linux") {
        return ("Linux".to_string(), String::new());
    }
    if ua_lower.contains("cros") {
        return ("ChromeOS".to_string(), String::new());
    }
    (String::new(), String::new())
}

// --- Version extraction utilities ---

/// Extract the version string that follows `token` in the UA string.
/// Stops at the first space, semicolon, or `)`.
///
/// `ua_lower` must be `ua.to_ascii_lowercase()`, never
/// `ua.to_lowercase()`. The byte offset `find` returns is measured
/// against the lowercased string and then applied to `ua`, which is
/// sound only while the two have the same length. `str::to_lowercase`
/// does not promise that: U+0130 is two bytes and lowercases to three,
/// so a UA built from a few of those would produce an offset past the
/// end of `ua`. `to_ascii_lowercase` leaves every non-ASCII byte alone
/// and is length-preserving by construction.
fn extract_version_after(ua: &str, ua_lower: &str, token: &str) -> Option<String> {
    let pos = ua_lower.find(token)?;
    let start = pos + token.len();
    // Defense in depth against a caller that builds `ua_lower` some
    // other way: an offset that is out of range, or that lands
    // mid-codepoint, yields no version rather than a panic. `parse` is
    // `pub` and re-exported from the crate root, so this is reachable
    // from outside this module.
    let rest = ua.get(start..)?;
    let end = rest.find([' ', ';', ')']).unwrap_or(rest.len());
    let version = &rest[..end];
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

/// Extract iOS version from patterns like "CPU iPhone OS 17_0 like" or "CPU OS 16_0 like".
fn extract_ios_version(ua_lower: &str) -> Option<String> {
    for token in &["cpu iphone os ", "cpu os "] {
        if let Some(pos) = ua_lower.find(token) {
            let start = pos + token.len();
            let rest = &ua_lower[start..];
            let end = rest.find([' ', ')']).unwrap_or(rest.len());
            let raw = &rest[..end];
            if !raw.is_empty() {
                return Some(raw.replace('_', "."));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_on_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Safari/537.36";
        let parsed = ParsedUserAgent::parse(ua);
        assert_eq!(parsed.browser_name, "Chrome");
        assert_eq!(parsed.browser_version, "120.0.6099.109");
        assert_eq!(parsed.os_name, "Windows");
        assert_eq!(parsed.os_version, "10");
        assert_eq!(parsed.device_type, "desktop");
    }

    #[test]
    fn firefox_on_linux() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0";
        let parsed = ParsedUserAgent::parse(ua);
        assert_eq!(parsed.browser_name, "Firefox");
        assert_eq!(parsed.browser_version, "121.0");
        assert_eq!(parsed.os_name, "Linux");
        assert_eq!(parsed.device_type, "desktop");
    }

    #[test]
    fn safari_on_macos() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15";
        let parsed = ParsedUserAgent::parse(ua);
        assert_eq!(parsed.browser_name, "Safari");
        assert_eq!(parsed.os_name, "macOS");
        assert_eq!(parsed.os_version, "14.2.1");
        assert_eq!(parsed.device_type, "desktop");
    }

    #[test]
    fn mobile_chrome_on_android() {
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36";
        let parsed = ParsedUserAgent::parse(ua);
        assert_eq!(parsed.browser_name, "Chrome");
        assert_eq!(parsed.os_name, "Android");
        assert_eq!(parsed.os_version, "14");
        assert_eq!(parsed.device_type, "mobile");
    }

    #[test]
    fn safari_on_iphone() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1";
        let parsed = ParsedUserAgent::parse(ua);
        assert_eq!(parsed.os_name, "iOS");
        assert_eq!(parsed.os_version, "17.2");
        assert_eq!(parsed.device_type, "mobile");
    }

    #[test]
    fn ipad_detected_as_tablet() {
        let ua = "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        let parsed = ParsedUserAgent::parse(ua);
        assert_eq!(parsed.device_type, "tablet");
        assert_eq!(parsed.os_name, "iOS");
    }

    #[test]
    fn googlebot_detected_as_bot() {
        let ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        let parsed = ParsedUserAgent::parse(ua);
        assert_eq!(parsed.device_type, "bot");
        assert!(parsed.browser_name.is_empty());
        assert!(parsed.os_name.is_empty());
    }

    #[test]
    fn bingbot_detected_as_bot() {
        let ua = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)";
        let parsed = ParsedUserAgent::parse(ua);
        assert_eq!(parsed.device_type, "bot");
    }

    #[test]
    fn empty_ua_is_unknown() {
        let parsed = ParsedUserAgent::parse("");
        assert_eq!(parsed.device_type, "unknown");
        assert!(parsed.browser_name.is_empty());
        assert!(parsed.os_name.is_empty());
    }

    #[test]
    fn unknown_ua_returns_partial_info() {
        let ua = "SomeObscureClient/1.0";
        let parsed = ParsedUserAgent::parse(ua);
        // No known browser or OS, device defaults to desktop (no mobile token).
        assert_eq!(parsed.device_type, "desktop");
        assert!(parsed.browser_name.is_empty());
        assert!(parsed.os_name.is_empty());
    }

    #[test]
    fn edge_on_windows_detected_correctly() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91";
        let parsed = ParsedUserAgent::parse(ua);
        assert_eq!(parsed.browser_name, "Edge");
        assert_eq!(parsed.browser_version, "120.0.2210.91");
        assert_eq!(parsed.os_name, "Windows");
    }

    #[test]
    fn curl_detected_as_bot() {
        let ua = "curl/8.5.0";
        let parsed = ParsedUserAgent::parse(ua);
        assert_eq!(parsed.device_type, "bot");
    }

    /// Regression test for the boolean-bug fix in device_type detection.
    /// The old expression had a redundant `(is_android && is_mobile_token)`
    /// clause subsumed by a trailing `is_mobile_token`. After cleanup the
    /// classification table must still match these canonical UAs.
    #[test]
    fn device_type_classification_matrix() {
        // Android phone -> mobile.
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36";
        assert_eq!(ParsedUserAgent::parse(ua).device_type, "mobile");

        // Android tablet (no "Mobile" token) -> tablet.
        let ua = "Mozilla/5.0 (Linux; Android 14; SM-X510) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36";
        assert_eq!(ParsedUserAgent::parse(ua).device_type, "tablet");

        // iPhone -> mobile.
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148";
        assert_eq!(ParsedUserAgent::parse(ua).device_type, "mobile");

        // iPad -> tablet (carries "Mobile" token but is_ipad wins).
        let ua = "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) Mobile/15E148";
        assert_eq!(ParsedUserAgent::parse(ua).device_type, "tablet");

        // Windows desktop -> desktop.
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";
        assert_eq!(ParsedUserAgent::parse(ua).device_type, "desktop");

        // Generic non-iPhone/non-Android UA carrying "Mobile" still maps
        // to mobile. This is the case the old redundant clause masked.
        let ua = "Mozilla/5.0 (X11; Mobile; Linux x86_64; rv:121.0) Firefox/121.0";
        assert_eq!(ParsedUserAgent::parse(ua).device_type, "mobile");
    }

    #[test]
    fn deserialize_config_defaults() {
        let val = serde_json::json!({});
        let policy = UserAgentPolicy::from_config(val).unwrap();
        assert_eq!(policy.inject_header, "x-parsed-ua");
        assert!(policy.inject);
    }

    #[test]
    fn deserialize_config_overrides() {
        let val = serde_json::json!({
            "inject_header": "x-ua-info",
            "inject": false
        });
        let policy = UserAgentPolicy::from_config(val).unwrap();
        assert_eq!(policy.inject_header, "x-ua-info");
        assert!(!policy.inject);
    }

    /// `parse` is `pub` and re-exported from the crate root, so it has
    /// to survive a `&str` that is not visible ASCII, whatever
    /// `HeaderValue::to_str` does or does not guarantee at the one call
    /// site inside this workspace.
    ///
    /// The specific hazard is byte-offset arithmetic across a case
    /// conversion. U+0130 is two bytes and `str::to_lowercase` maps it
    /// to three, so with the old `to_lowercase` the offset found in the
    /// lowercased string ran past the end of the original and
    /// `&ua[start..]` panicked. Four of them are enough to push the
    /// offset past `ua.len()`; a shorter run lands mid-codepoint and
    /// panics on the boundary assertion instead. Both are covered here.
    #[test]
    fn parse_survives_a_user_agent_whose_case_conversion_changes_its_length() {
        for prefix_len in 1..=6 {
            let ua = format!("{}Chrome/120.0.0.0", "\u{130}".repeat(prefix_len));
            let parsed = ParsedUserAgent::parse(&ua);
            // The only property under test is that this returns rather
            // than panicking. What it extracts from a UA like this is
            // not something a caller should rely on.
            assert!(
                !parsed.device_type.is_empty(),
                "parse must return a device_type for {ua:?}"
            );
        }

        // The same hazard through the other entry point that searches a
        // lowercased copy.
        assert_eq!(
            ParsedUserAgent::headless_library("\u{130}\u{130}HeadlessChrome/120"),
            Some("headless_chrome"),
            "an ASCII token is still found past a non-ASCII prefix"
        );
    }

    #[test]
    fn parse_populates_all_fields_for_valid_ua() {
        let parsed =
            ParsedUserAgent::parse("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0");
        assert_eq!(parsed.browser_name, "Chrome");
        assert_eq!(parsed.os_name, "Windows");
        assert_eq!(parsed.device_type, "desktop");
    }

    #[test]
    fn parse_handles_missing_ua_header_as_empty_string() {
        // The enforcer passes "" when the request carries no
        // User-Agent header at all; this must not panic and must
        // classify the same way an explicitly empty UA does.
        let parsed = ParsedUserAgent::parse("");
        assert_eq!(parsed.device_type, "unknown");
    }

    // --- Headless-library signal ---

    #[test]
    fn headless_chrome_ua_detected() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
                  HeadlessChrome/120.0.6099.109 Safari/537.36";
        assert_eq!(
            ParsedUserAgent::headless_library(ua),
            Some("headless_chrome")
        );
    }

    #[test]
    fn phantomjs_ua_detected() {
        let ua = "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) \
                  PhantomJS/2.1.1 Safari/538.1";
        assert_eq!(ParsedUserAgent::headless_library(ua), Some("phantomjs"));
    }

    #[test]
    fn puppeteer_ua_token_detected() {
        let ua = "Mozilla/5.0 (compatible; puppeteer-bot/1.0)";
        assert_eq!(ParsedUserAgent::headless_library(ua), Some("puppeteer"));
    }

    #[test]
    fn playwright_ua_token_detected() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64) playwright/1.40.0";
        assert_eq!(ParsedUserAgent::headless_library(ua), Some("playwright"));
    }

    #[test]
    fn selenium_ua_token_detected() {
        let ua = "selenium/4.16.1 (java linux)";
        assert_eq!(ParsedUserAgent::headless_library(ua), Some("selenium"));
    }

    #[test]
    fn ordinary_chrome_is_not_headless() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Safari/537.36";
        assert_eq!(ParsedUserAgent::headless_library(ua), None);
    }

    #[test]
    fn search_crawler_bot_is_not_headless() {
        // device_type == "bot" for Googlebot, but it is not a
        // headless *browser* automation library; the two signals are
        // independent.
        let ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        assert_eq!(ParsedUserAgent::headless_library(ua), None);
    }

    #[test]
    fn headless_library_none_for_empty_ua() {
        assert_eq!(ParsedUserAgent::headless_library(""), None);
    }

    #[test]
    fn parse_populates_headless_library_field() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
                  HeadlessChrome/120.0.6099.109 Safari/537.36";
        let parsed = ParsedUserAgent::parse(ua);
        assert_eq!(parsed.headless_library.as_deref(), Some("headless_chrome"));
        // The browser/OS fields still resolve normally alongside it.
        assert_eq!(parsed.browser_name, "Chrome");
    }

    #[test]
    fn parse_leaves_headless_library_none_for_ordinary_browser() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Safari/537.36";
        assert_eq!(ParsedUserAgent::parse(ua).headless_library, None);
    }

    #[test]
    fn parse_leaves_headless_library_none_for_bot_and_empty() {
        assert_eq!(ParsedUserAgent::parse("").headless_library, None);
        assert_eq!(
            ParsedUserAgent::parse(
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            )
            .headless_library,
            None
        );
    }
}
