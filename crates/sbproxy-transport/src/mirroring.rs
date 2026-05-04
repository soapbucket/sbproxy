//! Traffic mirroring / shadowing.
//!
//! Sends a copy of the request to a shadow upstream in the background.
//! The shadow response is discarded.  Used for testing new upstreams
//! without affecting production traffic.
//!
//! The [`MirrorConfig::sample_rate`] controls what fraction of requests are
//! mirrored (0.0 = none, 1.0 = all).

use serde::Deserialize;
use tracing::{debug, warn};

// --- MirrorConfig ---

/// Configuration for traffic mirroring to a shadow upstream.
#[derive(Debug, Clone, Deserialize)]
pub struct MirrorConfig {
    /// Full URL of the shadow upstream (scheme + host + optional path prefix).
    ///
    /// Example: `"http://shadow.internal:8080"`
    pub shadow_url: String,

    /// Fraction of requests to mirror (0.0 – 1.0).
    ///
    /// `0.0` disables mirroring; `1.0` mirrors every request.
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
}

fn default_sample_rate() -> f64 {
    1.0
}

// --- mirror_request ---

/// Mirror a request to the shadow upstream.  Fire-and-forget.
///
/// When the random sample falls outside `config.sample_rate` the function
/// returns immediately without spawning a task.
///
/// The shadow response (including any errors) is silently discarded so that
/// shadow traffic never affects production latency or error rates.
pub fn mirror_request(
    config: &MirrorConfig,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) {
    // --- Sampling ---
    let sample_rate = config.sample_rate.clamp(0.0, 1.0);
    if sample_rate <= 0.0 {
        return;
    }
    if sample_rate < 1.0 {
        // Use a fast, non-cryptographic random check.
        let r: f64 = random_f64();
        if r >= sample_rate {
            return;
        }
    }

    // --- Build the full target URL ---
    let shadow_url = config.shadow_url.trim_end_matches('/').to_string();
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let target_url = format!("{shadow_url}{path}");

    let method = method.to_string();
    let headers: Vec<(String, String)> = headers.to_vec();
    let body: Option<Vec<u8>> = body.map(|b| b.to_vec());

    tokio::spawn(async move {
        debug!(url = %target_url, "mirroring request to shadow upstream");

        let client = reqwest::Client::new();

        let req_method = match reqwest::Method::from_bytes(method.as_bytes()) {
            Ok(m) => m,
            Err(e) => {
                warn!("mirror: invalid HTTP method {method}: {e}");
                return;
            }
        };

        let mut builder = client.request(req_method, &target_url);

        for (name, value) in &headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        if let Some(bytes) = body {
            builder = builder.body(bytes);
        }

        // Discard both the response and any errors.
        match builder.send().await {
            Ok(resp) => {
                debug!(
                    url = %target_url,
                    status = resp.status().as_u16(),
                    "mirror response received (discarded)"
                );
            }
            Err(e) => {
                warn!("mirror request to {target_url} failed (ignored): {e}");
            }
        }
    });
}

// --- Internal helpers ---

/// Return a pseudo-random f64 in [0, 1) using the system time as entropy.
///
/// This is intentionally lightweight; cryptographic quality is not required
/// for sampling decisions.
fn random_f64() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // Map nanos (0..1_000_000_000) into [0, 1)
    (nanos % 1_000_000) as f64 / 1_000_000.0
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_config_default_sample_rate() {
        let json = r#"{"shadow_url": "http://shadow.internal:8080"}"#;
        let cfg: MirrorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.shadow_url, "http://shadow.internal:8080");
        assert_eq!(cfg.sample_rate, 1.0);
    }

    #[test]
    fn mirror_config_custom_sample_rate() {
        let json = r#"{"shadow_url": "http://shadow.internal", "sample_rate": 0.25}"#;
        let cfg: MirrorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.sample_rate, 0.25);
    }

    #[test]
    fn mirror_zero_sample_rate_does_not_panic() {
        // When sample_rate == 0.0 the function must return immediately.
        let cfg = MirrorConfig {
            shadow_url: "http://shadow.internal".to_string(),
            sample_rate: 0.0,
        };
        // Should not panic or block.
        mirror_request(&cfg, "GET", "/health", &[], None);
    }

    #[test]
    fn mirror_request_fires_with_body() {
        // Verify the call does not panic when a body is supplied.
        // The actual HTTP request will fail (no server running), but the
        // function is fire-and-forget so this is fine.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();

        let cfg = MirrorConfig {
            shadow_url: "http://127.0.0.1:1".to_string(), // port 1 will refuse
            sample_rate: 1.0,
        };
        mirror_request(
            &cfg,
            "POST",
            "/api/data",
            &[("content-type".to_string(), "application/json".to_string())],
            Some(b"{\"key\":\"value\"}"),
        );
        // No assertions; we only verify no panic occurs.
    }

    #[test]
    fn mirror_request_no_body() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();

        let cfg = MirrorConfig {
            shadow_url: "http://127.0.0.1:1".to_string(),
            sample_rate: 1.0,
        };
        mirror_request(&cfg, "GET", "/ping", &[], None);
    }

    #[test]
    fn mirror_invalid_method_does_not_panic() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();

        let cfg = MirrorConfig {
            shadow_url: "http://127.0.0.1:1".to_string(),
            sample_rate: 1.0,
        };
        // "GET PATH" contains a space which is invalid for a method token.
        mirror_request(&cfg, "INVALID METHOD", "/", &[], None);
    }

    #[test]
    fn random_f64_in_range() {
        for _ in 0..100 {
            let r = random_f64();
            assert!((0.0..1.0).contains(&r), "random_f64 out of range: {r}");
        }
    }
}
