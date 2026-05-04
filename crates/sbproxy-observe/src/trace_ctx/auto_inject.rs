//! Automatic trace span injection without application code changes.
//!
//! Provides deterministic sampling and `traceparent` / `x-service-name` header
//! generation for requests that pass through the proxy. The sampling decision
//! is based on a stable hash of the request ID so repeated retries of the same
//! logical request get the same sampling outcome.

// --- Config ---

/// Configuration for automatic trace header injection.
pub struct AutoInjectConfig {
    /// Whether automatic injection is enabled at all.
    pub enabled: bool,
    /// Service name embedded in injected headers.
    pub service_name: String,
    /// Fraction of requests to sample (0.0 = none, 1.0 = all).
    pub sample_rate: f64,
}

// --- Sampling ---

/// Determine whether this request should be sampled for tracing.
///
/// The decision is deterministic: the same `request_id` always produces the
/// same outcome for a given `sample_rate`, which avoids inconsistencies
/// across retries of the same logical request.
///
/// Returns `false` immediately when injection is disabled.
pub fn should_sample(config: &AutoInjectConfig, request_id: &str) -> bool {
    if !config.enabled {
        return false;
    }
    if config.sample_rate >= 1.0 {
        return true;
    }
    if config.sample_rate <= 0.0 {
        return false;
    }
    // Deterministic hash: FNV-1a-like accumulation over bytes.
    let hash = request_id
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
    (hash % 1000) < (config.sample_rate * 1000.0) as u64
}

// --- Header generation ---

/// Generate W3C `traceparent` and `x-service-name` headers for injection.
///
/// The trace and span IDs are randomly generated per invocation.
/// Returns a list of `(header-name, header-value)` pairs.
pub fn generate_trace_headers(service_name: &str) -> Vec<(String, String)> {
    let trace_id = format!("{:032x}", rand::random::<u128>());
    let span_id = format!("{:016x}", rand::random::<u64>());
    vec![
        (
            "traceparent".to_string(),
            format!("00-{trace_id}-{span_id}-01"),
        ),
        ("x-service-name".to_string(), service_name.to_string()),
    ]
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn enabled_config(sample_rate: f64) -> AutoInjectConfig {
        AutoInjectConfig {
            enabled: true,
            service_name: "sbproxy".to_string(),
            sample_rate,
        }
    }

    // --- Sampling tests ---

    #[test]
    fn test_disabled_config_never_samples() {
        let config = AutoInjectConfig {
            enabled: false,
            service_name: "sbproxy".to_string(),
            sample_rate: 1.0,
        };
        for i in 0..100 {
            assert!(
                !should_sample(&config, &i.to_string()),
                "disabled config should never sample"
            );
        }
    }

    #[test]
    fn test_full_sample_rate_always_samples() {
        let config = enabled_config(1.0);
        for i in 0..50 {
            assert!(should_sample(&config, &format!("req-{i}")));
        }
    }

    #[test]
    fn test_zero_sample_rate_never_samples() {
        let config = enabled_config(0.0);
        for i in 0..50 {
            assert!(!should_sample(&config, &format!("req-{i}")));
        }
    }

    #[test]
    fn test_sampling_is_deterministic() {
        // Same request_id must always produce the same sampling decision.
        let config = enabled_config(0.5);
        let request_id = "deterministic-request-id-abc";
        let first = should_sample(&config, request_id);
        for _ in 0..20 {
            assert_eq!(
                should_sample(&config, request_id),
                first,
                "sampling must be deterministic for the same request_id"
            );
        }
    }

    #[test]
    fn test_sampling_distributes_at_50_percent() {
        // Over a large enough sample set, roughly half should be sampled.
        let config = enabled_config(0.5);
        let sampled_count = (0..1000)
            .filter(|i| should_sample(&config, &format!("req-{i}")))
            .count();
        // Accept a ±10% tolerance.
        assert!(
            sampled_count > 400 && sampled_count < 600,
            "50% sampling should yield ~500/1000 (got {sampled_count})"
        );
    }

    #[test]
    fn test_sampling_distributes_at_10_percent() {
        let config = enabled_config(0.1);
        let sampled_count = (0..1000)
            .filter(|i| should_sample(&config, &format!("id-{i}")))
            .count();
        // Accept a ±10% tolerance of the expected 100.
        assert!(
            sampled_count < 200,
            "10% sampling should yield ~100/1000 (got {sampled_count})"
        );
    }

    // --- Header generation tests ---

    #[test]
    fn test_generate_trace_headers_count() {
        let headers = generate_trace_headers("my-service");
        assert_eq!(headers.len(), 2, "should produce exactly 2 headers");
    }

    #[test]
    fn test_generate_trace_headers_names() {
        let headers = generate_trace_headers("my-service");
        let names: HashSet<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains("traceparent"));
        assert!(names.contains("x-service-name"));
    }

    #[test]
    fn test_generate_trace_headers_traceparent_format() {
        let headers = generate_trace_headers("my-service");
        let traceparent = headers
            .iter()
            .find(|(k, _)| k == "traceparent")
            .map(|(_, v)| v.as_str())
            .unwrap();

        // Format: 00-{32 hex}-{16 hex}-01
        let parts: Vec<&str> = traceparent.split('-').collect();
        assert_eq!(
            parts.len(),
            4,
            "traceparent must have 4 dash-separated parts"
        );
        assert_eq!(parts[0], "00", "version must be '00'");
        assert_eq!(parts[1].len(), 32, "trace_id must be 32 hex chars");
        assert_eq!(parts[2].len(), 16, "span_id must be 16 hex chars");
        assert_eq!(parts[3], "01", "flags must be '01' (sampled)");

        assert!(
            parts[1].chars().all(|c| c.is_ascii_hexdigit()),
            "trace_id must be hex"
        );
        assert!(
            parts[2].chars().all(|c| c.is_ascii_hexdigit()),
            "span_id must be hex"
        );
    }

    #[test]
    fn test_generate_trace_headers_service_name() {
        let headers = generate_trace_headers("my-proxy-service");
        let service = headers
            .iter()
            .find(|(k, _)| k == "x-service-name")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert_eq!(service, "my-proxy-service");
    }

    #[test]
    fn test_generate_trace_headers_unique_trace_ids() {
        // Each call should generate a new, unique trace ID.
        let ids: HashSet<String> = (0..50)
            .map(|_| {
                let headers = generate_trace_headers("svc");
                headers
                    .iter()
                    .find(|(k, _)| k == "traceparent")
                    .unwrap()
                    .1
                    .clone()
            })
            .collect();
        assert!(ids.len() > 45, "most trace IDs should be unique");
    }
}
