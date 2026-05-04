// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! HTTP framing policy: detects request smuggling primitives.
//!
//! Defends against the request-smuggling / desync attack class
//! documented at
//! <https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn>
//! by rejecting requests whose framing is ambiguous BEFORE they
//! reach the upstream. Pingora's parser strictness handles a chunk
//! of the wire-level malformed input; this policy adds the
//! semantic-ambiguity layer.
//!
//! ## Violations rejected (all return 400 Bad Request)
//!
//! 1. **Dual CL+TE** - request carries both `Content-Length` and
//!    `Transfer-Encoding`. Per RFC 9112 § 6.1 the receiver MUST
//!    pick one and SHOULD reject; we reject so a downstream proxy /
//!    upstream can't disagree with our choice.
//! 2. **Duplicate CL** - multiple `Content-Length` headers. Even
//!    if every value matches, picking which copy to forward is
//!    proxy-implementation-specific; reject the ambiguity.
//! 3. **Malformed TE** - any `Transfer-Encoding` value that is not
//!    exactly `chunked` after trimming + lowercasing. Catches
//!    `xchunked`, `chunked\r\n`, leading whitespace,
//!    `Transfer-Encoding: gzip, chunked` (legitimate per RFC but
//!    rare in practice and a known smuggling vector), etc.
//! 4. **Duplicate TE** - multiple `Transfer-Encoding` headers.
//!    The classic TE.TE attack relies on one parser honoring the
//!    first and another the last.
//! 5. **Control chars** - CR, LF, or NUL in any header value the
//!    proxy still sees after Pingora's parser. Defense in depth:
//!    Pingora rejects most of these at parse time, but some bytes
//!    (NUL in particular) historically slip through.
//!
//! Each violation increments
//! `sbproxy_http_framing_blocks_total{reason}` so operators can see
//! the attack rate independently of policy_denied counters.

use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::HeaderMap;
use serde::Deserialize;

/// Per-origin http_framing policy. No tunable knobs today; the
/// defense set is hard-coded because each violation maps to a known
/// smuggling primitive that no legitimate caller produces. Future
/// work may expose an `allow_te_chains: bool` knob for backends
/// that genuinely use `Transfer-Encoding: gzip, chunked`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HttpFramingPolicy {
    /// Reserved for future per-origin tuning. Today the policy
    /// applies the default defense set unconditionally.
    #[serde(default)]
    pub _reserved: serde_json::Value,
}

/// Reason a request was rejected by the framing policy. The
/// discriminant string is what feeds the
/// `sbproxy_http_framing_blocks_total{reason}` metric label, so
/// values are short and stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingViolation {
    /// Both `Content-Length` and `Transfer-Encoding` headers present.
    DualClTe,
    /// Multiple `Content-Length` headers (or comma-folded list).
    DuplicateCl,
    /// `Transfer-Encoding` value is not exactly `chunked`.
    MalformedTe,
    /// Multiple `Transfer-Encoding` headers.
    DuplicateTe,
    /// Control characters (CR, LF, NUL) in a header value.
    ControlChars,
}

impl FramingViolation {
    /// Stable label for the Prometheus metric.
    pub fn metric_reason(self) -> &'static str {
        match self {
            Self::DualClTe => "dual_cl_te",
            Self::DuplicateCl => "duplicate_cl",
            Self::MalformedTe => "malformed_te",
            Self::DuplicateTe => "duplicate_te",
            Self::ControlChars => "control_chars",
        }
    }

    /// Short message suitable for the 400 response body. Does not
    /// expose the offending header value, only the rule.
    pub fn message(self) -> &'static str {
        match self {
            Self::DualClTe => {
                "ambiguous framing: both Content-Length and Transfer-Encoding present"
            }
            Self::DuplicateCl => "ambiguous framing: duplicate Content-Length",
            Self::MalformedTe => "malformed Transfer-Encoding",
            Self::DuplicateTe => "ambiguous framing: duplicate Transfer-Encoding",
            Self::ControlChars => "control characters in header value",
        }
    }
}

impl HttpFramingPolicy {
    /// Construct from the policy block in `sb.yml`. The shape is
    /// intentionally empty; we accept any JSON object so operators
    /// who write `policies: [{type: http_framing}]` work without
    /// extra fields.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let policy: Self = serde_json::from_value(value).unwrap_or_default();
        Ok(policy)
    }

    /// Inspect the request headers and return the first
    /// [`FramingViolation`] found, or `Ok(())` if framing is clean.
    /// The order of checks is deterministic so dashboards can rely
    /// on a stable reason label per attack pattern.
    pub fn check_request(&self, headers: &HeaderMap) -> Result<(), FramingViolation> {
        // Count CL / TE occurrences.
        let cl_count = headers.get_all(CONTENT_LENGTH).iter().count();
        let te_count = headers.get_all(TRANSFER_ENCODING).iter().count();

        // 1. Dual CL+TE.
        if cl_count > 0 && te_count > 0 {
            return Err(FramingViolation::DualClTe);
        }

        // 2. Duplicate CL. Multiple headers OR a single header with a
        //    comma-folded list (`Content-Length: 5, 5`) are both
        //    considered duplicate; the second case is what intermediate
        //    proxies sometimes produce when they rewrite headers.
        if cl_count > 1 {
            return Err(FramingViolation::DuplicateCl);
        }
        if cl_count == 1 {
            let val = headers
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if val.contains(',') {
                return Err(FramingViolation::DuplicateCl);
            }
            // Numeric sanity: reject negative / non-integer values
            // outright. Pingora generally catches these, but the
            // policy enforces explicitly so a future loosening of
            // Pingora's parser does not silently re-open the hole.
            if val.trim().parse::<u64>().is_err() {
                return Err(FramingViolation::DuplicateCl);
            }
        }

        // 3. Duplicate TE.
        if te_count > 1 {
            return Err(FramingViolation::DuplicateTe);
        }

        // 4. Malformed TE. The only value we accept is `chunked`
        //    (case-insensitive after trimming). Comma-folded chains
        //    like `gzip, chunked` are rare in practice and a known
        //    smuggling primitive; reject them.
        if te_count == 1 {
            let raw = headers
                .get(TRANSFER_ENCODING)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let normalized = raw.trim().to_ascii_lowercase();
            if normalized != "chunked" {
                return Err(FramingViolation::MalformedTe);
            }
        }

        // 5. Control characters in any header value. Pingora's HTTP/1
        //    parser strips most of these at parse time; this is a
        //    belt-and-suspenders check so a future parser regression
        //    does not silently smuggle CRLF through.
        for value in headers.values() {
            let bytes = value.as_bytes();
            if bytes.iter().any(|b| matches!(*b, 0 | b'\r' | b'\n')) {
                return Err(FramingViolation::ControlChars);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderName, HeaderValue};

    fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_bytes(v.as_bytes()).unwrap(),
            );
        }
        h
    }

    fn policy() -> HttpFramingPolicy {
        HttpFramingPolicy::default()
    }

    // --- Clean traffic passes ---

    #[test]
    fn clean_request_with_content_length_passes() {
        let h = headers_from(&[("content-length", "42")]);
        assert!(policy().check_request(&h).is_ok());
    }

    #[test]
    fn clean_request_with_transfer_encoding_chunked_passes() {
        let h = headers_from(&[("transfer-encoding", "chunked")]);
        assert!(policy().check_request(&h).is_ok());
    }

    #[test]
    fn clean_request_with_neither_passes() {
        let h = headers_from(&[("host", "api.example.com")]);
        assert!(policy().check_request(&h).is_ok());
    }

    #[test]
    fn case_insensitive_chunked_passes() {
        let h = headers_from(&[("transfer-encoding", "Chunked")]);
        assert!(policy().check_request(&h).is_ok());
        let h = headers_from(&[("transfer-encoding", "CHUNKED")]);
        assert!(policy().check_request(&h).is_ok());
    }

    #[test]
    fn whitespace_around_chunked_passes() {
        let h = headers_from(&[("transfer-encoding", "  chunked  ")]);
        assert!(policy().check_request(&h).is_ok());
    }

    // --- Dual CL+TE ---

    #[test]
    fn dual_cl_te_rejected() {
        let h = headers_from(&[("content-length", "6"), ("transfer-encoding", "chunked")]);
        assert_eq!(policy().check_request(&h), Err(FramingViolation::DualClTe));
    }

    // --- Duplicate CL ---

    #[test]
    fn duplicate_cl_via_two_headers_rejected() {
        let h = headers_from(&[("content-length", "6"), ("content-length", "6")]);
        assert_eq!(
            policy().check_request(&h),
            Err(FramingViolation::DuplicateCl)
        );
    }

    #[test]
    fn duplicate_cl_via_disagreeing_two_headers_rejected() {
        let h = headers_from(&[("content-length", "6"), ("content-length", "12")]);
        assert_eq!(
            policy().check_request(&h),
            Err(FramingViolation::DuplicateCl)
        );
    }

    #[test]
    fn duplicate_cl_via_comma_folded_value_rejected() {
        let h = headers_from(&[("content-length", "6, 6")]);
        assert_eq!(
            policy().check_request(&h),
            Err(FramingViolation::DuplicateCl)
        );
    }

    #[test]
    fn non_numeric_cl_rejected() {
        let h = headers_from(&[("content-length", "abc")]);
        assert_eq!(
            policy().check_request(&h),
            Err(FramingViolation::DuplicateCl)
        );
    }

    #[test]
    fn negative_cl_rejected() {
        let h = headers_from(&[("content-length", "-5")]);
        assert_eq!(
            policy().check_request(&h),
            Err(FramingViolation::DuplicateCl)
        );
    }

    // --- Duplicate TE ---

    #[test]
    fn duplicate_te_rejected() {
        let h = headers_from(&[
            ("transfer-encoding", "chunked"),
            ("transfer-encoding", "chunked"),
        ]);
        assert_eq!(
            policy().check_request(&h),
            Err(FramingViolation::DuplicateTe)
        );
    }

    #[test]
    fn duplicate_te_with_one_obfuscated_rejected() {
        // The classic TE.TE smuggling: one parser sees the first,
        // one sees the last. We reject before that ambiguity matters.
        let h = headers_from(&[("transfer-encoding", "chunked"), ("transfer-encoding", "x")]);
        assert_eq!(
            policy().check_request(&h),
            Err(FramingViolation::DuplicateTe)
        );
    }

    // --- Malformed TE ---

    #[test]
    fn malformed_te_xchunked_rejected() {
        let h = headers_from(&[("transfer-encoding", "xchunked")]);
        assert_eq!(
            policy().check_request(&h),
            Err(FramingViolation::MalformedTe)
        );
    }

    #[test]
    fn malformed_te_gzip_chunked_chain_rejected() {
        // RFC-legal but a known smuggling vector and rare in practice.
        let h = headers_from(&[("transfer-encoding", "gzip, chunked")]);
        assert_eq!(
            policy().check_request(&h),
            Err(FramingViolation::MalformedTe)
        );
    }

    #[test]
    fn malformed_te_identity_rejected() {
        let h = headers_from(&[("transfer-encoding", "identity")]);
        assert_eq!(
            policy().check_request(&h),
            Err(FramingViolation::MalformedTe)
        );
    }

    // --- Control characters ---
    //
    // `http::HeaderValue::from_bytes` already rejects CR / LF / NUL
    // at construction time, so a request that survives Pingora's
    // parser cannot carry these bytes in a header value. The check
    // in [`HttpFramingPolicy::check_request`] stays as defense in
    // depth for any future parser regression that loosens this
    // invariant. We assert HeaderValue's rejection directly here so
    // a regression in the http crate would still surface.

    #[test]
    fn http_crate_rejects_cr_in_header_value() {
        let v = http::HeaderValue::from_bytes(b"value\rwith\rcr");
        assert!(
            v.is_err(),
            "the http crate should reject CR in header values; \
             if this changes, the policy's ControlChars branch becomes \
             reachable and needs explicit test coverage"
        );
    }

    #[test]
    fn http_crate_rejects_lf_in_header_value() {
        let v = http::HeaderValue::from_bytes(b"value\nwith\nlf");
        assert!(v.is_err());
    }

    #[test]
    fn http_crate_rejects_nul_in_header_value() {
        let v = http::HeaderValue::from_bytes(b"value\0with\0nul");
        assert!(v.is_err());
    }

    // --- Metric labels stable ---

    #[test]
    fn metric_reason_labels_are_short_and_stable() {
        // The metric labels are hard-coded into dashboards; this test
        // pins them.
        assert_eq!(FramingViolation::DualClTe.metric_reason(), "dual_cl_te");
        assert_eq!(
            FramingViolation::DuplicateCl.metric_reason(),
            "duplicate_cl"
        );
        assert_eq!(
            FramingViolation::MalformedTe.metric_reason(),
            "malformed_te"
        );
        assert_eq!(
            FramingViolation::DuplicateTe.metric_reason(),
            "duplicate_te"
        );
        assert_eq!(
            FramingViolation::ControlChars.metric_reason(),
            "control_chars"
        );
    }

    // --- Order of checks is stable ---

    #[test]
    fn dual_cl_te_takes_precedence_over_duplicate_cl() {
        // When both rules trigger, the per-stream metric always
        // increments dual_cl_te. Pin the precedence so dashboards
        // count the right reason.
        let h = headers_from(&[
            ("content-length", "5"),
            ("content-length", "5"),
            ("transfer-encoding", "chunked"),
        ]);
        assert_eq!(policy().check_request(&h), Err(FramingViolation::DualClTe));
    }
}
