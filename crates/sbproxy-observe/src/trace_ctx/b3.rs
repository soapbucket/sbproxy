//! B3 trace context propagation (Zipkin compatibility).
//!
//! Supports both single-header and multi-header formats.
//! Single:  `b3: {trace_id}-{span_id}-{sampled}[-{parent_span_id}]`
//! Multi:   `X-B3-TraceId`, `X-B3-SpanId`, `X-B3-Sampled`, `X-B3-ParentSpanId`

use super::w3c::TraceContext;

/// Parsed B3 context.
#[derive(Debug, Clone, PartialEq)]
pub struct B3Context {
    /// Trace identifier (32 or 16 hex chars; always stored as 32 chars, zero-padded).
    pub trace_id: String,
    /// Span identifier (16 hex chars).
    pub span_id: String,
    /// Sampling decision (`true` = sampled, `false` = not sampled, `None` = deferred).
    pub sampled: Option<bool>,
    /// Optional parent span identifier (16 hex chars).
    pub parent_span_id: Option<String>,
}

impl B3Context {
    /// Parse from the single `b3` header.
    ///
    /// Format: `{trace_id}-{span_id}[-{sampled}[-{parent_span_id}]]`
    ///
    /// Additionally handles the deny shorthand `b3: 0` and accept shorthand `b3: 1`.
    pub fn parse_single(header: &str) -> Option<Self> {
        let h = header.trim();
        // Shorthand deny/accept
        if h == "0" {
            // Propagate a placeholder with sampled=false; IDs are synthetic.
            let id = uuid::Uuid::new_v4().to_string().replace('-', "");
            return Some(Self {
                trace_id: id.clone(),
                span_id: id[..16].to_string(),
                sampled: Some(false),
                parent_span_id: None,
            });
        }
        if h == "1" {
            let id = uuid::Uuid::new_v4().to_string().replace('-', "");
            return Some(Self {
                trace_id: id.clone(),
                span_id: id[..16].to_string(),
                sampled: Some(true),
                parent_span_id: None,
            });
        }

        let parts: Vec<&str> = h.split('-').collect();
        if parts.len() < 2 {
            return None;
        }
        let trace_id = normalize_trace_id(parts[0])?;
        let span_id = validate_span_id(parts[1])?;
        let sampled = if parts.len() >= 3 {
            match parts[2] {
                "1" => Some(true),
                "0" => Some(false),
                // "d" = debug flag (treat as sampled)
                "d" => Some(true),
                _ => None,
            }
        } else {
            None
        };
        let parent_span_id = if parts.len() >= 4 {
            Some(validate_span_id(parts[3])?)
        } else {
            None
        };
        Some(Self {
            trace_id,
            span_id,
            sampled,
            parent_span_id,
        })
    }

    /// Parse from multi-header B3 fields.
    ///
    /// `sampled` corresponds to the `X-B3-Sampled` header value ("1" or "0").
    /// `parent` corresponds to the `X-B3-ParentSpanId` header value.
    pub fn parse_multi(
        trace_id: &str,
        span_id: &str,
        sampled: Option<&str>,
        parent: Option<&str>,
    ) -> Option<Self> {
        let trace_id = normalize_trace_id(trace_id)?;
        let span_id = validate_span_id(span_id)?;
        let sampled = sampled.and_then(|s| match s.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        });
        let parent_span_id = parent.and_then(validate_span_id);
        Some(Self {
            trace_id,
            span_id,
            sampled,
            parent_span_id,
        })
    }

    /// Convert to a W3C `TraceContext`.
    ///
    /// The B3 `span_id` becomes the W3C `parent_id` (the sending span).
    /// Sampling defaults to `true` when unset in B3 (deferred decision).
    pub fn to_w3c(&self) -> TraceContext {
        let trace_flags: u8 = if self.sampled.unwrap_or(true) {
            0x01
        } else {
            0x00
        };
        TraceContext {
            trace_id: self.trace_id.clone(),
            parent_id: self.span_id.clone(),
            trace_flags,
            tracestate: None,
        }
    }

    /// Serialize to the single `b3` header format.
    ///
    /// Format: `{trace_id}-{span_id}-{sampled}[-{parent_span_id}]`
    pub fn to_single_header(&self) -> String {
        let sampled_str = match self.sampled {
            Some(true) => "1",
            Some(false) => "0",
            None => "1", // omit decision defaults to sampled in Zipkin
        };
        match &self.parent_span_id {
            Some(parent) => format!(
                "{}-{}-{}-{}",
                self.trace_id, self.span_id, sampled_str, parent
            ),
            None => format!("{}-{}-{}", self.trace_id, self.span_id, sampled_str),
        }
    }
}

// --- Helpers ---

/// Normalize B3 trace_id: accept 16 or 32 hex chars; zero-pad 16-char IDs to 32.
fn normalize_trace_id(s: &str) -> Option<String> {
    let s = s.trim();
    match s.len() {
        32 => {
            if s.chars().all(|c| c.is_ascii_hexdigit()) {
                Some(s.to_string())
            } else {
                None
            }
        }
        16 => {
            if s.chars().all(|c| c.is_ascii_hexdigit()) {
                // Zero-pad to 32 chars (128-bit representation).
                Some(format!("{:0>32}", s))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Validate that a span/parent ID is exactly 16 hex chars.
fn validate_span_id(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(s.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Parse single header ---

    #[test]
    fn parse_single_sampled() {
        let ctx =
            B3Context::parse_single("80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1").unwrap();
        assert_eq!(ctx.trace_id, "80f198ee56343ba864fe8b2a57d3eff7");
        assert_eq!(ctx.span_id, "e457b5a2e4d86bd1");
        assert_eq!(ctx.sampled, Some(true));
        assert!(ctx.parent_span_id.is_none());
    }

    #[test]
    fn parse_single_not_sampled() {
        let ctx =
            B3Context::parse_single("80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-0").unwrap();
        assert_eq!(ctx.sampled, Some(false));
    }

    #[test]
    fn parse_single_with_parent() {
        let ctx = B3Context::parse_single(
            "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1-05e3ac9a4f6e3b90",
        )
        .unwrap();
        assert_eq!(ctx.parent_span_id.as_deref(), Some("05e3ac9a4f6e3b90"));
    }

    #[test]
    fn parse_single_16char_trace_id_zero_padded() {
        let ctx = B3Context::parse_single("64fe8b2a57d3eff7-e457b5a2e4d86bd1-1").unwrap();
        assert_eq!(ctx.trace_id.len(), 32);
        assert!(ctx.trace_id.starts_with("0000000000000000"));
    }

    #[test]
    fn parse_single_invalid_returns_none() {
        assert!(B3Context::parse_single("").is_none());
        assert!(B3Context::parse_single("garbage").is_none());
        // Span ID too short
        assert!(B3Context::parse_single("80f198ee56343ba864fe8b2a57d3eff7-short-1").is_none());
    }

    // --- Parse multi headers ---

    #[test]
    fn parse_multi_sampled() {
        let ctx = B3Context::parse_multi(
            "80f198ee56343ba864fe8b2a57d3eff7",
            "e457b5a2e4d86bd1",
            Some("1"),
            None,
        )
        .unwrap();
        assert_eq!(ctx.trace_id, "80f198ee56343ba864fe8b2a57d3eff7");
        assert_eq!(ctx.sampled, Some(true));
    }

    #[test]
    fn parse_multi_with_parent() {
        let ctx = B3Context::parse_multi(
            "80f198ee56343ba864fe8b2a57d3eff7",
            "e457b5a2e4d86bd1",
            Some("0"),
            Some("05e3ac9a4f6e3b90"),
        )
        .unwrap();
        assert_eq!(ctx.sampled, Some(false));
        assert_eq!(ctx.parent_span_id.as_deref(), Some("05e3ac9a4f6e3b90"));
    }

    #[test]
    fn parse_multi_invalid_returns_none() {
        // Bad trace_id
        assert!(B3Context::parse_multi("tooshort", "e457b5a2e4d86bd1", None, None).is_none());
        // Bad span_id
        assert!(
            B3Context::parse_multi("80f198ee56343ba864fe8b2a57d3eff7", "tooshort", None, None,)
                .is_none()
        );
    }

    // --- Convert B3 to W3C ---

    #[test]
    fn b3_to_w3c_sampled() {
        let b3 =
            B3Context::parse_single("80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1").unwrap();
        let w3c = b3.to_w3c();
        assert_eq!(w3c.trace_id, "80f198ee56343ba864fe8b2a57d3eff7");
        assert_eq!(w3c.parent_id, "e457b5a2e4d86bd1");
        assert!(w3c.is_sampled());
    }

    #[test]
    fn b3_to_w3c_not_sampled() {
        let b3 =
            B3Context::parse_single("80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-0").unwrap();
        let w3c = b3.to_w3c();
        assert!(!w3c.is_sampled());
    }

    #[test]
    fn b3_to_w3c_deferred_sampled_defaults_to_true() {
        // No sampled field -> deferred -> treat as sampled
        let b3 = B3Context {
            trace_id: "80f198ee56343ba864fe8b2a57d3eff7".to_string(),
            span_id: "e457b5a2e4d86bd1".to_string(),
            sampled: None,
            parent_span_id: None,
        };
        assert!(b3.to_w3c().is_sampled());
    }

    // --- Format single header ---

    #[test]
    fn format_single_header_no_parent() {
        let b3 = B3Context {
            trace_id: "80f198ee56343ba864fe8b2a57d3eff7".to_string(),
            span_id: "e457b5a2e4d86bd1".to_string(),
            sampled: Some(true),
            parent_span_id: None,
        };
        assert_eq!(
            b3.to_single_header(),
            "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1"
        );
    }

    #[test]
    fn format_single_header_with_parent() {
        let b3 = B3Context {
            trace_id: "80f198ee56343ba864fe8b2a57d3eff7".to_string(),
            span_id: "e457b5a2e4d86bd1".to_string(),
            sampled: Some(false),
            parent_span_id: Some("05e3ac9a4f6e3b90".to_string()),
        };
        assert_eq!(
            b3.to_single_header(),
            "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-0-05e3ac9a4f6e3b90"
        );
    }
}
