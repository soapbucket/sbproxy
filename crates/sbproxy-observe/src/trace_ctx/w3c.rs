//! W3C Trace Context propagation (traceparent + tracestate).
//!
//! Spec: <https://www.w3.org/TR/trace-context/>
//! Format: traceparent: 00-{trace_id}-{parent_id}-{flags}

/// Parsed W3C trace context.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceContext {
    /// 32 hex chars identifying the overall trace.
    pub trace_id: String,
    /// 16 hex chars identifying the current span (parent in the downstream).
    pub parent_id: String,
    /// Trace flags byte: 0x00 = not sampled, 0x01 = sampled.
    pub trace_flags: u8,
    /// Optional vendor-specific tracestate header value.
    pub tracestate: Option<String>,
}

impl TraceContext {
    /// Parse from a `traceparent` header value.
    ///
    /// Expected format: `00-{trace_id(32)}-{parent_id(16)}-{flags(2)}`
    /// Returns `None` if the header is malformed or uses an unknown version.
    pub fn parse(traceparent: &str) -> Option<Self> {
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() < 4 {
            return None;
        }
        // Only version 00 is supported.
        if parts[0] != "00" {
            return None;
        }
        let trace_id = parts[1];
        let parent_id = parts[2];
        let flags_str = parts[3];
        // Validate lengths and hex encoding.
        if trace_id.len() != 32 || !trace_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if parent_id.len() != 16 || !parent_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if flags_str.len() != 2 || !flags_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let trace_flags = u8::from_str_radix(flags_str, 16).ok()?;
        Some(Self {
            trace_id: trace_id.to_string(),
            parent_id: parent_id.to_string(),
            trace_flags,
            tracestate: None,
        })
    }

    /// Parse from both `traceparent` and optional `tracestate` header values.
    pub fn parse_with_state(traceparent: &str, tracestate: Option<&str>) -> Option<Self> {
        let mut ctx = Self::parse(traceparent)?;
        ctx.tracestate = tracestate.map(|s| s.to_string());
        Some(ctx)
    }

    /// Generate a new root trace context with random IDs (sampled by default).
    pub fn new_random() -> Self {
        let trace_id = uuid::Uuid::new_v4().to_string().replace('-', "");
        let parent_id = uuid::Uuid::new_v4().to_string().replace('-', "")[..16].to_string();
        Self {
            trace_id,
            parent_id,
            trace_flags: 0x01, // sampled
            tracestate: None,
        }
    }

    /// Generate a child span context.
    ///
    /// Preserves the `trace_id` and `tracestate` but assigns a fresh `parent_id`
    /// so the child span can be correlated back to this context.
    pub fn child(&self) -> Self {
        let new_parent_id = uuid::Uuid::new_v4().to_string().replace('-', "")[..16].to_string();
        Self {
            trace_id: self.trace_id.clone(),
            parent_id: new_parent_id,
            trace_flags: self.trace_flags,
            tracestate: self.tracestate.clone(),
        }
    }

    /// Serialize to a `traceparent` header value.
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id, self.parent_id, self.trace_flags
        )
    }

    /// Return `true` if the sampled flag (bit 0) is set.
    pub fn is_sampled(&self) -> bool {
        self.trace_flags & 0x01 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Parse tests ---

    #[test]
    fn parse_valid_traceparent() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::parse(tp).expect("should parse valid traceparent");
        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.parent_id, "00f067aa0ba902b7");
        assert_eq!(ctx.trace_flags, 0x01);
        assert!(ctx.tracestate.is_none());
    }

    #[test]
    fn parse_not_sampled() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
        let ctx = TraceContext::parse(tp).unwrap();
        assert_eq!(ctx.trace_flags, 0x00);
        assert!(!ctx.is_sampled());
    }

    #[test]
    fn parse_with_tracestate() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ts = "vendor1=abc,vendor2=def";
        let ctx = TraceContext::parse_with_state(tp, Some(ts)).unwrap();
        assert_eq!(ctx.tracestate.as_deref(), Some("vendor1=abc,vendor2=def"));
    }

    #[test]
    fn parse_invalid_format_returns_none() {
        assert!(TraceContext::parse("garbage").is_none());
        assert!(TraceContext::parse("").is_none());
        assert!(TraceContext::parse("00-short-id-01").is_none());
        // Wrong version
        assert!(
            TraceContext::parse("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                .is_none()
        );
        // Bad trace_id length
        assert!(TraceContext::parse("00-4bf92f-00f067aa0ba902b7-01").is_none());
        // Bad parent_id length
        assert!(TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067-01").is_none());
        // Non-hex chars
        assert!(
            TraceContext::parse("00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01")
                .is_none()
        );
    }

    // --- new_random tests ---

    #[test]
    fn new_random_generates_valid_format() {
        let ctx = TraceContext::new_random();
        assert_eq!(ctx.trace_id.len(), 32, "trace_id must be 32 hex chars");
        assert_eq!(ctx.parent_id.len(), 16, "parent_id must be 16 hex chars");
        assert!(ctx.trace_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(ctx.parent_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(
            ctx.is_sampled(),
            "new contexts should be sampled by default"
        );
    }

    #[test]
    fn new_random_ids_are_unique() {
        let a = TraceContext::new_random();
        let b = TraceContext::new_random();
        // Astronomically unlikely to collide with UUIDs.
        assert_ne!(a.trace_id, b.trace_id);
        assert_ne!(a.parent_id, b.parent_id);
    }

    // --- child tests ---

    #[test]
    fn child_preserves_trace_id_changes_parent_id() {
        let root = TraceContext::new_random();
        let child = root.child();
        assert_eq!(child.trace_id, root.trace_id, "child must share trace_id");
        assert_ne!(
            child.parent_id, root.parent_id,
            "child must have a new parent_id"
        );
        assert_eq!(child.trace_flags, root.trace_flags);
    }

    #[test]
    fn child_inherits_tracestate() {
        let mut root = TraceContext::new_random();
        root.tracestate = Some("foo=bar".to_string());
        let child = root.child();
        assert_eq!(child.tracestate.as_deref(), Some("foo=bar"));
    }

    // --- Round-trip tests ---

    #[test]
    fn round_trip_parse_format_parse() {
        let original = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::parse(original).unwrap();
        let formatted = ctx.to_traceparent();
        let reparsed = TraceContext::parse(&formatted).unwrap();
        assert_eq!(ctx, reparsed);
    }

    #[test]
    fn to_traceparent_format() {
        let ctx = TraceContext {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            parent_id: "00f067aa0ba902b7".to_string(),
            trace_flags: 0x01,
            tracestate: None,
        };
        assert_eq!(
            ctx.to_traceparent(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );
    }

    // --- Sampled flag tests ---

    #[test]
    fn sampled_flag_parsing() {
        let sampled =
            TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap();
        assert!(sampled.is_sampled());

        let not_sampled =
            TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00").unwrap();
        assert!(!not_sampled.is_sampled());
    }
}
