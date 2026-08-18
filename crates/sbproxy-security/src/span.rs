//! Bounded detection spans (WOR-2492 item 6).
//!
//! A PII/secret detector today reports only that a shape matched, plus its
//! entity type. That is enough to block or redact, but not enough to audit:
//! two "email detected" records look identical whether the prompt carried
//! one address or five hundred, and a downstream reviewer replaying the
//! event has no way to jump to where the match was without re-running the
//! detector against a body the record does not carry.
//!
//! [`DetectionSpan`] closes that gap with the minimum that is actually
//! safe to keep: an entity type plus a byte offset and length into the
//! *scanned* (pre-redaction) text. Never the matched substring itself --
//! a span answers "where", not "what", so a record built from spans cannot
//! become a second place the PII or secret it flagged leaks from.
//!
//! [`cap_spans`] bounds every caller at [`MAX_DETECTION_SPANS`]. The cap is
//! deliberately not configurable: a pathological body (a prompt that is
//! nothing but a few thousand email addresses, say) must cost a detector a
//! fixed amount of record space, not a multiple of its own size.

/// Maximum spans one detection record carries. Config-free by design:
/// nothing in `sb.yml` raises it, so a record's size from this field is
/// bounded regardless of how adversarial the scanned body is.
pub const MAX_DETECTION_SPANS: usize = 32;

/// One bounded detection: an entity type plus its position in the
/// scanned (pre-redaction) text.
///
/// Positions only. There is no field for the matched text anywhere on
/// this type, on purpose -- a caller reaching for "what matched" has to
/// go get it from the live scan, not from a record that outlives the
/// request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DetectionSpan {
    /// The detector/rule name that matched (e.g. `email`, `aws_access`).
    pub entity_type: String,
    /// Byte offset of the match's start in the scanned text.
    pub offset: usize,
    /// Byte length of the match.
    pub len: usize,
}

impl DetectionSpan {
    /// Build one span.
    pub fn new(entity_type: impl Into<String>, offset: usize, len: usize) -> Self {
        Self {
            entity_type: entity_type.into(),
            offset,
            len,
        }
    }
}

/// Cap an iterator of spans at [`MAX_DETECTION_SPANS`], in encounter
/// order. Returns the kept spans plus a count of everything past the
/// cap, so a caller can say "and N more" without carrying them.
pub fn cap_spans(spans: impl IntoIterator<Item = DetectionSpan>) -> (Vec<DetectionSpan>, usize) {
    let mut kept = Vec::new();
    let mut dropped = 0usize;
    for span in spans {
        if kept.len() < MAX_DETECTION_SPANS {
            kept.push(span);
        } else {
            dropped += 1;
        }
    }
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_cap_keeps_everything_and_drops_nothing() {
        let spans = (0..5).map(|i| DetectionSpan::new("email", i * 10, 5));
        let (kept, dropped) = cap_spans(spans);
        assert_eq!(kept.len(), 5);
        assert_eq!(dropped, 0);
    }

    #[test]
    fn exactly_at_cap_drops_nothing() {
        let spans = (0..MAX_DETECTION_SPANS).map(|i| DetectionSpan::new("email", i, 1));
        let (kept, dropped) = cap_spans(spans);
        assert_eq!(kept.len(), MAX_DETECTION_SPANS);
        assert_eq!(dropped, 0);
    }

    /// Red-first (WOR-2492 item 6): the 33rd span is dropped, and the
    /// drop shows up as a count rather than silently vanishing.
    #[test]
    fn the_33rd_span_is_dropped_with_a_count() {
        let spans = (0..MAX_DETECTION_SPANS + 1).map(|i| DetectionSpan::new("email", i, 1));
        let (kept, dropped) = cap_spans(spans);
        assert_eq!(kept.len(), MAX_DETECTION_SPANS);
        assert_eq!(dropped, 1);
        assert_eq!(kept.last().unwrap().offset, MAX_DETECTION_SPANS - 1);
    }

    #[test]
    fn well_past_cap_counts_every_excess() {
        let spans = (0..MAX_DETECTION_SPANS + 50).map(|i| DetectionSpan::new("email", i, 1));
        let (kept, dropped) = cap_spans(spans);
        assert_eq!(kept.len(), MAX_DETECTION_SPANS);
        assert_eq!(dropped, 50);
    }

    #[test]
    fn a_span_never_carries_the_matched_text() {
        // Structural assertion: DetectionSpan has exactly the three
        // position fields. If a `text`/`value`/`matched` field is ever
        // added, this test's field list stops compiling.
        let span = DetectionSpan::new("email", 3, 17);
        let DetectionSpan {
            entity_type,
            offset,
            len,
        } = span;
        assert_eq!(entity_type, "email");
        assert_eq!(offset, 3);
        assert_eq!(len, 17);
    }
}
