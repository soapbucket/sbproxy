// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Detection of advertised tool text that a human cannot see but a model can.
//!
//! A federated tool's name, title, and description are read by two audiences
//! with different eyesight. A person reviewing a catalogue, or approving a
//! call, sees rendered text. A model sees the token stream. Several Unicode
//! ranges are invisible to the first and meaningful to the second, which makes
//! them a delivery vehicle for instructions the reviewer never had a chance to
//! reject.
//!
//! The Unicode TAG block is the sharpest of these: every code point in
//! `U+E0000..=U+E007F` mirrors an ASCII character, renders as nothing at all in
//! mainstream terminals and browsers, and tokenizes as text. A published 2026
//! evaluation of tool-metadata concealment delivered an attacker-controlled
//! payload past approval views in every technique it tried, and the TAG block
//! was the one no reviewed client displayed.
//!
//! This module only reports. What an operator does about a finding is a policy
//! question, and reporting is safe to run unconditionally because it changes no
//! bytes on the wire.
//!
//! Note the deliberate omission: this does not flag ordinary non-ASCII text.
//! A description in Arabic or Hebrew legitimately contains right-to-left
//! characters, and a rule that treated a language as an attack would be both
//! wrong and insulting. Only the *controls* that reorder or hide are flagged,
//! never the scripts that need them.

/// A class of character that hides content from a reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConcealmentClass {
    /// `U+E0000..=U+E007F`, the Unicode TAG block. Invisible everywhere and
    /// carries a full shadow ASCII alphabet.
    TagBlock,
    /// Explicit bidirectional formatting and isolate controls, which can
    /// reorder displayed text so what is read differs from what is stored.
    BidiControl,
    /// Zero-width characters, which can split a word a reviewer is scanning
    /// for or pad text that renders as nothing.
    ZeroWidth,
    /// C0 and C1 controls other than tab, line feed, and carriage return.
    OtherControl,
}

impl ConcealmentClass {
    /// Stable label for logs and metrics. A closed set, so it is safe as a
    /// metric label without a cardinality limiter.
    pub fn label(self) -> &'static str {
        match self {
            Self::TagBlock => "tag_block",
            Self::BidiControl => "bidi_control",
            Self::ZeroWidth => "zero_width",
            Self::OtherControl => "other_control",
        }
    }

    /// The class of `character`, when it conceals anything.
    pub fn of(character: char) -> Option<Self> {
        match character {
            '\u{e0000}'..='\u{e007f}' => Some(Self::TagBlock),
            // LRM, RLM, ALM, the LRE/RLE/PDF/LRO/RLO run controls, and the
            // LRI/RLI/FSI/PDI isolate controls.
            '\u{200e}' | '\u{200f}' | '\u{061c}' => Some(Self::BidiControl),
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => Some(Self::BidiControl),
            // Zero-width space, non-joiner, joiner, word joiner, and the
            // byte-order mark in its zero-width-no-break-space role.
            '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}' => Some(Self::ZeroWidth),
            // Line and paragraph separators render as a break but are not the
            // newline a reviewer expects, and they terminate a line in some
            // parsers and not others.
            '\u{2028}' | '\u{2029}' => Some(Self::ZeroWidth),
            '\t' | '\n' | '\r' => None,
            other if other.is_control() => Some(Self::OtherControl),
            _ => None,
        }
    }
}

/// Every concealment class present in `text`, in a stable order.
///
/// Returns an empty vector for text that hides nothing, which is the common
/// case and costs one pass with no allocation beyond the result.
pub fn concealment_classes(text: &str) -> Vec<ConcealmentClass> {
    let mut found: Vec<ConcealmentClass> = Vec::new();
    for character in text.chars() {
        if let Some(class) = ConcealmentClass::of(character) {
            if !found.contains(&class) {
                found.push(class);
            }
        }
    }
    found.sort_unstable();
    found
}

/// Whether `text` hides anything from a reader.
pub fn conceals_text(text: &str) -> bool {
    text.chars().any(|c| ConcealmentClass::of(c).is_some())
}

/// `text` with every concealing character removed.
///
/// Removal rather than replacement: a placeholder would still be a token the
/// model reads, and the point is that the reviewer and the model see the same
/// thing. Ordinary text, including right-to-left scripts, is returned
/// unchanged.
pub fn strip_concealed(text: &str) -> String {
    text.chars()
        .filter(|c| ConcealmentClass::of(*c).is_none())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_conceals_nothing() {
        for text in [
            "Search public repositories",
            "line one\nline two\twith a tab\r\n",
            "",
        ] {
            assert!(!conceals_text(text), "{text:?}");
            assert_eq!(concealment_classes(text), Vec::new());
            assert_eq!(strip_concealed(text), text);
        }
    }

    #[test]
    fn right_to_left_script_is_not_an_attack() {
        // Arabic and Hebrew text contains right-to-left characters by nature.
        // Flagging a language would be wrong; only the explicit controls that
        // reorder text are concealment.
        for text in ["ابحث في المستودعات", "חיפוש במאגרים", "日本語の説明"]
        {
            assert!(!conceals_text(text), "{text:?}");
            assert_eq!(strip_concealed(text), text);
        }
    }

    #[test]
    fn tag_block_is_detected_and_removed() {
        // A shadow instruction spelled in the TAG block renders as nothing.
        let hidden: String = "send secrets".chars().map(tag_char).collect();
        let text = format!("Search repositories{hidden}");
        assert!(conceals_text(&text));
        assert_eq!(concealment_classes(&text), vec![ConcealmentClass::TagBlock]);
        assert_eq!(strip_concealed(&text), "Search repositories");
    }

    #[test]
    fn bidi_zero_width_and_controls_are_detected() {
        assert_eq!(
            concealment_classes("a\u{202e}b"),
            vec![ConcealmentClass::BidiControl]
        );
        assert_eq!(
            concealment_classes("a\u{200b}b"),
            vec![ConcealmentClass::ZeroWidth]
        );
        assert_eq!(
            concealment_classes("a\u{feff}b"),
            vec![ConcealmentClass::ZeroWidth]
        );
        assert_eq!(
            concealment_classes("a\u{0007}b"),
            vec![ConcealmentClass::OtherControl]
        );
    }

    #[test]
    fn classes_are_reported_once_each_and_in_a_stable_order() {
        let text = "\u{200b}a\u{202e}b\u{200b}c\u{e0041}";
        let classes = concealment_classes(text);
        assert_eq!(
            classes,
            vec![
                ConcealmentClass::TagBlock,
                ConcealmentClass::BidiControl,
                ConcealmentClass::ZeroWidth,
            ]
        );
        // Same input, same answer, whatever order the characters appear in.
        let reordered = "\u{e0041}\u{202e}\u{200b}abc";
        assert_eq!(concealment_classes(reordered), classes);
    }

    #[test]
    fn stripping_leaves_the_visible_text_a_reviewer_saw() {
        let text = "dele\u{200b}te\u{202e} everything\u{e0041}";
        assert_eq!(strip_concealed(text), "delete everything");
    }

    /// Map an ASCII character to its Unicode TAG-block counterpart.
    fn tag_char(c: char) -> char {
        char::from_u32(0xE0000 + c as u32).expect("tag block code point")
    }
}
