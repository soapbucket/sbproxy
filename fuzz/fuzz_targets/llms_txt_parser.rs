//! Q4.11 - fuzz harness for the llms.txt parser (G4.6).
//!
//! Feeds arbitrary bytes through the llms.txt parser. The llms.txt
//! format is Markdown-shaped (per the llmstxt.org spec): a top-level
//! H1 + summary, then H2 sections each containing a bulleted list of
//! `[label](url): description` entries. The production parser
//! (G4.6) is expected to be a small CommonMark walker; the stub here
//! exercises a comparable byte-level walk so the harness machinery is
//! functional today.
//!
//! Goal: no panics, no infinite loops, bounded memory.
//!
//! Once G4.6 ships a public
//! `sbproxy_modules::transform::llms_txt::parse(bytes)` entry-point,
//! replace the call to `stub_parse` and the contract still holds.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    stub_parse(data);
});

/// Stub llms.txt parser. Recognises:
///
///   - `# Heading` (top-level title).
///   - `## Section` (one section per group of links).
///   - `- [Label](URL): Description` (one entry per link).
///   - `> Summary` (block-quote, used for the per-page summary).
///
/// Designed to never panic. Caps work at 64k entries so an adversarial
/// well-formed input cannot wedge libFuzzer past its per-input
/// timeout.
fn stub_parse(input: &[u8]) {
    let mut titles: u32 = 0;
    let mut sections: u32 = 0;
    let mut entries: u32 = 0;
    const MAX_ENTRIES: u32 = 65_536;

    for line in input.split(|&b| b == b'\n') {
        let mut line = line;
        if let Some((&b'\r', rest)) = line.split_last() {
            line = rest;
        }
        let line = trim_ascii_left(line);
        if line.is_empty() {
            continue;
        }

        if line.starts_with(b"# ") {
            titles = titles.saturating_add(1);
        } else if line.starts_with(b"## ") {
            sections = sections.saturating_add(1);
        } else if line.starts_with(b"- ") || line.starts_with(b"* ") {
            // Try to find the link `[label](url)` shape. This is the
            // common case for llms.txt entries; the stub intentionally
            // tolerates any payload after the link.
            if let Some(open_bracket) = find_byte(line, b'[') {
                if let Some(close_bracket_rel) = find_byte(&line[open_bracket..], b']') {
                    let close_bracket = open_bracket + close_bracket_rel;
                    if line.get(close_bracket + 1) == Some(&b'(') {
                        if let Some(close_paren_rel) = find_byte(&line[close_bracket + 2..], b')') {
                            let close_paren = close_bracket + 2 + close_paren_rel;
                            let _label = &line[open_bracket + 1..close_bracket];
                            let _url = &line[close_bracket + 2..close_paren];
                            entries = entries.saturating_add(1);
                            if entries >= MAX_ENTRIES {
                                break;
                            }
                        }
                    }
                }
            }
        } else if line.starts_with(b"> ") {
            // Block-quote summary. No structured fields to extract;
            // count it for the assertion-free read.
            std::hint::black_box(line);
        }
    }
    std::hint::black_box((titles, sections, entries));
}

fn find_byte(s: &[u8], needle: u8) -> Option<usize> {
    for (i, &b) in s.iter().enumerate() {
        if b == needle {
            return Some(i);
        }
    }
    None
}

fn trim_ascii_left(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() && s[start].is_ascii_whitespace() {
        start += 1;
    }
    &s[start..]
}
