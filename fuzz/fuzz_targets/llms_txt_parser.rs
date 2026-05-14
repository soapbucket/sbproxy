//! Q4.11 - fuzz harness for the llms.txt parser (G4.6 + WOR-130).
//!
//! Feeds arbitrary bytes through the production llms.txt parser. The
//! llms.txt format is Markdown-shaped (per the llmstxt.org spec): a
//! top-level H1 + summary, then H2 sections each containing a bulleted
//! list of `[label](url): description` entries.
//!
//! WOR-130 ships the production parser at
//! `sbproxy_modules::transform::llms_txt::parse(&str)`. This target
//! re-encodes arbitrary bytes as a `&str` (lossy on non-UTF-8 sequences)
//! and drives the public parser. The contract is the same as the
//! stub-era harness: no panics, no infinite loops, bounded memory.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sbproxy_modules::transform::llms_txt;

fuzz_target!(|data: &[u8]| {
    // The production parser takes `&str`. `from_utf8_lossy` keeps the
    // harness lenient (it never short-circuits on a non-UTF-8 byte) so
    // libFuzzer keeps producing useful coverage signal on the parser's
    // line-walking and bracket-matching paths.
    let text = String::from_utf8_lossy(data);
    let _ = llms_txt::parse(text.as_ref());
});
