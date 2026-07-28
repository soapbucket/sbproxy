//! Q4.11 / WOR-14 fuzz harness for the llms.txt parser family.
//!
//! Feeds arbitrary valid UTF-8 through the production parser in the
//! `sbproxy-modules` transform layer:
//!
//! `llms_txt::parse(text)` (WOR-130, PR #157) takes `&str`; the
//! harness gates the call on a successful `str::from_utf8` so it
//! exercises the parser on every valid-UTF-8 corpus entry without a
//! lossy re-encoding step.
//!
//! The contract is no panics, no infinite loops, and bounded memory.
//! The llms.txt format is
//! Markdown-shaped per the llmstxt.org spec (top-level H1 + summary,
//! H2 sections each containing `[label](url): description` bullets).

#![no_main]

use libfuzzer_sys::fuzz_target;
use sbproxy_modules::transform::llms_txt;

fuzz_target!(|data: &[u8]| {
    // `llms_txt::parse` requires `&str`. Gate on UTF-8 validity so
    // the harness exercises the parser only on inputs it is
    // contracted to accept.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = llms_txt::parse(text);
    }
});
