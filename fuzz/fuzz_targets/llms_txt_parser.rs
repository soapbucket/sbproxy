//! Q4.11 / WOR-14 fuzz harness for the llms.txt parser family.
//!
//! Feeds arbitrary bytes through both production parsers in the
//! `sbproxy-modules` transform layer:
//!
//! * `llms_pricing::parse(bytes)` (WOR-188, PR #160) takes raw
//!   `&[u8]` and is the natural fit for the libFuzzer contract
//!   ("never panic on arbitrary bytes").
//! * `llms_txt::parse(text)` (WOR-130, PR #157) takes `&str`; we
//!   gate the call on a successful `str::from_utf8` so we exercise
//!   the parser on every valid-UTF-8 corpus entry without burning a
//!   lossy re-encoding step.
//!
//! The contract is the same for both targets: no panics, no
//! infinite loops, bounded memory. The llms.txt format is
//! Markdown-shaped per the llmstxt.org spec (top-level H1 + summary,
//! H2 sections each containing `[label](url): description` bullets);
//! the pricing variant layers in optional `(price)` annotations.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sbproxy_modules::transform::{llms_pricing, llms_txt};

fuzz_target!(|data: &[u8]| {
    // `llms_pricing::parse` accepts arbitrary bytes; drive it
    // unconditionally so libFuzzer keeps coverage signal on the
    // byte-level line walker for non-UTF-8 inputs too.
    let _ = llms_pricing::parse(data);

    // `llms_txt::parse` requires `&str`. Gate on UTF-8 validity so
    // the harness exercises the parser only on inputs it is
    // contracted to accept; non-UTF-8 fuzz inputs are still useful
    // for the pricing target above.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = llms_txt::parse(text);
    }
});
