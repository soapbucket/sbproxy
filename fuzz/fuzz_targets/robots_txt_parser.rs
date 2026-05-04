//! Q4.11 - fuzz harness for the robots.txt parser (G4.5).
//!
//! Feeds arbitrary bytes through a robots.txt directive parser. Goal:
//!
//!   - No panics on any input.
//!   - No infinite loops.
//!   - Bounded allocations.
//!
//! Until G4.5 lands a public parser, this harness uses an in-file
//! line-oriented stub that matches the directive set the production
//! parser is expected to handle (`User-agent`, `Disallow`, `Allow`,
//! `Sitemap`, `Crawl-delay`, plus the SBproxy `SBproxy-AI-Extension`
//! directive defined in `docs/adr-policy-graph-projections.md`). The
//! stub is intentionally minimal so the fuzzer exercises the byte
//! handling, not the parser semantics.
//!
//! Once G4.5 ships a public
//! `sbproxy_modules::transform::robots::parse(bytes)` entry-point,
//! replace the call to `stub_parse` with a call to the production
//! function and the same panic / timeout / RSS contract holds.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The production parser is byte-oriented, not UTF-8-oriented;
    // robots.txt is officially ASCII per RFC 9309 but in practice
    // mirrors any byte. We mirror that and operate on bytes.
    stub_parse(data);
});

/// Stub robots.txt parser. Walks the input line-by-line and recognises
/// the directive set described above. Designed to never panic on any
/// byte sequence.
fn stub_parse(input: &[u8]) {
    let mut groups: u32 = 0;
    let mut directives: u32 = 0;
    // Line-split on `\n`. A real parser also splits on `\r\n`; the
    // stub treats `\r` as part of the line and trims it later.
    for line in input.split(|&b| b == b'\n') {
        let mut line = line;
        // Trim trailing \r.
        if let Some((&b'\r', rest)) = line.split_last() {
            line = rest;
        }
        // Comments: anything after `#` is ignored.
        let body = match memchr_b(line, b'#') {
            Some(idx) => &line[..idx],
            None => line,
        };
        // Trim leading + trailing ASCII whitespace.
        let body = trim_ascii(body);
        if body.is_empty() {
            continue;
        }
        // Split at the first `:`. No colon = malformed line; the
        // stub just skips it (a real parser would log + skip).
        let colon = match memchr_b(body, b':') {
            Some(idx) => idx,
            None => continue,
        };
        let directive = trim_ascii(&body[..colon]);
        let value = trim_ascii(&body[colon + 1..]);
        if directive.is_empty() {
            continue;
        }
        // Normalize directive to lowercase via byte arithmetic so
        // we never allocate (a real parser would intern, the fuzzer
        // does not need to).
        let mut lower = [0u8; 32];
        let n = std::cmp::min(directive.len(), lower.len());
        for i in 0..n {
            lower[i] = directive[i].to_ascii_lowercase();
        }
        match &lower[..n] {
            b"user-agent" => groups = groups.saturating_add(1),
            b"disallow" | b"allow" | b"sitemap" | b"crawl-delay" | b"sbproxy-ai-extension" => {
                directives = directives.saturating_add(1);
            }
            _ => {}
        }
        // Belt + suspenders: `value` must be valid UTF-8 to land in
        // the output. We don't decode here, just acknowledge it.
        std::hint::black_box(value);
    }
    std::hint::black_box((groups, directives));
}

/// Find the first occurrence of `needle` in `haystack`. Inlined
/// because the harness wants to avoid a `memchr` crate dep until the
/// production parser pulls it in.
fn memchr_b(haystack: &[u8], needle: u8) -> Option<usize> {
    for (i, &b) in haystack.iter().enumerate() {
        if b == needle {
            return Some(i);
        }
    }
    None
}

/// Trim ASCII whitespace from both ends. Mirrors `str::trim_ascii`
/// (stable since 1.80) on `[u8]`.
fn trim_ascii(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && s[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && s[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &s[start..end]
}
