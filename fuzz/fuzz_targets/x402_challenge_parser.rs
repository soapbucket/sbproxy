//! W3 follow-up - x402 challenge body fuzzer.
//!
//! The Wave 3 fuzz harness file is referenced by the Q4.11 task spec
//! ("match the existing `x402_challenge_parser.rs` shape"). It lives
//! here in the Wave 4 fuzz crate so a single `cargo fuzz` invocation
//! covers both the W3 substrate and the W4 parsers.
//!
//! Goal: no panics, no infinite loops, bounded memory.
//!
//! Feeds arbitrary bytes into a JSON parse of the multi-rail 402
//! body envelope (per `docs/adr-multi-rail-402-challenge.md` A3.1).
//! Replace with a call to the production parser
//! (`sbproxy_modules::policy::accept_payment::parse_402_body`) once
//! that public entry-point lands.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try a full JSON parse first. Malformed input must not panic.
    let _ = parse_x402_body(data);
});

fn parse_x402_body(bytes: &[u8]) -> Option<usize> {
    // Cap input size so an adversarial input cannot consume gigabytes
    // of memory through the JSON parser. Real 402 bodies top out
    // around 8 KiB; 64 KiB is a generous cap.
    const MAX_LEN: usize = 65_536;
    if bytes.len() > MAX_LEN {
        return None;
    }
    // Stub JSON walk: count balanced braces and brackets. Replace
    // with a real parse once the public entry-point lands.
    let mut depth_brace: i32 = 0;
    let mut depth_bracket: i32 = 0;
    let mut in_string = false;
    let mut escape = false;
    let mut tokens: usize = 0;
    for &b in bytes {
        if escape {
            escape = false;
            continue;
        }
        if in_string {
            match b {
                b'\\' => escape = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => {
                depth_brace = depth_brace.saturating_add(1);
                tokens = tokens.saturating_add(1);
            }
            b'}' => depth_brace = depth_brace.saturating_sub(1),
            b'[' => {
                depth_bracket = depth_bracket.saturating_add(1);
                tokens = tokens.saturating_add(1);
            }
            b']' => depth_bracket = depth_bracket.saturating_sub(1),
            _ => {}
        }
        // Bail early on absurd nesting; libFuzzer's per-input timeout
        // also guards this, but a tight cap keeps the fuzzer from
        // wasting time on pathological inputs.
        if depth_brace > 1024 || depth_bracket > 1024 {
            return None;
        }
    }
    if depth_brace != 0 || depth_bracket != 0 {
        return None;
    }
    Some(tokens)
}
