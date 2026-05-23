//! WOR-650 - fuzz harness for the JavaScript scripting engine.
//!
//! Feeds arbitrary bytes as a JavaScript script into
//! `JsEngine::execute` (and the function-call entry point) under a
//! tight sandbox: a short CPU budget watchdog, a small heap cap, and
//! a small native stack cap. The CPU-budget watchdog is what keeps
//! the fuzzer from hanging on `while (true) {}`; the heap and stack
//! caps bound memory and recursion. The harness asserts only that
//! the host process never panics.
//!
//! Goal: no panic, no infinite loop, bounded memory. Every script
//! drives the engine to a typed `Ok`/`Err`. Sandbox-escape attempts
//! (`eval` reintroduction, `__proto__` mutation, unbounded recursion)
//! take the `Err` path or are neutralised, which is the documented
//! sandbox behaviour.

#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use sbproxy_extension::js::{JsEngine, JsSandboxConfig};

/// Cap on the script length handed to QuickJS. The ticket asks for a
/// 4 KiB ceiling on random JS scripts so a fuzzer cannot wedge on a
/// pathological multi-megabyte source.
const MAX_SCRIPT_LEN: usize = 4 * 1024;

/// Tight per-invocation sandbox so a hostile script cannot stall the
/// fuzzer: a 25 ms CPU budget, a 4 MiB heap, and a 256 KiB native
/// stack. All three are well under the documented defaults but ample
/// for any script the fuzzer can synthesize.
fn fuzz_sandbox() -> JsSandboxConfig {
    JsSandboxConfig {
        budget_ms: 25,
        memory_mb: 4,
        stack_kb: 256,
    }
}

fuzz_target!(|data: &[u8]| {
    drive(data);
});

fn drive(input: &[u8]) {
    if input.len() > MAX_SCRIPT_LEN {
        return;
    }

    // JS source is text. Lossy decoding keeps the harness fed on
    // non-UTF-8 input; QuickJS treats the replacement characters as
    // ordinary (usually invalid) tokens.
    let script = String::from_utf8_lossy(input);

    // Engine construction can fail only on QuickJS runtime setup;
    // treat that as a no-op input rather than a crash.
    let engine = match JsEngine::with_sandbox(fuzz_sandbox()) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Path A: bare-script evaluation. Exercises the parser, the
    // sandbox `eval`-removal, the heap cap, and the CPU-budget
    // watchdog all at once.
    let _ = engine.execute(&script, HashMap::new());

    // Path B: function-definition + call. Drives the `call_function`
    // path production request/response modifiers use, including the
    // hardened func-name lookup (no string interpolation). Random
    // input rarely defines the target function, so this usually fails
    // at the global lookup, which is the expected path.
    let _ = engine.call_function(&script, "modify_request", vec![serde_json::json!({})]);
}
