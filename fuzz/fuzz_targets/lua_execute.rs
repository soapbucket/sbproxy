//! WOR-650 - fuzz harness for the Lua scripting engine.
//!
//! Feeds arbitrary bytes as a Lua script into `LuaEngine::execute`
//! (and the function-call entry points) under a tight sandbox: a
//! short wall-clock budget, a small memory cap, and the pattern API
//! left enabled so the pattern-matcher's known catastrophic-backtrack
//! inputs are exercised too. The sandbox limits are what keep the
//! fuzzer from hanging on `while true do end` or an out-of-memory
//! allocation loop; the harness asserts only that the host process
//! never panics.
//!
//! Goal: no panic, no infinite loop, bounded memory. Every script
//! drives the engine to a typed `Ok`/`Err`. Adversarial scripts that
//! try to escape the sandbox (`os`, `io`, `load`, ...) take the
//! `Err` path, which is the documented sandbox behaviour.

#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use sbproxy_extension::lua::{LuaEngine, SandboxConfig};

/// Cap on the script length handed to the Lua VM. The ticket asks
/// for a 4 KiB ceiling on random Lua scripts so a fuzzer cannot wedge
/// on a pathological multi-megabyte source before the sandbox budget
/// even engages.
const MAX_SCRIPT_LEN: usize = 4 * 1024;

/// Tight per-invocation sandbox so a hostile script cannot stall the
/// fuzzer. 25 ms wall-clock and 4 MiB of heap are well under the
/// documented defaults but ample for any script the fuzzer can
/// synthesize; `allow_patterns` stays on so `string.find` ReDoS
/// inputs are reachable.
fn fuzz_sandbox() -> SandboxConfig {
    SandboxConfig {
        max_execution_ms: 25,
        max_memory: 4 * 1024 * 1024,
        allow_patterns: true,
    }
}

fuzz_target!(|data: &[u8]| {
    drive(data);
});

fn drive(input: &[u8]) {
    if input.len() > MAX_SCRIPT_LEN {
        return;
    }

    // Lua source is text. Lossy decoding keeps the harness fed on
    // non-UTF-8 input; the loader treats the replacement characters
    // as ordinary (usually invalid) tokens.
    let script = String::from_utf8_lossy(input);

    // Engine construction can fail only on allocator/sandbox setup
    // errors; treat that as a no-op input rather than a crash.
    let engine = match LuaEngine::with_config(fuzz_sandbox()) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Path A: bare-script execution. Exercises the loader, the
    // sandbox global-nilling, the memory cap, and the wall-clock
    // interrupt all at once.
    let _ = engine.execute(&script, HashMap::new());

    // Path B: function-definition + call. Drives the `call_function`
    // path that production request/response modifiers use. The
    // function is unlikely to be defined by random input, so this
    // usually fails at the global lookup, which is the expected
    // missing-function path.
    let _ = engine.call_function(&script, "modify_request", vec![serde_json::json!({})]);
}
