//! WOR-650 - fuzz harness for the WASM extension runtime.
//!
//! Feeds arbitrary bytes as a candidate WebAssembly module into
//! `WasmRuntime::new`, which hands them to wasmtime's validating
//! compiler. The overwhelming majority of random inputs are rejected
//! at compile time (`compiling WASM bytes: ...`), which is the
//! intended behaviour; the point is that the wasmtime parser /
//! validator must never panic on malformed bytes. When a module does
//! compile, the harness instantiates and runs it under a tight
//! sandbox (small memory page cap, short epoch deadline, low fuel
//! budget) so a hostile module cannot stall the fuzzer or exhaust
//! host memory.
//!
//! Goal: no panic, no infinite loop, bounded memory. Both the
//! compile path and the (rare) execute path must drive the runtime
//! to a typed `Ok`/`Err`, never an abort.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sbproxy_extension::wasm::{WasmConfig, WasmRuntime};

/// Cap on the candidate-module length handed to the wasmtime
/// compiler. Real transform modules are tens to hundreds of KiB;
/// 256 KiB is a generous ceiling that keeps a fuzzer from feeding the
/// validator a multi-megabyte blob each iteration.
const MAX_MODULE_LEN: usize = 256 * 1024;

fuzz_target!(|data: &[u8]| {
    drive(data);
});

fn drive(input: &[u8]) {
    if input.len() > MAX_MODULE_LEN {
        return;
    }

    // Treat the fuzzer bytes as a candidate compiled WASM module. The
    // sandbox caps below bound any module that does manage to compile:
    // 16 pages (1 MiB) of linear memory, a 25 ms epoch deadline, and a
    // small fuel budget that traps a runaway module deterministically.
    let config = WasmConfig {
        module_path: None,
        module_bytes: Some(input.to_vec()),
        allowed_hosts: Vec::new(),
        max_memory_pages: Some(16),
        timeout_ms: Some(25),
        max_fuel: Some(5_000_000),
    };

    // Compilation rejects almost every random input. A valid module
    // (a corpus seed, say) is then instantiated and run with a tiny
    // input on stdin; either branch is acceptable to the fuzzer.
    if let Ok(runtime) = WasmRuntime::new(config) {
        if runtime.is_available() {
            let _ = runtime.execute("transform", b"fuzz");
        }
    }
}
