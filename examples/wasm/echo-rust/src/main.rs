//! Minimal sbproxy WASM transform: copy stdin to stdout.
//!
//! sbproxy invokes `_start` (the WASI entry point) for every
//! transform call. The host pipes the request body in on stdin and
//! captures whatever the module writes to stdout. There is no other
//! ABI to learn; if your code can read stdin and write stdout, it
//! can be an sbproxy WASM transform.
//!
//! Build:
//!     cargo build --release --target wasm32-wasi
//!
//! The output `target/wasm32-wasi/release/echo.wasm` is what you
//! point sbproxy at via `wasm.module_path`.

use std::io::{self, Read, Write};

fn main() {
    let mut input = Vec::new();
    if io::stdin().read_to_end(&mut input).is_err() {
        // A read failure leaves the body empty; do nothing.
        return;
    }
    // Echo the bytes back out unchanged. A real transform would
    // mutate `input` here before writing.
    let _ = io::stdout().write_all(&input);
}
