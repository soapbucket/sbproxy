# WASM transform development guide

*Last modified: 2026-04-27*

This guide covers writing WebAssembly modules for sbproxy's `wasm`
transform. Two minimal example modules live in `examples/wasm/`,
one in Rust and one in TinyGo. Both compile against the same WASI
preview-1 contract; pick the toolchain you prefer.

## Why WASM

The other scripting engines (CEL, Lua, JavaScript) cover most needs
inside a single language. WASM is the right pick when you want:

- A language sbproxy does not ship a first-class engine for (Rust,
  TinyGo, AssemblyScript, Zig, Swift, C/C++).
- Stronger isolation than an interpreter. Each invocation gets a
  fresh `Store` with capped memory and a wall-clock deadline.
- Reuse of a compiled body-transform module across origins or
  environments without rewriting in the proxy's scripting languages.

WASM transforms run after the upstream response has been buffered
and replace the response body. They cannot read the request, modify
headers, or short-circuit the response.

## The contract

The host invokes the module's WASI `_start` export once per request.
There is no custom calling convention. The host pipes:

| Channel | Direction | Contents |
|---|---|---|
| stdin | host -> module | The full upstream response body |
| stdout | module -> host | The new response body |
| stderr | module -> host | Captured for debug logging |

Whatever the module writes to stdout becomes the new response body.
If the module writes nothing, the body becomes empty. If `_start`
traps (panics, hits the timeout, exhausts memory), the transform
fails and the request follows the standard transform error path
(see `transforms.fail_on_error` in `configuration.md`).

That is the whole ABI. No imports beyond standard WASI. No exports
beyond `_start`. Any `wasm32-wasi` binary that reads stdin and
writes stdout works.

## Hello world: Rust

```rust
use std::io::{self, Read, Write};

fn main() {
    let mut buf = Vec::new();
    let _ = io::stdin().read_to_end(&mut buf);
    // Real transforms mutate `buf`. This one just echoes.
    let _ = io::stdout().write_all(&buf);
}
```

Build:

```bash
cargo build --release --target wasm32-wasi
```

The output `target/wasm32-wasi/release/<crate>.wasm` is what you
point sbproxy at. The full example is in `examples/wasm/echo-rust/`,
including a Docker-based build script so contributors do not need
to install rustup or the `wasm32-wasi` target locally.

## Hello world: TinyGo

```go
package main

import (
    "bytes"
    "io"
    "os"
)

func main() {
    body, err := io.ReadAll(os.Stdin)
    if err != nil {
        return
    }
    _, _ = os.Stdout.Write(bytes.ToUpper(body))
}
```

Build:

```bash
tinygo build -o uppercase.wasm -target=wasi -no-debug main.go
```

The full example is in `examples/wasm/uppercase-tinygo/`. The
`-no-debug` flag is worth keeping; debug info inflates the module
size by 5x to 10x for trivial programs. TinyGo's WASI target lacks
parts of the Go standard library (`net`, `os/exec`, anything that
needs a real OS), but the basics (`io`, `bytes`, `strings`, `unicode`,
`encoding/json`, `regexp`) all work.

## Configuring a transform

```yaml
origins:
  "wasm.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "hello from sbproxy"
    transforms:
      - type: wasm
        module_path: examples/wasm/echo-rust/echo.wasm
        timeout_ms: 500
        max_memory_pages: 256
```

Field reference:

| Field | Default | Notes |
|---|---|---|
| `module_path` | required (or `module_bytes`) | Path to the `.wasm`, resolved relative to the proxy's working directory. Use an absolute path in production. |
| `module_bytes` | required (or `module_path`) | Inline bytes. Most useful when configs are fetched from a control plane that already has the module bytes. |
| `timeout_ms` | 1000 | Hard wall-clock cap. Enforced via wasmtime's epoch interruption, ticked once per millisecond. A module that doesn't yield within this many ticks is aborted with `Trap`. |
| `max_memory_pages` | 256 | Linear-memory cap in 64 KiB pages. 256 pages = 16 MiB. Raise for transforms that buffer large bodies. Allocations past this cap trap. |
| `allowed_hosts` | `[]` | Reserved. WASI sockets are not wired in today; this field is parsed for forward compatibility but currently does nothing. |

Module compilation happens once at config load. A bogus path or a
malformed `.wasm` fails the load (the proxy will not start with a
broken transform), which surfaces problems at deploy time rather
than at first request.

## Sandbox boundaries

What the host enforces:

- **Memory.** `max_memory_pages` caps the module's linear memory. A
  module that grows past this cap traps on the offending `memory.grow`
  or allocator call.
- **CPU.** `timeout_ms` is enforced via epoch interruption. A
  background thread bumps the engine's epoch once per millisecond;
  the module is interrupted at the next instruction boundary after
  the deadline.
- **Filesystem.** No preopens. The module sees an empty FS.
- **Network.** Not exposed.
- **Environment.** No environment variables forwarded; `std::env`
  reads return empty.
- **Random.** WASI's `random_get` is allowed and produces
  cryptographically random bytes from the host. Use this for any
  randomness; do not seed from a fixed value.
- **Time.** WASI's clock is allowed (modules can read wall-clock and
  monotonic time). The host does not pin or skew the clock.

What the module observes:

- A working stdin (the response body) and stdout (the new body).
- A working stderr that the host pipes to the proxy's debug log.
- A WASI clock and a WASI random source.
- Nothing else. No FS, no network, no env, no `args`.

## Performance notes

The wasmtime `Engine` is shared process-wide and the compiled
`Module` is cached per `wasm` transform. Per-request cost is one
fresh `Store`, one `instantiate`, and one `_start` call. For a
trivial transform (under a few KB of `.wasm`) that adds up to tens
of microseconds plus whatever the module itself does.

Tips:

- Keep the module small. A Rust binary built with default settings
  ships ~200 KB of bytecode for a hello world. Adding `[profile.release]
  opt-level = "z"`, `lto = true`, and `strip = true` typically cuts
  that to under 50 KB. TinyGo with `-no-debug` is similar.
- Avoid heap allocations in the hot path. The Rust echo example uses
  `io::copy` to round-trip without buffering more than a stack frame.
- Buffer the body to a `Vec` only when you actually need random
  access. Streaming transforms (uppercase, gzip, JSON-line filters)
  can process stdin chunk by chunk.
- The first call after process start triggers compilation if the
  module has not been cached. Subsequent calls reuse the compiled
  module across requests.

## Debugging

A WASM transform that traps is logged at warn level with the trap
type (epoch deadline, memory exhaustion, unreachable, etc.) and the
guest stack frame names if available. To get more from the module
itself:

- Write debug output to stderr. The host captures stderr and routes
  it through the proxy log when `--log-level debug` is set.
- Add a feature flag in your module that emits a hex dump of the
  input on stderr. Cheaper than a full debugger, often enough to
  diagnose payload mismatches.
- Validate the module locally with `wasmtime run --invoke _start
  module.wasm < input.txt > output.txt` before wiring it into a
  proxy config. The same wasmtime version sbproxy uses is in the
  `wasmtime` workspace dependency in `Cargo.toml`.

## Common mistakes

**Forgetting `_start`.** If you build with a `cdylib` crate type or
a TinyGo target that omits `_start`, instantiation fails with
"module is missing the WASI `_start` export". Use the default
binary crate type for Rust and `-target=wasi` for TinyGo.

**Output not flushed.** Stdout in `wasm32-wasi` is line-buffered for
text and unbuffered for `write_all` of bytes. Both example modules
write the whole body in one `write_all` call, which the host sees
as soon as `_start` returns. If your module uses `print!` or a
formatted writer, call `.flush()` before exiting or use `writeln!`
on a buffered writer that flushes on drop.

**Reading more than the body.** stdin contains exactly the response
body bytes the upstream sent. There is no framing, no header, no
trailer. `read_to_end` is the right tool; do not try to consume a
specific number of bytes unless you know the body length.

**Holding the timeout open.** `timeout_ms` is wall clock, not CPU
time. A module that sleeps (TinyGo's `time.Sleep`, Rust's
`std::thread::sleep` if you compile a runtime that supports it)
still counts against the deadline.

## Module versioning

There is no in-band module versioning. Two patterns work in practice:

1. **File-name versioning.** Bake the version into the file name
   (`uppercase-v3.wasm`) and update the config to point at the new
   file. Combine with the proxy's hot reload to swap modules without
   restarting.
2. **Inline bytes.** Keep the module in the config store so the
   control plane can bump versions atomically with the rest of the
   config.

There is no migration story today for modules that need to maintain
state across requests; the WASI sandbox is per-invocation by design.

## See also

- [scripting.md](scripting.md) - the broader scripting overview
  (CEL, Lua, JavaScript, WASM).
- [configuration.md](configuration.md) - the full transform field
  reference, including `fail_on_error` semantics.
- `examples/38-wasm-transform/sb.yml` - the runnable end-to-end
  example used in this guide.
- `examples/wasm/echo-rust/` - the Rust hello-world module with a
  Docker-based build script.
- `examples/wasm/uppercase-tinygo/` - the TinyGo equivalent.
