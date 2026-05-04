# WASM transform examples

*Last modified: 2026-04-27*

Reference modules for the SBproxy WASM transform. A WASM transform is a sandboxed module loaded by the `wasm` transform action; SBproxy invokes it once per request body, hands the body in on stdin, and reads the transformed body back from stdout. The host ABI follows WASI preview 1 so any toolchain that produces `wasm32-wasip1` (or the older `wasm32-wasi`) modules will work. Sandbox limits (memory, fuel, timeout) are configured per transform on the proxy side. Use these examples as the starting points for your own transforms; both are minimal "hello world" modules that exercise the same WASI contract from different toolchains.

## Subdirectories

| Path | What it shows |
|------|---------------|
| [echo-rust/](echo-rust/) | Minimal Rust transform that copies stdin to stdout. Built with `cargo build --target wasm32-wasi`. |
| [uppercase-tinygo/](uppercase-tinygo/) | TinyGo transform that uppercases every byte. Built with `tinygo build -target wasi`. |

## Toolchain

Building each module requires its own toolchain. Both example directories ship a `build.sh` script that runs the build inside a Docker image so contributors do not need a host install; set `LOCAL=1` to use the host toolchain instead.

```bash
# Rust echo: produces target/wasm32-wasi/release/echo.wasm
cd examples/wasm/echo-rust && ./build.sh

# TinyGo uppercase: produces uppercase.wasm in the same directory
cd examples/wasm/uppercase-tinygo && ./build.sh
```

The Rust example checks in a pre-built `echo.wasm` for convenience; rebuild after editing `src/main.rs`. The TinyGo build is not checked in (output size and shape change across TinyGo releases); rebuild on first use.

Wire either module into a proxy config with the `wasm` transform:

```yaml
transforms:
  - type: wasm
    module_path: examples/wasm/echo-rust/echo.wasm
    timeout_ms: 500
```

`examples/38-wasm-transform/sb.yml` is a complete config that loads the echo module and pipes a static HTML response through it.

## See also

- [docs/scripting.md](../../docs/scripting.md) - scripting engines overview (CEL, Lua, JavaScript, WASM)
- [docs/wasm-development.md](../../docs/wasm-development.md) - full WASM authoring guide (host ABI, sandbox limits, debugging, Rust + TinyGo recipes)
- [docs/features.md](../../docs/features.md)
