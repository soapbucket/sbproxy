# Rust echo WASM module
*Last modified: 2026-04-27*

A minimal SBproxy WASM transform written in Rust. Reads stdin, writes
stdout. Used as the "hello world" reference for [the WASM development
guide](../../../docs/wasm-development.md).

## Build

```bash
./build.sh
```

By default this runs the build inside a `rust:1.82` Docker container
so contributors do not need to install rustup or the wasm32-wasi
target on their host machine. Set `LOCAL=1` to use the host toolchain
instead.

The output is `target/wasm32-wasi/release/echo.wasm`. A pre-built copy
is checked in at `echo.wasm` for convenience; rebuild after editing
`src/main.rs`.

## Run via sbproxy

See `examples/38-wasm-transform/sb.yml` for a complete config that
loads this module and pipes a static HTML response through it.

```bash
sbproxy serve -f examples/38-wasm-transform/sb.yml
curl http://127.0.0.1:8080/
# echoes whatever the upstream sends, transformed by the WASM module
```

## See also

- [`docs/wasm-development.md`](../../../docs/wasm-development.md) for
  the full authoring guide (host ABI, sandbox limits, debugging,
  Rust + TinyGo recipes).
- [`docs/scripting.md`](../../../docs/scripting.md) for the scripting
  engines overview (CEL, Lua, JavaScript, WASM).
