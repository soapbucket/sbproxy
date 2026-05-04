# TinyGo uppercase WASM module
*Last modified: 2026-04-27*

A minimal SBproxy WASM transform written in TinyGo. Reads stdin,
uppercases every byte, writes stdout. Demonstrates the same WASI
contract used by [`echo-rust`](../echo-rust/) but in a different
toolchain.

## Build

```bash
./build.sh
```

Default uses the `tinygo/tinygo:0.34.0` Docker image. Set `LOCAL=1`
to use the host TinyGo install.

The output is `uppercase.wasm`. The pre-built file is **not** checked
in (TinyGo's output is larger than the trivial Rust echo and changes
across TinyGo releases); rebuild on first use.

## Run via sbproxy

```yaml
transforms:
  - type: wasm
    module_path: examples/wasm/uppercase-tinygo/uppercase.wasm
    timeout_ms: 500
```

Pipe any text body through this transform; the response will come
back uppercased.

## See also

- [`docs/wasm-development.md`](../../../docs/wasm-development.md) for
  the full authoring guide, including TinyGo-specific gotchas
  (memory model, stdlib limitations).
- [`examples/wasm/echo-rust/`](../echo-rust/) for the Rust version of
  the same hello-world transform.
