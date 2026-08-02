# geo-gate-proxy-wasm (proposed proxy-wasm bundle)

*Last modified: 2026-08-02*

> **Status: design preview.** Not runnable against sbproxy today —
> sbproxy does not implement the proxy-wasm host ABI (see
> [`examples/bundles/README.md`](../README.md) and
> [epic #890](https://github.com/soapbucket/sbproxy/issues/890),
> [ticket #893](https://github.com/soapbucket/sbproxy/issues/893)).
> The Rust genuinely compiles against the real `proxy-wasm` SDK crate
> and has been built to a real `.wasm` module (see "Verification" below)
> — what doesn't exist yet is a host that speaks this ABI.

The same "deny requests from denylisted countries" policy as
[`../geo-gate-wasm/`](../geo-gate-wasm/), implemented against the real,
standardized **proxy-wasm** host ABI — the one Envoy, Kong (WasmX), and
Apache APISIX all share — instead of sbproxy's own envelope-routed
bare-WASI convention. Design doc:
https://app.notion.com/p/3b068ca7910e81f6b086ff1ecf912054 (§3 "WASM hook
dispatch and ABI").

## Why this example exists alongside geo-gate-wasm

The design doc originally picked one WASM approach over the other. Both
are now in scope: sbproxy's own lightweight envelope convention (no new
host-ABI implementation required, ships sooner, no shared SDK) and
proxy-wasm (real new infrastructure to implement, but gets sbproxy
compatibility with an existing SDK ecosystem — Rust, C++, TinyGo,
AssemblyScript — and any proxy-wasm filter already written for
Envoy/Kong/APISIX). This pair of examples exists so the two are directly
comparable, side by side, on the same policy.

## What's genuinely different from geo-gate-wasm, not just cosmetic

| | `geo-gate-wasm` (envelope) | `geo-gate-proxy-wasm` (this one) |
|---|---|---|
| Target triple | `wasm32-wasip1` | `wasm32-unknown-unknown` (no WASI at all) |
| I/O | stdin/stdout, one JSON envelope per call | Host-imported functions (`get_http_request_header`, `send_http_response`, ...) proxy-wasm's ABI defines |
| Dispatch | One `_start`, routes on `hook.type` in the envelope | `RootContext`/`HttpContext` trait callbacks (`on_http_request_headers`, ...) the proxy-wasm dispatcher calls directly |
| Config | sbproxy's `config_schema` (validated JSON, passed in the envelope) | proxy-wasm's own `on_configure`/`get_plugin_configuration()` — the module reads whatever config block the *host* attaches, which is why this example can't assume `bundle.yaml`'s shape |
| Crate type | `bin` | `cdylib` (proxy-wasm's own `main!` macro wires the entry point) |

## Verification

This has genuinely been built and tested, not just written:

```
cargo test                                          # 4/4 pass — pure decision logic + config parsing
cargo build --release --target wasm32-unknown-unknown   # produces a real .wasm binary
```

The `HttpContext`/`RootContext` trait methods themselves aren't
unit-tested here — they call into `hostcalls::` externs that only
resolve when linked into a real proxy-wasm host (Envoy, Kong, a test
harness using the `proxy-wasm-test-framework` crate), so they can't run
under plain `cargo test`. The actual decision logic (`is_denied`) and
config parsing are pulled out into plain functions specifically so they
*are* testable natively — see `src/lib.rs`.

## Building it

```bash
./build.sh              # Docker, no local toolchain needed
LOCAL=1 ./build.sh      # host toolchain (rustup target add wasm32-unknown-unknown)
```

Output: `target/wasm32-unknown-unknown/release/geo_gate_proxy_wasm.wasm`.

## Open questions this example doesn't resolve

- How a proxy-wasm filter attaches to an sbproxy origin — as a new kind
  of `hooks[]` entry, or as a separate `filters:` list outside the
  policy/transform/action model entirely, since proxy-wasm's
  `HttpContext` covers the whole request/response lifecycle rather than
  being cleanly one policy or one transform.
- How proxy-wasm's own config-attachment mechanism should map onto
  `sb.yml` (the `proxy_wasm_config:` block in `bundle.yaml` here is a
  placeholder, not a settled design).

Both are tracked as open questions on
[ticket #893](https://github.com/soapbucket/sbproxy/issues/893).
