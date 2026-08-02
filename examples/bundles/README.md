# Bundle extension examples (proposed, not yet implemented)

*Last modified: 2026-08-02*

> **Status: design preview.** Nothing in this directory runs against
> sbproxy today. These are reference examples for the bundle extension
> interface proposed in
> [epic #890](https://github.com/soapbucket/sbproxy/issues/890) and the
> [design doc](https://app.notion.com/p/3b068ca7910e81f6b086ff1ecf912054).
> They exist so implementers of #891-#895 have a concrete target to
> build against, and so reviewers can see the manifest shape and calling
> convention worked through end to end. Not swept by
> `validate_examples` (that test only checks `examples/<dir>/sb.yml`
> one level deep; nothing here is named `sb.yml`).

For scripting that already works today, see
[`docs/scripting.md`](../../docs/scripting.md) (CEL, Lua, JavaScript,
WASM as inline `sb.yml` blocks or a bare `module_path`) and
[`examples/wasm/`](../wasm/) / [`examples/wasm-transform/`](../wasm-transform/)
/ [`examples/transform-javascript/`](../transform-javascript/) for
working, runnable examples of the current (non-bundle) mechanism.

## What a bundle is

A directory with a `bundle.yaml` manifest (name, `runtime`, `hooks[]`,
`failure_posture`, `sandbox` limits) plus source code, which a future
`DynamicBundleRegistry` would discover from a configured directory,
validate, sandbox, and register as a `policy`/`transform`/`action`
`type:` usable from `sb.yml` exactly like a built-in module.

## Examples

| Path | Runtime | Shows |
|------|---------|-------|
| [`rate-limit-by-plan/`](rate-limit-by-plan/) | `javascript` | A policy hook with a `config_schema`, the no-`package.json`/no-build-step path (TypeScript transpiled in-process, no `dist/`), and `sbproxy-ext test`-style fixtures. |
| [`geo-gate-wasm/`](geo-gate-wasm/) | `wasm` | Two hooks (a policy and a transform) in one module, dispatched via sbproxy's own envelope-routed `hook: {kind, type}` convention (§3 of the design doc). Real, buildable Rust targeting `wasm32-wasip1`. |
| [`geo-gate-proxy-wasm/`](geo-gate-proxy-wasm/) | `proxy_wasm` | The same policy as `geo-gate-wasm/`, implemented against the real, standardized proxy-wasm host ABI (the one Envoy, Kong WasmX, and Apache APISIX share) instead of sbproxy's own convention — both ABIs are in scope. Real, buildable Rust against the `proxy-wasm` SDK crate, targeting `wasm32-unknown-unknown`. |

`geo-gate-wasm` and `geo-gate-proxy-wasm` implement the identical policy
on purpose — compare them side by side to see exactly what each ABI
choice costs and buys (target triple, I/O model, dispatch, config
mechanism); see the "Why this example exists alongside geo-gate-wasm"
section in `geo-gate-proxy-wasm/README.md`.

Each example's own `README.md` explains its `bundle.yaml`, walks through
the calling convention, links back to the relevant section of the design
doc, and — for the two WASM examples — describes exactly how each was
built and tested for real (`cargo test`, `cargo build --target ...`),
since neither can run against sbproxy yet.