# geo-gate-wasm (proposed WASM bundle)

*Last modified: 2026-08-02*

> **Status: design preview.** Not runnable against sbproxy today —
> see [`examples/bundles/README.md`](../README.md) and
> [epic #890](https://github.com/soapbucket/sbproxy/issues/890).
> The Rust *is* real and buildable (see below); what doesn't exist yet
> is a host that speaks the envelope this module expects.

Two hooks — a `policy` (`geo_block`) and a `transform`
(`tag_geo_header`) — implemented in one WASM module, dispatched from a
single `_start` on the JSON envelope's `hook.type` field. This is the
concrete case for why bundle-registered WASM hooks need an envelope at
all: a bare-WASI module only gets one entry point, so registering more
than one hook in it needs *some* way to tell them apart, and the design
doc's §3 ("WASM hook dispatch and ABI") picks a `hook: {kind, type}`
discriminator over adopting proxy-wasm's named-export ABI. Design doc:
https://app.notion.com/p/3b068ca7910e81f6b086ff1ecf912054

## Files

| Path | Purpose |
|------|---------|
| `bundle.yaml` | Manifest: `runtime: wasm`, two `hooks[]` entries (note: no `export:` field — WASM hooks dispatch on the envelope, not a named function). |
| `src/main.rs` | The module: parses the envelope, routes on `hook.type`, writes one JSON verdict per call. |
| `Cargo.toml` | Standalone crate (not a member of the root workspace — same pattern as `examples/wasm/echo-rust`), targets `wasm32-wasip1`. |
| `build.sh` | Docker-based build, mirroring `examples/wasm/echo-rust/build.sh`. |
| `fixtures/*.json` | One envelope + expected verdict per hook, doubling as documentation of the stdin/stdout contract. |

## The envelope contract

```jsonc
// stdin
{
  "hook": { "kind": "policy", "type": "geo_block" },
  "config": { "denylist": ["KP", "IR"], "country_header": "x-geo-country" },
  "request": { "headers": { "x-geo-country": "KP" } }
}
```

```jsonc
// stdout
{ "kind": "deny", "status": 451, "message": "requests from 'KP' are not permitted" }
```

Compare with **today's** `type: wasm` transform (`examples/wasm-transform/sb.yml`,
`examples/wasm/echo-rust/`): that ABI pipes raw body bytes in and out,
no JSON envelope, no hooks, no config, transform-only. This proposal's
envelope is additive — the existing bare-WASI body-transform path is
untouched (see the design doc's §3 note on this).

## Building it

```bash
./build.sh              # Docker, no local toolchain needed
LOCAL=1 ./build.sh      # host toolchain (rustup target add wasm32-wasip1)
```

Output: `target/wasm32-wasip1/release/geo_gate.wasm`. This has been built
and run locally against the fixtures above (see the crate's own test,
`cargo test`) — the Rust is real; only the sbproxy-side loader (#893)
that would invoke it is not.

## How it would be wired up

```yaml
origins:
  api.example.com:
    policies:
      - type: geo_block
        denylist: ["KP", "IR"]
    transforms:
      - type: tag_geo_header
```
