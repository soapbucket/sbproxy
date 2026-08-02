# rate-limit-by-plan (proposed JavaScript/TypeScript bundle)

*Last modified: 2026-08-02*

> **Status: design preview.** Not runnable against sbproxy today —
> see [`examples/bundles/README.md`](../README.md) and
> [epic #890](https://github.com/soapbucket/sbproxy/issues/890).

A `policy` hook that denies requests on the `free` plan once they exceed
a configured rate, demonstrating the `runtime: javascript` path's
no-`package.json` shape: raw TypeScript in `src/`, no build step, no
`dist/`. Design doc: https://app.notion.com/p/3b068ca7910e81f6b086ff1ecf912054
(§§1-2, 5-6).

## Files

| Path | Purpose |
|------|---------|
| `bundle.yaml` | Manifest: declares one `policy` hook (`rate_limit_by_plan`), its `config_schema`, `failure_posture: closed`, and sandbox limits. |
| `src/index.ts` | The hook itself — `enforce(req, config)`, matching the calling convention in §5 of the design doc. |
| `fixtures/*.json` | Sample envelopes + expected verdicts, for what `sbproxy-ext test` would run once it exists. |

## How it would be wired up

Once `DynamicBundleRegistry` and the `compile_policy` registry fallback
(#891, #892) exist, this bundle would be dropped into the directory
configured by `extensions.bundles_dir`, and referenced from `sb.yml`
exactly like a built-in policy:

```yaml
origins:
  api.example.com:
    policies:
      - type: rate_limit_by_plan
        requests_per_minute: 120
        plan_header: "x-tier"
        failure_posture: open   # optional per-attachment override
```

## Why there's no real rate counter here

Bundles run in a sandboxed engine with no state that survives across
calls — the same isolation guarantee sbproxy's built-in Lua/JS scripting
already gives (see `docs/scripting.md`'s sandbox section). A real
rate limiter needs a host-provided counter (a future KV binding, most
likely), which isn't part of this proposal yet. `src/index.ts` reads a
pre-computed request count from an `x-request-count` header instead, as
a stand-in for whatever eventually supplies that number — see the
comment in the source for where a real implementation would plug in.
