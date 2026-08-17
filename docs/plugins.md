# Extending SBproxy

*Last modified: 2026-08-16*

Most custom logic in sbproxy is a config field, not a rebuild. Before reaching for any of the surfaces on this page, check [configuration.md](configuration.md) and [features.md](features.md); a surprising amount of what looks like "I need to write code" is a block someone already shipped.

When it isn't, sbproxy gives you four ways to extend a running gateway without touching Rust or the `sbproxy` binary: CEL, Lua, JavaScript, and WebAssembly. All four load from config, all four hot-reload, and all four are covered in full below. Compiling a linked Rust plugin against `sbproxy-plugin` also exists. It's the last section on this page because it's for organizations building and shipping their own fork of the binary; most deployments don't need it.

## The four extension surfaces

| Surface | Good for | Detail doc |
|---|---|---|
| **CEL** | One-line boolean gates evaluated in microseconds: policy allow/deny expressions, rate-limit keys, WAF persistent-block keys, forward-rule matching, response header rules. No loops, no I/O. | [scripting.md](scripting.md) |
| **Lua** | Header and JSON body rewriting that needs variables or loops: request/response modifiers, `lua_json` transforms, WAF custom rules. Runs in a fresh sandboxed Luau VM per request. | [scripting.md](scripting.md) |
| **JavaScript** | Same jobs as Lua, JS-flavored, plus the runtime for hot-loaded extension bundles (see below). Inline scripts get a fresh QuickJS engine per request; bundle hooks run as ES modules in their own sandbox. | [scripting.md](scripting.md), [extension-bundles.md](extension-bundles.md) |
| **WebAssembly (WASM)** | A language sbproxy has no built-in interpreter for (Rust, TinyGo, AssemblyScript, Zig, Swift, C/C++), stronger isolation than an interpreter gives you, or one compiled artifact reused across origins. Compiled once via Wasmtime; a fresh WASI `Store` per invocation, capped memory and wall clock. | [wasm-development.md](wasm-development.md), [extension-bundles.md](extension-bundles.md) |

Runnable examples for each: [examples/cel-policy](../examples/cel-policy/), [examples/transform-lua](../examples/transform-lua/), [examples/transform-javascript](../examples/transform-javascript/), and [examples/wasm-transform](../examples/wasm-transform/) with modules under [examples/wasm](../examples/wasm/) (Rust and TinyGo).

One more engine exists alongside these four: Rego, via the Regorus interpreter, for teams migrating policies they already wrote for OPA. It's a narrower audience than the four above, so it isn't in the main table, but it's documented in the same place: [scripting.md](scripting.md).

Reach for CEL first. It's the fastest and the cheapest to reason about. Move to Lua, JavaScript, or WASM only when the logic needs state, loops, or a helper function CEL can't express as one expression.

## Extension bundles: add behavior without a rebuild

Inline scripting attaches to one config field. When you want a self-contained unit of logic, one you can version separately, share across environments, or reload without redeploying the proxy, that's an extension bundle.

A bundle is a directory: a `bundle.yaml` manifest plus one entry file (JavaScript, TypeScript, or a compiled `.wasm` module). Point sbproxy at a directory of them:

```yaml
extensions:
  bundles_dir: bundles
```

or at a verified git checkout, pinned to a commit SHA (or a signed reference), with a required content digest and an optional refresh interval:

```yaml
extensions:
  sources:
    - type: git
      repo: https://github.com/acme/sbproxy-extensions.git
      revision: production
      path: bundles
      sha256: 1f0a4c7e6b25d3908c11a4f52e7b0d63c9a8f4e21b5d7c6083ae95f2d41b7c60
      credential: secret://primary/extension-git-token
      verify_signature: true
      refresh_interval_secs: 60
```

Either way, nothing gets recompiled into the binary. Config load, `sbproxy validate`, `sbproxy doctor`, a file-watcher hot reload, `SIGHUP`, or `POST /admin/reload` all build a candidate registry from the current bundles, check every manifest, digest, and export, and only then swap it in atomically. A bad bundle (a digest mismatch, a syntax error, a missing export, a hook collision) refuses that candidate outright; the previous generation keeps serving. Nothing partially loads.

A bundle that wants outbound HTTP has to declare the destinations in its manifest, and the operator has to grant the same destinations separately in `extensions.grants`. Declaring without granting does nothing; granting without a matching declaration is harmless. That two-sided handshake is what keeps a bundle from reaching anywhere its author didn't ask for and its operator didn't approve.

Full reference, including the git-source signature and digest model: [extension-bundles.md](extension-bundles.md). Runnable layout with a bundle for every hook kind below: [examples/extension-bundles](../examples/extension-bundles/).

## What a bundle can hook into

A bundle's manifest declares one or more hooks, each with a `kind` and a `type` name you reference from `sb.yml` the same way you'd reference a built-in module. Four kinds cover the core request pipeline:

- **action** ships an origin's response itself: it receives the request and config, and returns a status, headers, and body. It's terminal, the same slot a `static` or `proxy` action fills, and (because there's nothing left to fall through to if it fails) it always fails closed.
- **auth** runs before the action and decides whether the request gets in. It attaches to an origin's `auth:` block, the same slot `jwt` or `api_key` use, and answers `allow` (optionally naming who the request is now authenticated as), `deny`, or `deny_with_headers` (for a `WWW-Authenticate` challenge, for example). Like action, it always fails closed.
- **policy** is an allow/deny gate over the request, the same shape as a built-in policy like rate limiting or a WAF rule, except the decision logic is yours.
- **transform** rewrites a request or response body. It reads the current body and content type and returns a replacement.

A hook never shadows a built-in or a linked plugin of the same name; a built-in with that `type` always wins, and the bundle is only reached when nothing else claims it. Beyond these four, a bundle can also hook narrower events: AI guardrail and tool-call events, AI routing decisions, streaming HTTP filters (Proxy-Wasm), and payment lifecycle events. Those are event-shaped rather than pipeline-shaped and are covered in [extension-bundles.md](extension-bundles.md) alongside [mcp-and-agents.md](mcp-and-agents.md) and [payments.md](payments.md).

For a look at real ones: [examples/extension-bundles/bundles/hello-javascript](../examples/extension-bundles/bundles/hello-javascript/) ships both an action and a transform hook, [examples/extension-bundles/bundles/hmac-auth-javascript](../examples/extension-bundles/bundles/hmac-auth-javascript/) is an auth hook that verifies an HMAC-signed request, and [examples/extension-bundles/bundles/header-policy-typescript](../examples/extension-bundles/bundles/header-policy-typescript/) is a policy hook written in TypeScript.

A bundle hook is a plain JavaScript or TypeScript export, or a WASI module reading stdin and writing stdout, with no Rust trait to implement. The sandbox and the manifest are the whole contract.

## Advanced: linked Rust plugins

Everything above covers the config-level extension story, which is what almost every deployment needs and the path this documentation leads with. There's a second, heavier path underneath it: compiling your own logic directly into the `sbproxy` binary as a linked Rust plugin.

This path is for organizations that build and maintain their own fork or embedding of sbproxy. A typical deployment does not need it. It costs a rebuild on every change, ships on your own release cadence instead of a hot reload, and (because a linked plugin dispatches through `Box<dyn Trait>` instead of a built-in's branch-predicted match) it pays one dynamic-dispatch call per phase it runs in. Reach for it only when a bundle can't get there, for example a synchronous hot-path callback that can't tolerate any dispatch through a bundle sandbox.

`sbproxy-plugin` is one of three crates in sbproxy's public API (the other two are `sbproxy-config` and `sbproxy-httpkit`). It exposes four traits, `PolicyEnforcer`, `ActionHandler`, `AuthProvider`, and `TransformHandler`, mirroring the same four hook kinds a bundle registers. Each has a typed `inventory::submit!` registration channel: implement the trait, submit the registration, and compile the crate into the binary. No central wiring file, no separate registry to update.

```rust,no_run
inventory::submit! {
    PolicyPluginRegistration {
        name: "rate_limit_custom",
        factory: |raw| {
            let cfg: MyConfig = serde_json::from_value(raw)
                .map_err(|e| PluginError::Config(e.to_string()))?;
            Ok(Box::new(MyPolicy::new(cfg)))
        },
    }
}
```

Full trait definitions, the registration pattern, and how the config compiler chooses between a built-in, a linked plugin, and a bundle for the same `type` string live in the "Plugin system" section of [architecture.md](architecture.md).

One narrower, already-shipped example of this same pattern: [routing-strategies.md](routing-strategies.md) documents the `RoutingStrategy` trait, an opt-in extension point for custom load-balancer target selection. It's a smaller, single-purpose trait rather than the general plugin surface, but it's the same idea: an accepted exception for logic that has to run inline on the hot path.

A related but different question: adding a new AI model-serving engine (llama.cpp, vLLM, SGLang, mistral.rs today) is not a request-pipeline extension at all, and none of the above applies to it. See [custom-engines.md](custom-engines.md) for why that's a separate, typed driver seam.

Adding a module to sbproxy itself, an in-tree `action`, `auth`, `policy`, or `transform` under `sbproxy-modules`, is a different track again: that's contributing to the project rather than extending a deployment of it. See [CONTRIBUTING.md](../CONTRIBUTING.md) and the "Module system" section of the repository's `CLAUDE.md` for that path.
