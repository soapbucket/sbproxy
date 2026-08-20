# OPA-compatible policies (Rego)

*Last modified: 2026-08-19*

SBproxy evaluates standard [Rego](https://www.openpolicyagent.org/docs/policy-language) through [Regorus](https://github.com/microsoft/regorus), Microsoft's Rust interpreter, in the same process as the request pipeline. If you already write Rego for OPA, the policy body is portable: paste the module in, and it runs against the same request context a CEL policy sees. There is no OPA server to run alongside the proxy, no bundle endpoint to poll, and no REST decision API. Regorus is a Rego evaluator, not an OPA deployment, and this page only covers what that evaluator does inside SBproxy.

## Where Rego runs

Two config surfaces accept Rego today, both grep-verified against the compiler:

| Surface | Key path | Fields |
|---|---|---|
| Rego gate policy | `origins.<host>.policies[].type: rego` (`crates/sbproxy-modules/src/compile.rs`) | `module` or `module_path` (exactly one required), `query` (default `data.sbproxy.allow`), `deny_status` (default `403`), `deny_message` (default `forbidden by policy`), `budget_ms` (default `50`), `data` (optional JSON object), `rego_v0` (default `false`) |
| AI routing policy | `origins.<host>.action.ai_routing_policy.engine: rego` (only under `action.type: ai_proxy`; `crates/sbproxy-ai/src/ai_routing_policy.rs`) | `source` or `module_path` (exactly one required), `query` (default `data.sbproxy.route`), `data`, `budget_ms` (default `50`), `rego_v0` (default `false`), `on_error` (`decline` or `block`, default `decline`), `reason_codes` (allowlist for the routing metric's `reason_code` label; an unlisted code collapses to `other`) |

The first is a plain allow/deny gate, the same job `policy: expression` does in CEL. The second returns a routing plan (which provider and model to send a request to) rather than a boolean, and only fires for gateway-owned AI traffic. This page focuses on the gate policy, since that is the surface an OPA shop is most likely to be replacing. The full field reference, including the failure posture and the base-data override rule, is in [scripting.md §3a](scripting.md#3a-rego-policies). Routing-specific behavior (candidate re-checking, the security override) is in [ai-gateway.md](ai-gateway.md).

## Loading a module from a file, and pre-OPA-1.0 syntax

`module` is inline Rego source in the YAML; `module_path` is a path to a `.rego` file on disk, read once at config load and again on every reload, the same convention `transforms[] type: wasm` already uses for its own `module_path`. The two are mutually exclusive on both surfaces above: set exactly one, and a config that sets both or neither is refused at load with a message naming the surface. Keeping the policy in its own `.rego` file is what makes a migration from an OPA bundle close to a copy: the file itself is unmodified Rego, and `sb.yml` only points at it.

Regorus defaults to Rego v1 (`if`/`contains` required), matching OPA 1.0. A module written before that switch, `allow { ... }` with no `if`, fails to parse unless `rego_v0: true` is set on the same policy or routing entry, which runs Regorus's own compatibility switch before parsing. Set it per policy for a pasted-in legacy module rather than rewriting the module; a module authored fresh against current OPA should not need it.

A `print()` call inside a Rego module never reaches the process's stderr. It is gathered per evaluation and logged through `tracing` at INFO under the `rego_print` target, naming the site, the query, and the tenant when the evaluated request resolved to one. Nothing needs to be configured for this; it is the default behavior of Rego evaluation itself, and it covers every surface that compiles a Rego module in sbproxy, not only the gate and routing policies described here: a [request/response modifier's](scripting.md#rego-modifiers) `rego_module`, and a signed extension bundle's `runtime: rego` policy hook ([extension-bundles.md](extension-bundles.md)), print through the same path.

## Testing a module offline: `sbproxy rego test`

`sbproxy rego test <path>` runs Rego fixtures without booting the proxy, the offline analogue of `opa test`. Point it at a single fixture YAML file, or a directory searched recursively for `*_test.yaml` / `*_test.yml` files, and each fixture compiles its module through the same engine construction a live `policy: rego` or `ai_routing_policy` uses (`module_path` and `rego_v0` honored identically), runs every named case, and reports per-module line coverage.

A fixture's top-level fields mirror `policies[] type: rego` exactly, `module` or `module_path`, `query`, `data`, `budget_ms`, `rego_v0`, so a block pasted from a fixture into a `policies[]` entry, or the other way around, is the same policy:

```yaml
module_path: policy.rego
cases:
  - name: strong trust tier is allowed
    input:
      request: { trust_tier: strong, method: GET, path: /private/status }
    expect: true
  - name: private path with no strong trust tier is denied
    input:
      request: { trust_tier: anonymous, method: GET, path: /private/status }
    expect: false
```

`--min-coverage <PCT>` fails the run (exit 1) when aggregate line coverage across every fixture module falls short; coverage is always gathered and printed, so the flag only changes whether it gates the exit code. `--format json` emits one structured result object instead of the default per-case text output, for a CI step to parse. Exit code 2 means a fixture file itself is malformed, distinct from exit 1's "a case failed or coverage fell short." [`examples/rego-modifier-parity/`](../examples/rego-modifier-parity/) ships a fixture alongside its policy and is the runnable version of the pattern above.

## The input document

A Rego policy reads `input`. For the gate policy, `input` is the same assembled request context a CEL expression reads, converted to JSON: `request.trust_tier` in CEL is `input.request.trust_tier` in Rego. The routing policy's `input` is narrower: it is `{"ai": ...}` only, the same vocabulary the CEL-based AI policy plane uses as an `ai.*` namespace, and nothing else, so `input.request` is undefined there even though the gate policy has one; see [ai-policy-cel.md's namespace table](ai-policy-cel.md#the-ai-namespace) and the [Routing policy section of ai-gateway.md](ai-gateway.md#routing-policy) for the full field list rather than a copy of it here. Both engines are kept in sync by a parity test, so a binding available to one is available to the other within its own surface.

Two things carry over from CEL with different consequences in Rego. `input.jwt.claims` is decoded, not verified, so gating on a claim without first authenticating through the `jwt` auth provider trusts whatever the client sent. And a misspelled binding, `input.request.trust_teir`, is not a config-load error the way it would be in CEL: Rego treats an undefined value as legitimate, so the rule just never fires, and you find out from traffic behavior instead of a startup message. `budget_ms` bounds one evaluation's wall clock the way every other scripting engine bounds its own; it defaults to 50 ms and cannot be zero.

## A worked example

The policy below gates AI traffic on a `X-Tenant` header, first requiring the header to be present, then checking it against an allow-list kept in `data` so an operator can edit the list without touching the Rego:

<!-- sbproxy-config-excerpt -->
```yaml
origins:
  "ai.local":
    action:
      type: ai_proxy
      routing: round_robin
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          default_model: gpt-4o-mini

    policies:
      - type: rego
        module: |
          package sbproxy

          default allow := false

          allow if {
            input.request.headers["x-tenant"] != ""
          }
        deny_status: 403
        deny_message: "X-Tenant header required for AI access"

      - type: rego
        module: |
          package sbproxy

          default allow := false

          allow if {
            input.request.headers["x-tenant"] == data.allowed_tenants[_]
          }
        data:
          allowed_tenants: ["acme", "globex", "initech"]
        deny_status: 403
        deny_message: "tenant not provisioned for AI access"
```

A request with no tenant header never reaches the AI handler:

```bash
curl -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
# HTTP/1.1 403 Forbidden
# {"error":"X-Tenant header required for AI access"}
```

A tenant outside the allow-list is denied by the second policy, with a message that tells the operator this is an unprovisioned tenant rather than a missing header:

```bash
curl -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'X-Tenant: stranger' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
# HTTP/1.1 403 Forbidden
# {"error":"tenant not provisioned for AI access"}
```

A provisioned tenant passes both rules and reaches the provider. The runnable version of this config, with the run and test commands filled in, is [`examples/ai-rego-tenant-gate/`](../examples/ai-rego-tenant-gate/).

## Rego versus CEL

Both engines read the same request context and can express the same gate, so the choice is about the team, not the traffic. Reach for Rego when a policy already exists and has been reviewed as Rego, when `data` needs to be an operator-editable table separate from the rule logic, or when the policy has to look the same here as it does in an OPA-fronted service elsewhere in your stack. Reach for CEL when you are writing a new policy from nothing: a CEL expression that names a binding the config surface does not provide is refused at load, and Rego cannot offer that guarantee, since an undefined binding is a value the language is designed to accept rather than an error to raise. [scripting.md §3a](scripting.md#3a-rego-policies) states this directly: prefer `expression` when either engine would do, and reach for Rego for the one reason that matters, which is that rewriting a working Rego policy set is worse than running it.

One more divergence from upstream OPA is worth knowing before porting a policy: Regorus treats a builtin error as a fault that denies the request, where OPA treats it as `undefined` and moves on. A policy that leans on that forgiveness, calling `net.cidr_contains` on a header that is not always a CIDR, works on OPA and denies here. Guard the input first.

## Operational model: config-wide, not bundle-scoped

OPA activates a downloaded policy bundle only after verifying it, and keeps serving the previous bundle if activation fails. SBproxy's hot reload works the same way at the scale of the whole config: a Rego module that fails to parse, or one whose query names no rule, refuses the reload outright, and the previously active config keeps serving traffic. Both faults are caught before the first request, because the compiler runs one trial evaluation against an empty input at load time rather than deferring that check to whenever the module happens to see live traffic. See [extension-bundles.md's comparison to OPA bundle management](extension-bundles.md#context-from-other-extension-systems) for where SBproxy draws that analogy explicitly for its own bundle registry; the same last-good posture applies here, one config generation at a time rather than one bundle at a time.

## Rego beyond policies

The gate and routing policies above are not the only place Rego runs. `request_modifiers[]` and `response_modifiers[]` accept a Rego form (`rego_module` / `rego_module_path`, `rego_budget_ms`) beside the existing Lua and JavaScript forms, evaluating against the same request/response document those two engines see and returning the same `set_headers` shape. A signed extension bundle can also ship a `.rego` policy hook (`runtime: rego`), compiled and verified through the same last-good posture every other bundle asset uses. Neither surface is this page's focus; see [scripting.md's Rego modifiers section](scripting.md#rego-modifiers) and [extension-bundles.md's Rego section](extension-bundles.md#rego) for their field references.

## See also

- [scripting.md §3a](scripting.md#3a-rego-policies) - the full Rego policy reference: config fields, the base-data override rule, and the failure-posture table.
- [`examples/rego-modifier-parity/`](../examples/rego-modifier-parity/) - a file-based `policy: rego` module plus a Rego response modifier, with the offline `sbproxy rego test` fixture for the same module.
- [ai-gateway.md](ai-gateway.md) - the AI routing policy surface, including the multi-engine `ai_routing_policy` block.
- [ai-policy-cel.md](ai-policy-cel.md) - the CEL-first AI policy plane and the `ai.*` namespace Rego reads as `input.ai`.
- [extension-bundles.md](extension-bundles.md) - the bundle registry and its own OPA comparison.
- [`examples/ai-rego-tenant-gate/`](../examples/ai-rego-tenant-gate/) - the runnable version of the worked example above.
