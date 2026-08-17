# Rego module_path policy and response modifier

*Last modified: 2026-08-16*

Two Rego surfaces on one origin: `policies[] type: rego` loading its module from a file (`module_path: policy.rego`) instead of an inline YAML block scalar, and a `response_modifiers[]` entry using Rego (`rego_module`) instead of `lua_script` or `js_script`. `policy.rego` allows a request when the caller's trust tier is `strong`, or when the method is `GET` under `/public/`; anything else is denied 403. The response modifier tags any 5xx response with `x-status-bucket: 5xx`, the same `set_headers` contract the Lua and JavaScript modifier forms use.

## Run

```bash
make run CONFIG=examples/rego-modifier-parity/sb.yml
```

Run it from the repository root: the config's `module_path` (`examples/rego-modifier-parity/policy.rego`) is resolved relative to the working directory the proxy is started from, the same convention `transforms[] type: wasm` uses. Use an absolute path in production.

## Test the policy offline first

Before the module ever reaches `sb.yml`, `sbproxy rego test` runs it against a fixture of named cases and reports line coverage:

```bash
sbproxy rego test examples/rego-modifier-parity/policy_test.yaml
```

```text
PASS examples/rego-modifier-parity/policy_test.yaml :: strong trust tier is allowed
PASS examples/rego-modifier-parity/policy_test.yaml :: public GET is allowed regardless of trust tier
PASS examples/rego-modifier-parity/policy_test.yaml :: private path with no strong trust tier is denied
PASS examples/rego-modifier-parity/policy_test.yaml :: POST to a public path is denied
coverage: policy.rego 3/3 lines (100.0%)
4 passed, 0 failed, 0 errored, 100.0% total coverage
```

See [docs/scripting.md](../../docs/scripting.md#3a-rego-policies) for the fixture format and the coverage / exit-code contract.

## Try it

```bash
# Public GET: allowed by the second `allow` rule.
curl -i -H 'Host: rego.local' http://127.0.0.1:8080/public/status
# HTTP/1.1 200 OK (or whatever status the upstream returns)

# No path under /public/, and no strong trust tier: denied by the policy.
curl -i -H 'Host: rego.local' http://127.0.0.1:8080/private/status
# HTTP/1.1 403 Forbidden
# forbidden by policy
```

A response with a 5xx status carries `x-status-bucket: 5xx`, set by the Rego response modifier.

## What this exercises

- `policies[] type: rego` with `module_path` instead of an inline `module`
- `response_modifiers[].rego_module`, the Rego form of a response modifier
- `sbproxy rego test`, the offline fixture runner and its line-coverage report

## See also

- [docs/scripting.md](../../docs/scripting.md) - the full scripting reference, including [Rego policies](../../docs/scripting.md#3a-rego-policies) and [Rego modifiers](../../docs/scripting.md#rego-modifiers).
- [docs/configuration.md](../../docs/configuration.md)
