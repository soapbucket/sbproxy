# MCP tool composition

*Last modified: 2026-08-18*

A `federated_servers[]` entry can be `type: local`: tools the gateway
serves itself, declared entirely in config, with no upstream MCP
server or REST spec behind them. A local tool is one of three
handlers: a fixed value, one HTTP call, or a dependency-ordered DAG of
HTTP calls whose outputs are shaped into a single response. This page
is the field reference for all three, the interpolation language that
connects them, and how the rest of the gateway's governance surface
applies to them.

For the action-level fields and every other `federated_servers[]`
type, see [mcp.md](mcp.md). For the runnable examples this page
describes, see [`examples/mcp-local-tools`](../examples/mcp-local-tools/)
(a static tool and a single HTTP call, no DAG) and
[`examples/mcp-compose`](../examples/mcp-compose/) (a two-step DAG,
`condition`, and Lua response shaping) plus its JavaScript twin,
[`examples/mcp-compose-js`](../examples/mcp-compose-js/).

## Why a local server

Federating an existing MCP or OpenAPI-backed service is the common
case: the tool logic already exists somewhere else, and the gateway's
job is to govern the call. A `type: local` server is for the other
case, a tool that is only a call, or a short sequence of calls, glued
together with no separate service worth standing up and no code worth
writing. It still goes through the same catalog, the same RBAC, the
same versioning gate, and the same evidence feed as a federated tool,
because it publishes into the exact same registry federation does; see
[Governance inheritance](#governance-inheritance) below for what that
buys you.

```yaml
federated_servers:
  - origin: local-tools
    type: local
    prefix: local
    egress:
      mode: deny_by_default
      hosts: [api.internal]
    tools:
      - name: status
        description: Fixed status blob. Makes no HTTP call.
        input_schema: { type: object, properties: {} }
        static: { ok: true }
```

`origin:` is still required on a `type: local` entry even though
nothing is ever dialed there; it is a nominal label only (used the way
every other server's `origin` feeds a derived name when `prefix` is
absent). Set it to anything readable.

## Handler kinds

A tool in `tools[]` sets `name`, `description`, `input_schema` (a JSON
Schema object describing the arguments; see
[Honest limits](#honest-limits) for what gets checked at config-load
time and what does not), and exactly one of `static`, `http`, or
`steps`. Declaring zero or more than one is a config-compile error.

### `static`

Always returns the same JSON value, unconditionally. Makes no HTTP
call, so a server whose every tool is `static` needs no `egress:` at
all.

```yaml
static:
  service: my-gateway
  ok: true
```

### `http`

Makes one HTTP call and returns its response. Same call shape a DAG
step's `http:` field uses:

```yaml
http:
  method: GET
  url: "https://api.internal/widgets/${args.id}"
  headers:
    accept: application/json
  timeout: 10s
  retry:
    max_attempts: 3
    retry_on: [connect_error, timeout, "503"]
    backoff_ms: 100
```

`method` and `url` are required; `headers`, `body`, `retry`, and
`timeout` are all optional. `retry` is the same `RetryConfig` shape a
`proxy` or `load_balancer` action's `retry:` uses: `max_attempts`
(default `1`, no retry), `retry_on` (`connect_error`, `timeout`, or a
numeric status code, default `[connect_error, timeout]`), and
`backoff_ms` (default `100`, doubled per attempt, capped at 5s).

### `steps`

Runs a dependency-ordered DAG of HTTP calls, then shapes one response
from their outputs:

```yaml
steps:
  steps:
    - name: fetch
      http: { method: GET, url: "https://api.internal/widgets/${args.id}" }
    - name: enrich
      depends_on: [fetch]
      http:
        method: GET
        url: "https://api.internal/vendors/${steps.fetch.body.vendor_id}"
  response:
    template: "${steps.enrich.body}"
```

See [DAG semantics](#dag-semantics) for execution order, `condition`,
`continue_on_error`, retry, and the whole-call budget, and
[Response shaping](#response-shaping) for `template` / `js` / `lua`.

## Egress

A local server needs an `egress:` policy the moment any of its tools
can make an HTTP call: an `http` handler, or a `steps` handler with at
least one step (every step always carries `http`, so a `steps` tool
counts the same as an `http` tool). A server whose every tool is
`static` needs none. This is checked once per server, not per tool:

```yaml
federated_servers:
  - type: local
    egress:
      mode: deny_by_default
      hosts: [api.internal]
    tools: [...]
```

Unlike an `openapi`-backed server, a local server never falls back to
the action-level `egress:` default: since there is no legacy config to
stay compatible with, an HTTP-calling local server with no `egress:`
is a compile error, not a silent allow-all. Every dial goes through
the same DNS-pinned, egress-gated client an `openapi`-backed server's
REST calls use, authorized under the same egress purpose an
`openapi`-backed tool's REST calls use, and lands in the same `GET
/api/egress` inventory rows (labeled `openapi_tool`, not a separate
label of its own); see
[mcp-gateway-guardrails.md#deterministic-egress](mcp-gateway-guardrails.md#deterministic-egress).
A local tool's denied or allowed dials are therefore visible in that
inventory, but not separable from an `openapi`-backed server's by
purpose alone; `origin` (the denied host, or the local server's own
name) is what tells them apart in practice.

## Interpolation vocabulary

Three forms, resolved wherever a config string in an `http` call
(`url`, a `headers` value, `body` field values) or a `template`
response contains one:

| Form | Resolves to |
|---|---|
| `${args.<path>}` | A value from the tool call's parsed arguments. |
| `${steps.<name>.status}` | The HTTP status code a completed step's call returned. |
| `${steps.<name>.body.<path>}` | A value from a completed step's parsed response body. |

`<path>` is a **dot-separated JSON object path only**
(`user.id`, `billing.plan.tier`): each segment is looked up as an
object key. There is no array indexing of any kind, bracket or
numeric, and no full JSONPath engine behind it: a path that steps into
an array fails to resolve the same way a genuinely missing key does.
This matters in practice because a raw MCP `tools/call` result wraps
its payload in a `content` array (`result.content[0].text`), which
means `${steps.<name>.body...}` can reach `status` and any flat,
object-shaped field of a step's body, but not into that array; pull a
value out of an array in [response shaping](#response-shaping)
instead, where a real script indexes it natively. Only steps that have
already completed, in dependency order, are in scope for
`${steps...}`: a step can read any step named in its own `depends_on`
chain (transitively), never a step declared after it or one it does
not depend on.

**Escaping.** `$$` renders one literal `$` and never opens a
placeholder, so `$$` followed by `{args.x}` renders the literal text
`${args.x}`, with `args.x` never looked up. Any other bare `$` not
immediately followed by `{` or another `$` is also literal. An
unterminated or empty `${...}` is a call-time fail-closed error, the
same as a missing path.

**Whole-string splice vs. stringify.** This distinction only applies
to `body:` field values, which are JSON, not plain strings. When a
`${...}` placeholder there is the *entire* value of a field
(`body: {"id": "${args.id}"}`), it splices in the underlying JSON
value as-is, preserving its type: an object stays an object, a number
stays a number, so a typed argument reaches the upstream typed rather
than as a quoted string. `url` and header values can only ever be
strings, so there this distinction collapses: whether the placeholder
is the whole value or embedded in a larger one
(`url: "https://api.internal/widgets/${args.id}"`), the resolved value
is always stringified into position -- a string passes through
unchanged, a number or boolean renders as its bare text, `null`
renders as an empty string, and an object or array renders as compact
JSON text. The same stringify rule applies to any placeholder embedded
inside a larger `body:` string too, not just whole-value splices.

**Missing paths fail closed.** A path that does not resolve, an
argument that was not supplied, or a field absent from a step's body
is a tool-call error, not an empty string. Nothing here has an
implicit default; if a value might be absent, gate its use behind a
`condition` (below) rather than relying on the splice to degrade
gracefully.

### Worked example: reading a prior step's output

[`examples/mcp-compose`](../examples/mcp-compose/) composes two calls
to `test.sbproxy.dev`'s own `hello` and `echo` tools. The `hello` step
calls with the caller's `name`:

```yaml
- name: hello
  http:
    method: POST
    url: "https://test.sbproxy.dev/mcp"
    body:
      jsonrpc: "2.0"
      id: 1
      method: tools/call
      params:
        name: hello
        arguments:
          name: "${args.name}"
```

Calling the composed tool with `{"name": "Ada"}` resolves
`${args.name}` to the whole string `"Ada"` (a whole-string splice: the
entire `name:` value is the placeholder). `hello` completes with a
parsed body shaped like:

```json
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Hello, Ada!"}]}}
```

The `echo` step, which `depends_on: [hello]`, builds its own message
from that call's outcome:

```yaml
- name: echo
  depends_on: [hello]
  http:
    body:
      params:
        arguments:
          message: "Echo after hello returned HTTP ${steps.hello.status}"
```

Here the placeholder is embedded in a larger string, so
`${steps.hello.status}` (`200`, a number) is stringified into
position: `message` resolves to `"Echo after hello returned HTTP
200"`. `status` and any flat field of `hello`'s parsed body are in
reach this way; `hello`'s actual greeting text is not, because it sits
inside `result.content[0]`, an array element -- exactly the case
[Response shaping](#response-shaping) below exists for.
`response.lua` reads `steps.hello.body.result.content[1].text`
directly (Luau, 1-indexed) to pull that greeting into the tool's final
result, something no `${}` field can do.

### What `condition` cannot see

A step's `condition` is a CEL expression, but it is compiled against
the same, narrower vocabulary `argument_policies[]` uses (`mcp.tool`,
`mcp.arguments`, `mcp.principal`, `mcp.server`, `mcp.session`,
`mcp.tenant`), not the `${}` interpolation context above. This means a
`condition` can gate a step on the tool call's own arguments, the
caller's identity, or the session's flow labels, but **not** on
another step's result: there is no `steps.*` binding in CEL. If you
need to skip a step based on what an earlier step returned, that
belongs in `response` shaping (below), reading the earlier step's
output there instead.

```yaml
condition: "mcp.arguments.verbose == true"
```

## DAG semantics

**Ordering.** Steps run in dependency order (a topological sort of
`depends_on`), one at a time. Among steps whose dependencies are all
already satisfied, ties break by declaration order in `steps[]`.
There is no parallel execution: setting `steps.parallel` to anything
is a config-compile error naming dependency-ordered execution as the
current behavior and a parallel scheduler as a tracked follow-up,
rather than accepting the key and ignoring it.

**`condition`.** Evaluated immediately before a step would otherwise
run. `false` skips the step: it is not attempted, and skipping is not
itself an error. A step whose `depends_on` names a step that did not
complete (skipped by its own `condition`, or failed without
`continue_on_error`) is itself skipped if its own `condition`
evaluates false, and is a tool-call error otherwise, since it would
have run but has nothing to run against.

**`continue_on_error`.** By default, a failed step call (a non-2xx
response, a connect failure, a timeout that exhausts its `retry`)
fails the whole tool call. Setting `continue_on_error: true` on a step
records that failure onto its `steps.<name>` context entry instead of
stopping the DAG, so steps that do not depend on it still run.

**Retry.** Each step's own `http.retry` applies to that step's call
only, the same `RetryConfig` shape [`http` handlers](#http) use.

**The whole-call budget.** One deadline covers the entire tool call,
every step included, defaulting to 30 seconds and never configurable
past 5 minutes. Exceeding it fails the call closed rather than
returning a partial response from whichever steps happened to finish.

## Response shaping

A `steps` handler's `response:` is exactly one of `template`, `js`, or
`lua`; declaring more than one is a config-compile error. All three
read the same context: the call's arguments and every step's
outcome, bound as `input = {args, steps}` in the script engines
(`input.args.<name>`, `input.steps.<name>.status`,
`input.steps.<name>.body`), and as the `${args...}` / `${steps...}`
vocabulary above in a template.

A script that throws, a template with an unresolved path, or a
watchdog timeout all fail the tool call closed. Nothing here returns a
partial result: either shaping succeeds and its return value is the
tool result, or the call errors.

### `template`

The same `${}` engine [above](#interpolation-vocabulary), evaluated
once against the completed step context rather than the request:

```yaml
response:
  template: "${steps.enrich.body}"
```

A whole-string placeholder like this one splices the entire parsed
body through unchanged; build a literal JSON document with embedded
placeholders (`'{"vendor": "${steps.enrich.body.name}"}'`) when you
need to reshape rather than pass through.

### `js`

QuickJS, the same sandbox `js_json` transforms and `response_cache`'s
`admit_event`/`key_event` scripts already run in (see
[scripting.md](scripting.md#5-javascript-scripting)). The script is
evaluated as a single expression: a script with branches wraps itself
in an immediately invoked function so the whole thing still evaluates
to one value. Arrays and `content[]` blocks index from 0.

```yaml
response:
  js: |
    (() => {
      const body = input.steps.enrich.body;
      return { vendor: body.name, sku: input.args.id };
    })()
```

### `lua`

Luau, the same sandbox request/response modifiers and `js_json`'s
sibling `lua_json` transform use (see
[scripting.md](scripting.md#4-lua-scripting)). The script's top-level
`return` value is the tool result, the same convention
`response_cache`'s Lua `key_event`/`admit_event` scripts use. Luau
tables index from 1, not 0.

```lua
local body = input.steps.enrich.body
return { vendor = body.name, sku = input.args.id }
```

## Governance inheritance

A local server publishes its tools into the exact same catalog a
federated `mcp` or `openapi` server does: the same `FederatedTool`
entries, built the same way, so nothing downstream can tell a local
tool apart from an upstream one by looking at the registry. Every
WOR-2384 gate that reads that catalog therefore applies unchanged,
with no local-specific wiring of its own:

- **`rbac_policies`** filters a local tool out of `tools/list` and
  refuses its `tools/call` exactly like a federated tool, keyed on the
  same `federated_servers[].rbac` label.
- **`status: draft \| approved \| deprecated`** applies per server: a
  `draft` local server's tools are hidden and refused, a `deprecated`
  one stays callable but logs a warning on every call.
- **`tool_versioning`** diffs a local tool's `name`/`description`/
  `input_schema` against the committed lockfile on every config
  reload, the identical contract-digest mechanism an upstream tool's
  definition change trips. Editing a local tool's config without a
  matching version bump is caught the same way editing an upstream
  server would be.
- **`argument_policies[]` / `result_policies[]`** evaluate against a
  local tool's call the same way they do any other tool's: CEL or
  Rego, before and after dispatch respectively. These are the
  action-level policies, distinct from a DAG step's own `condition`;
  see [What `condition` cannot see](#what-condition-cannot-see).
- **`tool_quotas`** (under `rbac_policies`) rate-limit a local tool by
  name the same way they rate-limit a federated one.
- **`content_filters`** scan a local tool's call arguments and result
  for secret and PII shapes, the same detector catalog every tool's
  traffic runs through.
- **`flow`** (session-scoped taint tracking) treats a local server's
  name in `trusted_servers` / `sensitive_servers` and its tool names
  in `outbound_tools` exactly like any other server's.
- **`mcp_audit.capture_arguments`** and the `mcp_governance_decision`
  evidence feed (`events:`) cover a local tool's dispatch, refused or
  successful, the same as any other.

See [mcp-security-coverage.md](mcp-security-coverage.md) for how this
maps onto the OWASP MCP Top 10 scorecard, and
[mcp-governance](../examples/mcp-governance/) for every one of these
turned on at once against a federated server; the same config shape
applies verbatim to a `type: local` one.

## Honest limits

- **No in-process origin shortcut.** A step's `http.url` is always
  dialed as a normal external HTTP request through the egress-gated
  client. There is no `origin_host`-style reference to call another
  origin defined in the same config in-process; pointing a step at
  this same gateway means giving its real listening URL, a real
  network round trip like any other. An in-process dispatch seam is a
  deferred follow-up, not shipped today.
- **Sequential execution only.** Steps never run concurrently, even
  when nothing in the DAG depends on ordering them; see
  [DAG semantics](#dag-semantics). `steps.parallel` names this
  explicitly rather than silently ignoring the key.
- **Schema notes.** `input_schema` is checked at config-compile time
  only for being a JSON object (not, for instance, a bare array or
  string); it is not validated as a well-formed JSON Schema document.
  A malformed schema is not caught at load time the way a malformed
  CEL `condition` is; validate it yourself (a JSON Schema linter, or a
  quick `tools/call` against a case you expect to fail) before relying
  on it to reject bad arguments.
- **No JSONPath engine, and no array indexing.** `${}` paths are
  plain dot-separated object-key lookups, not a JSONPath or JMESPath
  expression: no wildcards, no filters, no slicing, and no way to step
  into a JSON array by index either. A path that needs an array
  element (an MCP result's `content[0]`, most commonly) has to go
  through `response` shaping instead, where a real script indexes it
  natively.

## See also

- [mcp.md](mcp.md) - the `mcp` action and `federated_servers[]` in
  full, including `mcp`- and `openapi`-typed servers.
- [mcp-gateway-guardrails.md](mcp-gateway-guardrails.md) - egress,
  registry status, argument/result policies, content filters, and
  session flow in depth.
- [mcp-security-coverage.md](mcp-security-coverage.md) - the OWASP MCP
  Top 10 scorecard.
- [scripting.md](scripting.md) - the CEL, Lua, and JavaScript
  reference shared with every other scripting surface.
- [configuration.md](configuration.md#mcp) - the flat field table for
  the `mcp` action.
- [`examples/mcp-local-tools`](../examples/mcp-local-tools/),
  [`examples/mcp-compose`](../examples/mcp-compose/),
  [`examples/mcp-compose-js`](../examples/mcp-compose-js/) - runnable
  examples for everything on this page.
