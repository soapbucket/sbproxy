# SBproxy scripting reference: CEL, Lua, JavaScript, and WASM

*Last modified: 2026-07-09*

SBproxy includes four scripting engines for custom logic: CEL (Common Expression Language), Lua, JavaScript, and WASM. All run in sandboxed environments with access to request context.

| Engine | Implementation | Best for |
|--------|----------------|----------|
| CEL | `cel-rust` (the `cel` crate), with custom SBproxy functions | Policy gates, routing keys, response header rules |
| Lua | `mlua` running the Luau runtime, sandboxed | Header modifiers, JSON body rewriting, WAF custom rules |
| JavaScript | `rquickjs` (QuickJS), sandboxed with JSON helpers | JS-native body transforms and response modifiers |
| WASM | `wasmtime` running WASI preview-1 modules, no filesystem or network | Polyglot body transforms, untrusted code with strong isolation |

Reach for CEL for one-liner expressions that evaluate in microseconds. Reach for Lua, JavaScript, or WASM when you need variables, loops, helper functions, or multi-step logic.

---

## 1. Overview

| Engine | Execution | Isolation |
|--------|-----------|-----------|
| CEL | Non-Turing-complete expression, compiled and evaluated by the engine per call | No loops, no side effects, no I/O |
| Lua | Interpreted, fresh sandboxed VM per invocation | Globals set by one call never leak into the next |
| JavaScript | QuickJS interpreter, fresh engine per invocation | Dangerous globals removed, CPU/memory/stack caps |
| WASM | Compiled to native via Wasmtime once at config load | Fresh `Store` per request; module state never leaks |

Lua and JavaScript deliberately build a fresh interpreter state for every invocation so one request's script can never observe another's globals. WASM modules compile once and instantiate per request.

---

## 2. Where scripts are used

| Config field | Engine | Contract |
|---|---|---|
| `policies[] type: expression`, field `expression` | CEL | Returns bool; `false` denies the request with `deny_status` / `deny_message` |
| `policies[] type: rate_limiting`, field `key` | CEL | Returns the rate-limit bucket key (e.g. `jwt.claims.tenant_id`) |
| `request_modifiers[].lua_script` | Lua | Defines `modify_request(req, ctx)`; returned `set_headers` are applied to the upstream request |
| `response_modifiers[].lua_script` | Lua | Defines `modify_response(resp, ctx)`; returned `set_headers` are applied to the response |
| `response_modifiers[].js_script` | JavaScript | Defines `modify_response(resp, ctx)`; returned `set_headers` are applied to the response |
| `transforms[] type: lua_json`, field `script` | Lua | Defines `modify_json(data, ctx)`; return value replaces the JSON response body |
| `transforms[] type: javascript`, field `script` | JavaScript | Defines `transform(body, ctx)` over the raw body string |
| `transforms[] type: js_json`, field `script` | JavaScript | Defines `modify_json(data, ctx)` over the parsed JSON body |
| `transforms[] type: cel`, fields `on_response` / `headers` | CEL | Rewrites the response body and sets/removes response headers from CEL |
| `transforms[] type: wasm`, field `module_path` | WASM | Body on stdin, transformed body on stdout |
| `policies[] type: waf` custom rules | Lua or JavaScript | Rule script defines `match(request)`; `true` fires the rule |
| `action.ai_policy.expression` (in `ai_proxy`) | CEL | Returns typed action tokens over the `ai.*` namespace; see [ai-policy-cel.md](ai-policy-cel.md) |

Two AI-gateway surfaces are deliberately not free-form scripting: the `ai_policy` block is a single CEL expression over gateway-computed signals ([ai-policy-cel.md](ai-policy-cel.md)), and guardrails are typed `guardrails: input:` / `output:` blocks (`injection`, `pii`, `jailbreak`, `toxicity`, `schema`, ...) documented in [ai-gateway.md](ai-gateway.md).

Forward rules are not a scripting surface. A forward rule matches with declarative matchers only (path, header, query); see section 3.4 for the shapes, and use an `expression` policy when you need a scripted request gate.

---

## 3. CEL expressions

CEL is a non-Turing-complete expression language. No loops, no side effects, no I/O. What it does have is fast, safe evaluation of conditions over the request context.

### 3.1 Context variables

The CEL context is built per request. Every namespace below is available to `expression` policies; rate-limit `key:` expressions see the core `request`, `connection`, and `jwt` namespaces plus `envelope` and `features`.

#### `request` - incoming HTTP request

| Field | Type | Description |
|---|---|---|
| `request.method` | string | HTTP method (GET, POST, etc.) |
| `request.path` | string | URL path |
| `request.host` | string | Hostname the request was routed by |
| `request.headers` | map | Request headers, keys lowercase with hyphens preserved |
| `request.query` | string | Raw query string (empty string when absent) |
| `request.scheme` | string | URL scheme when known |
| `request.time` | int | Wall clock at context build, Unix epoch seconds |
| `request.unix_nanos` | int | Same instant in epoch nanoseconds |
| `request.agent_id` | string | Resolved agent identifier (`human`, `anonymous`, `unknown`, or a catalog id like `openai-gptbot`) |
| `request.agent_class` | string | Alias of `agent_id`: the catalog id is the class |
| `request.agent_vendor` | string | Operator display name (`OpenAI`, `Google`, ...) |
| `request.agent_purpose` | string | Operator-stated purpose (`training`, `search`, `assistant`, ...) |
| `request.agent_id_source` | string | Which resolver signal matched (`bot_auth`, `rdns`, `user_agent`, `anonymous_bot_auth`, `fallback`) |
| `request.agent_rdns_hostname` | string | Forward-confirmed reverse-DNS hostname when the rDNS path matched |
| `request.aipref.train` | bool | Parsed `aipref:` header, training axis (default `true`) |
| `request.aipref.search` | bool | Search axis (default `true`) |
| `request.aipref.ai_input` | bool | Inference-input axis (default `true`) |
| `request.tls.ja3` / `request.tls.ja4` / `request.tls.ja4h` | string | TLS fingerprints, `""` when unavailable |
| `request.tls.trustworthy` | bool | Whether the fingerprint reflects the actual client |
| `request.headless_signal.detected` | bool | Whether the JA4 headless-browser detector matched |
| `request.headless_signal.library` | string | Library label (`puppeteer`, `playwright`, ...) or `""` |
| `request.headless_signal.confidence` | double | Detector confidence in `[0.0, 1.0]` |

> Header normalization: header keys are lowercased only; hyphens are preserved. Always use bracket notation: `request.headers["content-type"]`, not `request.headers["Content-Type"]` or `request.headers.content_type`.

Enterprise builds additionally populate `request.kya.*` (Know-Your-Agent verifier verdict) and `request.ml_classification.*` (ML agent classifier verdict) when those subsystems run.

#### `connection` - peer information

| Field | Type | Description |
|---|---|---|
| `connection.remote_ip` | string | Client IP address, when known |

#### `jwt` - decoded Authorization Bearer claims

| Field | Type | Description |
|---|---|---|
| `jwt.claims` | map | Claims from `Authorization: Bearer <jwt>`, decoded but not signature-verified. Empty map when no header, no Bearer prefix, fewer than three segments, or non-object payload. |

`jwt.claims` is for keying and routing decisions (rate-limit buckets, route gates). It is not an authentication boundary. Signature verification stays with the `jwt` auth provider configured under `authentication:`. A common pattern: gate the route with `authentication: jwt`, then key the rate limiter on `jwt.claims.tenant_id` using the same token.

```
# Rate-limit by tenant: each tenant_id gets its own bucket.
key: 'jwt.claims.tenant_id'

# Composite key: per-user inside per-tenant.
key: 'jwt.claims.tenant_id + ":" + jwt.claims.sub'
```

![a JWT-bearing request rate-limited per tenant_id claim, each tenant getting its own token bucket](assets/ratelimit-by-claim.gif)

When the claim expression comes back empty the limiter falls back to client IP ([config](../examples/ratelimit-by-claim/)).

#### `agent` - resolved agent class

A top-level alias namespace for the `request.agent_*` fields, for cleaner expressions.

| Field | Type | Description |
|---|---|---|
| `agent.id` | string | Resolved agent identifier |
| `agent.class` | string | Alias of `agent.id` |
| `agent.vendor` | string | Operator display name |
| `agent.purpose` | string | Operator-stated purpose |
| `agent.source` | string | Resolver signal that matched |
| `agent.rdns_hostname` | string | rDNS hostname when the rDNS path matched |

#### `envelope` - capture envelope dimensions

| Field | Type | Description |
|---|---|---|
| `envelope.user_id` | string | Resolved user identifier |
| `envelope.user_id_source` | string | Where `user_id` came from (`header`, `jwt`, `forward_auth`) |
| `envelope.session_id` | string | Session identifier |
| `envelope.parent_session_id` | string | Caller-supplied parent session |
| `envelope.workspace_id` | string | Tenant scope |
| `envelope.properties` | map | Custom properties captured at request entry |

#### `principal` - unified caller identity

| Field | Type | Description |
|---|---|---|
| `principal.tenant_id` | string | Tenant the request resolved to |
| `principal.sub` | string | Subject identifier (JWT sub, virtual-key name, basic-auth username) |
| `principal.source` | string | Provider slug (`bearer`, `api_key`, `virtual_key`, ...) |
| `principal.virtual_key` | map | `{ name, allowed_providers: [...] }`, empty fields when no virtual key matched |
| `principal.attrs.project` | string | Attribution: project |
| `principal.attrs.user` | string | Attribution: user |
| `principal.attrs.team` | string | Attribution: team |
| `principal.attrs.tags` | list | Operator-supplied tags |
| `principal.attrs.metadata` | map | Metadata fan-out |
| `principal.attrs.roles` | list | Roles claimed by the principal |
| `principal.claims` | map | Verbatim claims map when JWT or OIDC auth stamped them |

#### `features` - per-request feature flags

| Field | Type | Description |
|---|---|---|
| `features.debug` | bool | Built-in debug flag |
| `features.trace` | bool | Built-in trace flag |
| `features["no-cache"]` | bool | Built-in no-cache flag (bracket access: hyphens are not valid CEL identifiers) |
| `features.any_set` | bool | True when any flag, built-in or extra, is set |
| `features["<key>"]` | string | Free-form k=v flag entries; unset keys render as `""` |

#### `response` - response data (response-time evaluation only)

| Field | Type | Description |
|---|---|---|
| `response.status` | int | HTTP status code |
| `response.headers` | map | Response headers, lowercase keys |
| `response.body_size` | int | Response body size in bytes, when known |

The `response` namespace is available where CEL runs at response time: assertion policies and the `cel` transform. The `cel` transform additionally binds `response.body` (the body as a UTF-8 string).

Within a populated namespace, missing fields render as zero values (`""`, `0`, `false`, empty map), so expressions like `size(request.agent_id) > 0` work without probing for presence first. A namespace whose subsystem never ran for the request (for example `request.tls` on a plain HTTP listener) may be absent entirely; guard those accesses or accept the fail-closed deny.

### 3.2 Built-in functions

CEL includes the standard operators (`+`, `-`, `*`, `/`, `%`, `in`, `==`, `!=`, `<`, `>`, `<=`, `>=`, `&&`, `||`, `!`) and the `cel` crate's stock helpers such as `contains`, `startsWith`, `endsWith`, and `size`. SBproxy registers these additional functions on every evaluation context:

| Function | Returns | Description |
|---|---|---|
| `ip_in_cidr(ip, cidr)` | bool | True if `ip` falls within `cidr` (e.g. `"10.0.0.0/8"`); false on unparseable input |
| `uuid_v4()` | string | Random UUID v4 |
| `now()` | string | Current UTC time as an RFC 3339 string |
| `sha256(s)` | string | SHA-256 hex digest of `s` |
| `base64_encode(s)` | string | Standard base64 encoding |
| `base64_decode(s)` | string | Standard base64 decoding; errors on invalid input |
| `regex_match(s, pattern)` | bool | True if `s` matches `pattern`. Patterns over 1024 bytes or that exceed the compile size limit are rejected (returns false, logs a warning) |
| `s.toLowerCase()` | string | Lowercase |
| `s.toUpperCase()` | string | Uppercase |
| `s.trim()` | string | Trim leading and trailing whitespace |
| `s.split(sep)` | list | Split `s` on `sep` |
| `flag_enabled(name, key)` | bool | Resolve a feature flag against the live flag store; unknown flags evaluate false |
| `tls_fingerprint_matches(ja4, agent_class_id)` | bool | True when `ja4` is a known fingerprint for the catalogued agent class, or when the catalogue has no entry for the class (conservative) |

### 3.3 CEL policy examples

The scripted request gate is the `expression` policy. It takes one CEL expression; `false` (or an evaluation error) denies the request with `deny_status` (default 403) and `deny_message`.

#### Gate a route on a header value

```yaml
origins:
  "cel.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: expression
        expression: 'request.headers["x-tenant"] == "acme"'
        deny_status: 403
        deny_message: "tenant not allowed"
```

#### API traffic only, specific methods

```yaml
policies:
  - type: expression
    expression: 'request.path.startsWith("/api/") && request.method in ["GET", "POST"]'
    deny_message: "only GET/POST under /api/"
```

#### Requests from a CIDR range

```yaml
policies:
  - type: expression
    expression: 'ip_in_cidr(connection.remote_ip, "10.0.0.0/8")'
    deny_status: 403
    deny_message: "internal network only"
```

#### JWT-claim role gate

```yaml
policies:
  - type: expression
    expression: '"admin" in principal.attrs.roles || jwt.claims.role == "admin"'
    deny_status: 403
    deny_message: "admin role required"
```

#### Block traffic that opted out of training

```yaml
policies:
  - type: expression
    expression: 'request.aipref.train || request.headers["x-research-license"] != ""'
    deny_message: "Training use requires aipref: train=yes or a research license header."
```

#### Agent-class gate with TLS fingerprint check

```yaml
policies:
  - type: expression
    expression: >
      request.agent_id != "openai-gptbot" ||
      tls_fingerprint_matches(request.tls.ja4, request.agent_id)
    deny_status: 403
    deny_message: "fingerprint does not match claimed agent"
```

#### Rate limiting keyed on a claim

```yaml
policies:
  - type: rate_limiting
    requests_per_minute: 100
    burst: 20
    key: 'jwt.claims.tenant_id'
```

The full working config is in [examples/ratelimit-by-claim/](../examples/ratelimit-by-claim/).

### 3.4 Forward-rule matchers (not CEL)

Forward rules dispatch to inline child origins with declarative matchers, evaluated in order with first match winning. Each entry in a rule's `rules:` list may carry a `path`, `header`, and `query` matcher; matchers present in one entry are ANDed, entries in the list are ORed.

```yaml
origins:
  "gateway.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    forward_rules:
      # Path prefix.
      - rules:
          - path:
              prefix: /api/
        origin:
          action:
            type: proxy
            url: https://api-backend.internal

      # Exact path.
      - rules:
          - path:
              exact: /healthz
        origin:
          action:
            type: static
            status: 200
            content_type: text/plain
            body: ok

      # Template with named segments and a per-segment constraint.
      - rules:
          - path:
              template: /users/{id:[0-9]+}/posts/{post_id}
        origin:
          action:
            type: proxy
            url: https://posts-backend.internal

      # Whole-path regex escape hatch.
      - rules:
          - path:
              regex: '^/v[0-9]+/reports/.*$'
        origin:
          action:
            type: proxy
            url: https://reports-backend.internal

      # Header AND query in one entry.
      - rules:
          - header:
              name: X-Beta-User
              value: "true"
            query:
              name: env
              value: staging
        origin:
          action:
            type: static
            status: 200
            content_type: application/json
            body: '{"beta": true}'
```

The shorthand `match: /api/` on an entry is equivalent to `path: { prefix: /api/ }`. Header matchers take `name` plus either `value` (exact) or `prefix`; header name lookup is case-insensitive, value comparison is case-sensitive. Query matchers take `name` and an optional exact `value`; with no `value`, parameter presence is enough. Template captures surface as `path_params` on the request context.

There is no `cel:` or `lua:` matcher inside forward rules. To route on anything a matcher cannot express, gate with an `expression` policy or split hostnames.

### 3.5 The `cel` response transform

The `cel` transform is the CEL surface on the response path. It can rewrite the response body (`on_response`, alias `expression`) and set, append, or remove response headers via per-header rules with `value_expr` CEL expressions.

```yaml
origins:
  "api.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    transforms:
      - type: cel
        on_response: |
          response.status >= 500
            ? "upstream error, request id " + request.headers["x-request-id"]
            : response.body
        headers:
          - { op: set, name: x-served-by, value_expr: '"sbproxy"' }
          - { op: remove, name: x-internal-trace }
```

The expression sees `response.body`, `response.status`, `response.headers`, and the `request.*` namespace. A string result is written back verbatim; ints, floats, and bools render as strings; maps and lists are JSON-serialised; null leaves the body unchanged. `Set-Cookie` is on a deny-list: a CEL header rule cannot set it.

---

## 4. Lua scripting

Lua gives you a full scripting language: variables, conditionals, helper functions, and string handling. The proxy uses the Luau runtime via `mlua`. Every invocation runs in a fresh sandboxed VM under a configurable wall-clock and memory budget; see [§4.6](#46-sandbox-limits) for the operator knobs.

### 4.1 Function contract

Lua modifier scripts define a named function; the proxy calls it with the request or response data plus a context table.

```lua
-- Request modifier: define modify_request(req, ctx), return a table.
function modify_request(req, ctx)
  return {
    set_headers = {
      ["X-Original-Path"] = req.path,
      ["X-Method"] = req.method
    }
  }
end
```

```lua
-- Response modifier: define modify_response(resp, ctx), return a table.
function modify_response(resp, ctx)
  if resp.status_code >= 500 then
    return { set_headers = { ["X-Upstream-Health"] = "degraded" } }
  end
  return { set_headers = { ["X-Upstream-Health"] = "ok" } }
end
```

On both paths, the only field the proxy applies from the returned table is `set_headers`: a map of header name to string value, inserted onto the upstream request or the client response. Lua modifiers cannot change the path, method, query, status, or body; use the typed modifier fields for those (section 7).

A legacy Go-style request script that defines `match_request(req, ctx)` and calls `req:set_header(name, value)` also works: the proxy falls back to it when `modify_request` is not defined.

### 4.2 Context tables

#### `req` (request modifiers)

```lua
req.method    -- "GET", "POST", ...
req.path      -- "/api/users"
req.headers   -- table, keys lowercase
req.host      -- the origin hostname that routed the request
```

That is the full request surface. Anything else you need (client IP, agent class, claims) has to arrive as a header or be handled in CEL, where the wider namespace lives.

#### `resp` (response modifiers)

```lua
resp.status_code  -- numeric HTTP status
resp.headers      -- response headers table
```

#### `ctx` (second argument)

Response modifiers and JSON transforms receive a context table carrying the parsed aipref signal:

```lua
ctx.request.aipref.train     -- boolean, default true
ctx.request.aipref.search    -- boolean, default true
ctx.request.aipref.ai_input  -- boolean, default true
```

Request modifiers currently receive an empty `ctx` table.

### 4.3 JSON helpers

Two global functions are registered in every Lua VM:

```lua
json_encode({name = "alice"})   -- '{"name":"alice"}'
json_decode('{"x":1}')          -- {x = 1}
-- json_decode raises an error on invalid input; wrap with pcall
-- when the input is untrusted.
local ok, t = pcall(json_decode, maybe_json)
```

These are the only host helpers. There is no logging, crypto, UUID, or time module in the Lua sandbox; if you need hashing, UUIDs, or timestamps, use CEL (`sha256`, `uuid_v4`, `now`) or do the work upstream.

### 4.4 JSON transformation

The `lua_json` transform parses a JSON response body, hands it to `modify_json(data, ctx)`, and replaces the body with whatever the function returns.

```yaml
origins:
  "api.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    transforms:
      - type: lua_json
        script: |
          function modify_json(data, ctx)
            data.password = nil
            data.internal_id = nil
            data.processed = true
            return data
          end
```

A legacy format is also supported: a script with no `modify_json` function runs with the parsed body bound to a `body` global, and the script's return value replaces the body.

### 4.5 Lua examples

#### Classify the caller from the User-Agent

```yaml
origins:
  "api.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    request_modifiers:
      - lua_script: |
          function modify_request(req, ctx)
            local ua = req.headers["user-agent"] or ""
            local kind = "browser"
            if string.find(ua, "GPTBot") or string.find(ua, "ClaudeBot") then
              kind = "crawler"
            end
            return {
              set_headers = {
                ["X-Caller-Kind"] = kind,
                ["X-Original-Path"] = req.path
              }
            }
          end
```

#### Conditional header from a role header

```yaml
request_modifiers:
  - lua_script: |
      function modify_request(req, ctx)
        local role = req.headers["x-role"] or ""
        local is_admin = "false"
        if role == "admin" then
          is_admin = "true"
        end
        return {
          set_headers = { ["X-Is-Admin"] = is_admin }
        }
      end
```

#### Tag responses by upstream status

```yaml
response_modifiers:
  - lua_script: |
      function modify_response(resp, ctx)
        local bucket = "2xx"
        if resp.status_code >= 500 then
          bucket = "5xx"
        elseif resp.status_code >= 400 then
          bucket = "4xx"
        end
        return {
          set_headers = {
            ["X-Status-Bucket"] = bucket,
            ["X-Content-Type-Options"] = "nosniff"
          }
        }
      end
```

#### Stamp the aipref verdict onto the response

```yaml
response_modifiers:
  - lua_script: |
      function modify_response(resp, ctx)
        local train = "yes"
        if ctx.request.aipref.train == false then
          train = "no"
        end
        return {
          set_headers = { ["X-AIPref-Train"] = train }
        }
      end
```

#### Compute a JSON field from two others

```yaml
transforms:
  - type: lua_json
    script: |
      function modify_json(data, ctx)
        if data.first_name and data.last_name then
          data.full_name = data.first_name .. " " .. data.last_name
        end
        data.is_adult = (data.age or 0) >= 18
        return data
      end
```

For path rewriting, method overrides, query-string edits, and body replacement, use the typed modifier fields alongside (or instead of) a script; see section 7.

### 4.6 Sandbox limits

Every Lua invocation runs under a configurable sandbox. The defaults are tight enough to keep an adversarial script from stalling a worker; raise them if your scripts legitimately need more headroom, or tighten them further on sensitive deployments.

```yaml
proxy:
  scripting:
    lua:
      sandbox:
        max_execution_ms: 100   # wall-clock budget per invocation
        max_memory_mb: 8        # cap on the Lua VM's allocator footprint
        allow_patterns: true    # expose string.find / string.match / string.gmatch
```

| Field | Default | Notes |
|---|---|---|
| `max_execution_ms` | `100` | Wall-clock budget per invocation. Scripts that exceed it abort with a sandbox-timeout error and the request fails closed. Set `0` to disable the timer (not recommended). |
| `max_memory_mb` | `8` | Hard ceiling on the Lua VM's allocator footprint. Allocations past the cap fail the script rather than letting it grow the proxy's resident set. |
| `allow_patterns` | `true` | Whether to expose the Lua pattern API (`string.find`, `string.match`, `string.gmatch`). The pattern engine has known pathological inputs; flip to `false` if your scripts do not need pattern matching. The rest of `string.*` keeps working either way. |

Limits apply to every Lua surface uniformly: request modifiers, response modifiers, JSON transforms, and WAF custom rules. Changes take effect on the next config reload (SIGHUP, admin reload, or filesystem watch) without restarting the process.

---

## 5. JavaScript scripting

JavaScript runs on QuickJS via `rquickjs`. Every invocation gets a sandboxed engine with `eval` removed and two global helpers registered: `json_encode` (alias of `JSON.stringify`) and `json_decode` (alias of `JSON.parse`).

Response modifiers define `modify_response(resp, ctx)` and, like Lua, only the returned `set_headers` map is applied:

```yaml
response_modifiers:
  - js_script: |
      function modify_response(resp, ctx) {
        return {
          set_headers: {
            "X-Processed-By": "js",
            "X-Status": String(resp.status_code)
          }
        };
      }
```

Body transforms come in two shapes. `type: javascript` runs `transform(body, ctx)` over the raw body string (a non-string return value is JSON-serialised); `type: js_json` runs `modify_json(data, ctx)` over the parsed JSON body. Both accept an optional `function_name` to call a differently named entrypoint.

```yaml
transforms:
  - type: javascript
    script: |
      function transform(body, ctx) {
        return body.toUpperCase();
      }
  - type: js_json
    script: |
      function modify_json(data, ctx) {
        data.processed = true;
        return data;
      }
```

The `ctx` argument carries `ctx.request.aipref.train`, `ctx.request.aipref.search`, and `ctx.request.aipref.ai_input`, each defaulting to `true` when the request has no valid `aipref` header.

Sandbox limits live under `proxy.scripting.javascript.sandbox`:

```yaml
proxy:
  scripting:
    javascript:
      sandbox:
        budget_ms: 100    # CPU time budget per invocation
        memory_mb: 16     # QuickJS heap cap
        stack_kb: 1024    # native stack cap
```

A script that exceeds `budget_ms` is aborted by a watchdog with an uncatchable exception; the modifier or transform is skipped and the error is logged.

---

## 6. WASM scripting

WASM modules run in `wasmtime` against the WASI preview-1 ABI. The host pipes the response body in on the module's stdin and captures whatever the module writes to stdout. There is no custom calling convention to learn; any `wasm32-wasi` binary that reads stdin and writes stdout works.

WASM is currently exposed as a body transform (`type: wasm`), not as a request/response modifier. Use it when you need to mutate the response body in a language that does not have a first-class engine here (Rust, TinyGo, AssemblyScript, Zig, etc.) or when you want stronger isolation than CEL or Lua provide.

```yaml
origins:
  "wasm.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "hello from sbproxy"
    transforms:
      - type: wasm
        module_path: /etc/sbproxy/modules/uppercase.wasm
        timeout_ms: 500
        max_memory_pages: 256
```

Sandbox tunables:

| Field | Default | Description |
|---|---|---|
| `module_path` | required | Filesystem path to a `.wasm` module compiled for `wasm32-wasi`. Resolved relative to the proxy's working directory. |
| `module_bytes` | optional | Inline bytes of a precompiled module. One of `module_path` or `module_bytes` must be set. |
| `timeout_ms` | 1000 | Hard wall-clock cap per invocation. Enforced via wasmtime's epoch interruption. |
| `max_memory_pages` | 256 | Linear-memory cap in 64 KiB pages. 256 = 16 MiB. |
| `allowed_hosts` | `[]` | Reserved for a future WASI-sockets integration. Currently parsed but not enforced; modules cannot open sockets today. |

There is no filesystem access, no network access, no environment variables, and no clock skew the host can observe. The full authoring guide is in [wasm-development.md](wasm-development.md), with hello-world Rust and TinyGo modules in `examples/wasm/`.

---

## 7. Modifier reference

Request and response modifiers are lists of typed entries. Each entry can combine the structural fields below with an optional script; entries apply in order.

### Request modifier fields

| Field | Type | Description |
|---|---|---|
| `headers.set` | map | Set headers, replacing existing values |
| `headers.add` | map | Append headers, preserving existing values |
| `headers.remove` | list | Remove headers by name (alias: `delete`) |
| `url.path.replace` | map | `{ old, new }` substring replacement on the path |
| `query.set` | map | Set (overwrite) query parameters |
| `query.add` | map | Add query parameters, appending even when the key exists |
| `query.remove` | list | Remove query parameters by name (alias: `delete`) |
| `method` | string | Override the HTTP method (e.g. `"POST"`) |
| `body.replace` | string | Replace the request body with this string |
| `body.replace_json` | any | Replace the request body with this JSON value |
| `lua_script` | string | Lua `modify_request(req, ctx)`; returned `set_headers` applied |

```yaml
request_modifiers:
  - headers:
      set:
        X-Forwarded-Env: production
      remove:
        - X-Internal-Debug
    url:
      path:
        replace:
          old: /v1/
          new: /v2/
    query:
      add:
        source: proxy
      remove:
        - debug
    method: POST
```

### Response modifier fields

| Field | Type | Description |
|---|---|---|
| `headers.set` / `headers.add` / `headers.remove` | map / map / list | Same semantics as the request side |
| `status.code` | int | Override the response status code |
| `status.text` | string | Optional reason phrase (informational; not sent in HTTP/2) |
| `body.replace` | string | Replace the response body with this string |
| `body.replace_json` | any | Replace the response body with this JSON value |
| `lua_script` | string | Lua `modify_response(resp, ctx)`; returned `set_headers` applied |
| `js_script` | string | JavaScript `modify_response(resp, ctx)`; returned `set_headers` applied |

```yaml
response_modifiers:
  - headers:
      set:
        X-Frame-Options: DENY
        Strict-Transport-Security: max-age=31536000
      remove:
        - X-Powered-By
        - Server
    status:
      code: 503
    body:
      replace_json:
        error: "Service temporarily unavailable"
```

For JSON body surgery on responses, prefer the JSON transforms: the typed `json` transform (`set` / `remove` / `rename` fields) for static edits, or `lua_json` / `js_json` for computed edits.

---

## 8. AI-gateway scripting pointers

The AI proxy action does not embed the general scripting engines. It has two dedicated surfaces:

- **`ai_policy`**: a single sandboxed CEL expression over the `ai.*` namespace (surface, model, provider, principal tier, guardrail verdicts, budget state, token estimates) that returns typed action tokens (`allow`, `block`, `redact`, `route_to:<model>`, `set_sink_tag:<tag>`, `audit:<priority>`). See [ai-policy-cel.md](ai-policy-cel.md) and [examples/ai-policy-cel/](../examples/ai-policy-cel/).
- **Guardrails**: typed `guardrails: input:` / `output:` blocks (`injection`, `pii`, `jailbreak`, `toxicity`, `schema`, ...), configured declaratively rather than as expressions. See [ai-gateway.md](ai-gateway.md) and [examples/ai-guardrails/](../examples/ai-guardrails/).

---

## 9. Sandbox limits summary

### CEL

- Non-Turing-complete: no loops, no side effects, no I/O.
- No access to secrets. Evaluation typically completes in microseconds.
- User-supplied regex patterns (`regex_match`) are capped at 1024 bytes and a bounded compile size; oversized or invalid patterns evaluate false.

### Lua

- Fresh VM per invocation: globals never leak between calls.
- Nil'd out: `os`, `io`, `loadfile`, `dofile`, `require`, `rawset`, `rawget`, `load`, `loadstring`, `debug`, `package`.
- No network operations.
- Wall-clock budget (default 100 ms) enforced via the Luau interrupt callback; memory cap (default 8 MB) enforced by the allocator.
- Available standard library: `string.*` (pattern functions gated by `allow_patterns`), `table.*`, `math.*`, `tonumber`, `tostring`, `type`, `pairs`, `ipairs`, `select`, `pcall`, `error`.

### JavaScript

- Fresh sandboxed engine per invocation; `eval` removed.
- CPU budget (default 100 ms) enforced via a watchdog interrupt; heap cap (default 16 MB) and native stack cap (default 1 MB) enforced by the runtime.
- No filesystem, no network, no module loader.

### WASM

- Wasmtime sandbox running WASI preview-1. No network, no filesystem, no environment variables, no host clock beyond the epoch-interruption deadline.
- Per-request `Store` so module state never leaks between requests; the compiled `Module` is shared across calls so per-invocation cost is one instantiate plus one `_start`.
- `timeout_ms` is enforced via epoch interruption; `max_memory_pages` caps linear memory.

---

## 10. Performance notes

CEL evaluates in microseconds per request and fits any routing decision, including high-frequency hot paths. Prefer CEL over Lua, JavaScript, or WASM when the logic fits.

Lua and JavaScript build a fresh interpreter state per invocation. That is the isolation guarantee, and it means simple scripts complete in well under a millisecond but there is no cross-request state to amortize into.

WASM has a one-time compilation cost at config load; subsequent invocations run at near-native speed inside the Wasmtime sandbox, paying one instantiation per request.

Tips:
- Prefer `startsWith`, `endsWith`, or `contains` over `regex_match` in CEL hot paths.
- In Lua, use `local` variables. Local variable access is faster than global lookup.
- In Lua, prefer `table.concat()` over string concatenation in loops.
- Keep scripts under ~30 lines. If you need more, consider whether a typed modifier, transform, or policy fits better.
- Expressions that always return the same result regardless of request data should be replaced with static config values.

---

## 11. Debugging scripts

### Config validation

Validate your config before deployment:

```bash
sbproxy validate sb.yml
```

Validation checks the YAML shape and typed fields. Script bodies (CEL expressions, Lua, JavaScript) are strings to the validator; their syntax errors surface at request time in the logs, not at validation time. Exercise a scripted route once in staging before relying on it.

### Enabling debug logging

```bash
sbproxy --log-level debug -f sb.yml
```

With debug logging on, script failures are logged with the engine, the error message, and (for Lua and JavaScript) the failing function. Script health is also visible in metrics: `sbproxy_script_compile_total{engine, result}`, `sbproxy_script_invocations_total{engine, result}`, and `sbproxy_script_duration_seconds{engine}`.

### Error behavior

| Surface | On error |
|---|---|
| `expression` policy | Fails open on a CEL parse error (misconfiguration), fails closed on an evaluation error (the expression could not prove the request is allowed) |
| Lua / JS modifiers | Error logged per request; the modifier's headers are not applied; the request proceeds |
| `lua_json` / `js_json` / `javascript` transforms | Error logged per request; the body is left unchanged |
| `cel` transform | Missing both `on_response` and `headers` fails config compile; runtime evaluation errors leave the body unchanged |
| WASM transform | Missing `module_path` / `module_bytes` or a module that fails to compile fails config compile; runtime errors skip the transform |

### Common mistakes

CEL header key case. Headers are normalized to lowercase. Use `request.headers["content-type"]`, not `request.headers["Content-Type"]`.

CEL missing keys. Accessing a missing key can surface as an evaluation error, and the `expression` policy fails closed on evaluation errors. Guard with `size(...)` checks (e.g. `size(jwt.claims) > 0`) before indexing into maps that may be empty.

Lua array indexing is 1-based. `arr[1]` is the first element. `#arr` is the length.

Lua inequality operator. Lua uses `~=` for not-equal, not `!=`.

Lua modifiers only set headers. Returning `path`, `status_code`, or `body` from `modify_request` / `modify_response` does nothing; those belong to the typed modifier fields (section 7).

AI policy CEL is a different namespace. The `ai_policy` expression sees `ai.*` variables, not `request.*`; see [ai-policy-cel.md](ai-policy-cel.md).

## See also

- [configuration.md](configuration.md) - general configuration model and the full `sb.yml` field reference.
- [features.md](features.md) - higher-level feature overview.
- [ai-gateway.md](ai-gateway.md) - AI gateway routing and guardrails.
- [ai-policy-cel.md](ai-policy-cel.md) - the unified CEL policy plane for the AI gateway.
