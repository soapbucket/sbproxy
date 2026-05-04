# SBproxy scripting reference: CEL, Lua, JavaScript, and WASM

*Last modified: 2026-04-24*

SBproxy includes four scripting engines for custom logic: CEL (Common Expression Language), Lua, JavaScript, and WASM. All run in sandboxed environments with access to request context.

| Engine | Implementation | Best for |
|--------|----------------|----------|
| CEL | `cel-rust` (the `cel` crate), with custom HTTP request inspection functions | Routing decisions, simple checks, AI selectors |
| Lua | `mlua` running the Luau runtime, sandboxed | Larger transformations, multi-step logic, body rewriting |
| JavaScript | `rquickjs` (QuickJS), V8-compatible API surface | JS-native logic, importing existing helpers |
| WASM | `wasmtime` running WASI preview-1 modules, no filesystem or network | Polyglot body transforms, untrusted code with strong isolation |

Reach for CEL for one-liner expressions that evaluate in microseconds. Reach for Lua, JavaScript, or WASM when you need variables, loops, helper functions, or multi-step logic.

---

## 1. Overview

| Engine | Execution | Compilation | Best for |
|--------|-----------|-------------|----------|
| CEL | Compiled, non-Turing-complete | Once at config load | Routing decisions, simple checks, AI selectors |
| Lua | Interpreted, sandboxed VM | Cached after first load | Larger transformations, multi-step logic, body rewriting |
| JavaScript | QuickJS interpreter, sandboxed | Cached after first load | JS-friendly transformations |
| WASM | Compiled to native via Wasmtime | Cached after first load | Polyglot body transforms, strong isolation |

CEL expressions compile once when your config loads. Syntax errors surface at startup, not request time. Lua VMs and JavaScript runtimes are pooled and reused across requests to amortize initialization cost. WASM modules compile once and instantiate per request.

---

## 2. Where scripts are used

| Config field | Accepts | Return type | Purpose |
|---|---|---|---|
| `forward_rules[].match.cel` | CEL | bool | Match requests for routing |
| `forward_rules[].match.lua` | Lua | bool | Match requests for routing |
| `request_modifiers.cel` | CEL | map | Modify outgoing requests |
| `request_modifiers.lua` | Lua | table | Modify outgoing requests |
| `request_modifiers.js` | JavaScript | object | Modify outgoing requests |
| `response_modifiers.cel` | CEL | map | Modify upstream responses |
| `response_modifiers.lua` | Lua | table | Modify upstream responses |
| `response_modifiers.js` | JavaScript | object | Modify upstream responses |
| `transforms[].type: wasm` | WASM (`wasm32-wasi`) | bytes | Mutate the response body via a sandboxed module |
| `policies[].expression` | CEL or Lua | bool | Policy enforcement conditions |
| `routing.model_selector` | CEL | string | AI model override per request |
| `routing.provider_selector` | CEL | string | AI provider preference |
| `routing.cache_bypass` | CEL | bool | Skip response cache |
| `routing.dynamic_rpm` | CEL | int | Per-request RPM override |
| `cel_guardrails[].condition` | CEL | bool | AI content safety rules |

---

## 3. CEL expressions

CEL is a non-Turing-complete expression language. No loops, no side effects, no I/O. What it does have is fast, safe evaluation of conditions and transformations.

### 3.1 Context variables

All nine namespaces are available in every CEL expression except where noted.

#### `request` - incoming HTTP request

| Field | Type | Description |
|---|---|---|
| `request.method` | string | HTTP method (GET, POST, etc.) |
| `request.path` | string | URL path |
| `request.host` | string | Host header value |
| `request.scheme` | string | `http` or `https` |
| `request.query` | string | Raw query string |
| `request.headers` | map | Request headers, keys lowercase with hyphens preserved |
| `request.body` | string | Request body (if buffered) |
| `request.body_json` | any | Parsed JSON body (when body is JSON) |
| `request.is_json` | bool | Whether the body is JSON |
| `request.content_type` | string | Content-Type header value |
| `request.remote_addr` | string | Raw remote address |
| `request.size` | int | Content-Length value |
| `request.protocol` | string | HTTP protocol version |
| `request.data` | map | Data from on_request callbacks |

> Header normalization: headers are lowercased only; hyphens are preserved. Always use bracket notation: `request.headers["content-type"]`, not `request.headers["Content-Type"]` or `request.headers.content_type`.

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

#### `connection` - peer information

| Field | Type | Description |
|---|---|---|
| `connection.remote_ip` | string | Client IP address (when known). Always populated from the trusted-proxy chain when `trusted_proxies` is configured. |

#### `session` - session state

| Field | Type | Description |
|---|---|---|
| `session.id` | string | Session ID |
| `session.expires` | string | Session expiry |
| `session.is_authenticated` | bool | Whether the user is authenticated |
| `session.data` | map | Custom session data from session callbacks |
| `session.auth` | map | Auth data (type, email, roles, permissions, etc.) |
| `session.visited` | list | List of visited URLs |

#### `origin` - config metadata for this origin

| Field | Type | Description |
|---|---|---|
| `origin.id` | string | Origin UUID |
| `origin.workspace_id` | string | Workspace UUID |
| `origin.hostname` | string | Origin hostname |
| `origin.environment` | string | Environment name (dev, stage, prod) |
| `origin.version` | string | Config version |
| `origin.name` | string | Origin name |
| `origin.tags` | list | User-defined tags |
| `origin.params` | map | Origin parameters from on_load callbacks |

#### `server` - proxy instance info

| Field | Type | Description |
|---|---|---|
| `server.instance_id` | string | Server instance ID |
| `server.version` | string | Proxy version |
| `server.build_hash` | string | Build hash |
| `server.hostname` | string | OS hostname |
| `server.start_time` | string | Instance start time (RFC 3339) |
| `server.environment` | string | Server environment |
| `server.custom` | map | Custom server variables |

#### `vars` - user-defined variables

A map of variables set via `on_load` callbacks or config-level variable definitions. Access with `vars["my_var"]` or `vars.my_var`.

#### `features` - feature flags

A map of workspace-scoped feature flags. Access with `features["flag_name"]` or `features.flag_name`.

#### `client` - client enrichment data

| Field | Type | Description |
|---|---|---|
| `client.ip` | string | Client IP address |
| `client.location` | map | GeoIP data (country, country_code, continent, asn, etc.) |
| `client.user_agent` | map | Parsed user agent (family, os_family, device_family, major, etc.) |
| `client.fingerprint` | map | Device fingerprint (hash, composite, etc.) |

> The top-level `request_ip` variable is also available as a shorthand for `client.ip`.

#### `ctx` - per-request mutable state

| Field | Type | Description |
|---|---|---|
| `ctx.id` | string | Request ID |
| `ctx.cache_status` | string | Cache hit/miss status |
| `ctx.debug` | bool | Whether debug mode is enabled |
| `ctx.no_cache` | bool | Whether caching is disabled |
| `ctx.data` | map | Mutable per-request data |

#### `response` - response data (response_modifiers only)

| Field | Type | Description |
|---|---|---|
| `response.status_code` | int | HTTP status code |
| `response.headers` | map | Response headers |
| `response.body` | string | Response body (if buffered) |

#### `oauth_user` - OAuth user data (response_modifiers only)

Available when OAuth authentication is active. Contains provider-specific user profile fields.

---

### 3.2 Built-in functions

CEL includes standard operators (`+`, `-`, `*`, `/`, `%`, `in`, `==`, `!=`, `<`, `>`, `<=`, `>=`, `&&`, `||`, `!`) plus the following functions.

#### String functions

| Function | Description |
|---|---|
| `s.contains(sub)` | Returns true if `s` contains `sub` |
| `s.startsWith(prefix)` | Returns true if `s` starts with `prefix` |
| `s.endsWith(suffix)` | Returns true if `s` ends with `suffix` |
| `s.matches(pattern)` | Returns true if `s` matches the regex `pattern` |
| `s.substring(start)` | Substring from `start` to end |
| `s.substring(start, end)` | Substring from `start` to `end` (exclusive) |
| `s.replace(old, new)` | Replace all occurrences of `old` with `new` |
| `s.split(sep)` | Split `s` on `sep`, returns list |
| `s.trim()` | Trim leading and trailing whitespace |
| `s.upperAscii()` | Uppercase ASCII characters |
| `s.lowerAscii()` | Lowercase ASCII characters |

#### Encoder functions

| Function | Description |
|---|---|
| `base64.encode(bytes)` | Base64-encode a byte string |
| `base64.decode(string)` | Base64-decode a string |
| `url.encode(string)` | URL-encode a string |
| `url.decode(string)` | URL-decode a string |

#### Type conversion functions

| Function | Description |
|---|---|
| `int(value)` | Convert to integer |
| `string(value)` | Convert to string |
| `double(value)` | Convert to float |
| `size(value)` | Length of string, list, or map |
| `type(value)` | Return the type name as a string |

#### Utility functions

| Function | Returns | Description |
|---|---|---|
| `sha256(str)` | string | SHA-256 hex digest of `str` |
| `hmacSHA256(data, key)` | string | HMAC-SHA256 hex digest |
| `uuid()` | string | Random UUID v4 (e.g., `"550e8400-e29b-..."`) |
| `now()` | timestamp | Current time as a CEL timestamp (supports `.getFullYear()`, `.getHours()`, etc.) |

> `base64.encode()`, `base64.decode()`, `url.encode()`, and `url.decode()` are provided by the built-in encoder extension (see Encoder functions above).

#### IP functions

| Function | Returns | Description |
|---|---|---|
| `ip.parse(ip)` | map | Parse IP, returns `{valid, ip, is_ipv4, is_ipv6, is_private, is_loopback}` |
| `ip.inCIDR(ip, cidr)` | bool | True if `ip` falls within `cidr` (e.g., `"10.0.0.0/8"`) |
| `ip.isPrivate(ip)` | bool | True if `ip` is in a private range (RFC 1918, link-local, loopback) |
| `ip.isLoopback(ip)` | bool | True if `ip` is a loopback address |
| `ip.isIPv4(ip)` | bool | True if `ip` is an IPv4 address |
| `ip.isIPv6(ip)` | bool | True if `ip` is an IPv6 address |
| `ip.inRange(ip, start, end)` | bool | True if `ip` is between `start` and `end` (inclusive) |
| `ip.compare(ip1, ip2)` | int | -1, 0, or 1 (less than, equal, greater than) |

> Note: CEL uses camelCase for IP functions (`inCIDR`, `isPrivate`). Lua uses snake_case (`in_cidr`, `is_private`).

---

### 3.3 CEL examples

#### Match: API traffic only

```yaml
forward_rules:
  - match:
      cel: request["path"].startsWith("/api/") && request["method"] in ["GET", "POST"]
    origin:
      action:
        type: proxy
        url: https://test.sbproxy.dev
```

#### Match: requests from a CIDR range

```yaml
forward_rules:
  - match:
      cel: ip.inCIDR(request_ip, "10.0.0.0/8")
    origin:
      action:
        type: proxy
        url: https://test.sbproxy.dev
```

#### Match: authenticated admin users

```yaml
forward_rules:
  - match:
      cel: >
        size(session) > 0 &&
        session["is_authenticated"] == true &&
        size(session["auth"]) > 0 &&
        "admin" in session["auth"]["roles"]
    origin:
      action:
        type: proxy
        url: https://test.sbproxy.dev
```

#### Match: mobile users from Europe

```yaml
forward_rules:
  - match:
      cel: >
        size(client["user_agent"]) > 0 &&
        client["user_agent"]["os_family"] in ["iOS", "Android"] &&
        client["country"] == "EU"
    origin:
      action:
        type: proxy
        url: https://test.sbproxy.dev
```

#### Request modifier: add geo headers

```yaml
request_modifiers:
  cel:
    - expression: >
        {
          "add_headers": {
            "X-Country": size(client) > 0 ? client["country"] : "UNKNOWN",
            "X-Client-IP": request_ip,
            "X-IP-Type": ip.isPrivate(request_ip) ? "private" : "public"
          }
        }
```

#### Request modifier: rewrite path

```yaml
request_modifiers:
  cel:
    - expression: >
        {
          "path": request["path"].startsWith("/old/")
            ? "/new/" + request["path"].substring(5)
            : request["path"]
        }
```

#### Request modifier: add and remove query params

```yaml
request_modifiers:
  cel:
    - expression: >
        {
          "add_query": {"source": "proxy", "version": "v2"},
          "delete_query": ["debug", "internal_id"]
        }
```

#### Response modifier: security headers

```yaml
response_modifiers:
  cel:
    - expression: >
        {
          "add_headers": {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000"
          }
        }
```

#### Response modifier: custom error body

```yaml
response_modifiers:
  cel:
    - expression: >
        response["status"] >= 500
          ? {
              "status": 503,
              "set_headers": {"Content-Type": "application/json"},
              "body": "{\"error\": \"Service temporarily unavailable\"}"
            }
          : {}
```

#### Rate limiting by header value

```yaml
policies:
  - name: premium-rate
    expression: request["headers"]["x-tier"] == "premium"
    rate_limit:
      requests: 10000
      window: "1m"
```

#### Block private IPs from public routes

```yaml
forward_rules:
  - match:
      cel: '!ip.isPrivate(request_ip) && request["path"].startsWith("/public/")'
    origin:
      action:
        type: proxy
        url: https://test.sbproxy.dev
```

#### Traffic splitting by request hash

```yaml
forward_rules:
  - match:
      cel: int(string(request_ip).substring(string(request_ip).length() - 1)) % 2 == 0
    origin:
      action:
        type: proxy
        url: https://test.sbproxy.dev
```

#### Request modifier: add request ID and hash

```yaml
request_modifiers:
  cel:
    - expression: >
        {
          "add_headers": {
            "X-Request-ID": uuid(),
            "X-Path-Hash": sha256(request["path"])
          }
        }
```

#### Request modifier: HMAC signature header

```yaml
request_modifiers:
  cel:
    - expression: >
        {
          "add_headers": {
            "X-Timestamp": string(now()),
            "X-Signature": hmacSHA256(request["path"] + string(now()), "shared-secret")
          }
        }
```

#### JSON modifier: strip sensitive fields

```yaml
response_modifiers:
  cel:
    - expression: >
        {
          "delete_fields": ["password", "ssn", "credit_card"]
        }
```

#### JSON modifier: add computed fields

```yaml
response_modifiers:
  cel:
    - expression: >
        {
          "set_fields": {
            "full_name": json["first_name"] + " " + json["last_name"],
            "is_adult": json["age"] >= 18
          }
        }
```

---

## 4. Lua scripting

Lua gives you a full scripting language: variables, loops, helper functions, conditionals, and string pattern matching. The proxy uses the Luau runtime via `mlua`. Scripts run in a sandboxed VM with a 100ms timeout and a 1,000,000 instruction limit.

### 4.1 Function signature

Lua scripts define a top-level expression or return a value directly. Most scripts use the inline return style, but you can define local functions:

```lua
-- Request matcher: return bool
return request.method == "POST" and ip.is_private(request_ip)
```

```lua
-- Request modifier: return table
local function tier_for_ip(ip_addr)
  if ip.in_cidr(ip_addr, "10.0.1.0/24") then return "admin" end
  if ip.in_cidr(ip_addr, "10.0.0.0/16") then return "user" end
  return "guest"
end

return {
  add_headers = {
    ["X-Access-Level"] = tier_for_ip(request_ip)
  }
}
```

Forward rule matchers using the `lua.script` field must `return` a boolean. Request and response modifiers must return a table.

### 4.2 Context variables

Lua scripts have the same nine namespaces as CEL, accessed via dot or bracket notation.

#### `request` table

```lua
request.method           -- "GET", "POST", etc.
request.path             -- "/api/users"
request.host             -- "example.com"
request.scheme           -- "http" or "https"
request.query            -- raw query string
request.protocol         -- "HTTP/1.1", "HTTP/2.0"
request.headers          -- table, keys are lowercase
request.size             -- Content-Length as number

-- Example access:
request.headers["content-type"]
request.headers["authorization"]
```

#### `request_ip` (string)

The client IP, resolved in this order: `X-Real-IP`, first entry of `X-Forwarded-For`, then `RemoteAddr`.

#### `session` table

```lua
session.id               -- session ID string
session.is_authenticated -- boolean
session.expires          -- expiration time string
session.auth.type        -- "oauth", "jwt", "apikey", etc.
session.auth.email       -- user email (from auth data)
session.auth.name        -- user display name
session.auth.provider    -- OAuth provider name
session.auth.roles       -- array of role strings
session.auth.permissions -- permissions table
session.data             -- custom data from session callbacks
session.visited_count    -- number of URLs visited in this session
session.cookie_count     -- number of cookies
```

#### `origin` table

```lua
origin.id            -- origin UUID
origin.hostname      -- origin hostname
origin.workspace_id  -- workspace UUID
origin.environment   -- "dev", "stage", "prod", etc.
origin.name          -- origin slug name
origin.version       -- config version string
origin.tags          -- array of tag strings
origin.params        -- on_load callback data
```

#### `server` table

```lua
server.version       -- proxy version string
server.hostname      -- OS hostname
server.start_time    -- RFC 3339 start time
server.environment   -- deployment environment
```

#### `vars` table

User-defined variables from `on_load` callbacks or config-level variable definitions.

```lua
vars["my_key"]       -- access by key
vars.my_key          -- dot notation also works
```

#### `features` table

Feature flag values for the workspace.

```lua
features["beta_ui"]
```

#### `client` table

```lua
client.ip                      -- client IP string
client.location.country        -- country name
client.location.country_code   -- ISO country code
client.location.continent      -- continent name
client.location.continent_code -- continent code
client.location.asn            -- ASN string
client.location.as_name        -- AS organization name
client.location.as_domain      -- AS domain
client.user_agent.family        -- browser family
client.user_agent.major         -- browser major version
client.user_agent.os_family     -- OS family
client.user_agent.device_family -- device family
client.user_agent.device_brand  -- device brand
```

> Legacy top-level variables `location` and `user_agent` are also available and mirror `client.location` and `client.user_agent` respectively.

#### `ctx` table

```lua
ctx.id           -- request ID
ctx.cache_status -- cache hit/miss status
ctx.start_time   -- RFC 3339 start time
ctx.data         -- mutable per-request data table
```

#### `response` table (response_modifiers only)

```lua
response.status_code   -- numeric HTTP status code
response.status        -- status text (e.g. "200 OK")
response.headers       -- response headers table
response.body          -- response body string
```

#### `secrets` table

Resolved secrets from the origin's secret store. Available in Lua but not in CEL (by design).

```lua
secrets["api_key"]
secrets["webhook_secret"]
```

#### Cookies and query params

```lua
cookies["session_id"]   -- cookie value by name
params["page"]          -- query parameter value by name
```

### 4.3 Utility functions (`sb` module)

Lua scripts have access to a `sb` global table with helpers for logging, encoding, crypto, UUID, and time.

#### Logging

```lua
sb.log.info("message")
sb.log.warn("message")
sb.log.error("message")
sb.log.debug("message")
sb.log.info("with context", {path = request.path, ip = request_ip})
```

#### Base64

```lua
sb.base64.encode("hello")        -- "aGVsbG8="
sb.base64.decode("aGVsbG8=")     -- "hello"
-- decode returns nil + error on failure
local val, err = sb.base64.decode("bad")
```

#### JSON

```lua
sb.json.encode({name = "alice"})  -- '{"name":"alice"}'
sb.json.decode('{"x":1}')        -- {x = 1}
-- decode returns nil + error on failure
```

#### Crypto

```lua
sb.crypto.sha256("hello")                  -- "2cf24dba..."
sb.crypto.hmac_sha256("data", "secret")    -- "88aab3ed..."
```

#### UUID

```lua
sb.uuid()  -- "550e8400-e29b-41d4-a716-446655440000"
```

#### Time

```lua
sb.time.now()                              -- Unix timestamp (float)
sb.time.unix()                             -- Unix timestamp (integer)
sb.time.format(1712345678, "2006-01-02")   -- "2024-04-05"
sb.time.format("2006-01-02")               -- today's date
sb.time.format()                           -- RFC3339 of current time
```

### 4.4 Request modification

Return a table from a request modifier script. All fields are optional.

```lua
return {
  add_headers    = { ["X-Key"] = "value" },  -- add or append header
  set_headers    = { ["X-Key"] = "value" },  -- replace header
  delete_headers = { "X-Internal", "X-Debug" },
  path           = "/new/path",
  method         = "POST",
  add_query      = { source = "proxy" },
  delete_query   = { "debug" }
}
```

### 4.5 Response modification

```lua
return {
  add_headers    = { ["X-Cache"] = "HIT" },
  set_headers    = { ["Content-Type"] = "application/json" },
  delete_headers = { "X-Powered-By", "Server" },
  status_code    = 200,
  body           = '{"status": "ok"}'
}
```

### 4.6 JSON transformation

When the response is JSON, you can also use:

```lua
return {
  set_fields    = { full_name = "Alice Smith", is_adult = true },
  delete_fields = { "password", "internal_id" },
  modified_json = { replace = "the", whole = "body" }  -- replace entire JSON
}
```

### 4.7 Lua examples

#### Add headers based on GeoIP

```yaml
request_modifiers:
  lua:
    script: |
      return {
        add_headers = {
          ["X-Country"] = client.location.country_code or "UNKNOWN",
          ["X-Continent"] = client.location.continent_code or "UNKNOWN",
          ["X-Client-IP"] = request_ip,
          ["X-IP-Type"] = ip.is_private(request_ip) and "private" or "public"
        }
      }
```

#### Custom authentication check

```yaml
forward_rules:
  - match:
      lua:
        script: |
          local function has_role(roles, role)
            if not roles then return false end
            for i = 1, #roles do
              if roles[i] == role then return true end
            end
            return false
          end

          return session and
                 session.is_authenticated and
                 session.auth and
                 has_role(session.auth.roles, "admin")
    origin:
      action:
        type: proxy
        url: https://test.sbproxy.dev
```

#### Block by multiple CIDRs

```yaml
forward_rules:
  - match:
      lua:
        script: |
          return ip.in_cidr(request_ip, "10.0.0.0/8") or
                 ip.in_cidr(request_ip, "172.16.0.0/12") or
                 ip.in_cidr(request_ip, "192.168.0.0/16")
    origin:
      action:
        type: proxy
        url: https://test.sbproxy.dev
```

#### Path rewriting by version prefix

```yaml
request_modifiers:
  lua:
    script: |
      local path = request.path
      if string.sub(path, 1, 4) == "/v1/" then
        path = "/v2/" .. string.sub(path, 5)
      end
      return {
        path = path,
        set_headers = { ["X-API-Version"] = "v2" }
      }
```

#### Device-based routing

```yaml
request_modifiers:
  lua:
    script: |
      local ua = client.user_agent
      local is_mobile = ua and
        (ua.device_family == "iPhone" or
         ua.os_family == "Android")

      return {
        path = is_mobile and "/mobile" .. request.path or request.path,
        add_headers = {
          ["X-Device-Type"] = is_mobile and "mobile" or "desktop"
        }
      }
```

#### Geo-based content restriction

```yaml
response_modifiers:
  lua:
    script: |
      local code = client.location.country_code
      local allowed = code == "US" or code == "CA" or code == "GB"

      if not allowed then
        return {
          status_code = 451,
          set_headers = { ["Content-Type"] = "application/json" },
          body = '{"error": "Content not available in your region"}'
        }
      end

      return {
        add_headers = {
          ["X-User-Country"] = code or "UNKNOWN"
        }
      }
```

#### HMAC signature verification

```yaml
request_modifiers:
  lua:
    script: |
      local body = request.body or ""
      local sig = request.headers["x-signature"] or ""
      local expected = sb.crypto.hmac_sha256(body, secrets["webhook_secret"])
      if sig ~= expected then
        return {
          set_headers = { ["X-Signature-Valid"] = "false" },
          path = "/error/unauthorized"
        }
      end
      return {
        set_headers = { ["X-Signature-Valid"] = "true" }
      }
```

#### Add request ID and hash headers

```yaml
request_modifiers:
  lua:
    script: |
      return {
        set_headers = {
          ["X-Request-ID"] = sb.uuid(),
          ["X-Path-Hash"] = sb.crypto.sha256(request.path)
        }
      }
```

#### Conditional response body rewrite

```yaml
response_modifiers:
  lua:
    script: |
      local body = response.body
      if response.status_code >= 500 then
        body = '{"error": "Service temporarily unavailable", "code": ' ..
               response.status_code .. '}'
      end
      return {
        body = body,
        add_headers = {
          ["X-Content-Type-Options"] = "nosniff"
        }
      }
```

#### Tiered access by CIDR

```yaml
request_modifiers:
  lua:
    script: |
      local access_level = "guest"
      if ip.in_cidr(request_ip, "10.0.1.0/24") then
        access_level = "admin"
      elseif ip.in_cidr(request_ip, "10.0.0.0/16") then
        access_level = "user"
      end

      return {
        add_headers = { ["X-Access-Level"] = access_level },
        add_query   = { access_level = access_level }
      }
```

---

## 5. JavaScript scripting

JavaScript runs on QuickJS via `rquickjs`. The runtime exposes a V8-compatible API surface for common operations and provides the same context namespaces as Lua.

Scripts must export a default function or return a value from the top-level expression. Request modifiers return an object with the same shape as the Lua table. Response modifiers return an object with the response-modification fields.

```javascript
// Request modifier
export default function (request, ctx) {
  if (request.path.startsWith("/api/")) {
    return {
      add_headers: { "X-API-Hit": "true" },
    };
  }
  return {};
}
```

Globals mirror the Lua context: `request`, `session`, `origin`, `server`, `vars`, `features`, `client`, `ctx`, and (for response modifiers) `response`. Helpers on the `sb` object include `sb.log`, `sb.json`, `sb.base64`, `sb.crypto`, `sb.uuid`, and `sb.time`.

JavaScript runtimes are pooled and reused. The per-execution timeout is 100ms with a memory cap; see `configuration.md` for tunables.

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

## 7. Modification operations reference

CEL, Lua, and JavaScript request/response modifiers all return the same shape. CEL returns a map literal, Lua returns a table, and JavaScript returns an object. WASM is a body transform with a different contract (stdin/stdout) and does not use these fields; see Section 6.

### Request modifications

| Field | Type | Description |
|---|---|---|
| `add_headers` | map | Add or append header values |
| `set_headers` | map | Replace header values |
| `delete_headers` | list | Remove headers by name |
| `path` | string | Override the request path |
| `method` | string | Override the HTTP method |
| `add_query` | map | Add query string parameters |
| `delete_query` | list | Remove query string parameters |

### Response modifications

| Field | Type | Description |
|---|---|---|
| `add_headers` | map | Add or append header values |
| `set_headers` | map | Replace header values |
| `delete_headers` | list | Remove headers by name |
| `status_code` | int | Override the response status code |
| `body` | string | Replace the response body |

### JSON modifications

| Field | Type | Description |
|---|---|---|
| `set_fields` | map | Add or update JSON fields (dot-notation keys supported) |
| `delete_fields` | list | Remove JSON fields by key |
| `modified_json` | map | Replace the entire JSON response body |

---

## 8. AI-specific scripting

In the AI proxy action, CEL expressions control routing and safety at the AI layer. These use a different variable set than standard proxy CEL expressions.

### 8.1 AI CEL selector variables

AI selector expressions (`model_selector`, `provider_selector`, `cache_bypass`, `dynamic_rpm`) receive these variables:

| Variable | Type | Description |
|---|---|---|
| `request["model"]` | string | Requested model name |
| `request["messages"]` | list | List of `{role, content}` message maps |
| `request["temperature"]` | double | Sampling temperature |
| `request["max_tokens"]` | int | Token limit |
| `request["tools"]` | bool | Whether tools/functions are present |
| `request["stream"]` | bool | Whether streaming is requested |
| `headers` | map | HTTP request headers (canonical case) |
| `workspace` | string | Workspace identifier |
| `timestamp["hour"]` | int | Current hour (0-23) |
| `timestamp["minute"]` | int | Current minute (0-59) |
| `timestamp["day_of_week"]` | string | e.g. `"Monday"` |
| `timestamp["date"]` | string | e.g. `"2024-01-15"` |

### 8.2 CEL model selectors

`model_selector` returns a model name string that overrides the model in the request. Return an empty string to use the default.

```yaml
action:
  type: ai_proxy
  routing:
    model_selector: >
      request["headers"]["X-Tier"] == "premium"
        ? "gpt-4o"
        : "gpt-4o-mini"
```

```yaml
# Route by requested model token budget
routing:
  model_selector: >
    request["max_tokens"] > 8000
      ? "gpt-4o"
      : "gpt-4o-mini"
```

```yaml
# Time-based routing (off-peak uses larger model)
routing:
  model_selector: >
    timestamp["hour"] >= 22 || timestamp["hour"] < 6
      ? "gpt-4o"
      : "gpt-4o-mini"
```

```yaml
# Route by request header tag
routing:
  model_selector: >
    request["headers"]["x-plan"] == "pro"
      ? "claude-sonnet-4-20250514"
      : "claude-3-5-haiku-20241022"
```

### 8.3 CEL provider selectors

`provider_selector` returns a provider name string. Return empty to fall back to normal cost-based routing.

```yaml
routing:
  provider_selector: >
    request["model"].startsWith("gpt-")
      ? "openai"
      : "anthropic"
```

### 8.4 Cache bypass

`cache_bypass` returns a bool. When true, the response cache is skipped for this request.

```yaml
routing:
  cache_bypass: >
    request["temperature"] > 0.5 ||
    "no-cache" in request["headers"]
```

### 8.5 Dynamic RPM

`dynamic_rpm` returns an int that overrides the per-model rate limit for this request.

```yaml
routing:
  dynamic_rpm: >
    request["headers"]["x-tier"] == "premium" ? 1000 : 100
```

### 8.6 CEL guardrails

Guardrails are CEL expressions evaluated before (input phase) or after (output phase) the provider call. A condition returning `true` means the rule triggered.

Input guardrail variables:

| Variable | Type | Description |
|---|---|---|
| `request["model"]` | string | Model name |
| `request["messages"]` | list | Message list (`{role, content}`) |
| `request["temperature"]` | double | Temperature |
| `request["max_tokens"]` | int | Token limit |

Output guardrail variables:

| Variable | Type | Description |
|---|---|---|
| `response["content"]` | string | First choice message content |
| `response["model"]` | string | Model used |
| `response["finish_reason"]` | string | Stop reason |
| `response["tokens_input"]` | int | Prompt token count |
| `response["tokens_output"]` | int | Completion token count |

```yaml
action:
  type: ai_proxy
  cel_guardrails:
    - name: block-jailbreak
      phase: input
      condition: >
        request["messages"].exists(m,
          m["content"].contains("ignore previous instructions") ||
          m["content"].contains("jailbreak")
        )
      action: block
      message: "Request blocked by content policy."

    - name: flag-long-output
      phase: output
      condition: response["tokens_output"] > 4000
      action: flag

    - name: block-ssn-in-response
      phase: output
      condition: >
        response["content"].matches("\\b\\d{3}-\\d{2}-\\d{4}\\b")
      action: block
      message: "Response blocked: contains sensitive data pattern."
```

Actions:
- `block`. Reject the request (input) or suppress the response (output) and return the `message` as an error.
- `flag`. Record the violation in audit logs. Does not stop the request.

Guardrails are evaluated in order. The first `block` action wins and evaluation stops. All `flag` actions are recorded.

---

## 9. IP function reference

CEL and Lua share the same IP functions, with different naming conventions.

| CEL | Lua | Description |
|---|---|---|
| `ip.parse(ip)` | `ip.parse(ip)` | Parse IP, returns info map/table |
| `ip.inCIDR(ip, cidr)` | `ip.in_cidr(ip, cidr)` | True if IP is in CIDR range |
| `ip.isPrivate(ip)` | `ip.is_private(ip)` | True if IP is private (RFC 1918, loopback, link-local) |
| `ip.isLoopback(ip)` | `ip.is_loopback(ip)` | True if IP is loopback |
| `ip.isIPv4(ip)` | `ip.is_ipv4(ip)` | True if IP is IPv4 |
| `ip.isIPv6(ip)` | `ip.is_ipv6(ip)` | True if IP is IPv6 |
| `ip.inRange(ip, start, end)` | `ip.in_range(ip, start, end)` | True if IP is between start and end (inclusive) |
| `ip.compare(ip1, ip2)` | `ip.compare(ip1, ip2)` | -1, 0, or 1 |

`ip.parse()` returns a map/table with these fields:

```
valid        bool   - whether the string was a valid IP
ip           string - normalized IP string
is_ipv4      bool
is_ipv6      bool
is_private   bool
is_loopback  bool
```

Private ranges covered by `isPrivate`/`is_private`:
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `169.254.0.0/16` (link-local)
- `127.0.0.0/8` (loopback)
- `fc00::/7` (IPv6 ULA)
- `fe80::/10` (IPv6 link-local)

---

## 10. Sandbox limits

### CEL

- Non-Turing-complete: no loops, no side effects, no I/O.
- Expressions compile once at config load time. Syntax errors fail fast.
- No access to secrets (intentionally). Use Lua, JavaScript, or WASM if you need `secrets["key"]`.
- Evaluation typically completes in microseconds.

### Lua

- No file I/O (`io` module blocked).
- No OS operations (`os` module blocked).
- No package loading (`require`, `dofile`, `loadfile` blocked).
- No debug access (`debug` module blocked).
- No meta-operations (`getmetatable`, `setmetatable`, `rawset`, `rawget` blocked).
- No network operations.
- Global variable modification is blocked.

Available Lua standard library functions:
- `string.*`. Full string library (find, match, gmatch, gsub, sub, upper, lower, format, etc.)
- `table.*`. insert, remove, sort, concat
- `math.*`. abs, ceil, floor, max, min, sqrt, random, etc.
- `tonumber`, `tostring`, `type`, `pairs`, `ipairs`, `unpack`, `select`, `pcall`, `error`

Execution limits:
- Timeout: 100ms per script execution.
- Instruction limit: 1,000,000 instructions. Stops infinite loops without depending on timers.
- Call stack: 1,000 levels maximum.

### JavaScript

- Sandboxed QuickJS runtime; no `eval` of untrusted strings outside the sandbox.
- No filesystem, no `require()` to arbitrary modules.
- 100ms timeout per execution and a per-runtime memory cap.

### WASM

- Wasmtime sandbox running WASI preview-1. No network, no filesystem, no environment variables, no host clock beyond the epoch-interruption deadline.
- Per-request `Store` so module state never leaks between requests; the compiled `Module` is shared across calls so per-invocation cost is one instantiate plus one `_start`.
- `timeout_ms` is enforced via epoch interruption; `max_memory_pages` caps linear memory.

---

## 11. Performance notes

CEL compiles at config load time and evaluates in microseconds per request. It fits any routing decision, including high-frequency hot paths. Prefer CEL over Lua, JavaScript, or WASM when the logic fits.

Lua runs interpreted per-request from a pooled VM. Simple scripts complete in tens of microseconds. VMs are reused to amortize initialization cost.

JavaScript uses pooled QuickJS runtimes. Slightly higher overhead than Lua for short scripts, but ergonomic for JS-savvy teams.

WASM has a one-time compilation cost; subsequent invocations run at near-native speed inside the Wasmtime sandbox.

Tips:
- Avoid regex in CEL hot paths (`matches()`). Use `startsWith`, `endsWith`, or `contains` instead.
- In Lua, use `local` variables. Local variable access is faster than global lookup.
- In Lua, prefer `table.concat()` over string concatenation in loops.
- Keep scripts under ~30 lines. If you need more, consider whether a config-level callback fits better.
- CEL expressions that always return the same result regardless of request data should be replaced with static config values.

---

## 12. Debugging scripts

### Config validation

Validate your config and catch CEL compilation errors before deployment:

```bash
sbproxy validate -c sb.yml
```

CEL expressions compile at validation time. Any syntax error or type mismatch is reported with the field name and expression.

### Enabling debug logging

```bash
sbproxy --log-level debug -c sb.yml
```

With debug logging on:
- CEL evaluation results are logged per request.
- Lua and JavaScript script execution times are logged.
- Lua, JavaScript, and WASM runtime errors include the script name, error message, and stack trace.

### Error behavior

| Engine | Compile error | Runtime error |
|---|---|---|
| CEL | Config load fails immediately | Logged, expression returns zero value |
| Lua | Config load fails immediately | Logged per-request, script returns false/nil |
| JavaScript | Config load fails immediately | Logged per-request, script returns undefined |
| WASM | Config load fails immediately | Logged per-request, modifier is skipped |

### Common mistakes

CEL header key case. Headers are normalized to lowercase. Use `request["headers"]["content-type"]`, not `request["headers"]["Content-Type"]`.

CEL nil map access. Accessing a missing key in a CEL map returns a zero value (empty string, 0, false), not an error. Check `size(session) > 0` before reading session fields when session middleware may not be active.

Lua array indexing is 1-based. `arr[1]` is the first element. `#arr` is the length.

Lua nil context variables. Context tables like `client.user_agent` and `client.location` may be empty tables when the corresponding middleware is off. Check `client.location.country_code ~= nil` or use `or "UNKNOWN"` as a default.

Lua inequality operator. Lua uses `~=` for not-equal, not `!=`.

CEL: AI selector vs proxy CEL. AI routing selectors (`model_selector`, `provider_selector`, etc.) and guardrail expressions use a different set of variables than standard proxy CEL expressions. The `request` variable in selectors refers to the AI chat completion request, not the HTTP request.

## See also

- [configuration.md](configuration.md) - general configuration model and the full `sb.yml` field reference.
- [features.md](features.md) - higher-level feature overview.
- [ai-gateway.md](ai-gateway.md) - AI gateway routing and guardrails.
