# Scripting Guide: CEL and Lua

sbproxy supports two scripting languages for custom logic: CEL (Common Expression Language) and Lua. Both run in sandboxed environments with access to request context, and both can be used for matching requests, modifying requests, and modifying responses.

Choose CEL for simple one-liner expressions. Choose Lua when you need variables, loops, or multi-step logic.

## Where Scripts Are Used

Scripts appear in several places in your config:

| Location | Purpose | Return type |
|----------|---------|-------------|
| `forward_rules[].match.cel` | Route matching | boolean |
| `forward_rules[].match.lua` | Route matching | boolean |
| `request_modifiers.cel` | Modify requests | map |
| `request_modifiers.lua` | Modify requests | table |
| `response_modifiers.cel` | Modify responses | map |
| `response_modifiers.lua` | Modify responses | table |
| `routing.model_selector` | AI model override | string |
| `routing.provider_selector` | AI provider override | string |
| `routing.cache_bypass` | Skip cache | boolean |
| `routing.dynamic_rpm` | Override rate limit | int |

## Context Variables

Both CEL and Lua have access to the same context variables:

| Variable | Type | Description |
|----------|------|-------------|
| `request.method` | string | HTTP method (GET, POST, etc.) |
| `request.path` | string | URL path |
| `request.host` | string | Host header |
| `request.scheme` | string | http or https |
| `request.query` | string | Raw query string |
| `request.headers` | map | Request headers (lowercase keys) |
| `request.size` | int | Content-Length |
| `request_ip` | string | Client IP address |
| `params` | map | Parsed query parameters |
| `cookies` | map | Parsed cookies |
| `user_agent` | map | Parsed user agent (family, os_family, device_family, etc.) |
| `location` | map | GeoIP data (country_code, continent_code, asn, etc.) |
| `fingerprint` | map | Client fingerprint (hash, cookie_count, etc.) |
| `session` | map | Session data (is_authenticated, auth.email, auth.roles, etc.) |

In response modifiers, you also have:

| Variable | Type | Description |
|----------|------|-------------|
| `response.status_code` | int | Response status |
| `response.body` | string | Response body |
| `response.headers` | map | Response headers |

Context variables like `user_agent`, `location`, `fingerprint`, and `session` may be empty. Always check before accessing.

---

## CEL Examples

### Match: API traffic only

```yaml
forward_rules:
  - match:
      cel: request.path.startsWith('/api/') && request.method in ['GET', 'POST']
    origin:
      action:
        type: proxy
        url: https://api-backend.example.com
```

### Match: Authenticated admin users

```yaml
forward_rules:
  - match:
      cel: >
        size(session) > 0 &&
        session['is_authenticated'] == true &&
        size(session['auth']) > 0 &&
        'admin' in session['auth']['roles']
    origin:
      action:
        type: proxy
        url: https://admin-backend.example.com
```

### Match: Requests from a CIDR range

```yaml
forward_rules:
  - match:
      cel: ip.inCIDR(request_ip, "10.0.0.0/8")
    origin:
      action:
        type: proxy
        url: https://internal-backend.example.com
```

### Match: Mobile users from Europe

```yaml
forward_rules:
  - match:
      cel: >
        size(user_agent) > 0 &&
        user_agent['os_family'] in ['iOS', 'Android'] &&
        size(location) > 0 &&
        location['continent_code'] == 'EU'
    origin:
      action:
        type: proxy
        url: https://eu-mobile.example.com
```

### Modify request: Add geo headers

```yaml
request_modifiers:
  cel:
    - expression: >
        {
          "add_headers": {
            "X-Country": size(location) > 0 ? location['country_code'] : "UNKNOWN",
            "X-Client-IP": request_ip,
            "X-IP-Type": ip.isPrivate(request_ip) ? "private" : "public"
          }
        }
```

### Modify request: Rewrite path

```yaml
request_modifiers:
  cel:
    - expression: >
        {
          "path": request.path.startsWith('/old/')
            ? '/new/' + request.path.substring(5)
            : request.path
        }
```

### Modify request: Strip and add query params

```yaml
request_modifiers:
  cel:
    - expression: >
        {
          "add_query": {"source": "proxy", "version": "v2"},
          "delete_query": ["debug", "internal_id"]
        }
```

### Modify response: Security headers

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

### Modify response: CORS headers

```yaml
response_modifiers:
  cel:
    - expression: >
        {
          "set_headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
          }
        }
```

### Modify response: Custom error body

```yaml
response_modifiers:
  cel:
    - expression: >
        response.status_code >= 500
          ? {
              "status_code": 503,
              "set_headers": {"Content-Type": "application/json"},
              "body": "{\"error\": \"Service temporarily unavailable\"}"
            }
          : {}
```

### JSON modifier: Strip sensitive fields

```yaml
response_modifiers:
  cel:
    - expression: >
        {
          "delete_fields": ["password", "ssn", "credit_card"]
        }
```

### JSON modifier: Add computed fields

```yaml
response_modifiers:
  cel:
    - expression: >
        {
          "set_fields": {
            "full_name": json.first_name + " " + json.last_name,
            "is_adult": json.age >= 18
          }
        }
```

---

## Lua Examples

### Match: API traffic only

```yaml
forward_rules:
  - match:
      lua:
        script: |
          return string.find(request.path, "^/api/") ~= nil and
                 (request.method == "GET" or request.method == "POST")
    origin:
      action:
        type: proxy
        url: https://api-backend.example.com
```

### Match: Admin role check with helper function

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
        url: https://admin-backend.example.com
```

### Match: CIDR range with multiple subnets

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
        url: https://internal.example.com
```

### Modify request: Tiered access control

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
        add_headers = {
          ["X-Access-Level"] = access_level
        },
        add_query = {
          access_level = access_level
        }
      }
```

### Modify request: Device-based routing

```yaml
request_modifiers:
  lua:
    script: |
      local is_mobile = user_agent and
        (user_agent.device_family == "iPhone" or
         user_agent.device_family == "Android")

      return {
        path = is_mobile and "/mobile" .. request.path or request.path,
        add_headers = {
          ["X-Device-Type"] = is_mobile and "mobile" or "desktop",
          ["X-Country"] = location.country_code or "UNKNOWN",
          ["X-Browser"] = user_agent and user_agent.family or "UNKNOWN"
        }
      }
```

### Modify request: Path rewriting

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
        set_headers = {
          ["X-API-Version"] = "v2"
        }
      }
```

### Modify response: Geo-based content restriction

```yaml
response_modifiers:
  lua:
    script: |
      local allowed = location.country_code == "US" or
                      location.country_code == "CA" or
                      location.country_code == "GB"

      if not allowed then
        return {
          status_code = 451,
          set_headers = {
            ["Content-Type"] = "application/json"
          },
          body = '{"error": "Content not available in your region"}'
        }
      end

      return {
        add_headers = {
          ["X-User-Country"] = location.country_code or "UNKNOWN",
          ["X-Content-Region"] = location.continent_code == "EU" and "EU" or "US"
        }
      }
```

### Modify response: Security headers

```yaml
response_modifiers:
  lua:
    script: |
      return {
        add_headers = {
          ["X-Content-Type-Options"] = "nosniff",
          ["X-Frame-Options"] = "DENY",
          ["X-XSS-Protection"] = "1; mode=block",
          ["Strict-Transport-Security"] = "max-age=31536000"
        },
        delete_headers = {"X-Powered-By", "Server"}
      }
```

---

## IP Functions

Both CEL and Lua include built-in IP functions:

| CEL | Lua | Description |
|-----|-----|-------------|
| `ip.parse(ip)` | `ip.parse(ip)` | Parse IP, returns info map/table |
| `ip.inCIDR(ip, cidr)` | `ip.in_cidr(ip, cidr)` | Check if IP is in CIDR range |
| `ip.isPrivate(ip)` | `ip.is_private(ip)` | Check if IP is private |
| `ip.isLoopback(ip)` | `ip.is_loopback(ip)` | Check if IP is loopback |
| `ip.isIPv4(ip)` | `ip.is_ipv4(ip)` | Check if IP is IPv4 |
| `ip.isIPv6(ip)` | `ip.is_ipv6(ip)` | Check if IP is IPv6 |
| `ip.inRange(ip, start, end)` | `ip.in_range(ip, start, end)` | Check if IP is in range |
| `ip.compare(ip1, ip2)` | `ip.compare(ip1, ip2)` | Compare two IPs (-1, 0, 1) |

Note: CEL uses camelCase (`inCIDR`, `isPrivate`). Lua uses snake_case (`in_cidr`, `is_private`).

## Modification Operations Reference

Both CEL and Lua support the same modification operations. CEL returns a map, Lua returns a table.

### Request modifications

| Field | Type | Description |
|-------|------|-------------|
| `add_headers` | map | Add or append headers |
| `set_headers` | map | Replace headers |
| `delete_headers` | list | Remove headers |
| `path` | string | Override request path |
| `method` | string | Override HTTP method |
| `add_query` | map | Add query parameters |
| `delete_query` | list | Remove query parameters |

### Response modifications

| Field | Type | Description |
|-------|------|-------------|
| `add_headers` | map | Add or append headers |
| `set_headers` | map | Replace headers |
| `delete_headers` | list | Remove headers |
| `status_code` | int | Override status code |
| `body` | string | Override response body |

### JSON modifications

| Field | Type | Description |
|-------|------|-------------|
| `set_fields` | map | Add or update JSON fields |
| `delete_fields` | list | Remove JSON fields |
| `modified_json` | map | Replace entire JSON object |

## Sandbox Limits

Both languages run in a restricted sandbox:

- **CEL**: Non-Turing complete by design. No loops, no side effects, no I/O.
- **Lua**: Sandboxed with a 100ms default timeout. No file I/O, no OS calls, no `require`, no `debug`, no metatable access. Only `string`, `table`, and `math` standard libraries are available.

## Tips

- Always check context variables before use. CEL: `size(user_agent) > 0`. Lua: `if user_agent then`.
- Provide defaults. CEL: `location['country_code'] : "UNKNOWN"`. Lua: `location.country_code or "UNKNOWN"`.
- Keep scripts short. If your logic is more than ~20 lines, consider whether it belongs in a forward rule chain instead.
- CEL expressions are compiled once at config load time. Lua scripts are cached after first execution.
- Test scripts by running `sbproxy validate -c sb.yml` before deploying.
