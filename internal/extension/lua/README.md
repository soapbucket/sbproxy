# Lua Scripting Package

This package provides Lua scripting capabilities for HTTP request matching, request modification, response modification, JSON modification, and HTML token matching.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Context Variables](#context-variables)
- [IP Functions](#ip-functions)
- [Usage Examples](#usage-examples)
- [Security](#security)
- [Performance](#performance)
- [Testing](#testing)
- [Best Practices](#best-practices)
- [Additional Resources](#additional-resources)

## Overview

The Lua package allows you to write dynamic scripts that can:
- **Match** HTTP requests based on various criteria
- **Modify** HTTP requests (headers, path, method, query parameters)
- **Modify** HTTP responses (headers, status code, body)
- **Modify** JSON objects
- **Match** HTML tokens for parsing and manipulation

**Key Features:**
- ✅ Rich context variables (IP, user agent, geolocation, session)
- ✅ IP address manipulation functions (CIDR, private/public, IPv4/IPv6)
- ✅ Sandboxed execution for security
- ✅ High performance (sub-100μs for simple scripts)
- ✅ Comprehensive test coverage

## Quick Start

### Request Matcher

```lua
-- Match requests from private IPs
return ip.is_private(request_ip)
```

### Request Modifier

```lua
-- Add tracking headers
return {
  add_headers = {
    ["X-Client-IP"] = request_ip,
    ["X-Country"] = location and location.country_code or "UNKNOWN"
  }
}
```

### Response Modifier

```lua
-- Add security headers
return {
  add_headers = {
    ["X-Content-Type-Options"] = "nosniff",
    ["X-Frame-Options"] = "DENY"
  }
}
```

## Context Variables

Lua scripts have access to rich context variables extracted from HTTP requests:

### Request Context (`request`)
- `request.method` - HTTP method (GET, POST, etc.)
- `request.path` - URL path
- `request.host` - Host header value
- `request.scheme` - URL scheme (http, https)
- `request.query` - URL-encoded query string
- `request.protocol` - HTTP protocol version
- `request.headers` - HTTP headers table (keys are lowercase)
- `request.size` - Content-Length of request body

### Request IP (`request_ip`)
The client's IP address extracted from the request (string):
- Checks `X-Real-IP` header first
- Falls back to first IP in `X-Forwarded-For` header
- Falls back to `RemoteAddr` if headers not present

### Cookies (`cookies`)
Table of cookie names to values

### Query Parameters (`params`)
Table of query parameter names to values

### User Agent (`user_agent`)
Parsed user agent information (table, may be nil):
- `user_agent.family` - Browser family (e.g., "Chrome", "Firefox")
- `user_agent.major` - Browser major version
- `user_agent.minor` - Browser minor version
- `user_agent.patch` - Browser patch version
- `user_agent.os_family` - OS family (e.g., "Windows", "Mac OS X")
- `user_agent.os_major` - OS major version
- `user_agent.os_minor` - OS minor version
- `user_agent.os_patch` - OS patch version
- `user_agent.os_patch_minor` - OS patch minor version
- `user_agent.device_family` - Device family (e.g., "iPhone", "Samsung")
- `user_agent.device_brand` - Device brand
- `user_agent.device_model` - Device model

### Location (`location` / `client.location`)
Location and ASN information (table, may be nil). Available as `location` in legacy scripts or `client.location` in the current `client` namespace:
- `location.country` - Country name
- `location.country_code` - ISO country code (e.g., "US", "GB")
- `location.continent` - Continent name
- `location.continent_code` - Continent code (e.g., "NA", "EU")
- `location.asn` - Autonomous System Number
- `location.as_name` - AS organization name
- `location.as_domain` - AS domain

**Note**: Location data is populated by enterprise enrichers registered via the `plugin.RequestEnricher` interface. The data may be nil if no location enricher is registered.

### Session (`session`)
Session data if available (table, may be nil):
- `session.id` - Session ID
- `session.expires` - Session expiration time
- `session.is_authenticated` - Boolean indicating if user is authenticated
- `session.auth` - Authentication data table (if authenticated, may be nil)
  - `session.auth.type` - Authentication type (e.g., "oauth", "jwt", "apikey")
  - `session.auth.data` - Nested auth data table (contains all auth data fields)
  - `session.auth.id` - User ID (from auth data, also in `data`)
  - `session.auth.email` - User email address (from auth data, also in `data`)
  - `session.auth.name` - User display name (from auth data, also in `data`)
  - `session.auth.provider` - OAuth provider (from auth data, also in `data`, e.g., "google", "github")
  - `session.auth.roles` - Array of roles (from auth data, also in `data`)
  - `session.auth.permissions` - Permissions table (from auth data, also in `data`)
  - All other fields from `AuthData.Data` are accessible both via `session.auth.data` and directly under `session.auth`
- `session.data` - Custom session data (set by session callbacks)
- `session.visited_count` - Number of URLs visited in session
- `session.cookie_count` - Number of cookies in session

**Note**: `session.auth` is set by authentication middleware (OAuth, JWT, etc.) and contains user identity, roles, and permissions. `session.data` is set by session callbacks and contains custom session-specific data.

### Data Sources Overview

There are **4 persistent data objects** available in Lua scripts, each serving a different purpose:

1. **`config`** - Immutable configuration data from `on_load` callback
2. **`request_data`** - General request data from callbacks (excluding `on_load` and session/auth callbacks)
3. **`session.data`** - Session-specific data from session callbacks
4. **`session.auth.data`** - Authentication data from authentication callbacks

### Config (`config`)

Immutable configuration data from `on_load` callback stored in `RequestData.Config`:
- `config` - Table containing configuration data from `on_load` callback
- Separate from other data sources to ensure immutability
- Set once during config initialization and never changes

**Set by**: `on_load` callback executed during config initialization
**When available**: After config initialization (before any request processing)
**Storage**: `RequestData.Config` (internal)
**Example**: `config.api_key` - Access API key from `on_load` callback

### Request Data (`request_data`)

General request data from callbacks (excluding `on_load`, session, and auth callbacks):
- `request_data` - Table containing callback data
- Used for general-purpose data that doesn't belong in session or auth
- Keys depend on which callbacks have executed

**Set by**: Callbacks (excluding `on_load`, `session_config.callbacks`, and `authentication_callback`)
**When available**: After callback execution (varies by callback type)
**Storage**: `RequestData.Data` (internal)
**Example**: `request_data.feature_flags.beta` - Access feature flags from callback

**Note**: This is for general request data. Session-specific data should use `session.data`, and authentication data should use `session.auth.data`.

### Session Data (`session.data`)

Session-specific data from session callbacks stored in `SessionData.Data`:
- `session.data` - Table containing custom session data
- Persists across requests within the same session
- Set by callbacks configured in `session_config.callbacks`

**Set by**: Session callbacks (configured in `session_config.callbacks`)
**When available**: After session callback execution (on first request or session refresh)
**Storage**: `SessionData.Data` (internal)
**Example**: `session.data.user_prefs.theme` - Access user preferences from session callback

**Note**: Session callbacks store data in `SessionData.Data`, not `RequestData.Data`. Use `session.data` to access this data.

### Auth Data (`session.auth.data`)

Authentication data from authentication callbacks stored in `AuthData.Data`:
- `session.auth.data` - Table containing authentication data (user identity, roles, permissions)
- Also accessible directly via `session.auth.user_id`, `session.auth.roles`, etc.
- Set by authentication middleware (OAuth, JWT, API Key with `authentication_callback`, etc.)

**Set by**: Authentication callbacks (e.g., `authentication_callback` in API Key auth, OAuth, JWT)
**When available**: After successful authentication
**Storage**: `AuthData.Data` (internal, stored in `SessionData.AuthData.Data`)
**Example**: `session.auth.data.user_id` or `session.auth.user_id` - Access user ID from auth callback

**Note**: Authentication data is stored in `AuthData.Data` and is accessible via `session.auth`. All fields from `AuthData.Data` are also directly accessible under `session.auth` for convenience.

## IP Functions

The `ip` table provides IP address manipulation functions:

### `ip.parse(ip_string)`
Parses an IP address and returns information table:
```lua
local info = ip.parse("192.168.1.1")
-- info.valid (boolean)
-- info.ip (string)
-- info.is_ipv4 (boolean)
-- info.is_ipv6 (boolean)
-- info.is_private (boolean)
-- info.is_loopback (boolean)
```

### `ip.in_cidr(ip, cidr)`
Checks if IP is within CIDR range:
```lua
if ip.in_cidr("192.168.1.100", "192.168.1.0/24") then
  -- IP is in range
end
```

### `ip.is_private(ip)`
Checks if IP is in private range:
```lua
if ip.is_private("192.168.1.1") then
  -- Private IP
end
```

### `ip.is_loopback(ip)`
Checks if IP is loopback:
```lua
if ip.is_loopback("127.0.0.1") then
  -- Loopback
end
```

### `ip.is_ipv4(ip)` / `ip.is_ipv6(ip)`
Check IP version:
```lua
if ip.is_ipv4("192.168.1.1") then
  -- IPv4
end
```

### `ip.in_range(ip, start, end)`
Check if IP is in range (inclusive):
```lua
if ip.in_range("192.168.1.100", "192.168.1.1", "192.168.1.255") then
  -- In range
end
```

### `ip.compare(ip1, ip2)`
Compare two IPs (returns -1, 0, or 1):
```lua
local cmp = ip.compare("192.168.1.1", "192.168.1.2")
-- cmp < 0 (first is less)
```

## Utility Functions (`sb` module)

The `sb` global table provides utility functions for logging, encoding, crypto, UUID, and time.

### Logging (`sb.log`)

Structured logging that outputs to the proxy's log stream with `[lua]` prefix:

```lua
sb.log.info("request processed")
sb.log.warn("rate limit approaching")
sb.log.error("upstream failed")
sb.log.debug("cache miss for key")

-- With structured attributes (pass a table as second argument)
sb.log.info("request handled", {path = req.path, status = 200})
```

### Base64 (`sb.base64`)

```lua
-- Encode
sb.base64.encode("hello")       -- "aGVsbG8="

-- Decode (returns nil + error on failure)
sb.base64.decode("aGVsbG8=")    -- "hello"
local val, err = sb.base64.decode("invalid!")
if not val then
  sb.log.error("decode failed: " .. err)
end
```

### JSON (`sb.json`)

```lua
-- Encode a table to JSON
sb.json.encode({name = "alice", age = 30})  -- '{"age":30,"name":"alice"}'
sb.json.encode({1, 2, 3})                   -- '[1,2,3]'

-- Decode JSON to a table (returns nil + error on failure)
local data = sb.json.decode('{"name":"bob"}')
-- data.name == "bob"

local val, err = sb.json.decode("not json")
if not val then
  sb.log.error("parse failed: " .. err)
end
```

### Crypto (`sb.crypto`)

```lua
-- SHA-256 hex digest
sb.crypto.sha256("hello")
-- "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

-- HMAC-SHA256 hex digest
sb.crypto.hmac_sha256("hello", "secret")
-- "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"
```

### UUID (`sb.uuid`)

```lua
local id = sb.uuid()  -- "550e8400-e29b-41d4-a716-446655440000"
```

### Time (`sb.time`)

```lua
-- Current Unix timestamp (float, seconds with sub-second precision)
sb.time.now()        -- 1712345678.123

-- Current Unix timestamp (integer, seconds)
sb.time.unix()       -- 1712345678

-- Format a Unix timestamp using Go layout strings
sb.time.format(1712345678, "2006-01-02")  -- "2024-04-05"
sb.time.format(1712345678, "2006-01-02T15:04:05Z07:00")  -- RFC3339

-- Format current time
sb.time.format("2006-01-02")  -- today's date

-- No arguments: RFC3339 of current time
sb.time.format()  -- "2026-04-11T20:35:00Z"
```

## Usage Examples

### Request Matching

```lua
-- Match by method
return request.method == "POST"

-- Match by path
return string.sub(request.path, 1, 5) == "/api/"

-- Match by IP
return ip.is_private(request_ip)

-- Match by user agent
return user_agent and user_agent.family == "Chrome"

-- Match by country
return location.country_code == "US"

-- Complex matching
return request.method == "POST" and
       ip.in_cidr(request_ip, "10.0.0.0/8") and
       user_agent and user_agent.os_family == "Windows"
```

### Response Matching

Response matching allows you to evaluate HTTP responses based on status code, headers, body content, and request context. The script must return a boolean value.

Available response variables:
- `response.status_code` - HTTP status code (number)
- `response.status` - HTTP status text (e.g., "200 OK")
- `response.headers` - Response headers table (keys are case-sensitive)
- `response.body` - Response body as string
- `request` - Original request context (all fields available)
- All request context variables (`request_ip`, `cookies`, `params`, `user_agent`, `location`, `session`)

```lua
-- Match specific status code
return response.status_code == 200

-- Match status code range (2xx success)
return response.status_code >= 200 and response.status_code < 300

-- Match 4xx client errors
return response.status_code >= 400 and response.status_code < 500

-- Match 5xx server errors
return response.status_code >= 500

-- Match with conditional
if response.status_code >= 500 then
  return true
end
return false

-- Match specific content type
return response.headers["Content-Type"]:find("application/json") ~= nil

-- Match body content
return response.body:find("error") ~= nil

-- Combined status and body check
return response.status_code == 200 and response.body:find("success") ~= nil

-- Match JSON error responses
return response.status_code >= 400 and 
       response.headers["Content-Type"]:find("json") ~= nil and 
       response.body:find("error") ~= nil

-- Match errors from specific endpoints
return response.status_code == 404 and request.path:sub(1, 5) == "/api/"

-- Match errors for POST requests only
return response.status_code >= 400 and request.method == "POST"

-- Match successful responses from specific countries
if response.status_code == 200 and location.country_code == "US" then
  return true
end
return false

-- Match empty responses (204 No Content)
return response.status_code == 204 and response.body == ""

-- Complex conditional logic
if response.status_code == 200 then
  if response.body:find("success") then
    return true
  end
elseif response.status_code == 201 then
  return true
end
return false
```

### Request Modification

```lua
-- Add headers
return {
  add_headers = {
    ["X-Client-IP"] = request_ip,
    ["X-IP-Type"] = ip.is_private(request_ip) and "private" or "public"
  }
}

-- Modify path based on IP
return {
  path = ip.is_private(request_ip) and "/internal" .. request.path or request.path,
  add_headers = {
    ["X-Internal"] = ip.is_private(request_ip) and "true" or "false"
  }
}

-- Add tracking headers
return {
  add_headers = {
    ["X-Country"] = location.country_code or "UNKNOWN",
    ["X-Browser"] = user_agent and user_agent.family or "UNKNOWN",
    ["X-Device"] = user_agent and user_agent.device_family or "UNKNOWN"
  }
}
```

### Response Modification

```lua
-- Add response headers based on request context
return {
  add_headers = {
    ["X-Request-IP"] = request_ip,
    ["X-Request-Country"] = location and location.country_code or "UNKNOWN"
  }
}

-- Modify status code based on IP
return {
  status_code = ip.in_cidr(request_ip, "10.0.0.0/8") and 200 or 403
}
```

## Security

### Sandbox Protection

The Lua sandbox provides a secure execution environment with:
- ✅ Access to safe string, math, and table functions
- ✅ IP manipulation functions
- ✅ Read-only access to context variables
- ✅ Execution timeout protection (default 100ms)
- ✅ Instruction limit protection (1,000,000 instructions max)
- ✅ Call stack limit (1000 levels)

Blocked for security:
- ❌ File I/O (`io`, `os` modules)
- ❌ Network operations
- ❌ Package loading (`require`, `dofile`, `loadfile`)
- ❌ Debug functions (`debug` module)
- ❌ Dangerous meta-operations (`setmetatable`, `rawset`, `rawget`, etc.)
- ❌ Global variable modification

### Execution Limits

- **Timeout**: 100ms default (configurable per script)
- **Instructions**: 1,000,000 instruction limit to prevent infinite loops
- **Call Stack**: 1,000 levels maximum
- **Context Cancellation**: Script execution respects Go context cancellation

## Performance

### Benchmark Results

Performance benchmarks on Apple M4 Max (arm64):

| Operation | Time per Op | Allocations |
|-----------|-------------|-------------|
| Simple Matcher | ~64μs | 995 allocs |
| Path Match | ~67μs | 995 allocs |
| Header Match | ~66μs | 995 allocs |
| IP Functions | ~64μs | 995 allocs |
| Complex Expression | ~71μs | 995 allocs |
| Matcher Compilation | ~66μs | 995 allocs |
| Memory Usage | ~233 KB/op | - |

**Key Takeaways:**
- Most operations complete in under 100μs
- Consistent allocation pattern (~995 allocs per operation)
- Low memory footprint (~233 KB per operation)
- IP functions add minimal overhead

### Optimization Tips

1. **Reuse Matchers/Modifiers**: Create once, use many times
2. **Minimize String Operations**: String concatenation is expensive
3. **Avoid Deep Nesting**: Keep expressions simple
4. **Cache Results**: Store computed values in local variables
5. **Profile Your Scripts**: Use benchmarks to identify bottlenecks

## Testing

### Test Coverage

The package includes comprehensive tests:

**Unit Tests:**
- ✅ Request context extraction
- ✅ IP functions (parse, CIDR, private/public, version)
- ✅ Request matching (method, path, headers, IP)
- ✅ Request modification (headers, path, query params)
- ✅ Response modification (headers, status, body)
- ✅ JSON modification
- ✅ HTML token matching
- ✅ Context variables (user agent, location, session)
- ✅ Error handling

**Benchmark Tests:**
- ✅ Matcher performance
- ✅ Modifier performance
- ✅ Response modifier performance
- ✅ IP function performance
- ✅ Memory allocation analysis

**Run Tests:**
```bash
# Unit tests
go test ./internal/extension/lua

# Benchmarks
go test ./internal/extension/lua -bench=. -benchtime=1s

# Coverage
go test ./internal/extension/lua -cover

# Verbose
go test ./internal/extension/lua -v
```

## Best Practices

### Script Development

1. **Check for nil**: Context variables may be nil if middleware is not enabled
   ```lua
   local country = location.country_code or "UNKNOWN"
   ```

2. **Use `and`/`or`**: Lua's logical operators for safe defaults and ternary-like expressions
   ```lua
   local status = ip.is_private(request_ip) and 200 or 403
   ```

3. **Keep scripts simple**: Complex logic should be in Go code
   - Avoid deep nesting and complex loops
   - Use helper functions for reusable logic
   - Focus on business rules, not implementation details

4. **Test thoroughly**: Verify scripts work with various inputs
   - Test with nil context variables
   - Test with different IP types (IPv4, IPv6, private, public)
   - Test with various user agents and browsers
   - Test error conditions

5. **Handle errors**: Scripts that error return false for matchers
   - Use safe navigation (`and`/`or`)
   - Check for nil before accessing nested fields
   - Provide sensible defaults

### Performance Best Practices

1. **Avoid string concatenation in loops**: Use `table.concat()` instead
2. **Use local variables**: Faster than global lookups
3. **Cache repeated operations**: Store results in local variables
4. **Minimize function calls**: Inline simple operations when possible
5. **Profile before optimizing**: Use benchmarks to identify bottlenecks

### Security Best Practices

1. **Never trust user input**: Validate and sanitize all user-provided data
2. **Use provided functions**: Don't try to work around sandbox restrictions
3. **Limit script complexity**: Keep execution time under 100ms
4. **Avoid infinite loops**: Use bounded loops with explicit limits
5. **Test in isolation**: Verify scripts don't have unintended side effects

## Additional Resources

- **[LUA_LANGUAGE_GUIDE.md](./LUA_LANGUAGE_GUIDE.md)** - Comprehensive language guide with detailed examples and patterns
- **[Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/)** - Official Lua documentation
- **[Programming in Lua](https://www.lua.org/pil/)** - Comprehensive Lua programming book
- **[Lua Tutorial](https://www.tutorialspoint.com/lua/)** - Interactive Lua learning resource

## Examples

See [LUA_LANGUAGE_GUIDE.md](./LUA_LANGUAGE_GUIDE.md) for:
- Complete Lua syntax reference
- Detailed examples for all context variables
- IP function usage patterns
- Common matching and modification patterns
- Advanced use cases and helper functions
- Sandbox limitations and workarounds
