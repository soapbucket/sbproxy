# Lua Language Guide for Proxy

## Overview

This guide provides comprehensive documentation for writing Lua scripts in the proxy. Lua scripts can be used for HTTP request matching, request/response modification, and dynamic routing logic.

**Official Lua Resources:**
- [Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/)
- [Programming in Lua](https://www.lua.org/pil/)
- [Lua Tutorial](https://www.tutorialspoint.com/lua/index.htm)

## Table of Contents

1. [Lua Basics](#lua-basics)
2. [Available Functions](#available-functions)
3. [Request Matchers](#request-matchers)
4. [Request Modifiers](#request-modifiers)
5. [Response Modifiers](#response-modifiers)
6. [Context Variables Reference](#context-variables-reference)
7. [IP Functions](#ip-functions)
8. [Common Patterns](#common-patterns)
9. [Sandbox Limitations](#sandbox-limitations)

---

## Lua Basics

### Data Types

Lua supports the following types:
- **nil**: Represents absence of value
- **boolean**: `true` or `false`
- **number**: All numbers are doubles (e.g., `42`, `3.14`)
- **string**: Text data (e.g., `"hello"`, `'world'`)
- **table**: Arrays and dictionaries (e.g., `{1, 2, 3}`, `{key = "value"}`)

### Operators

**Arithmetic:**
```lua
1 + 2           -- Addition: 3
5 - 3           -- Subtraction: 2
4 * 5           -- Multiplication: 20
10 / 2          -- Division: 5
10 % 3          -- Modulo: 1
-5              -- Negation: -5
```

**Comparison:**
```lua
1 < 2           -- Less than: true
5 > 3           -- Greater than: true
2 <= 2          -- Less than or equal: true
5 >= 3          -- Greater than or equal: true
1 == 1          -- Equality: true
1 ~= 2          -- Inequality: true (note: ~= not !=)
```

**Logical:**
```lua
true and false  -- AND: false
true or false   -- OR: true
not true        -- NOT: false
```

**Ternary-like:**
```lua
-- Lua uses 'and'/'or' for conditional expressions
condition and true_value or false_value
ip.is_private(request_ip) and "private" or "public"
```

### String Functions

```lua
string.sub("hello", 1, 2)       -- "he" (1-indexed!)
string.len("hello")              -- 5
string.upper("hello")            -- "HELLO"
string.lower("HELLO")            -- "hello"
string.find("hello", "ll")       -- 3, 4 (start, end)
string.match("hello123", "%d+")  -- "123"
string.gsub("hello", "l", "L")   -- "heLLo", 2
"hello" .. " world"              -- "hello world" (concatenation)
```

### Table Functions

```lua
-- Arrays (1-indexed!)
local arr = {1, 2, 3}
arr[1]                  -- 1
#arr                    -- 3 (length)
table.insert(arr, 4)    -- {1, 2, 3, 4}

-- Dictionaries
local dict = {key = "value", count = 5}
dict.key                -- "value"
dict["key"]             -- "value"
```

### Control Flow

```lua
-- if/then/else
if condition then
  -- do something
elseif other_condition then
  -- do something else
else
  -- default
end

-- for loop
for i = 1, 10 do
  -- loop body
end

-- while loop
while condition do
  -- loop body
end
```

### Variables

```lua
local x = 10            -- Local variable (preferred)
y = 20                  -- Global variable (avoid)
```

---

## Available Functions

The sandbox provides access to:

### String Library
- `string.byte`, `string.char`
- `string.find`, `string.match`, `string.gmatch`, `string.gsub`
- `string.len`, `string.lower`, `string.upper`
- `string.rep`, `string.reverse`, `string.sub`
- `string.format`

### Table Library
- `table.insert`, `table.remove`
- `table.sort`, `table.concat`

### Math Library
- `math.abs`, `math.ceil`, `math.floor`
- `math.max`, `math.min`
- `math.sqrt`, `math.pow`
- `math.sin`, `math.cos`, `math.tan`
- `math.random`, `math.randomseed`

### IP Functions (Custom)
- `ip.parse`, `ip.in_cidr`, `ip.is_private`
- `ip.is_loopback`, `ip.is_ipv4`, `ip.is_ipv6`
- `ip.in_range`, `ip.compare`

---

## Request Matchers

Request matchers must return a **boolean** value.

### Basic Examples

**Match HTTP Method:**
```lua
return request.method == "GET"
return request.method == "POST"
return request.method == "GET" or request.method == "POST"
```

**Match Path:**
```lua
return request.path == "/api/users"
return string.sub(request.path, 1, 5) == "/api/"
return string.find(request.path, "^/api/") ~= nil
return string.match(request.path, "/users/%d+") ~= nil
```

**Match Headers:**
```lua
return request.headers["content-type"] == "application/json"
return request.headers["user-agent"] and string.find(request.headers["user-agent"], "Mozilla") ~= nil
return request.headers["authorization"] ~= nil
```

**Match Host:**
```lua
return request.host == "api.example.com"
return string.find(request.host, "%.example%.com$") ~= nil
```

**Match Query Parameters:**
```lua
return params.source == "mobile"
return params.debug == "true"
return params.api_key ~= nil
```

**Match Cookies:**
```lua
return cookies.session_id ~= nil
return cookies.user_type == "premium"
```

### Context Variable Examples

**Match Request IP:**
```lua
-- Check if private
return ip.is_private(request_ip)

-- Check CIDR
return ip.in_cidr(request_ip, "10.0.0.0/8")

-- Check public
return not ip.is_private(request_ip)

-- Multiple CIDRs
return ip.in_cidr(request_ip, "10.0.0.0/8") or 
       ip.in_cidr(request_ip, "172.16.0.0/12") or
       ip.in_cidr(request_ip, "192.168.0.0/16")
```

**Match User Agent:**
```lua
-- Check if user agent exists
return user_agent ~= nil

-- Match browser
return user_agent and user_agent.family == "Chrome"
return user_agent and (user_agent.family == "Chrome" or user_agent.family == "Firefox")

-- Match OS
return user_agent and user_agent.os_family == "Windows"
return user_agent and (user_agent.os_family == "iOS" or user_agent.os_family == "Android")

-- Match device
return user_agent and user_agent.device_family == "iPhone"
return user_agent and string.find(user_agent.device_family, "Samsung") ~= nil

-- Browser version
return user_agent and tonumber(user_agent.major) >= 120
```

**Match IP/Location:**
```lua
-- Check if IP info exists
return location.country_code ~= nil

-- Match country
return location.country_code == "US"
return location.country_code == "US" or location.country_code == "CA"

-- Match continent
return location.continent_code == "EU"

-- Match ASN
return location.asn == "AS15169"
return string.find(location.as_name or "", "Google") ~= nil
```

**Match Session:**
```lua
-- Check if session exists
return session ~= nil

-- Check authentication
return session and session.is_authenticated == true

-- Match user email
return session and session.auth and string.find(session.auth.email, "@example%.com$") ~= nil

-- Check user roles
return session and session.auth and session.auth.roles and 
       table_contains(session.auth.roles, "admin")
```

### Complex Matcher Examples

**API Route with Authentication:**
```lua
return request.method == "POST" and
       string.sub(request.path, 1, 9) == "/api/v1/" and
       request.headers["content-type"] == "application/json" and
       request.headers["authorization"] ~= nil
```

**Mobile Users from Specific Country:**
```lua
return user_agent and
       (user_agent.device_family == "iPhone" or user_agent.device_family == "Android") and
       location.country_code == "US"
```

**Internal Network Only:**
```lua
return ip.is_private(request_ip) and
       ip.in_cidr(request_ip, "10.0.0.0/8")
```

**Admin Users Only:**
```lua
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
       has_role(session.auth.roles, "admin") and
       string.sub(request.path, 1, 7) == "/admin/"
```

---

## Request Modifiers

Request modifiers must return a **table** with modification instructions.

### Available Operations

```lua
return {
  add_headers = {key = "value"},      -- Add/append headers
  set_headers = {key = "value"},      -- Set/replace headers
  delete_headers = {"key"},           -- Remove headers
  path = "/new/path",                 -- New path
  method = "POST",                    -- New HTTP method
  add_query = {key = "value"},        -- Add query params
  delete_query = {"key"}              -- Remove query params
}
```

### Header Modification Examples

**Add Headers:**
```lua
return {
  add_headers = {
    ["X-Custom-Header"] = "value",
    ["X-Request-ID"] = "12345"
  }
}
```

**Add Headers with Context:**
```lua
return {
  add_headers = {
    ["X-Country"] = location.country_code or "UNKNOWN",
    ["X-Browser"] = user_agent and user_agent.family or "UNKNOWN"
  }
}
```

**Set Headers (Replace):**
```lua
return {
  set_headers = {
    ["Content-Type"] = "application/json",
    ["Cache-Control"] = "no-cache"
  }
}
```

**Delete Headers:**
```lua
return {
  delete_headers = {"X-Internal-Header", "X-Debug-Info"}
}
```

### Path Modification Examples

**Simple Path Change:**
```lua
return {
  path = "/v2/api/users"
}
```

**Conditional Path Based on Device:**
```lua
return {
  path = user_agent and 
         (user_agent.device_family == "iPhone" or user_agent.device_family == "Android")
         and "/mobile" .. request.path
         or request.path
}
```

**Path Rewriting:**
```lua
local path = request.path
if string.sub(path, 1, 5) == "/old/" then
  path = "/new/" .. string.sub(path, 6)
end

return {
  path = path
}
```

### Method Modification

```lua
return {
  method = "POST"
}
```

### Query Parameter Modification

**Add Query Parameters:**
```lua
return {
  add_query = {
    source = "proxy",
    version = "v1",
    country = location.country_code or "XX"
  }
}
```

**Delete Query Parameters:**
```lua
return {
  delete_query = {"debug", "internal_id"}
}
```

### Complete Modification Examples

**Add Tracking Headers:**
```lua
return {
  add_headers = {
    ["X-Client-Country"] = location.country_code or "UNKNOWN",
    ["X-Client-Browser"] = user_agent and user_agent.family or "UNKNOWN",
    ["X-Client-OS"] = user_agent and user_agent.os_family or "UNKNOWN",
    ["X-Client-Device"] = user_agent and user_agent.device_family or "UNKNOWN"
  }
}
```

**IP-Based Headers:**
```lua
return {
  add_headers = {
    ["X-Client-IP"] = request_ip,
    ["X-IP-Type"] = ip.is_private(request_ip) and "private" or "public",
    ["X-IP-Version"] = ip.is_ipv4(request_ip) and "v4" or "v6",
    ["X-Internal-Network"] = ip.in_cidr(request_ip, "10.0.0.0/8") and "true" or "false"
  }
}
```

**IP-Based Routing:**
```lua
return {
  path = ip.is_private(request_ip) and "/internal" .. request.path or request.path,
  add_headers = {
    ["X-Route-Type"] = ip.is_private(request_ip) and "internal" or "external"
  }
}
```

**CIDR-Based Access Control:**
```lua
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

**Complete Transformation:**
```lua
return {
  add_headers = {
    ["X-Country"] = geoip and geoip.country_code or "XX",
    ["X-Forwarded-For"] = request.headers["x-real-ip"] or request_ip
  },
  set_headers = {
    ["Content-Type"] = "application/json"
  },
  delete_headers = {"X-Internal-Debug"},
  path = "/api/v2" .. request.path,
  add_query = {
    client = "proxy",
    version = "2.0"
  },
  delete_query = {"debug"}
}
```

---

## Response Modifiers

Response modifiers must return a **table** with response modification instructions.

### Available Operations

```lua
return {
  add_headers = {key = "value"},      -- Add/append headers
  set_headers = {key = "value"},      -- Set/replace headers
  delete_headers = {"key"},           -- Remove headers
  status_code = 200,                  -- New status code
  body = "new body"                   -- New body content
}
```

### Header Modification Examples

**Add Response Headers:**
```lua
return {
  add_headers = {
    ["X-Response-Time"] = "150ms",
    ["X-Cache-Status"] = "HIT"
  }
}
```

**Add Headers Based on Request Context:**
```lua
return {
  add_headers = {
    ["X-Request-Country"] = location.country_code or "UNKNOWN",
    ["X-Request-Browser"] = user_agent and user_agent.family or "UNKNOWN",
    ["X-Request-Method"] = request.method,
    ["X-Request-Path"] = request.path
  }
}
```

**Set CORS Headers:**
```lua
return {
  set_headers = {
    ["Access-Control-Allow-Origin"] = "*",
    ["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE",
    ["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
  }
}
```

### Status Code Modification

**Simple Status Change:**
```lua
return {
  status_code = 200
}
```

**Conditional Status Based on Country:**
```lua
local status = 200
if location.country_code == "US" or location.country_code == "CA" then
  status = 200
else
  status = 403
end

return {
  status_code = status
}
```

**Status Based on Authentication:**
```lua
return {
  status_code = session and session.is_authenticated and 200 or 401
}
```

### Body Modification

**Simple Body Replacement:**
```lua
return {
  body = '{"status": "success", "message": "OK"}'
}
```

**Append to Body:**
```lua
return {
  body = response.body .. " [Modified by Proxy]"
}
```

**Conditional Body:**
```lua
local body = response.body
if response.status_code >= 400 then
  body = '{"error": "Request failed", "status": ' .. response.status_code .. '}'
end

return {
  body = body
}
```

### Complete Response Modification Examples

**Security Headers:**
```lua
return {
  add_headers = {
    ["X-Content-Type-Options"] = "nosniff",
    ["X-Frame-Options"] = "DENY",
    ["X-XSS-Protection"] = "1; mode=block",
    ["Strict-Transport-Security"] = "max-age=31536000"
  }
}
```

**Geo-Based Response:**
```lua
local is_allowed = location.country_code == "US" or 
                   location.country_code == "CA" or 
                   location.country_code == "GB"

return {
  add_headers = {
    ["X-User-Country"] = location.country_code or "UNKNOWN",
    ["X-Content-Region"] = location.continent_code == "EU" and "EU" or "US"
  },
  status_code = is_allowed and 200 or 451  -- 451 Unavailable For Legal Reasons
}
```

---

## Context Variables Reference

### Request Variables

```lua
request.method           -- HTTP method
request.path             -- URL path
request.host             -- Host header
request.scheme           -- URL scheme
request.query            -- Query string
request.protocol         -- HTTP protocol
request.headers          -- Header table (lowercase keys)
request.size             -- Content length
```

### Request IP

```lua
request_ip               -- Client IP address (string)
                         -- Extracted from X-Real-IP, X-Forwarded-For, or RemoteAddr
```

### Cookies

```lua
cookies.name             -- Cookie value by name
cookies["name"]          -- Alternative syntax
```

### Query Parameters

```lua
params.name              -- Parameter value
params["name"]           -- Alternative syntax
```

### User Agent (may be nil)

```lua
user_agent.family                -- Browser family
user_agent.major                 -- Major version
user_agent.minor                 -- Minor version
user_agent.patch                 -- Patch version
user_agent.os_family             -- OS family
user_agent.os_major              -- OS major version
user_agent.os_minor              -- OS minor version
user_agent.os_patch              -- OS patch version
user_agent.os_patch_minor        -- OS patch minor
user_agent.device_family         -- Device family
user_agent.device_brand          -- Device brand
user_agent.device_model          -- Device model
```

### IP Info (may be nil)

```lua
location.country                   -- Country name
location.country_code              -- Country code
location.continent                 -- Continent name
location.continent_code            -- Continent code
location.asn                       -- ASN
location.as_name                   -- AS name
location.as_domain                 -- AS domain
```

### Session (may be nil)

```lua
session.id                       -- Session ID
session.expires                  -- Expiration time
session.is_authenticated         -- Auth status
session.auth.type                -- Auth type (oauth, jwt, etc.)
session.auth.id                  -- User ID (from auth data)
session.auth.email               -- User email (from auth data)
session.auth.name                -- User name (from auth data)
session.auth.provider            -- OAuth provider (from auth data)
session.auth.roles               -- Roles (from auth data, array)
session.auth.permissions         -- Permissions (from auth data, table)
session.data                     -- Custom data
session.visited_count            -- Visited URLs
session.cookie_count             -- Cookie count
```

### User Variables

```lua
var.name                         -- Access user-defined variable by key
var.nested_key                   -- Access nested values
```

### Server Variables

```lua
server.instance_id               -- Proxy instance ID
server.version                   -- Proxy version
server.build_hash                -- Git build hash
server.start_time                -- Instance start time (RFC 3339)
server.hostname                  -- OS hostname
server.environment               -- Deployment environment
server.custom_key                -- Operator-defined custom values from sb.yml
```

### Environment Variables

Per-origin identity variables populated from config metadata (immutable):

```lua
env.workspace_id                 -- Workspace UUID
env.origin_id                    -- Origin UUID
env.hostname                     -- Origin hostname
env.version                      -- Config version string
env.environment                  -- Environment name (dev, stage, prod)
env.origin_name                  -- Origin slug name
env.tags                         -- User-defined tags table (if any)
```

### Feature Flags

Reserved namespace for workspace-scoped feature flags (not yet implemented):

```lua
feature.FLAG_NAME                -- Feature flag value (currently always empty table)
```

---

## IP Functions

### `ip.parse(ip_string)`

Parses an IP address and returns information table.

**Usage:**
```lua
local info = ip.parse("192.168.1.1")
-- info.valid (boolean)
-- info.ip (string)
-- info.is_ipv4 (boolean)
-- info.is_ipv6 (boolean)
-- info.is_private (boolean)
-- info.is_loopback (boolean)
```

**Examples:**
```lua
local info = ip.parse(request_ip)
if info.valid and info.is_private then
  -- Private IP
end

if ip.parse(request_ip).is_ipv4 then
  -- IPv4
end
```

### `ip.in_cidr(ip, cidr)`

Checks if IP is within CIDR range.

**Usage:**
```lua
if ip.in_cidr("192.168.1.100", "192.168.1.0/24") then
  -- IP is in range
end
```

**Examples:**
```lua
-- Check internal network
if ip.in_cidr(request_ip, "10.0.0.0/8") then
  -- Internal
end

-- Multiple ranges
if ip.in_cidr(request_ip, "10.0.0.0/8") or
   ip.in_cidr(request_ip, "172.16.0.0/12") or
   ip.in_cidr(request_ip, "192.168.0.0/16") then
  -- Private range
end
```

### `ip.is_private(ip)`

Checks if IP is in private range.

**Usage:**
```lua
if ip.is_private("192.168.1.1") then
  -- Private IP
end
```

**Examples:**
```lua
return ip.is_private(request_ip)

return {
  add_headers = {
    ["X-IP-Type"] = ip.is_private(request_ip) and "private" or "public"
  }
}
```

### `ip.is_loopback(ip)`

Checks if IP is loopback.

**Usage:**
```lua
if ip.is_loopback("127.0.0.1") then
  -- Loopback
end
```

### `ip.is_ipv4(ip)` / `ip.is_ipv6(ip)`

Check IP version.

**Usage:**
```lua
if ip.is_ipv4("192.168.1.1") then
  -- IPv4
end

if ip.is_ipv6("2001:db8::1") then
  -- IPv6
end
```

**Examples:**
```lua
return {
  add_headers = {
    ["X-IP-Version"] = ip.is_ipv4(request_ip) and "4" or "6"
  }
}
```

### `ip.in_range(ip, start, end)`

Check if IP is in range (inclusive).

**Usage:**
```lua
if ip.in_range("192.168.1.100", "192.168.1.1", "192.168.1.255") then
  -- In range
end
```

### `ip.compare(ip1, ip2)`

Compare two IPs (returns -1, 0, or 1).

**Usage:**
```lua
local cmp = ip.compare("192.168.1.1", "192.168.1.2")
if cmp < 0 then
  -- ip1 < ip2
elseif cmp == 0 then
  -- ip1 == ip2
else
  -- ip1 > ip2
end
```

---

## Common Patterns

### Checking Context Variables

Always check if context variables exist before accessing:

```lua
-- Safe access with default
local country = location.country_code or "UNKNOWN"
local browser = user_agent and user_agent.family or "UNKNOWN"
```

### Helper Functions

```lua
-- Check if array contains value
local function array_contains(arr, val)
  if not arr then return false end
  for i = 1, #arr do
    if arr[i] == val then return true end
  end
  return false
end

-- Check if string starts with
local function starts_with(str, prefix)
  return string.sub(str, 1, string.len(prefix)) == prefix
end

-- Check if string ends with
local function ends_with(str, suffix)
  return string.sub(str, -string.len(suffix)) == suffix
end
```

### String Manipulation

```lua
-- Concatenation
local full_path = "/api" .. request.path

-- Case conversion
local upper = string.upper("hello")  -- "HELLO"
local lower = string.lower("HELLO")  -- "hello"

-- Substring (1-indexed!)
local first_five = string.sub(request.path, 1, 5)

-- Find/Match
local start, end_pos = string.find(request.path, "/api/")
local version = string.match(request.path, "/v(%d+)/")
```

### Table Operations

```lua
-- Array iteration
local arr = {1, 2, 3}
for i = 1, #arr do
  print(arr[i])
end

-- Dictionary iteration
local dict = {a = 1, b = 2}
for key, value in pairs(dict) do
  print(key, value)
end
```

---

## Sandbox Limitations

### Allowed

- ✅ Safe string, math, and table functions
- ✅ IP manipulation functions
- ✅ Read-only access to context variables
- ✅ Local variables and functions
- ✅ Control flow (if/for/while)
- ✅ Pattern matching with string functions

### Blocked for Security

- ❌ File I/O (`io` module)
- ❌ OS operations (`os` module)
- ❌ Package loading (`require`, `dofile`, `loadfile`)
- ❌ Debug functions (`debug` module)
- ❌ Meta-operations (`getmetatable`, `setmetatable`, `rawset`, etc.)
- ❌ Network operations
- ❌ Global variable modification

### Execution Limits

- **Timeout**: 100ms default (configurable)
- **Context**: Script execution is cancelled if context timeout expires
- **Memory**: Limited to prevent excessive resource usage

### Best Practices

1. **Check for nil**: Always verify context variables exist before using
2. **Use local variables**: Declare variables with `local` keyword
3. **Keep scripts simple**: Complex logic should be in Go code
4. **Avoid loops**: Minimize loop usage or use small iterations
5. **Test thoroughly**: Verify scripts work with various inputs
6. **Handle errors**: Scripts that error return false for matchers
7. **Use helper functions**: Extract reusable logic
8. **Comment your code**: Explain non-obvious logic

---

## Additional Resources

- **[README.md](./README.md)** - Package overview and quick start
- **[Lua 5.1 Reference](https://www.lua.org/manual/5.1/)** - Official Lua documentation
- **[Programming in Lua](https://www.lua.org/pil/)** - Comprehensive Lua book
- **[Lua Tutorial](https://www.tutorialspoint.com/lua/)** - Interactive learning
