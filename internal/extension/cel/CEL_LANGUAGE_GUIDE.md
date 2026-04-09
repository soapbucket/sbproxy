# CEL Language Guide for Proxy

## Overview

This guide provides comprehensive documentation for writing CEL (Common Expression Language) expressions in the proxy. CEL is a non-Turing complete expression language designed for safe evaluation of expressions in a sandboxed environment.

**Official CEL Resources:**
- [CEL Specification](https://github.com/google/cel-spec)
- [CEL Go Implementation](https://github.com/google/cel-go)
- [CEL Language Definition](https://github.com/google/cel-spec/blob/master/doc/langdef.md)

## Table of Contents

1. [CEL Basics](#cel-basics)
2. [Available Functions](#available-functions)
3. [Request Matchers](#request-matchers)
4. [Request Modifiers](#request-modifiers)
5. [Response Modifiers](#response-modifiers)
6. [JSON Modifiers](#json-modifiers)
7. [Token Matchers](#token-matchers)
8. [Context Variables Reference](#context-variables-reference)
9. [Common Patterns](#common-patterns)

---

## CEL Basics

### Data Types

CEL supports the following primitive types:
- **int**: 64-bit signed integers (e.g., `42`, `-10`)
- **uint**: 64-bit unsigned integers (e.g., `42u`)
- **double**: 64-bit floating point (e.g., `3.14`, `-0.5`)
- **bool**: Boolean values (`true`, `false`)
- **string**: Unicode strings (e.g., `"hello"`, `'world'`)
- **bytes**: Byte sequences (e.g., `b'data'`)
- **list**: Ordered collections (e.g., `[1, 2, 3]`)
- **map**: Key-value mappings (e.g., `{"key": "value"}`)
- **null**: Null value (`null`)
- **timestamp**: Time values
- **duration**: Time duration values

### Operators

**Arithmetic:**
```cel
1 + 2           // Addition: 3
5 - 3           // Subtraction: 2
4 * 5           // Multiplication: 20
10 / 2          // Division: 5
10 % 3          // Modulo: 1
-5              // Negation: -5
```

**Comparison:**
```cel
1 < 2           // Less than: true
5 > 3           // Greater than: true
2 <= 2          // Less than or equal: true
5 >= 3          // Greater than or equal: true
1 == 1          // Equality: true
1 != 2          // Inequality: true
```

**Logical:**
```cel
true && false   // AND: false
true || false   // OR: true
!true           // NOT: false
```

**Ternary:**
```cel
condition ? true_value : false_value
size(map) > 0 ? map['key'] : "default"
```

### String Functions

```cel
"hello".startsWith("he")        // true
"hello".endsWith("lo")          // true
"hello".contains("ll")          // true
"hello".matches("h.*o")         // true (regex)
"hello" + " world"              // "hello world"
"hello".size()                  // 5
```

### List Functions

```cel
[1, 2, 3].size()                // 3
1 in [1, 2, 3]                  // true
[1, 2, 3].contains(2)           // true
```

### Map Functions

```cel
{"a": 1, "b": 2}.size()         // 2
"a" in {"a": 1, "b": 2}         // true
size(map) > 0                   // Check if map has data
```

### Macros

**has()** - Check if a field is present:
```cel
has(request.headers)            // true if headers exist
```

**all()** - Universal quantifier:
```cel
[1, 2, 3].all(x, x > 0)        // true if all elements > 0
```

**exists()** - Existential quantifier:
```cel
[1, 2, 3].exists(x, x == 2)    // true if any element == 2
```

**filter()** - Filter list:
```cel
[1, 2, 3, 4].filter(x, x > 2)  // [3, 4]
```

**map()** - Transform list:
```cel
[1, 2, 3].map(x, x * 2)        // [2, 4, 6]
```

---

## Available Functions

The proxy includes CEL extensions:

### String Extensions (ext.Strings())
- `startsWith(string)` - Check string prefix
- `endsWith(string)` - Check string suffix
- `contains(string)` - Check substring
- `matches(regex)` - Regular expression matching

### Encoding Extensions (ext.Encoders())
- `base64.encode(bytes)` - Base64 encoding
- `base64.decode(string)` - Base64 decoding

### IP Functions (IPFunctions())
- `ip.parse(string)` - Parse IP and return info map
- `ip.inCIDR(ip, cidr)` - Check if IP is in CIDR range
- `ip.isPrivate(ip)` - Check if IP is private
- `ip.isLoopback(ip)` - Check if IP is loopback
- `ip.isIPv4(ip)` - Check if IP is IPv4
- `ip.isIPv6(ip)` - Check if IP is IPv6
- `ip.inRange(ip, start, end)` - Check if IP is in range
- `ip.compare(ip1, ip2)` - Compare two IPs

---

## Request Matchers

Request matchers evaluate to a **boolean** value and determine if a request matches certain criteria.

### Basic Examples

**Match HTTP Method:**
```cel
request.method == 'GET'
request.method == 'POST'
request.method in ['GET', 'POST', 'PUT']
```

**Match Path:**
```cel
request.path == '/api/users'
request.path.startsWith('/api/')
request.path.endsWith('.json')
request.path.contains('/admin/')
request.path.matches('^/api/v[0-9]+/')
```

**Match Headers:**
```cel
request.headers['content-type'] == 'application/json'
request.headers['user-agent'].contains('Mozilla')
'authorization' in request.headers
request.headers['accept'].startsWith('text/')
```

**Match Host:**
```cel
request.host == 'api.example.com'
request.host.endsWith('.example.com')
request.host.contains('staging')
```

**Match Query Parameters:**
```cel
params['source'] == 'mobile'
params['debug'] == 'true'
'api_key' in params
params['version'].startsWith('v1')
```

**Match Cookies:**
```cel
cookies['session_id'] != ''
'auth_token' in cookies
cookies['user_type'] == 'premium'
```

### Context Variable Examples

**Match User Agent:**
```cel
// Check if user agent data exists
size(user_agent) > 0

// Match browser
size(user_agent) > 0 && user_agent['family'] == 'Chrome'
size(user_agent) > 0 && user_agent['family'] in ['Chrome', 'Firefox', 'Safari']

// Match OS
size(user_agent) > 0 && user_agent['os_family'] == 'Windows'
size(user_agent) > 0 && user_agent['os_family'] in ['iOS', 'Android']

// Match device
size(user_agent) > 0 && user_agent['device_family'] == 'iPhone'
size(user_agent) > 0 && user_agent['device_family'].startsWith('Samsung')

// Browser version
size(user_agent) > 0 && user_agent['major'] >= '120'
```

**Match IP/Location:**
```cel
// Check if IP info exists
size(location) > 0

// Match country
size(location) > 0 && location['country_code'] == 'US'
size(location) > 0 && location['country_code'] in ['US', 'CA', 'MX']

// Match continent
size(location) > 0 && location['continent_code'] == 'EU'
size(location) > 0 && location['continent_code'] in ['NA', 'SA']

// Match ASN
size(location) > 0 && location['asn'] == 'AS15169'
size(location) > 0 && location['as_name'].contains('Google')
```

**Match Session:**
```cel
// Check if session exists
size(session) > 0

// Check authentication
size(session) > 0 && session['is_authenticated'] == true

// Match user email
size(session) > 0 && size(session['auth']) > 0 && session['auth']['email'].endsWith('@example.com')

// Check user roles
size(session) > 0 && size(session['auth']) > 0 && 'admin' in session['auth']['roles']

// Session expiry
size(session) > 0 && session['expires'] > timestamp('2024-12-31T00:00:00Z')
```

**Match Request IP:**
```cel
// Check if request IP is private
ip.isPrivate(request_ip)

// Check if request IP is in CIDR range
ip.inCIDR(request_ip, "10.0.0.0/8")
ip.inCIDR(request_ip, "192.168.1.0/24")

// Check if request IP is public
!ip.isPrivate(request_ip)

// Check if request IP is IPv4
ip.isIPv4(request_ip)

// Check if request IP is IPv6
ip.isIPv6(request_ip)

// Check if request IP is in range
ip.inRange(request_ip, "192.168.1.1", "192.168.1.255")

// Check if request IP is loopback
ip.isLoopback(request_ip)

// Parse and check IP properties
ip.parse(request_ip)['is_private'] == true
ip.parse(request_ip)['is_ipv4'] == true

// Multiple CIDR ranges
ip.inCIDR(request_ip, "10.0.0.0/8") || ip.inCIDR(request_ip, "172.16.0.0/12") || ip.inCIDR(request_ip, "192.168.0.0/16")
```

### Complex Matcher Examples

**API Route with Authentication:**
```cel
request.method == 'POST' &&
request.path.startsWith('/api/v1/') &&
request.headers['content-type'] == 'application/json' &&
'authorization' in request.headers
```

**Mobile Users from Specific Country:**
```cel
size(user_agent) > 0 &&
user_agent['device_family'] in ['iPhone', 'iPad', 'Android'] &&
size(location) > 0 &&
location['country_code'] == 'US'
```

**Admin Users Only:**
```cel
size(session) > 0 &&
session['is_authenticated'] == true &&
size(session['auth']) > 0 &&
'admin' in session['auth']['roles'] &&
request.path.startsWith('/admin/')
```

**Block Suspicious Traffic:**
```cel
(size(user_agent) > 0 && user_agent['family'] == 'curl') ||
(size(location) > 0 && location['country_code'] in ['XX', 'ZZ'])
```

---

## Request Modifiers

Request modifiers return a **map** with modification instructions.

### Available Operations

```cel
{
  "add_headers": map[string]string,      // Add/append headers
  "set_headers": map[string]string,      // Set/replace headers
  "delete_headers": []string,            // Remove headers
  "path": string,                        // New path
  "method": string,                      // New HTTP method
  "add_query": map[string]string,        // Add query params
  "delete_query": []string               // Remove query params
}
```

### Header Modification Examples

**Add Headers:**
```cel
{
  "add_headers": {
    "X-Custom-Header": "value",
    "X-Request-ID": "12345"
  }
}
```

**Add Headers with Context:**
```cel
{
  "add_headers": {
    "X-Country": size(location) > 0 ? location['country_code'] : "UNKNOWN",
    "X-Browser": size(user_agent) > 0 ? user_agent['family'] : "UNKNOWN"
  }
}
```

**Set Headers (Replace):**
```cel
{
  "set_headers": {
    "Content-Type": "application/json",
    "Cache-Control": "no-cache"
  }
}
```

**Delete Headers:**
```cel
{
  "delete_headers": ["X-Internal-Header", "X-Debug-Info"]
}
```

### Path Modification Examples

**Simple Path Change:**
```cel
{
  "path": "/v2/api/users"
}
```

**Conditional Path Based on Device:**
```cel
{
  "path": size(user_agent) > 0 && user_agent['device_family'] in ['iPhone', 'iPad', 'Android']
    ? "/mobile" + request.path
    : request.path
}
```

**Path Rewriting:**
```cel
{
  "path": request.path.startsWith('/old/')
    ? '/new/' + request.path.substring(5)
    : request.path
}
```

### Method Modification

```cel
{
  "method": "POST"
}
```

### Query Parameter Modification

**Add Query Parameters:**
```cel
{
  "add_query": {
    "source": "proxy",
    "version": "v1",
    "country": size(location) > 0 ? location['country_code'] : "XX"
  }
}
```

**Delete Query Parameters:**
```cel
{
  "delete_query": ["debug", "internal_id"]
}
```

### Complete Modification Examples

**Add Tracking Headers:**
```cel
{
  "add_headers": {
    "X-Client-Country": size(location) > 0 ? location['country_code'] : "UNKNOWN",
    "X-Client-Browser": size(user_agent) > 0 ? user_agent['family'] : "UNKNOWN",
    "X-Client-OS": size(user_agent) > 0 ? user_agent['os_family'] : "UNKNOWN",
    "X-Client-Device": size(user_agent) > 0 ? user_agent['device_family'] : "UNKNOWN"
  }
}
```

**Mobile API Routing:**
```cel
{
  "path": size(user_agent) > 0 && user_agent['device_family'] in ['iPhone', 'Android']
    ? "/mobile/api" + request.path
    : "/desktop/api" + request.path,
  "add_headers": {
    "X-Device-Type": size(user_agent) > 0 ? user_agent['device_family'] : "UNKNOWN"
  }
}
```

**Authentication Enrichment:**
```cel
{
  "add_headers": {
    "X-User-ID": size(session) > 0 && session['is_authenticated'] && size(session['auth']) > 0
      ? session['auth']['id'] 
      : "",
    "X-User-Email": size(session) > 0 && session['is_authenticated'] && size(session['auth']) > 0
      ? session['auth']['email']
      : "",
    "X-User-Roles": size(session) > 0 && session['is_authenticated'] && size(session['auth']) > 0
      ? session['auth']['roles'].join(',')
      : ""
  }
}
```

**IP-Based Headers:**
```cel
{
  "add_headers": {
    "X-Client-IP": request_ip,
    "X-IP-Type": ip.isPrivate(request_ip) ? "private" : "public",
    "X-IP-Version": ip.isIPv4(request_ip) ? "v4" : "v6",
    "X-Internal-Network": ip.inCIDR(request_ip, "10.0.0.0/8") ? "true" : "false"
  }
}
```

**IP-Based Routing:**
```cel
{
  "path": ip.isPrivate(request_ip) ? "/internal" + request.path : request.path,
  "add_headers": {
    "X-Route-Type": ip.isPrivate(request_ip) ? "internal" : "external"
  }
}
```

**CIDR-Based Access Control:**
```cel
{
  "add_headers": {
    "X-Access-Level": ip.inCIDR(request_ip, "10.0.1.0/24") 
      ? "admin" 
      : (ip.inCIDR(request_ip, "10.0.0.0/16") ? "user" : "guest")
  },
  "add_query": {
    "access_level": ip.isPrivate(request_ip) ? "internal" : "external"
  }
}
```

**Complete Transformation:**
```cel
{
  "add_headers": {
    "X-Country": size(location) > 0 ? location['country_code'] : "XX",
    "X-Forwarded-For": request.headers['x-real-ip']
  },
  "set_headers": {
    "Content-Type": "application/json"
  },
  "delete_headers": ["X-Internal-Debug"],
  "path": "/api/v2" + request.path,
  "add_query": {
    "client": "proxy",
    "version": "2.0"
  },
  "delete_query": ["debug"]
}
```

---

## Response Modifiers

Response modifiers return a **map** with response modification instructions.

### Available Operations

```cel
{
  "add_headers": map[string]string,      // Add/append headers
  "set_headers": map[string]string,      // Set/replace headers
  "delete_headers": []string,            // Remove headers
  "status_code": int,                    // New status code
  "body": string                         // New body content
}
```

### Header Modification Examples

**Add Response Headers:**
```cel
{
  "add_headers": {
    "X-Response-Time": "150ms",
    "X-Cache-Status": "HIT"
  }
}
```

**Add Headers Based on Request Context:**
```cel
{
  "add_headers": {
    "X-Request-Country": size(location) > 0 ? location['country_code'] : "UNKNOWN",
    "X-Request-Browser": size(user_agent) > 0 ? user_agent['family'] : "UNKNOWN",
    "X-Request-Method": request.method,
    "X-Request-Path": request.path
  }
}
```

**Set CORS Headers:**
```cel
{
  "set_headers": {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  }
}
```

### Status Code Modification

**Simple Status Change:**
```cel
{
  "status_code": 200
}
```

**Conditional Status Based on Country:**
```cel
{
  "status_code": size(location) > 0 && location['country_code'] in ['US', 'CA']
    ? 200
    : 403
}
```

**Status Based on Authentication:**
```cel
{
  "status_code": size(session) > 0 && session['is_authenticated']
    ? 200
    : 401
}
```

### Body Modification

**Simple Body Replacement:**
```cel
{
  "body": "{\"status\": \"success\", \"message\": \"OK\"}"
}
```

**Append to Body:**
```cel
{
  "body": response.body + " [Modified by Proxy]"
}
```

**Conditional Body:**
```cel
{
  "body": response.status_code >= 400
    ? "{\"error\": \"Request failed\", \"status\": " + string(response.status_code) + "}"
    : response.body
}
```

### Complete Response Modification Examples

**Security Headers:**
```cel
{
  "add_headers": {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000"
  }
}
```

**Geo-Based Response:**
```cel
{
  "add_headers": {
    "X-User-Country": size(location) > 0 ? location['country_code'] : "UNKNOWN",
    "X-Content-Region": size(location) > 0 && location['continent_code'] == 'EU' ? "EU" : "US"
  },
  "status_code": size(location) > 0 && location['country_code'] in ['US', 'CA', 'GB']
    ? 200
    : 451  // Unavailable For Legal Reasons
}
```

**Error Handling:**
```cel
{
  "set_headers": {
    "Content-Type": "application/json"
  },
  "status_code": response.status_code >= 500 ? 503 : response.status_code,
  "body": response.status_code >= 500
    ? "{\"error\": \"Service temporarily unavailable\"}"
    : response.body
}
```

**Response Enrichment:**
```cel
{
  "add_headers": {
    "X-Request-ID": request.headers['x-request-id'],
    "X-Response-Time": "150ms",
    "X-Client-Country": size(location) > 0 ? location['country_code'] : "XX",
    "X-Cache-Status": "MISS"
  },
  "delete_headers": ["X-Internal-Version", "X-Server-ID"]
}
```

---

## JSON Modifiers

JSON modifiers manipulate JSON objects and return modification instructions.

### Available Operations

```cel
{
  "set_fields": map[string]any,          // Set/add fields
  "delete_fields": []string,             // Remove fields
  "modified_json": map[string]any        // Complete replacement
}
```

### Set Fields Examples

**Add Fields:**
```cel
{
  "set_fields": {
    "status": "processed",
    "timestamp": "2024-01-01T00:00:00Z",
    "version": 2
  }
}
```

**Computed Fields:**
```cel
{
  "set_fields": {
    "full_name": json.first_name + " " + json.last_name,
    "age_next_year": json.age + 1,
    "is_adult": json.age >= 18
  }
}
```

**Nested Objects:**
```cel
{
  "set_fields": {
    "metadata": {
      "processed": true,
      "timestamp": "2024-01-01T00:00:00Z",
      "version": "2.0"
    },
    "stats": {
      "count": 100,
      "sum": 5000
    }
  }
}
```

### Delete Fields Examples

**Remove Fields:**
```cel
{
  "delete_fields": ["password", "secret_key", "internal_id"]
}
```

**Conditional Deletion:**
```cel
{
  "delete_fields": json.is_public == false
    ? ["email", "phone", "address"]
    : []
}
```

### Complete JSON Replacement

**Transform Object:**
```cel
{
  "modified_json": {
    "id": json.id,
    "name": json.name,
    "status": "active",
    "created_at": json.timestamp
  }
}
```

**Selective Fields:**
```cel
{
  "modified_json": {
    "user_id": json.user.id,
    "user_name": json.user.name,
    "order_total": json.items.map(i, i.price).sum()
  }
}
```

### Combined Operations

**Set and Delete:**
```cel
{
  "set_fields": {
    "processed": true,
    "processed_at": "2024-01-01T00:00:00Z"
  },
  "delete_fields": ["temp_data", "internal_notes"]
}
```

**Data Sanitization:**
```cel
{
  "set_fields": {
    "email_hash": json.email.hash(),
    "sanitized": true
  },
  "delete_fields": ["email", "password", "ssn", "credit_card"]
}
```

---

## Token Matchers

Token matchers evaluate HTML tokens and return **boolean** values.

### Token Structure

```cel
token.data           // Tag name (e.g., "div", "a", "input")
token.attrs          // Map of attributes {"key": "value"}
```

### Tag Matching Examples

**Match Specific Tags:**
```cel
token.data == 'a'
token.data == 'div'
token.data == 'input'
token.data in ['a', 'button', 'form']
```

### Attribute Matching Examples

**Check Attribute Exists:**
```cel
'href' in token.attrs
'class' in token.attrs
'id' in token.attrs
```

**Match Attribute Value:**
```cel
token.attrs['href'] == 'https://example.com'
token.attrs['class'] == 'btn btn-primary'
token.attrs['type'] == 'submit'
```

**Attribute Contains:**
```cel
token.attrs['class'].contains('btn')
token.attrs['href'].contains('example.com')
token.attrs['id'].contains('submit')
```

**Attribute Patterns:**
```cel
token.attrs['href'].startsWith('https://')
token.attrs['href'].endsWith('.pdf')
token.attrs['src'].matches('^https://.*\\.jpg$')
```

### Complex Token Matching

**Match Links:**
```cel
token.data == 'a' && 'href' in token.attrs
```

**Match External Links:**
```cel
token.data == 'a' &&
'href' in token.attrs &&
token.attrs['href'].startsWith('http') &&
!token.attrs['href'].contains('mysite.com')
```

**Match Form Inputs:**
```cel
token.data == 'input' &&
token.attrs['type'] in ['text', 'email', 'password'] &&
'required' in token.attrs
```

**Match Buttons:**
```cel
(token.data == 'button' || (token.data == 'input' && token.attrs['type'] == 'submit')) &&
token.attrs['class'].contains('btn')
```

**Match Images:**
```cel
token.data == 'img' &&
'src' in token.attrs &&
(token.attrs['src'].endsWith('.jpg') || token.attrs['src'].endsWith('.png'))
```

---

## Context Variables Reference

### Request Variables

```cel
request.method           // HTTP method
request.path             // URL path
request.host             // Host header
request.scheme           // URL scheme
request.query            // Query string
request.protocol         // HTTP protocol
request.headers          // Header map
request.size             // Content length
```

### Cookies

```cel
cookies['name']          // Cookie value by name
'name' in cookies        // Check cookie exists
```

### Query Parameters

```cel
params['name']           // Parameter value
'name' in params         // Check parameter exists
```

### Request IP

```cel
request_ip               // Client IP address (string)
                         // Extracted from X-Real-IP, X-Forwarded-For, or RemoteAddr
```

### User Agent (may be empty)

```cel
user_agent['family']                // Browser family
user_agent['major']                 // Major version
user_agent['minor']                 // Minor version
user_agent['patch']                 // Patch version
user_agent['os_family']             // OS family
user_agent['os_major']              // OS major version
user_agent['os_minor']              // OS minor version
user_agent['os_patch']              // OS patch version
user_agent['os_patch_minor']        // OS patch minor
user_agent['device_family']         // Device family
user_agent['device_brand']          // Device brand
user_agent['device_model']          // Device model
```

### IP Info (may be empty)

```cel
location['country']                   // Country name
location['country_code']              // Country code
location['continent']                 // Continent name
location['continent_code']            // Continent code
location['asn']                       // ASN
location['as_name']                   // AS name
location['as_domain']                 // AS domain
```

### Session (may be empty)

```cel
session['id']                       // Session ID
session['expires']                  // Expiration time
session['is_authenticated']         // Auth status
session['auth']['type']             // Auth type (oauth, jwt, etc.)
session['auth']['id']               // User ID (from auth data)
session['auth']['email']            // User email (from auth data)
session['auth']['name']             // User name (from auth data)
session['auth']['provider']         // OAuth provider (from auth data)
session['auth']['roles']            // Roles (from auth data)
session['auth']['permissions']      // Permissions (from auth data)
session['data']                     // Custom data
session['visited_count']            // Visited URLs
session['cookie_count']             // Cookie count
```

---

## Common Patterns

### Checking Context Variables

Always use `size()` to check if context variables have data:

```cel
// Check if data exists
size(user_agent) > 0
size(location) > 0
size(session) > 0

// Safe access with default
size(location) > 0 ? location['country_code'] : "UNKNOWN"
```

### Combining Conditions

```cel
// AND conditions
condition1 && condition2 && condition3

// OR conditions
condition1 || condition2 || condition3

// Complex logic
(condition1 && condition2) || (condition3 && condition4)

// Negation
!(condition1 || condition2)
```

### String Manipulation

```cel
// Concatenation
"prefix_" + value + "_suffix"

// Case conversion
value.lower()
value.upper()

// Substring
value.substring(0, 5)

// Replace
value.replace("old", "new")

// Split
value.split(",")
```

### List Operations

```cel
// Check membership
value in [1, 2, 3]

// Filter
[1, 2, 3, 4].filter(x, x > 2)

// Map
[1, 2, 3].map(x, x * 2)

// Any
[1, 2, 3].exists(x, x == 2)

// All
[1, 2, 3].all(x, x > 0)
```

### Map Operations

```cel
// Access
map['key']

// Check key
'key' in map

// Size
size(map)
size(map) > 0

// Multiple keys
'key1' in map && 'key2' in map
```

### Type Conversions

```cel
// To string
string(123)
string(true)

// To int
int("123")

// To double
double("3.14")
```

### Regular Expressions

```cel
// Match pattern
value.matches('^[a-z]+$')

// Email validation
email.matches('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$')

// URL validation
url.matches('^https?://.*')
```

---

## Best Practices

1. **Always Check Context Variables**: Use `size(variable) > 0` before accessing
2. **Provide Defaults**: Use ternary operator for safe fallbacks
3. **Keep Expressions Simple**: Break complex logic into multiple rules
4. **Use Parentheses**: Make precedence explicit in complex expressions
5. **Test Thoroughly**: Verify expressions with various inputs
6. **Document Complex Logic**: Add comments to explain non-obvious expressions
7. **Avoid Side Effects**: CEL expressions should be pure (no external state changes)
8. **Consider Performance**: Complex expressions may be slower
9. **Use Type-Safe Operations**: CEL will error on type mismatches
10. **Handle Null/Empty Cases**: Always consider missing data scenarios

---

## Additional Resources

- [CEL Specification](https://github.com/google/cel-spec/blob/master/doc/langdef.md)
- [CEL Go Documentation](https://pkg.go.dev/github.com/google/cel-go/cel)
- [CEL Playground](https://playcel.undistro.io/)
- [Package README](./README.md)
- [Test Summary](./TEST_SUMMARY.md)

