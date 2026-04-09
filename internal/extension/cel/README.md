# CEL (Common Expression Language) Package

This package provides CEL expression evaluation capabilities for HTTP request matching, request modification, response modification, JSON modification, and HTML token matching.

## Overview

The CEL package allows you to write dynamic expressions that can:
- **Match** HTTP requests based on various criteria
- **Modify** HTTP requests (headers, path, method, query parameters)
- **Modify** HTTP responses (headers, status code, body)
- **Modify** JSON objects
- **Match** HTML tokens for parsing and manipulation

## Context Variables

CEL expressions have access to rich context variables extracted from HTTP requests:

### Request Context (`request`)
Standard HTTP request fields from the protobuf AttributeContext.Request:
- `request.id` - Unique request ID
- `request.method` - HTTP method (GET, POST, etc.)
- `request.path` - URL path
- `request.host` - Host header value
- `request.scheme` - URL scheme (http, https)
- `request.query` - URL-encoded query string
- `request.protocol` - HTTP protocol version
- `request.headers` - HTTP headers map (keys are lowercase with hyphens converted to underscores)
- `request.size` - Content-Length of request body
- `request.time` - Request timestamp

### Cookies (`cookies`)
Map of cookie names to values:
- `cookies['cookie_name']` - Access specific cookie value

### Query Parameters (`params`)
Map of query parameter names to values:
- `params['param_name']` - Access specific query parameter

### User Agent (`user_agent`)
Parsed user agent information (may be `null` if not available):
- `user_agent['family']` - Browser family (e.g., "Chrome", "Firefox")
- `user_agent['major']` - Browser major version
- `user_agent['minor']` - Browser minor version
- `user_agent['patch']` - Browser patch version
- `user_agent['os_family']` - OS family (e.g., "Windows", "Mac OS X")
- `user_agent['os_major']` - OS major version
- `user_agent['os_minor']` - OS minor version
- `user_agent['os_patch']` - OS patch version
- `user_agent['os_patch_minor']` - OS patch minor version
- `user_agent['device_family']` - Device family (e.g., "iPhone", "Samsung")
- `user_agent['device_brand']` - Device brand
- `user_agent['device_model']` - Device model

### Location Information (`location`)
Location/GeoIP and ASN information (always available as empty map if not present):
- `location['country']` - Country name
- `location['country_code']` - ISO country code (e.g., "US", "GB")
- `location['continent']` - Continent name
- `location['continent_code']` - Continent code (e.g., "NA", "EU")
- `location['asn']` - Autonomous System Number
- `location['as_name']` - AS organization name
- `location['as_domain']` - AS domain

### Session (`session`)
Session data if available (may be `null` if not authenticated):
- `session['id']` - Session ID
- `session['expires']` - Session expiration time (ISO 8601 format)
- `session['is_authenticated']` - Boolean indicating if user is authenticated
- `session['auth']` - Authentication data object (if authenticated, may be empty)
  - `session['auth']['type']` - Authentication type (e.g., "oauth", "jwt", "apikey")
  - `session['auth']['data']` - Nested auth data object (contains all auth data fields)
  - `session['auth']['id']` - User ID (from auth data, also in `data`)
  - `session['auth']['email']` - User email address (from auth data, also in `data`)
  - `session['auth']['name']` - User display name (from auth data, also in `data`)
  - `session['auth']['provider']` - OAuth provider (from auth data, also in `data`, e.g., "google", "github")
  - `session['auth']['roles']` - Array of roles (from auth data, also in `data`)
  - `session['auth']['permissions']` - Permissions map (from auth data, also in `data`)
  - All other fields from `AuthData.Data` are accessible both via `session['auth']['data']` and directly under `session['auth']`
- `session['data']` - Custom session data map (set by session callbacks)
- `session['visited_count']` - Number of URLs visited in session
- `session['cookie_count']` - Number of cookies in session

**Note**: `session['auth']` is set by authentication middleware (OAuth, JWT, etc.) and contains user identity, roles, and permissions. `session['data']` is set by session callbacks and contains custom session-specific data.

### Data Sources Overview

There are **4 persistent data objects** available in CEL expressions, each serving a different purpose:

1. **`config`** - Immutable configuration data from `on_load` callback
2. **`request_data`** - General request data from callbacks (excluding `on_load` and session/auth callbacks)
3. **`session['data']`** - Session-specific data from session callbacks
4. **`session['auth']['data']`** - Authentication data from authentication callbacks

### Config (`config`)

Immutable configuration data from `on_load` callback stored in `RequestData.Config`:
- `config` - Map containing configuration data from `on_load` callback
- Separate from other data sources to ensure immutability
- Set once during config initialization and never changes

**Set by**: `on_load` callback executed during config initialization
**When available**: After config initialization (before any request processing)
**Storage**: `RequestData.Config` (internal)
**Example**: `config['api_key']` - Access API key from `on_load` callback

### Request Data (`request_data`)

General request data from callbacks (excluding `on_load`, session, and auth callbacks):
- `request_data` - Map containing callback data
- Used for general-purpose data that doesn't belong in session or auth
- Keys depend on which callbacks have executed

**Set by**: Callbacks (excluding `on_load`, `session_config.callbacks`, and `authentication_callback`)
**When available**: After callback execution (varies by callback type)
**Storage**: `RequestData.Data` (internal)
**Example**: `request_data['feature_flags']['beta']` - Access feature flags from callback

**Note**: This is for general request data. Session-specific data should use `session['data']`, and authentication data should use `session['auth']['data']`.

### Session Data (`session['data']`)

Session-specific data from session callbacks stored in `SessionData.Data`:
- `session['data']` - Map containing custom session data
- Persists across requests within the same session
- Set by callbacks configured in `session_config.callbacks`

**Set by**: Session callbacks (configured in `session_config.callbacks`)
**When available**: After session callback execution (on first request or session refresh)
**Storage**: `SessionData.Data` (internal)
**Example**: `session['data']['user_prefs']['theme']` - Access user preferences from session callback

**Note**: Session callbacks store data in `SessionData.Data`, not `RequestData.Data`. Use `session['data']` to access this data.

### Auth Data (`session['auth']['data']`)

Authentication data from authentication callbacks stored in `AuthData.Data`:
- `session['auth']['data']` - Map containing authentication data (user identity, roles, permissions)
- Also accessible directly via `session['auth']['user_id']`, `session['auth']['roles']`, etc.
- Set by authentication middleware (OAuth, JWT, API Key with `authentication_callback`, etc.)

**Set by**: Authentication callbacks (e.g., `authentication_callback` in API Key auth, OAuth, JWT)
**When available**: After successful authentication
**Storage**: `AuthData.Data` (internal, stored in `SessionData.AuthData.Data`)
**Example**: `session['auth']['data']['user_id']` or `session['auth']['user_id']` - Access user ID from auth callback

**Note**: Authentication data is stored in `AuthData.Data` and is accessible via `session['auth']`. All fields from `AuthData.Data` are also directly accessible under `session['auth']` for convenience.

### Request IP (`request_ip`)
The client's IP address extracted from the request:
- Checks `X-Real-IP` header first (highest precedence)
- Falls back to first IP in `X-Forwarded-For` header
- Falls back to `RemoteAddr` if headers not present
- Returns empty string if IP cannot be determined

## IP Functions

CEL expressions have access to IP address manipulation functions:

### `ip.parse(string) -> map`
Parses an IP address and returns information about it:
```cel
ip.parse("192.168.1.1")
// Returns: {
//   "valid": true,
//   "ip": "192.168.1.1",
//   "is_ipv4": true,
//   "is_ipv6": false,
//   "is_private": true,
//   "is_loopback": false
// }
```

### `ip.inCIDR(ip, cidr) -> bool`
Checks if an IP address is within a CIDR range:
```cel
ip.inCIDR("192.168.1.100", "192.168.1.0/24")  // true
ip.inCIDR("10.0.1.50", "10.0.0.0/8")          // true
```

### `ip.isPrivate(ip) -> bool`
Checks if an IP address is in a private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.):
```cel
ip.isPrivate("192.168.1.1")  // true
ip.isPrivate("8.8.8.8")      // false
```

### `ip.isLoopback(ip) -> bool`
Checks if an IP address is a loopback address:
```cel
ip.isLoopback("127.0.0.1")  // true
ip.isLoopback("::1")        // true (IPv6)
```

### `ip.isIPv4(ip) -> bool`
Checks if an IP address is IPv4:
```cel
ip.isIPv4("192.168.1.1")    // true
ip.isIPv4("2001:db8::1")    // false
```

### `ip.isIPv6(ip) -> bool`
Checks if an IP address is IPv6:
```cel
ip.isIPv6("2001:db8::1")    // true
ip.isIPv6("192.168.1.1")    // false
```

### `ip.inRange(ip, start, end) -> bool`
Checks if an IP is within a range (inclusive):
```cel
ip.inRange("192.168.1.100", "192.168.1.1", "192.168.1.255")  // true
```

### `ip.compare(ip1, ip2) -> int`
Compares two IP addresses (returns -1, 0, or 1):
```cel
ip.compare("192.168.1.1", "192.168.1.2")  // -1 (first < second)
ip.compare("192.168.1.1", "192.168.1.1")  // 0 (equal)
ip.compare("192.168.1.2", "192.168.1.1")  // 1 (first > second)
```

## Usage Examples

### Request Matching

```go
// Match requests from Chrome browser
matcher, err := cel.NewMatcher(`user_agent != null && user_agent['family'] == 'Chrome'`)
if matcher.Match(req) {
    // Handle Chrome requests
}

// Match requests from US
matcher, err := cel.NewMatcher(`size(location) > 0 && location['country_code'] == 'US'`)

// Complex matching with multiple criteria
matcher, err := cel.NewMatcher(`
    request.method == 'POST' && 
    request.path.startsWith('/api/') &&
    user_agent != null &&
    user_agent['family'] == 'Chrome' &&
    size(location) > 0 &&
    location['country_code'] == 'US'
`)

// Match authenticated users with specific role
matcher, err := cel.NewMatcher(`
    session != null && 
    session['is_authenticated'] == true &&
    session['auth']['roles'].contains('admin')
`)

// Match requests from private IP ranges
matcher, err := cel.NewMatcher(`ip.isPrivate(request_ip)`)

// Match requests from specific CIDR range
matcher, err := cel.NewMatcher(`ip.inCIDR(request_ip, "10.0.0.0/8")`)

// Block requests from public IPs
matcher, err := cel.NewMatcher(`!ip.isPrivate(request_ip)`)

// Complex IP matching
matcher, err := cel.NewMatcher(`
    request.method == 'POST' &&
    (ip.inCIDR(request_ip, "10.0.0.0/8") || ip.inCIDR(request_ip, "172.16.0.0/12")) &&
    ip.isIPv4(request_ip)
`)
```

### Response Matching

Response matching allows you to evaluate HTTP responses based on status code, headers, body content, and request context. The expression must return a boolean value.

Available response variables:
- `response.status_code` - HTTP status code (int)
- `response.status` - HTTP status text (e.g., "200 OK")
- `response.headers` - Response headers map (keys are case-sensitive)
- `response.body` - Response body as string
- `request` - Original request context (all fields available)
- All request context variables (`request_ip`, `cookies`, `params`, `user_agent`, `location`, `session`, `oauth_user`)

```go
// Match specific status code
matcher, err := cel.NewResponseMatcher(`response.status_code == 200`)

// Match status code range (2xx success)
matcher, err := cel.NewResponseMatcher(`response.status_code >= 200 && response.status_code < 300`)

// Match 4xx client errors
matcher, err := cel.NewResponseMatcher(`response.status_code >= 400 && response.status_code < 500`)

// Match 5xx server errors
matcher, err := cel.NewResponseMatcher(`response.status_code >= 500`)

// Match specific content type
matcher, err := cel.NewResponseMatcher(`response.headers["Content-Type"].contains("application/json")`)

// Match body content
matcher, err := cel.NewResponseMatcher(`response.body.contains("error")`)

// Combined status and body check
matcher, err := cel.NewResponseMatcher(`response.status_code == 200 && response.body.contains("success")`)

// Match JSON error responses
matcher, err := cel.NewResponseMatcher(`
    response.status_code >= 400 && 
    response.headers["Content-Type"].contains("json") && 
    response.body.contains("error")
`)

// Match errors from specific endpoints
matcher, err := cel.NewResponseMatcher(`
    response.status_code == 404 && 
    request.path.startsWith("/api/")
`)

// Match errors for POST requests only
matcher, err := cel.NewResponseMatcher(`
    response.status_code >= 400 && 
    request.method == "POST"
`)

// Match successful responses from specific countries
matcher, err := cel.NewResponseMatcher(`
    response.status_code == 200 && 
    size(location) > 0 && 
    location["country_code"] == "US"
`)

// Match empty responses (204 No Content)
matcher, err := cel.NewResponseMatcher(`response.status_code == 204 && response.body == ""`)
```

### Request Modification

```go
// Add country header based on IP info
expr := `{
    "add_headers": {
        "X-Country": size(location) > 0 ? location['country_code'] : "UNKNOWN",
        "X-Continent": size(location) > 0 ? location['continent_code'] : "UNKNOWN"
    }
}`
modifier, err := cel.NewModifier(expr)
modifiedReq, err := modifier.Modify(req)

// Add browser and OS headers
expr := `{
    "add_headers": {
        "X-Browser": user_agent != null ? user_agent['family'] : "UNKNOWN",
        "X-OS": user_agent != null ? user_agent['os_family'] : "UNKNOWN"
    }
}`

// Add user email header if authenticated
expr := `{
    "add_headers": {
        "X-User-Email": size(session) > 0 && session['is_authenticated'] && size(session['auth']) > 0 ? session['auth']['email'] : ""
    }
}`

// Add IP-based headers
expr := `{
    "add_headers": {
        "X-Client-IP": request_ip,
        "X-IP-Type": ip.isPrivate(request_ip) ? "private" : "public",
        "X-IP-Version": ip.isIPv4(request_ip) ? "v4" : "v6"
    }
}`

// Add routing header based on IP range
expr := `{
    "add_headers": {
        "X-Internal": ip.inCIDR(request_ip, "10.0.0.0/8") ? "true" : "false"
    },
    "path": ip.isPrivate(request_ip) ? "/internal" + request.path : request.path
}`

// Modify path based on user agent
expr := `{
    "path": user_agent != null && user_agent['device_family'] == 'iPhone' ? "/mobile" + request.path : request.path
}`

// Add query parameter based on country
expr := `{
    "add_query": {
        "country": size(location) > 0 ? location['country_code'] : "XX"
    }
}`
```

### Response Modification

```go
// Add response headers based on request context
expr := `{
    "add_headers": {
        "X-Request-Country": size(location) > 0 ? location['country_code'] : "UNKNOWN",
        "X-Request-Browser": user_agent != null ? user_agent['family'] : "UNKNOWN"
    }
}`
modifier, err := cel.NewResponseModifier(expr)
err = modifier.ModifyResponse(resp)

// Modify response based on user role
expr := `{
    "set_headers": {
        "X-User-Role": session != null && session['is_authenticated'] ? "authenticated" : "anonymous"
    }
}`

// Change status code based on country
expr := `{
    "status_code": size(location) > 0 && location['country_code'] == 'US' ? 200 : 403
}`
```

### JSON Modification

```go
// Add country info to JSON response
expr := `{
    "set_fields": {
        "country": size(location) > 0 ? location['country_code'] : "UNKNOWN",
        "browser": user_agent != null ? user_agent['family'] : "UNKNOWN"
    }
}`
modifier, err := cel.NewJSONModifier(expr)
modifiedJSON, err := modifier.ModifyJSON(jsonObj)
```

## Null Safety and Map Checking

All context variables (`user_agent`, `location`, `session`) are always available as empty maps if the data is not available for a particular request. CEL doesn't support direct null comparison with maps, so use `size()` to check if a map has data:

```go
// Good: Check map size before accessing
`size(location) > 0 && location['country_code'] == 'US'`

// Good: Use ternary operator with size check
`size(location) > 0 ? location['country_code'] : 'UNKNOWN'`

// Good: Check specific field and use default
`size(user_agent) > 0 && user_agent['family'] == 'Chrome'`

// Bad: Direct null comparison with maps doesn't work in CEL
`location != null` // This will cause a compilation error - use size(location) > 0 instead

// Note: Maps are always present (never null) but may be empty
// Use size(map_name) to check if data is available
```

## Implementation Details

### Context Variable Extraction

Context variables are automatically extracted from the HTTP request when creating a `RequestContext`:

1. **User Agent**: Retrieved from `uaparser.Get(req)` - parsed user agent information
3. **IP Info**: Retrieved from `geoip.Get(req)` - GeoIP and ASN data
4. **Session**: Retrieved from context data with key "session" - session and authentication data

These values are converted to CEL-compatible maps using converter functions:
- `convertUserAgentToMap()` - Converts user agent result to map
- `convertLocationToMap()` - Converts Location to map
- `convertSessionDataToMap()` - Converts session data to map using reflection (to avoid import cycles)

### Avoiding Import Cycles

The session data conversion uses reflection to extract fields without importing the `session` package directly, which would create an import cycle since `session` imports `config`, and `config` imports `cel`.

## Testing

The package includes comprehensive unit tests for:
- Context variable conversion functions
- Request context creation and variable extraction
- CEL environment setup
- Null handling for all context variables

Run tests with:
```bash
go test ./internal/extension/cel -v
```

## Related Packages

- `internal/request/uaparser` - User agent parsing
- `internal/request/geoip` - GeoIP and ASN lookup
- `internal/request/session` - Session management
- `internal/request/reqctx` - Request context data storage

## Best Practices

1. **Always check for null**: Context variables may not be available for all requests
2. **Use meaningful variable names**: Make expressions readable and maintainable
3. **Test expressions**: Verify CEL expressions work as expected before deploying
4. **Performance**: Simple expressions are faster; avoid complex nested conditions when possible
5. **Security**: Be careful not to expose sensitive data in headers or logs
6. **Documentation**: Document complex expressions to explain their purpose

## Additional Resources

- **[CEL Language Guide](./CEL_LANGUAGE_GUIDE.md)** - Comprehensive CEL language reference with examples for all function types
- **[Test Summary](./TEST_SUMMARY.md)** - Test coverage, benchmarks, and performance metrics
- [CEL Specification](https://github.com/google/cel-spec/blob/master/doc/langdef.md) - Official CEL language definition
- [CEL Go Documentation](https://pkg.go.dev/github.com/google/cel-go/cel) - Go implementation docs
- [CEL Playground](https://playcel.undistro.io/) - Interactive CEL expression testing

