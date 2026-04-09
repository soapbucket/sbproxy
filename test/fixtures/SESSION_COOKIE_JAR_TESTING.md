# Session Cookie Jar Integration Testing

## Overview

This document describes how to test the session-based cookie jar feature end-to-end.

## Test Configuration

The test configuration is located at `test/fixtures/session_cookie_jar_test.json`.

### Configuration Details

```json
{
  "session_config": {
    "enable_cookie_jar": true,
    "cookie_jar_config": {
      "max_cookies": 50,
      "max_cookie_size": 4096,
      "store_secure_only": false,
      "disable_store_http_only": false
    }
  }
}
```

## Manual Testing Steps

### Setup

1. Start the proxy server with the test configuration:
```bash
cd /Users/rick/projects/proxy
./proxy --config test/fixtures/session_cookie_jar_test.json
```

2. Start a mock backend server that sets cookies:
```bash
# Simple Python backend for testing
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/login':
            # Set cookies on login
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Set-Cookie', 'session_id=abc123; Path=/api')
            self.send_header('Set-Cookie', 'auth_token=xyz789; Path=/')
            self.end_headers()
            self.wfile.write(b'{\"status\": \"logged_in\"}')
        elif self.path == '/api/profile':
            # Check for cookies
            cookies = self.headers.get('Cookie', '')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(f'{{\"cookies_received\": \"{cookies}\"}}'.encode())
        else:
            self.send_response(404)
            self.end_headers()

HTTPServer(('', 8080), Handler).serve_forever()
"
```

### Test Scenarios

#### Test 1: Cookie Storage

1. Make login request (creates session and stores backend cookies):
```bash
curl -v -c cookies.txt http://cookie-test.example.com/api/login
```

Expected:
- Response includes `Set-Cookie` for proxy session
- Backend cookies are stored in session (not visible to client)

2. Make profile request with same session:
```bash
curl -v -b cookies.txt http://cookie-test.example.com/api/profile
```

Expected:
- Proxy injects stored backend cookies into request
- Backend receives: `Cookie: session_id=abc123; auth_token=xyz789`
- Client only sends proxy session cookie

#### Test 2: Domain Isolation

1. Setup multiple backends with different domains
2. Set cookies from each backend
3. Verify cookies are only sent to matching domains

#### Test 3: Cookie Expiration

1. Set cookies with short expiration
2. Wait for expiration
3. Verify expired cookies are not sent

#### Test 4: Max Cookies Limit

1. Set `max_cookies: 5` in config
2. Generate 10 cookies from backend
3. Verify only 5 most recent cookies are stored

#### Test 5: Secure Only Filter

1. Set `store_secure_only: true` in config
2. Backend sets both secure and non-secure cookies
3. Verify only secure cookies are stored

## Automated Integration Test

Create `test/integration/cookie_jar_test.go`:

```go
package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCookieJarIntegration(t *testing.T) {
	// Setup mock backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{
				Name:  "session_id",
				Value: "test123",
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
			return
		}
		
		if r.URL.Path == "/profile" {
			cookies := r.Cookies()
			if len(cookies) == 0 {
				t.Error("Expected cookies to be injected")
			}
			w.WriteHeader(http.StatusOK)
			return
		}
	}))
	defer backend.Close()

	// Setup proxy config pointing to backend
	// ... create test proxy with session + cookie jar enabled ...

	// Test flow:
	// 1. Client -> Proxy -> Backend /login (sets cookie)
	// 2. Client -> Proxy -> Backend /profile (cookie injected)
	
	// TODO: Implement full integration test
}
```

## Debugging

### Enable Debug Logging

Set `debug: true` in config to see cookie jar operations:

```json
{
  "debug": true,
  "session_config": {
    "enable_cookie_jar": true
  }
}
```

Expected log output:
```
level=DEBUG msg="initialized session cookie jar" session_id=xyz cookie_count=0 max_cookies=50
level=DEBUG msg="injected cookies into proxied request" url=https://backend.example.com/api host=backend.example.com cookie_count=2
level=DEBUG msg="captured cookies from proxied response" url=https://backend.example.com/api host=backend.example.com cookie_count=1
level=DEBUG msg="synced cookie jar to session data" url=https://backend.example.com/api
level=DEBUG msg="synced cookie jar to session before save" session_id=xyz cookie_count=3
```

### Inspect Session Data

Use the API endpoint to inspect session:

```bash
curl -b cookies.txt http://cookie-test.example.com/__api/session | jq
```

Expected output:
```json
{
  "id": "session-id",
  "data": {
    "cookies": [
      {
        "name": "session_id",
        "value": "abc123",
        "domain": "backend.example.com",
        "path": "/api",
        "secure": false,
        "http_only": true
      }
    ]
  }
}
```

## Performance Testing

### Test Cookie Jar Overhead

```bash
# Without cookie jar
ab -n 1000 -c 10 http://cookie-test.example.com/api/profile

# With cookie jar enabled
# Compare requests/second and latency
```

Expected overhead: < 1ms per request

### Memory Usage

Monitor session storage size:

```bash
# Check Redis memory usage
redis-cli info memory

# Or Pebble database size
du -sh tmp/pebble.db
```

With 10,000 sessions × 20 cookies each:
- Expected: ~30-60 MB (with encryption)

## Troubleshooting

### Cookies Not Being Stored

**Symptoms**: Backend cookies not appearing in subsequent requests

**Check**:
1. `enable_cookie_jar: true` in config
2. Sessions are enabled (`disabled: false`)
3. Backend is actually setting cookies (check response headers)
4. Cookie domain matches proxied domain
5. Cookie size within `max_cookie_size` limit

**Debug**:
```bash
# Enable debug logging
# Check logs for: "initialized session cookie jar"
# Should see: "captured cookies from proxied response"
```

### Cookies Not Being Sent

**Symptoms**: Backend doesn't receive expected cookies

**Check**:
1. Domain matching (cookie domain must match request host)
2. Path matching (cookie path must match or be prefix of request path)
3. Cookie hasn't expired
4. `Secure` flag matches request scheme (HTTPS)

**Debug**:
```bash
# Check logs for: "injected cookies into proxied request"
# Count should match expected cookies
```

### Session Size Too Large

**Symptoms**: Redis errors, slow performance

**Solutions**:
1. Reduce `max_cookies` (default: 100)
2. Reduce `max_cookie_size` (default: 4096)
3. Enable `store_secure_only: true`
4. Increase Redis memory limit

## Next Steps

After successful integration testing:

1. **Load Testing**: Test with realistic traffic patterns
2. **Security Audit**: Verify cookie isolation between sessions
3. **Monitoring**: Set up alerts for cookie jar metrics
4. **Documentation**: Update API documentation with cookie jar examples

## Related Documentation

- [Session Cookie Jar Feature Documentation](../../docs/SESSION_COOKIE_JAR.md)
- [Session Management](../../docs/SESSION.md)
- [Configuration Guide](../../docs/CONFIG.md)

