# Middleware Package

The `middleware` package provides HTTP middleware for the proxy server, including authentication, tracing, IP geolocation, request tracking, and more.

## Overview

This package provides:
- Request/Response middleware chain
- Context management (RequestID, Fingerprint, Flags, CommonHeaders)
- IP geolocation integration
- OAuth authentication
- Session management
- Origin loading and routing

## Middleware Components

### 1. RequestID Middleware

Adds unique request ID for tracing:

```go
router.Use(middleware.RequestID)
```

### 2. IPInfo Middleware

Adds IP geolocation data:

```go
ipManager, _ := location.NewIPInfoManager("/path/to/ipinfo.mmdb")
router.Use(middleware.IPInfo(ipManager))
```

### 3. CommonHeaders Middleware

Parses User-Agent and Content-Type:

```go
uaParser, _ := uaparser.New("/path/to/regexes.yaml")
router.Use(middleware.CommonHeaders(uaParser))
```

### 4. Fingerprint Middleware

Generates request fingerprint:

```go
router.Use(middleware.Fingerprint)
```

### 5. Session Middleware

Manages user sessions:

```go
sessionCache := cacher.NewCacher(redisClient)
router.Use(middleware.Session(sessionCache))
```

### 6. OAuth Middleware

Handles OAuth authentication:

```go
router.Use(middleware.OAuth(sessionCache))
```

### 7. Origin Loader Middleware

Loads origin configuration:

```go
storageReader := storage.NewStorageReader(redisClient)
router.Use(middleware.OriginLoader(storageReader, 10, 5*time.Minute))
```

### 8. Flags Middleware

Parses query flags (debug, trace, etc.):

```go
router.Use(middleware.Flags)
```

### 9. ForceSSL Middleware

Redirects HTTP to HTTPS:

```go
router.Use(middleware.ForceSSL)
```

### 10. Tracing Middleware

Adds OpenTelemetry tracing:

```go
router.Use(middleware.Tracing)
```

## Local Types

### RequestID

Unique request identifier with recursion tracking:

```go
type RequestID struct {
    ID    uuid.UUID
    Index int
}

// Usage
requestID := middleware.GetRequestIDFromRequest(r)
fmt.Printf("Request: %s\n", requestID)
```

### FingerprintData

Request fingerprint for deduplication:

```go
type FingerprintData struct {
    IP             string
    UserAgent      string
    Fingerprint    string
    ConnectionTime int
}

// Usage
fingerprint := middleware.GetFingerprintFromRequest(r)
```

### Flags

Custom request flags from query parameters:

```go
type Flags map[string]string

// Usage
flags := middleware.GetFlagsFromRequest(r)
if _, debug := flags["debug"]; debug {
    // Debug mode enabled
}
```

### CommonHeadersData

Parsed common HTTP headers:

```go
type CommonHeadersData struct {
    UserAgent   *uaparser.Client
    ContentType string
    Charset     string
}

// Usage
headers := middleware.GetCommonHeadersFromRequest(r)
if headers.UserAgent != nil {
    fmt.Printf("Browser: %s\n", headers.UserAgent.UserAgent.Family)
}
```

## Complete Middleware Stack Example

```go
package main

import (
    "log/slog"
    "net/http"
    
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "github.com/soapbucket/proxy/internal/middleware" as proxymiddleware
    "github.com/soapbucket/proxy/internal/location"
    "github.com/soapbucket/proxy/lib/cacher"
    "github.com/soapbucket/proxy/lib/storage"
)

func SetupRouter(logger *slog.Logger) *chi.Mux {
    router := chi.NewRouter()
    
    // Standard chi middleware
    router.Use(middleware.RealIP)
    router.Use(middleware.Logger)
    router.Use(middleware.Recoverer)
    
    // Proxy middleware
    router.Use(proxymiddleware.RequestID)
    router.Use(proxymiddleware.Flags)
    router.Use(proxymiddleware.Fingerprint)
    
    // IP Info
    ipManager, _ := location.NewIPInfoManager("/etc/proxy/ipinfo.mmdb")
    router.Use(proxymiddleware.IPInfo(ipManager))
    
    // Common headers
    uaParser, _ := uaparser.New("/etc/proxy/regexes.yaml")
    router.Use(proxymiddleware.CommonHeaders(uaParser))
    
    // Session and OAuth
    sessionCache := cacher.NewCacher(redisClient)
    router.Use(proxymiddleware.Session(sessionCache))
    router.Use(proxymiddleware.OAuth(sessionCache))
    
    // Origin loading
    storageReader := storage.NewStorageReader(redisClient)
    router.Use(proxymiddleware.OriginLoader(storageReader, 10, 5*time.Minute))
    
    // Tracing (if enabled)
    router.Use(proxymiddleware.Tracing)
    
    return router
}
```

## Context Helper Functions

All middleware types provide context helpers:

```go
// RequestID
rid := middleware.GetRequestIDFromRequest(r)
r = middleware.AddRequestIDToRequest(r, rid)

// Fingerprint
fp := fingerprint.GetFingerprintFromRequest(r)
r = fingerprint.AddFingerprintToRequest(r, fp)

// Flags
flags := middleware.GetFlagsFromRequest(r)
r = middleware.AddFlagsToRequest(r, flags)

// CommonHeaders
headers := middleware.GetCommonHeadersFromRequest(r)
r = middleware.AddCommonHeadersToRequest(r, headers)

// Check debug mode
isDebug := middleware.IsDebugRequest(r)
```

## Integration with Other Packages

### With Location Package

```go
import "github.com/soapbucket/proxy/internal/location"

// Middleware
router.Use(middleware.IPInfo(ipManager))

// Handler
func MyHandler(w http.ResponseWriter, r *http.Request) {
    if ipInfo, ok := location.GetIPInfoFromRequest(r); ok {
        fmt.Fprintf(w, "Country: %s\n", ipInfo.Country)
    }
}
```

### With OAuth Package

```go
import "github.com/soapbucket/proxy/internal/oauth"

// Middleware
router.Use(middleware.OAuth(sessionCache))

// Handler - check authentication
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
    if !oauth.IsAuthenticated(r) {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    
    user, _ := oauth.GetOAuthUserFromRequest(r)
    fmt.Fprintf(w, "Hello, %s!\n", user.Name)
}
```

### With Session Package

```go
import "github.com/soapbucket/proxy/internal/session"

// Middleware
router.Use(middleware.Session(sessionCache))

// Handler - get session
func MyHandler(w http.ResponseWriter, r *http.Request) {
    sessionID := session.GetSessionIDFromRequest(r)
    if sessionID == "" {
        http.Error(w, "No session", http.StatusUnauthorized)
        return
    }
    
    fmt.Fprintf(w, "Session: %s\n", sessionID)
}
```

### With Origin Package

```go
import "github.com/soapbucket/proxy/internal/origin"

// Middleware
router.Use(middleware.OriginLoader(storageReader, 10, 5*time.Minute))

// Handler - get origin
func ProxyHandler(w http.ResponseWriter, r *http.Request) {
    originCfg := origin.GetOriginConfigFromRequest(r)
    if originCfg == nil {
        http.Error(w, "Origin not found", http.StatusNotFound)
        return
    }
    
    // Use origin transport
    transport := originCfg.GetTransport()
    resp, _ := transport.RoundTrip(r)
    // ... handle response
}
```

## Testing

### Unit Test Example

```go
func TestRequestIDMiddleware(t *testing.T) {
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        rid := middleware.GetRequestIDFromRequest(r)
        assert.NotNil(t, rid)
        assert.NotEqual(t, uuid.Nil, rid.ID)
        w.WriteHeader(http.StatusOK)
    })
    
    middleware := middleware.RequestID(handler)
    
    req := httptest.NewRequest("GET", "/", nil)
    w := httptest.NewRecorder()
    
    middleware.ServeHTTP(w, req)
    assert.Equal(t, http.StatusOK, w.Code)
}
```

### Integration Test

```go
func TestMiddlewareChain(t *testing.T) {
    router := chi.NewRouter()
    router.Use(middleware.RequestID)
    router.Use(middleware.Flags)
    router.Use(middleware.Fingerprint)
    
    router.Get("/test", func(w http.ResponseWriter, r *http.Request) {
        // All middleware should have run
        rid := middleware.GetRequestIDFromRequest(r)
        flags := middleware.GetFlagsFromRequest(r)
        fp := middleware.GetFingerprintFromRequest(r)
        
        assert.NotNil(t, rid)
        assert.NotNil(t, flags)
        assert.NotNil(t, fp)
        
        w.WriteHeader(http.StatusOK)
    })
    
    req := httptest.NewRequest("GET", "/test?debug=1", nil)
    w := httptest.NewRecorder()
    
    router.ServeHTTP(w, req)
    assert.Equal(t, http.StatusOK, w.Code)
}
```

## Architecture

```
middleware/
├── middleware.go         # Router setup
├── types.go             # Local types (RequestID, Flags, etc.)
├── request_id.go        # RequestID middleware
├── fingerprint.go       # Fingerprint middleware
├── flags.go             # Flags middleware
├── common_headers.go    # CommonHeaders middleware
├── ipinfo.go           # IPInfo middleware
├── session.go          # Session middleware
├── oauth.go            # OAuth middleware
├── origin_loader.go    # Origin loader middleware
├── tracing.go          # Tracing middleware
├── force_ssl.go        # ForceSSL middleware
└── README.md          # This file
```

## Related Packages

- **location**: IP geolocation
- **oauth**: OAuth authentication
- **session**: Session management
- **origin**: Origin loading
- **cacher**: Session caching
- **storage**: Origin storage

## Best Practices

1. **Order Matters**: Apply middleware in correct order
2. **Context Propagation**: Always pass context through chain
3. **Error Handling**: Handle middleware errors gracefully
4. **Performance**: Minimize middleware overhead
5. **Testing**: Test middleware in isolation and as chain

## See Also

- [Location Package README](../location/README.md)
- [OAuth Package README](../oauth/README.md)
- [Session Package README](../session/README.md)
- [Origin Package README](../origin/README.md)
