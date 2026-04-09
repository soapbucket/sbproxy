# Middleware Package

The `middleware` package provides HTTP middleware for the proxy server, including authentication, tracing, IP geolocation, request tracking, and more.

## Overview

This package provides:
- Request/Response middleware chain
- Context management (RequestID, Flags, CommonHeaders)
- IP geolocation integration
- Session management
- OpenTelemetry tracing integration
- Graceful shutdown support

## Middleware Components

### 1. RequestID Middleware

Adds unique request ID for tracing:

```go
router.Use(middleware.RequestID)
```

### 2. GeoIP Middleware

Adds IP geolocation data:

```go
settings := &geoip.Settings{Driver: geoip.DriverGeoIP, Params: map[string]string{geoip.ParamPath: "/path/to/geoip_country.mmdb"}}
ipManager, _ := geoip.NewManager(settings)
router.Use(middleware.GeoIP(ipManager))
```

### 3. CommonHeaders Middleware

Parses User-Agent and Content-Type:

```go
settings := &uaparser.Settings{Driver: uaparser.DriverUAParser, Params: map[string]string{uaparser.ParamRegexFile: "/path/to/regexes.yaml"}}
uaManager, _ := uaparser.NewManager(settings)
router.Use(middleware.CommonHeaders(uaManager))
```

### 4. Session Middleware

Manages user sessions:

```go
sessionCache, _ := cacher.NewCacher(&cacher.Settings{Driver: "redis"})
router.Use(middleware.Session(sessionCache))
```

### 6. Flags Middleware

Parses query flags (debug, trace, etc.):

```go
router.Use(middleware.Flags)
```

### 7. ForceSSL Middleware

Redirects HTTP to HTTPS:

```go
router.Use(middleware.ForceSSL)
```

### 8. Tracing Middleware

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
    chimiddleware "github.com/go-chi/chi/v5/middleware"
    proxymiddleware "github.com/soapbucket/sbproxy/internal/engine/middleware"
    "github.com/soapbucket/sbproxy/internal/request/geoip"
    "github.com/soapbucket/sbproxy/internal/request/uaparser"
    "github.com/soapbucket/sbproxy/internal/cache/store"
)

func SetupRouter(logger *slog.Logger) *chi.Mux {
    router := chi.NewRouter()
    
    // Standard chi middleware
    router.Use(chimiddleware.RealIP)
    router.Use(chimiddleware.Logger)
    router.Use(chimiddleware.Recoverer)
    
    // Proxy middleware
    router.Use(proxymiddleware.RequestID)
    router.Use(proxymiddleware.Flags)
    
    // GeoIP
    geoipSettings := &geoip.Settings{Driver: geoip.DriverGeoIP, Params: map[string]string{geoip.ParamPath: "/etc/sbproxy/geoip_country.mmdb"}}
    ipManager, _ := geoip.NewManager(geoipSettings)
    router.Use(proxymiddleware.GeoIP(ipManager))
    
    // Common headers (user-agent parsing)
    uaSettings := &uaparser.Settings{Driver: uaparser.DriverUAParser}
    uaManager, _ := uaparser.NewManager(uaSettings)
    router.Use(proxymiddleware.CommonHeaders(uaManager))
    
    // Session
    sessionCache, _ := cacher.NewCacher(&cacher.Settings{Driver: "redis"})
    router.Use(proxymiddleware.Session(sessionCache))
    
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

### With GeoIP Package

```go
import "github.com/soapbucket/sbproxy/internal/request/geoip"

// Middleware
router.Use(middleware.GeoIP(ipManager))

// Handler
func MyHandler(w http.ResponseWriter, r *http.Request) {
    if geoInfo, ok := geoip.GetFromRequest(r); ok {
        fmt.Fprintf(w, "Country: %s\n", geoInfo.Country)
    }
}
```

### With Session Package

```go
import "github.com/soapbucket/sbproxy/internal/request/session"

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
    
    router.Get("/test", func(w http.ResponseWriter, r *http.Request) {
        // All middleware should have run
        rid := middleware.GetRequestIDFromRequest(r)
        flags := middleware.GetFlagsFromRequest(r)
        
        assert.NotNil(t, rid)
        assert.NotNil(t, flags)
        
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
├── middleware.go          # Core middleware setup
├── geoip.go               # GeoIP middleware
├── uaparser.go            # User-agent parsing middleware
├── tracing.go             # OpenTelemetry tracing middleware
├── bot_detection.go       # Bot detection middleware
├── correlation_id.go      # Request correlation ID middleware
├── validation.go          # Request validation middleware
├── shutdown.go            # Graceful shutdown middleware
├── fastpath.go            # Fast-path routing optimization
└── README.md              # This file
```

## Related Packages

- **internal/request/geoip**: IP geolocation
- **internal/request/session**: Session management
- **internal/cache/store**: Session caching
- **internal/platform/storage**: Origin storage

## Best Practices

1. **Order Matters**: Apply middleware in correct order
2. **Context Propagation**: Always pass context through chain
3. **Error Handling**: Handle middleware errors gracefully
4. **Performance**: Minimize middleware overhead
5. **Testing**: Test middleware in isolation and as chain

## See Also

- [GeoIP Package](../../request/geoip/README.md)
- [Session Package](../../request/session/README.md)
