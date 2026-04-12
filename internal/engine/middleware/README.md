# Middleware Package

The `middleware` package provides HTTP middleware for the proxy server, including enrichment, tracing, bot detection, request tracking, and more.

## Overview

This package provides:
- Request/Response middleware chain
- Context management (RequestID, Flags)
- Enricher middleware (extensible per-request context enrichment via plugin system)
- Bot detection
- Threat protection
- Correlation ID assignment
- OpenTelemetry tracing integration
- Graceful shutdown support

## Middleware Components

### 1. RequestID Middleware

Adds unique request ID for tracing:

```go
router.Use(middleware.RequestID)
```

### 2. Enricher Middleware

Calls all registered `plugin.RequestEnricher` implementations to populate per-request context data (location, user agent, fingerprint, etc.). This replaces the previously hardcoded GeoIP and UA parser middleware.

Enterprise and third-party packages register enrichers via `plugin.RegisterEnricher()` in their `init()` functions. The enricher middleware runs them all without knowing what they do.

```go
router.Use(middleware.EnricherMiddleware)
```

See `pkg/plugin/` for the `RequestEnricher` interface.

### 3. Bot Detection Middleware

Detects and classifies bot traffic:

```go
router.Use(middleware.BotDetection)
```

### 4. Threat Protection Middleware

Protects against common attack patterns:

```go
router.Use(middleware.ThreatProtection)
```

### 5. Session Middleware

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

### 9. Correlation ID Middleware

Assigns or propagates correlation IDs across requests:

```go
router.Use(middleware.CorrelationID)
```

### 10. Validation Middleware

Validates incoming requests:

```go
router.Use(middleware.Validation)
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

// Check debug mode
isDebug := middleware.IsDebugRequest(r)
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

    // Enricher (calls all registered RequestEnrichers - GeoIP, UA parser, etc.)
    router.Use(proxymiddleware.EnricherMiddleware)

    // Session
    sessionCache, _ := cacher.NewCacher(&cacher.Settings{Driver: "redis"})
    router.Use(proxymiddleware.Session(sessionCache))

    // Tracing (if enabled)
    router.Use(proxymiddleware.Tracing)

    return router
}
```

## Integration with Other Packages

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

### With RequestData (Enrichment Results)

```go
import "github.com/soapbucket/sbproxy/internal/request/reqctx"

// Access enrichment data populated by EnricherMiddleware
func MyHandler(w http.ResponseWriter, r *http.Request) {
    rd := reqctx.GetRequestData(r.Context())
    if rd != nil && rd.Location != nil {
        fmt.Fprintf(w, "Country: %s\n", rd.Location.CountryCode)
    }
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

    mw := middleware.RequestID(handler)

    req := httptest.NewRequest("GET", "/", nil)
    w := httptest.NewRecorder()

    mw.ServeHTTP(w, req)
    assert.Equal(t, http.StatusOK, w.Code)
}
```

## Architecture

```
middleware/
├── middleware.go          # Core middleware setup
├── enricher.go            # Enricher middleware (calls registered RequestEnrichers)
├── tracing.go             # OpenTelemetry tracing middleware
├── bot_detection.go       # Bot detection middleware
├── threat_protection.go   # Threat protection middleware
├── correlation_id.go      # Request correlation ID middleware
├── validation.go          # Request validation middleware
├── shutdown.go            # Graceful shutdown middleware
├── fastpath.go            # Fast-path routing optimization
├── original_request.go    # Original request preservation
├── drain.go               # Connection drain support
├── errors.go              # Error definitions
└── README.md              # This file
```

## Related Packages

- **pkg/plugin**: RequestEnricher interface and registry
- **internal/request/reqctx**: Request context data (enrichment results)
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

- [Session Package](../../request/session/README.md)
