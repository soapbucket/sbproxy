// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	cmiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/soapbucket/sbproxy/internal/app/debug"
	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/httpkit/compressor"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/loader/configloader"
	"github.com/soapbucket/sbproxy/internal/loader/featureflags"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/platform/health"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// CompiledOriginLookup provides lock-free hostname lookup for the compiled
// config fast path. Implemented by service.CompiledConfigManager.
type CompiledOriginLookup interface {
	LookupOrigin(host string) *config.CompiledOrigin
}

// CompiledOriginAdder extends CompiledOriginLookup with the ability to add
// a single origin on the fly (compile-on-demand caching). Optional - if the
// CompiledOriginLookup also implements this, newly compiled origins are cached.
type CompiledOriginAdder interface {
	AddOrigin(origin *config.CompiledOrigin)
}

// RouterOptions holds optional dependencies for the router.
type RouterOptions struct {
	AdminKey    string                 // Admin API key for traffic inspector auth. Empty disables auth.
	CompiledCfg CompiledOriginLookup   // Pre-compiled config for fast-path serving. May be nil.
	Loader      *configloader.Loader   // Injected config loader. Falls back to configloader.DefaultLoader().
	SvcProvider plugin.ServiceProvider // Service provider for compile-on-demand. May be nil (disables compile-on-demand).
}

// Router builds the global HTTP middleware stack and attaches the origin handler.
//
// Middleware ordering rationale:
//   - Recoverer is first so panics in any layer are caught.
//   - Compression wraps early so all responses are compressed.
//   - RealIP and FastPath run before logging so the log sees the correct client IP.
//   - Validation/security run before enrichers to reject bad requests cheaply.
//   - Health check endpoints are registered before the catch-all origin handler
//     so they respond without loading any origin config.
func Router(m manager.Manager, opts ...RouterOptions) *chi.Mux {

	var routerOpts RouterOptions
	if len(opts) > 0 {
		routerOpts = opts[0]
	}

	router := chi.NewRouter()

	router.Use(cmiddleware.Recoverer)
	router.Use(compressor.Compressor(m.GetGlobalSettings().CompressionLevel))
	router.Use(cmiddleware.RealIP)
	router.Use(FastPathMiddleware) // Combined RequestData and CaptureOriginalRequest
	router.Use(CorrelationIDMiddleware)
	router.Use(logging.RequestLoggerMiddleware)

	// Graceful shutdown middleware (reject new requests during shutdown, track in-flight requests)
	healthManager := health.GetManager()
	router.Use(ShutdownMiddleware(healthManager))

	// NOTE: Security headers are now applied via security_headers policy in config, not globally
	// This prevents duplicate headers when both global middleware and config policies set them

	// Security validation middleware (applied early in the chain)
	router.Use(ValidationMiddleware(DefaultValidationConfig()))
	router.Use(RequestSizeLimitMiddleware(DefaultRequestSizeLimitConfig()))
	router.Use(ContentTypeValidationMiddleware(DefaultContentTypeValidationConfig()))

	// Run all registered enrichers (geoip, uaparser, etc.)
	router.Use(EnricherMiddleware)
	router.Use(featureflags.FlagsMiddleware)
	router.Use(debug.DebugMiddleware)

	// tracing
	router.Use(TracingMiddleware)

	// Health check endpoints (no authentication required)
	router.Get("/health", healthManager.HealthHandler())
	router.Get("/ready", healthManager.ReadyHandler())
	router.Get("/live", healthManager.LiveHandler())

	// K8s-style health check endpoints with dependency status
	router.Get("/healthz", healthManager.HealthzHandler())
	router.Get("/readyz", healthManager.ReadyzHandler())
	router.Get("/livez", healthManager.LivezHandler())

	// Internal workspace drain API (localhost-only for operator communication)
	router.Post("/_sb/internal/drain", handleDrainWorkspace)
	router.Post("/_sb/internal/undrain", handleUndrainWorkspace)
	router.Get("/_sb/internal/drain/status", handleDrainStatus)

	router.Handle("/*", NewOriginHandler(m, routerOpts))

	return router
}

// OriginHandler resolves an incoming request to the correct origin configuration
// and dispatches it through the pre-compiled per-origin handler chain.
//
// Three-tier lookup strategy:
//  1. Fast path: atomic load from CompiledConfigManager (map lookup, ~10ns, 0 allocs).
//  2. Compile-on-demand: load config from storage, compile, cache for future fast-path hits.
//  3. Not found: return 421 Misdirected Request.
type OriginHandler struct {
	manager     manager.Manager
	loader      *configloader.Loader   // injected config loader
	compiledCfg CompiledOriginLookup   // fast path: pre-compiled handler chain
	svcProvider plugin.ServiceProvider // for compile-on-demand (may be nil)
	opts        RouterOptions
}

// NewOriginHandler creates a handler that loads origin configs and dispatches requests.
func NewOriginHandler(m manager.Manager, opts RouterOptions) *OriginHandler {
	loader := opts.Loader
	if loader == nil {
		loader = configloader.DefaultLoader()
	}
	return &OriginHandler{
		manager:     m,
		loader:      loader,
		compiledCfg: opts.CompiledCfg,
		svcProvider: opts.SvcProvider,
		opts:        opts,
	}
}

func (h *OriginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path 1 - V2 fast path: pre-compiled handler chain (atomic load + map lookup, ~10ns, 0 allocs).
	// If the origin is in the compiled config, serve directly and skip the per-request
	// config loading path entirely. Origins not yet compiled fall through.
	if h.compiledCfg != nil {
		if origin := h.compiledCfg.LookupOrigin(r.Host); origin != nil {
			origin.ServeHTTP(w, r)
			return
		}
	}

	// Path 2 - Compile on demand: load config from storage, compile it, cache it,
	// and serve. This path handles database-loaded origins that were not in the
	// inline config snapshot. On success the compiled origin is added to the
	// CompiledConfigManager so subsequent requests use the fast path.
	if h.svcProvider != nil {
		compiled, err := h.loader.LoadCompiledOrigin(r, h.manager, h.svcProvider)
		if err != nil {
			slog.Error("error loading/compiling origin", "error", err,
				"error_category", logging.ErrorCategoryConfig, "error_source", logging.ErrorSourceConfig)
			httputil.HandleError(httputil.HttpStatusUnknownError, err, w, r)
			return
		}
		if compiled != nil {
			// Cache the compiled origin so the next request uses the fast path.
			if h.compiledCfg != nil {
				if adder, ok := h.compiledCfg.(CompiledOriginAdder); ok {
					adder.AddOrigin(compiled)
				}
			}
			compiled.ServeHTTP(w, r)
			return
		}
		// compiled == nil means no config found for this host.
		slog.Debug("no compiled origin found", "host", r.Host)
	}

	// Origin not found or compilation failed - return 421 Misdirected Request.
	httputil.HandleError(httputil.HttpStatusOriginUnreachable, ErrConfigNotReachable, w, r)
}
