// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	cmiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/soapbucket/sbproxy/internal/app/api"
	"github.com/soapbucket/sbproxy/internal/app/billing"
	"github.com/soapbucket/sbproxy/internal/app/capture"
	"github.com/soapbucket/sbproxy/internal/httpkit/compressor"
	"github.com/soapbucket/sbproxy/internal/loader/configloader"
	"github.com/soapbucket/sbproxy/internal/app/debug"
	"github.com/soapbucket/sbproxy/internal/request/fingerprint"
	"github.com/soapbucket/sbproxy/internal/loader/featureflags"
	"github.com/soapbucket/sbproxy/internal/platform/health"
	"github.com/soapbucket/sbproxy/internal/cache/response"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/request/session"
)

// RouterOptions holds optional dependencies for the router.
type RouterOptions struct {
	CaptureManager *capture.Manager
	Meter          *billing.Meter
	AdminKey       string // Admin API key for traffic inspector auth. Empty disables auth.
}

// Router performs the router operation.
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

	// set the user agent, flags and location
	router.Use(UAParserMiddleware)
	router.Use(MaxMindMiddleware)
	router.Use(featureflags.FlagsMiddleware)
	router.Use(fingerprint.FingerprintMiddleware)
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

	// Traffic capture API endpoints (if capture manager is available)
	if routerOpts.CaptureManager != nil {
		trafficAPI := api.NewTrafficAPI(routerOpts.CaptureManager, routerOpts.AdminKey)
		router.Get("/_sb/api/traffic/exchanges", trafficAPI.HandleList)
		router.Get("/_sb/api/traffic/exchange", trafficAPI.HandleGet)
		router.Get("/_sb/api/traffic/stream", trafficAPI.HandleStream)
		router.Get("/_sb/api/traffic/metrics", trafficAPI.HandleMetrics)
		slog.Info("traffic capture API endpoints registered")
	}

	router.Handle("/*", NewOriginHandler(m, routerOpts))

	return router
}

// OriginHandler handles requests by loading the origin config and dispatching
// through the per-origin middleware stack. Extracted from the Router anonymous
// function to enable independent testing.
type OriginHandler struct {
	manager manager.Manager
	opts    RouterOptions
}

// NewOriginHandler creates a handler that loads origin configs and dispatches requests.
func NewOriginHandler(m manager.Manager, opts RouterOptions) *OriginHandler {
	return &OriginHandler{manager: m, opts: opts}
}

func (h *OriginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestStart := time.Now()

	cfg, err := configloader.Load(r, h.manager)
	if err != nil {
		slog.Error("error loading origin configuration", "error", err,
			"error_category", logging.ErrorCategoryConfig, "error_source", logging.ErrorSourceConfig)
		httputil.HandleError(httputil.HttpStatusUnknownError, err, w, r)
		return
	}

	if cfg == nil {
		httputil.HandleError(httputil.HttpStatusOriginUnreachable, ErrConfigNotReachable, w, r)
		return
	}
	if cfg.Disabled {
		slog.Warn("origin disabled", "config_id", cfg.ID)
		httputil.HandleError(httputil.HttpStatusOriginUnreachable, ErrConfigNotReachable, w, r)
		return
	}

	requestData := reqctx.GetRequestData(r.Context())
	requestData.AddDebugHeader(httputil.HeaderXSbOriginConfig, cfg.ID)
	requestData.AddDebugHeader(httputil.HeaderXSbOrigin, cfg.OriginChain())
	requestData.AddDebugHeader(httputil.HeaderXSbConfigMode, cfg.ConfigMode)
	requestData.AddDebugHeader(httputil.HeaderXSbConfigVersion, cfg.Version)
	if cfg.ConfigReason != "" {
		requestData.AddDebugHeader(httputil.HeaderXSbConfigReason, cfg.ConfigReason)
	}
	if cfg.Revision != "" {
		requestData.AddDebugHeader(httputil.HeaderXSbConfigRevision, cfg.Revision)
	}
	if !requestData.Debug {
		requestData.Debug = cfg.Debug
	}

	var next http.Handler = cfg

	// Add metering middleware if meter is available
	if h.opts.Meter != nil {
		next = MeteringMiddlewareWithConfig(h.opts.Meter, cfg)(next)
	}

	// Add chunk cache middleware if configured (presence of ChunkCache enables it)
	if cfg.ChunkCache != nil && !requestData.NoCache {
		chunkCacher, err := responsecache.NewChunkCacher(h.manager.GetCache(manager.L3Cache), cfg.ChunkCache)
		if err != nil {
			slog.Error("failed to initialize chunk cacher", "error", err, "config_id", cfg.ID)
		} else {
			next = chunkCacher.Middleware(next)
		}
	}

	// Add response cache middleware if configured (outermost cache layer, wraps chunk cache)
	if cfg.ResponseCache != nil && cfg.ResponseCache.Enabled && !requestData.NoCache {
		cacheBackend := h.manager.GetCache(manager.L3Cache)
		if cacheBackend == nil {
			cacheBackend = h.manager.GetCache(manager.L1Cache)
		}
		if cacheBackend != nil {
			varyHeaders := cfg.ResponseCache.VaryBy
			if len(varyHeaders) == 0 {
				varyHeaders = cfg.ResponseCache.VaryHeaders
			}
			rcConfig := responsecache.ResponseCacheConfig{
				Enabled:       true,
				DefaultTTL:    cfg.ResponseCache.TTL.Duration,
				MaxSize:       responsecache.MaxCacheableSize,
				VaryHeaders:   varyHeaders,
				IgnoreNoCache: cfg.ResponseCache.IgnoreNoCache,
				CachePrivate:  cfg.ResponseCache.CachePrivate,
				StoreNon200:   cfg.ResponseCache.StoreNon200,
			}
			if rcConfig.DefaultTTL == 0 {
				rcConfig.DefaultTTL = responsecache.DefaultResponseTTL
			}
			next = responsecache.ResponseCacheHandler(cacheBackend, rcConfig)(next)
		}
	}

	// Add traffic capture middleware if configured
	if cfg.TrafficCapture != nil && cfg.TrafficCapture.Enabled && h.opts.CaptureManager != nil {
		next = CaptureMiddleware(h.opts.CaptureManager, cfg.TrafficCapture, cfg.Hostname)(next)
	}

	// Add bot detection middleware if configured
	if cfg.BotDetection != nil && cfg.BotDetection.Enabled {
		bdConfig := &BotDetectionConfig{
			Enabled:       true,
			Mode:          cfg.BotDetection.Mode,
			AllowList:     cfg.BotDetection.AllowList,
			DenyList:      cfg.BotDetection.DenyList,
			ChallengeType: cfg.BotDetection.ChallengeType,
			VerifyGoodBot: cfg.BotDetection.VerifyGoodBot,
		}
		next = BotDetectionMiddleware(bdConfig)(next)
	}

	// Add threat protection middleware if configured (validates JSON/XML body structure)
	if cfg.ThreatProtection != nil && cfg.ThreatProtection.Enabled {
		tpConfig := &ThreatProtectionConfig{
			Enabled: true,
		}
		if cfg.ThreatProtection.JSON != nil {
			tpConfig.JSON = &JSONThreatConfig{
				MaxDepth:        cfg.ThreatProtection.JSON.MaxDepth,
				MaxKeys:         cfg.ThreatProtection.JSON.MaxKeys,
				MaxStringLength: cfg.ThreatProtection.JSON.MaxStringLength,
				MaxArraySize:    cfg.ThreatProtection.JSON.MaxArraySize,
				MaxTotalSize:    cfg.ThreatProtection.JSON.MaxTotalSize,
			}
		}
		if cfg.ThreatProtection.XML != nil {
			tpConfig.XML = &XMLThreatConfig{
				MaxDepth:             cfg.ThreatProtection.XML.MaxDepth,
				MaxAttributes:        cfg.ThreatProtection.XML.MaxAttributes,
				MaxChildren:          cfg.ThreatProtection.XML.MaxChildren,
				EntityExpansionLimit: cfg.ThreatProtection.XML.EntityExpansionLimit,
			}
		}
		next = ThreatProtectionMiddleware(tpConfig)(next)
	}

	// Only add session middleware if SessionConfig is present (non-empty)
	if cfg.HasSessionConfig() {
		next = session.SessionMiddleware(h.manager, cfg.SessionConfig)(next)
	}

	wsID := cfg.WorkspaceID
	if wsID != "" {
		metric.WorkspaceActiveConnectionInc(wsID)
	}

	slog.Debug("serving request", "config_id", cfg.ID)
	next.ServeHTTP(w, r)

	if wsID != "" {
		metric.WorkspaceActiveConnectionDec(wsID)
		metric.WorkspaceRequestDuration(wsID, time.Since(requestStart).Seconds())
	}
}
