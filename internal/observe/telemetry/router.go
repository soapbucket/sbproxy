// Package telemetry collects and exports distributed tracing and observability data.
package telemetry

import (
	"log/slog"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// AdminRouteRegistrar is a function that registers admin routes on the telemetry
// router. Registrars are called during InitializeRouter after the core routes
// are set up.
type AdminRouteRegistrar func(router chi.Router)

var (
	adminRegistrarsMu sync.Mutex
	adminRegistrars   []AdminRouteRegistrar
)

// RegisterAdminRoutes registers a function that will add admin routes to the
// telemetry router. This must be called before the telemetry server starts.
func RegisterAdminRoutes(registrar AdminRouteRegistrar) {
	adminRegistrarsMu.Lock()
	defer adminRegistrarsMu.Unlock()
	adminRegistrars = append(adminRegistrars, registrar)
}

// InitializeRouter creates and configures the telemetry HTTP router
func InitializeRouter(enableProfiler bool) *chi.Mux {
	router := chi.NewRouter()

	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	router.Use(middleware.GetHead)
	router.Use(middleware.Recoverer)

	// Register healthz endpoint directly on the router
	router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		render.PlainText(w, r, "ok")
	})

	// Register metrics and profiler endpoints
	metric.AddMetricsEndpoint(metricsPath, router)

	// Register log level endpoint for runtime level changes
	router.Handle("/log/level", logging.LogLevelHTTPHandler())
	slog.Info("log level HTTP endpoint registered at /log/level")

	if enableProfiler {
		slog.Info("enabling the built-in profiler")
		router.Mount(pprofBasePath, middleware.Profiler())
	}

	// Apply any admin route registrars
	adminRegistrarsMu.Lock()
	registrars := make([]AdminRouteRegistrar, len(adminRegistrars))
	copy(registrars, adminRegistrars)
	adminRegistrarsMu.Unlock()

	for _, registrar := range registrars {
		registrar(router)
	}

	return router
}
