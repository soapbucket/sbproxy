// Package flags parses and propagates per-request feature flags from headers and configuration.
package featureflags

import (
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// FlagsMiddleware returns HTTP middleware for flags.
func FlagsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flags := GetFlagsFromRequest(r)

		slog.Debug("adding flags to request", "flags", flags.String())

		ctx := r.Context()
		requestData := reqctx.GetRequestData(ctx)
		requestData.Debug = flags.IsDebug()
		requestData.NoCache = flags.IsNoCache()
		requestData.NoTrace = flags.IsTrace()

		requestData.AddDebugHeader(httputil.HeaderXSbFlags, flags.String())

		// Track any other flags from the request
		for flagName, flagValue := range flags {
			// Skip already tracked flags
			enabled := flagValue == "true" || flagValue == ""
			metric.FeatureFlagUsage(flagName, enabled)
		}

		next.ServeHTTP(w, r)

	})
}
