// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// UAParserMiddleware returns HTTP middleware for ua parser.
func UAParserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		m := manager.GetManager(ctx)
		result, err := m.GetUserAgent(r)
		if err != nil {
			slog.Error("failed to get user agent", "error", err)
			next.ServeHTTP(w, r)
			return
		}

		if result == nil {
			next.ServeHTTP(w, r)
			return
		}

		requestData := reqctx.GetRequestData(ctx)

		userAgent := &reqctx.UserAgent{}

		if result.UserAgent != nil {
			userAgent.Family = result.UserAgent.Family
			userAgent.Major = result.UserAgent.Major
			userAgent.Minor = result.UserAgent.Minor
			userAgent.Patch = result.UserAgent.Patch
		}

		if result.OS != nil {
			userAgent.OSFamily = result.OS.Family
			userAgent.OSMajor = result.OS.Major
			userAgent.OSMinor = result.OS.Minor
			userAgent.OSPatch = result.OS.Patch
		}

		if result.Device != nil {
			userAgent.DeviceFamily = result.Device.Family
			userAgent.DeviceBrand = result.Device.Brand
			userAgent.DeviceModel = result.Device.Model
		}

		requestData.UserAgent = userAgent

		// Record distribution metrics
		configID := "unknown"
		if requestData := reqctx.GetRequestData(r.Context()); requestData != nil && requestData.Config != nil {
			configData := reqctx.ConfigParams(requestData.Config)
			if id := configData.GetConfigID(); id != "" {
				configID = id
			}
		}

		// Record device type distribution
		if userAgent.DeviceFamily != "" {
			metric.DeviceTypeDistribution(configID, userAgent.DeviceFamily)
		}

		// Record browser family distribution
		if userAgent.Family != "" {
			metric.BrowserDistribution(configID, userAgent.Family)
		}

		// Record OS family distribution
		if userAgent.OSFamily != "" {
			metric.OSDistribution(configID, userAgent.OSFamily)
		}

		requestData.AddDebugHeader(httputil.HeaderXSbUserAgent, userAgent.String())
		next.ServeHTTP(w, r)
	})
}
