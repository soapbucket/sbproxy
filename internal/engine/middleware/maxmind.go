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

// MaxMindMiddleware returns HTTP middleware for max mind.
func MaxMindMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ctx := r.Context()
		m := manager.GetManager(ctx)

		result, err := m.GetLocation(r)
		if err != nil {
			slog.Error("failed to get location", "error", err)
			next.ServeHTTP(w, r)
			return
		}
		slog.Debug("adding location to request", "location", result)

		if result == nil {
			next.ServeHTTP(w, r)
			return
		}

		requestData := reqctx.GetRequestData(ctx)
		location := &reqctx.Location{
			Country:       result.Country,
			CountryCode:   result.CountryCode,
			Continent:     result.Continent,
			ContinentCode: result.ContinentCode,
			ASN:           result.ASN,
			ASName:        result.ASName,
			ASDomain:      result.ASDomain,
		}
		requestData.Location = location
		requestData.AddDebugHeader(httputil.HeaderxSbMaxMind, location.String())

		// Record geographic request distribution
		configID := "unknown"
		if requestData := reqctx.GetRequestData(r.Context()); requestData != nil && requestData.Config != nil {
			configData := reqctx.ConfigParams(requestData.Config)
			if id := configData.GetConfigID(); id != "" {
				configID = id
			}
		}
		countryCode := location.CountryCode
		if countryCode == "" {
			countryCode = "unknown"
		}
		region := location.ContinentCode
		if region == "" {
			region = "unknown"
		}
		metric.GeoRequestDistribution(configID, countryCode, region)

		next.ServeHTTP(w, r)
	})

}
