// Package middleware contains HTTP middleware for the request processing pipeline.
//
// This package provides global and per-origin middleware including bot detection,
// threat protection, correlation ID assignment, request validation, tracing,
// fast-path request data population, and the enricher middleware that calls
// registered [plugin.RequestEnricher] implementations.
package middleware

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// EnricherMiddleware calls all registered RequestEnrichers on each request.
// It replaces the hardcoded GeoIP and UA parser middleware. Enterprise and
// third-party packages register enrichers via plugin.RegisterEnricher in their
// init() functions; this middleware runs them all without knowing what they do.
//
// Before calling enrichers, it stores an empty EnrichmentData in the request
// context. Enrichers populate this data, and the middleware applies the results
// to RequestData afterward.
func EnricherMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enrichers := plugin.GetEnrichers()
		if len(enrichers) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Create enrichment data and store in context so enrichers can populate it.
		ed := &plugin.EnrichmentData{}
		ctx := plugin.SetEnrichmentData(r.Context(), ed)
		r = r.WithContext(ctx)

		for _, e := range enrichers {
			if err := e.Enrich(r); err != nil {
				slog.Debug("enricher failed", "name", e.Name(), "error", err)
			}
		}

		// Apply enrichment results to RequestData.
		rd := reqctx.GetRequestData(r.Context())
		if rd != nil {
			applyGeoLocation(rd, ed)
			applyUserAgent(rd, ed)
		}

		next.ServeHTTP(w, r)
	})
}

// applyGeoLocation applies GeoIP enrichment results to RequestData.
func applyGeoLocation(rd *reqctx.RequestData, ed *plugin.EnrichmentData) {
	if ed.Location == nil {
		return
	}

	loc := ed.Location
	location := &reqctx.Location{
		Country:       loc.Country,
		CountryCode:   loc.CountryCode,
		Continent:     loc.Continent,
		ContinentCode: loc.ContinentCode,
		ASN:           loc.ASN,
		ASName:        loc.ASName,
		ASDomain:      loc.ASDomain,
	}
	rd.Location = location
	rd.AddDebugHeader(httputil.HeaderXSbGeoIP, location.String())

	// Record geographic request distribution
	configID := "unknown"
	if rd.Config != nil {
		configData := reqctx.ConfigParams(rd.Config)
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
}

// applyUserAgent applies UA parser enrichment results to RequestData.
func applyUserAgent(rd *reqctx.RequestData, ed *plugin.EnrichmentData) {
	if ed.UserAgent == nil {
		return
	}

	ua := ed.UserAgent
	userAgent := &reqctx.UserAgent{
		Family:       ua.Family,
		Major:        ua.Major,
		Minor:        ua.Minor,
		Patch:        ua.Patch,
		OSFamily:     ua.OSFamily,
		OSMajor:      ua.OSMajor,
		OSMinor:      ua.OSMinor,
		OSPatch:      ua.OSPatch,
		DeviceFamily: ua.DeviceFamily,
		DeviceBrand:  ua.DeviceBrand,
		DeviceModel:  ua.DeviceModel,
	}
	rd.UserAgent = userAgent

	// Record distribution metrics
	configID := "unknown"
	if rd.Config != nil {
		configData := reqctx.ConfigParams(rd.Config)
		if id := configData.GetConfigID(); id != "" {
			configID = id
		}
	}

	if userAgent.DeviceFamily != "" {
		metric.DeviceTypeDistribution(configID, userAgent.DeviceFamily)
	}
	if userAgent.Family != "" {
		metric.BrowserDistribution(configID, userAgent.Family)
	}
	if userAgent.OSFamily != "" {
		metric.OSDistribution(configID, userAgent.OSFamily)
	}

	rd.AddDebugHeader(httputil.HeaderXSbUserAgent, fmt.Sprintf(
		"family=%s,os=%s,device=%s", userAgent.Family, userAgent.OSFamily, userAgent.DeviceFamily))
}
