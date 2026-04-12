// enricher.go defines the RequestEnricher interface for populating request context data.
package plugin

import (
	"context"
	"net/http"
	"sync"
)

// RequestEnricher populates request context data during request processing.
// Implementations are registered at init time and called for every request
// by the enricher middleware in the pipeline.
//
// Lifecycle: Register (init) -> Enrich (per-request) -> results read by middleware.
// Enrichers must be stateless or thread-safe since they are called concurrently.
type RequestEnricher interface {
	// Name returns a unique identifier for this enricher (e.g., "geoip", "uaparser").
	Name() string

	// Enrich populates fields on the request or its context.
	// The enricher receives the raw HTTP request and can extract client IP,
	// headers, TLS info, etc.
	//
	// Use SetEnrichmentData to store results in the request context. The OSS
	// enricher middleware reads these results and applies them to RequestData.
	//
	// Errors are logged but do not stop request processing.
	Enrich(r *http.Request) error
}

// EnrichmentData carries enrichment results through the request context.
// The enricher middleware creates this before calling enrichers and reads
// the populated fields afterward to set them on RequestData.
type EnrichmentData struct {
	// Location holds geographic data from a GeoIP enricher.
	Location *GeoLocation
	// UserAgent holds parsed user-agent data from a UA enricher.
	UserAgent *ParsedUserAgent
}

// GeoLocation holds geographic data produced by a GeoIP enricher.
type GeoLocation struct {
	Country       string
	CountryCode   string
	Continent     string
	ContinentCode string
	ASN           string
	ASName        string
	ASDomain      string
}

// ParsedUserAgent holds user-agent data produced by a UA parser enricher.
type ParsedUserAgent struct {
	Family       string
	Major        string
	Minor        string
	Patch        string
	OSFamily     string
	OSMajor      string
	OSMinor      string
	OSPatch      string
	DeviceFamily string
	DeviceBrand  string
	DeviceModel  string
}

type enrichmentKey struct{}

// SetEnrichmentData stores enrichment data in the request context.
// Called by enricher implementations from within Enrich().
func SetEnrichmentData(ctx context.Context, data *EnrichmentData) context.Context {
	return context.WithValue(ctx, enrichmentKey{}, data)
}

// GetEnrichmentData retrieves enrichment data from the request context.
// Called by the enricher middleware after all enrichers have run.
func GetEnrichmentData(ctx context.Context) *EnrichmentData {
	if v, ok := ctx.Value(enrichmentKey{}).(*EnrichmentData); ok {
		return v
	}
	return nil
}

var (
	enricherMu sync.RWMutex
	enrichers  []RequestEnricher
)

// RegisterEnricher adds a request enricher to the global registry.
// Call from init() in the package that implements the enricher.
func RegisterEnricher(e RequestEnricher) {
	enricherMu.Lock()
	enrichers = append(enrichers, e)
	enricherMu.Unlock()
}

// GetEnrichers returns all registered request enrichers.
func GetEnrichers() []RequestEnricher {
	enricherMu.RLock()
	defer enricherMu.RUnlock()
	return append([]RequestEnricher{}, enrichers...)
}
