// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/security/core"
)

func init() {
	policyLoaderFns[PolicyTypeSRI] = NewSRIPolicy
}

// SRIPolicyConfig implements PolicyConfig for Subresource Integrity validation
type SRIPolicyConfig struct {
	SRIPolicy

	// Internal
	config    *Config
	validator *security.SRIValidator
	generator *security.SRIGenerator
}

// NewSRIPolicy creates a new SRI policy config
func NewSRIPolicy(data []byte) (PolicyConfig, error) {
	cfg := &SRIPolicyConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Init initializes the policy config
func (p *SRIPolicyConfig) Init(config *Config) error {
	p.config = config

	// Initialize validator with known hashes
	knownHashes := make(map[string][]string, len(p.KnownHashes))
	for url, hashes := range p.KnownHashes {
		knownHashes[url] = hashes
	}
	p.validator = security.NewSRIValidator(knownHashes)

	// Initialize generator if algorithm is specified
	if p.Algorithm != "" {
		generator, err := security.NewSRIGenerator(p.Algorithm)
		if err != nil {
			return fmt.Errorf("failed to create SRI generator: %w", err)
		}
		p.generator = generator
	} else {
		// Default to sha384
		generator, err := security.NewSRIGenerator("sha384")
		if err != nil {
			return fmt.Errorf("failed to create SRI generator: %w", err)
		}
		p.generator = generator
	}

	return nil
}

// Apply implements the middleware pattern for SRI validation
func (p *SRIPolicyConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		// Wrap the response writer to validate SRI
		wrapped := &sriResponseWriter{
			ResponseWriter: w,
			policy:         p,
			request:        r,
		}

		next.ServeHTTP(wrapped, r)
	})
}

// sriResponseWriter wraps http.ResponseWriter to validate SRI
type sriResponseWriter struct {
	http.ResponseWriter
	policy      *SRIPolicyConfig
	request     *http.Request
	wroteHeader bool
	bodyBuffer  []byte
}

// WriteHeader performs the write header operation on the sriResponseWriter.
func (w *sriResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

// Flush implements http.Flusher to support streaming responses and chunk caching
func (w *sriResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Write performs the write operation on the sriResponseWriter.
func (w *sriResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	// Buffer the body for validation if needed
	if w.policy.ValidateResponses && w.policy.validator != nil {
		w.bodyBuffer = append(w.bodyBuffer, b...)
	}

	return w.ResponseWriter.Write(b)
}

func (w *sriResponseWriter) validateSRI() error {
	if !w.policy.ValidateResponses || w.policy.validator == nil {
		return nil
	}

	// Check if this resource should be validated
	resourceURL := w.request.URL.String()
	knownHashes := w.policy.validator.GetKnownHashes(resourceURL)
	if len(knownHashes) == 0 {
		// No known hashes for this resource, skip validation
		return nil
	}

	// Get integrity from response headers
	integrity := w.ResponseWriter.Header().Get("Integrity")
	if integrity == "" {
		// Check Link header
		linkHeader := w.ResponseWriter.Header().Get("Link")
		if linkHeader != "" {
			integrity = extractIntegrityFromLinkHeader(linkHeader)
		}
	}

	if integrity == "" {
		if w.policy.FailOnMissingIntegrity {
			return fmt.Errorf("SRI validation failed: no integrity attribute found for resource %s", resourceURL)
		}
		slog.Debug("SRI validation skipped: no integrity attribute",
			"resource", resourceURL)
		return nil
	}

	// Validate integrity
	if err := w.policy.validator.ValidateIntegrity(resourceURL, integrity); err != nil {
		if w.policy.FailOnInvalidIntegrity {
			return fmt.Errorf("SRI validation failed: %w", err)
		}
		slog.Warn("SRI validation failed",
			"resource", resourceURL,
			"error", err)
		return nil
	}

	slog.Debug("SRI validation passed",
		"resource", resourceURL)
	return nil
}

// extractIntegrityFromLinkHeader extracts integrity value from Link header
func extractIntegrityFromLinkHeader(linkHeader string) string {
	parts := strings.Split(linkHeader, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "integrity=") {
			value := strings.TrimPrefix(part, "integrity=")
			value = strings.Trim(value, `"`)
			return value
		}
	}
	return ""
}

// ValidateRequest validates SRI integrity from an incoming request
// This is useful for validating resources referenced in HTML
func (p *SRIPolicyConfig) ValidateRequest(r *http.Request) error {
	if !p.ValidateRequests || p.validator == nil {
		return nil
	}

	resourceURL := r.URL.String()
	integrity := r.Header.Get("Integrity")
	if integrity == "" {
		return nil // No integrity to validate
	}

	return p.validator.ValidateIntegrity(resourceURL, integrity)
}

// GenerateIntegrityForResponse generates an SRI integrity hash for a response
func (p *SRIPolicyConfig) GenerateIntegrityForResponse(resp *http.Response) (string, error) {
	if p.generator == nil {
		return "", fmt.Errorf("SRI generator not configured")
	}

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	resp.Body.Close()

	// Restore body
	resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	// Generate integrity hash
	return p.generator.GenerateIntegrityAttribute(bodyBytes)
}

