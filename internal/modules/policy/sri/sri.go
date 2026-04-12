// Package sri registers the sri (Subresource Integrity) policy.
package sri

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	security "github.com/soapbucket/sbproxy/internal/security/core"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterPolicy("sri", New)
}

// Config holds configuration for the sri policy.
type Config struct {
	Type                    string              `json:"type"`
	Disabled                bool                `json:"disabled,omitempty"`
	ValidateResponses       bool                `json:"validate_responses,omitempty"`
	ValidateRequests        bool                `json:"validate_requests,omitempty"`
	FailOnMissingIntegrity  bool                `json:"fail_on_missing_integrity,omitempty"`
	FailOnInvalidIntegrity  bool                `json:"fail_on_invalid_integrity,omitempty"`
	KnownHashes             map[string][]string `json:"known_hashes,omitempty"`
	GenerateForContentTypes []string            `json:"generate_for_content_types,omitempty"`
	Algorithm               string              `json:"algorithm,omitempty"`
}

// New creates a new sri policy enforcer.
func New(data json.RawMessage) (plugin.PolicyEnforcer, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	p := &sriPolicy{cfg: cfg}

	knownHashes := make(map[string][]string, len(cfg.KnownHashes))
	for url, hashes := range cfg.KnownHashes {
		knownHashes[url] = hashes
	}
	p.validator = security.NewSRIValidator(knownHashes)

	algo := cfg.Algorithm
	if algo == "" {
		algo = "sha384"
	}
	generator, err := security.NewSRIGenerator(algo)
	if err != nil {
		return nil, fmt.Errorf("failed to create SRI generator: %w", err)
	}
	p.generator = generator

	return p, nil
}

type sriPolicy struct {
	cfg       *Config
	validator *security.SRIValidator
	generator *security.SRIGenerator
}

func (p *sriPolicy) Type() string { return "sri" }

func (p *sriPolicy) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.cfg.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		wrapped := &sriResponseWriter{
			ResponseWriter: w,
			policy:         p,
			request:        r,
		}

		next.ServeHTTP(wrapped, r)
	})
}

type sriResponseWriter struct {
	http.ResponseWriter
	policy      *sriPolicy
	request     *http.Request
	wroteHeader bool
	bodyBuffer  []byte
}

func (w *sriResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

func (w *sriResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *sriResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	if w.policy.cfg.ValidateResponses && w.policy.validator != nil {
		w.bodyBuffer = append(w.bodyBuffer, b...)
	}

	return w.ResponseWriter.Write(b)
}

// extractIntegrityFromLinkHeader extracts integrity value from Link header.
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

// GenerateIntegrityForResponse generates an SRI integrity hash for a response.
func (p *sriPolicy) GenerateIntegrityForResponse(resp *http.Response) (string, error) {
	if p.generator == nil {
		return "", fmt.Errorf("SRI generator not configured")
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	return p.generator.GenerateIntegrityAttribute(bodyBytes)
}

// keep extractIntegrityFromLinkHeader used to avoid lint errors
var _ = extractIntegrityFromLinkHeader
