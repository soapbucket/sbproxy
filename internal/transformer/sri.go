// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"bytes"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/security/core"
)

// SRITransform generates Subresource Integrity hashes for responses
type SRITransform struct {
	algorithm          string
	contentTypes       []string
	addIntegrityHeader bool
	addIntegrityToHTML bool
	cacheHashes        bool
	hashCache          map[string]string // URL -> hash cache
}

// NewSRITransform creates a new SRI transform
func NewSRITransform(algorithm string, contentTypes []string, addIntegrityHeader, addIntegrityToHTML, cacheHashes bool) (*SRITransform, error) {
	// Default to sha384 (recommended by W3C)
	if algorithm == "" {
		algorithm = security.SRIAlgorithmSHA384
	}

	// Default content types
	if len(contentTypes) == 0 {
		contentTypes = []string{"application/javascript", "text/css", "application/json"}
	}

	return &SRITransform{
		algorithm:          algorithm,
		contentTypes:       contentTypes,
		addIntegrityHeader: addIntegrityHeader,
		addIntegrityToHTML: addIntegrityToHTML,
		cacheHashes:        cacheHashes,
		hashCache:          make(map[string]string),
	}, nil
}

// Modify implements the Transformer interface
func (t *SRITransform) Modify(resp *http.Response) error {
	// Check content type
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		// Not a valid content type, skip
		return nil
	}

	// Check if this content type should have SRI generated
	shouldGenerate := false
	for _, ct := range t.contentTypes {
		if strings.Contains(contentType, ct) {
			shouldGenerate = true
			break
		}
	}

	if !shouldGenerate {
		return nil
	}

	// Check cache if enabled
	if t.cacheHashes && resp.Request != nil {
		url := resp.Request.URL.String()
		if cachedHash, exists := t.hashCache[url]; exists {
			slog.Debug("Using cached SRI hash",
				"url", url)
			t.addIntegrityToResponse(resp, cachedHash)
			return nil
		}
	}

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// Generate SRI hash
	generator, err := security.NewSRIGenerator(t.algorithm)
	if err != nil {
		return err
	}

	integrity, err := generator.GenerateIntegrityAttribute(bodyBytes)
	if err != nil {
		return err
	}

	// Cache hash if enabled
	if t.cacheHashes && resp.Request != nil {
		url := resp.Request.URL.String()
		t.hashCache[url] = integrity
	}

	// Restore body
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Add integrity to response
	t.addIntegrityToResponse(resp, integrity)

	slog.Debug("Generated SRI hash",
		"algorithm", t.algorithm,
		"integrity", integrity[:min(20, len(integrity))]+"...")

	return nil
}

// addIntegrityToResponse adds integrity hash to the response
func (t *SRITransform) addIntegrityToResponse(resp *http.Response, integrity string) {
	if t.addIntegrityHeader {
		// Add as Integrity header
		resp.Header.Set("Integrity", integrity)
	}

	if t.addIntegrityToHTML && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		// For HTML, we would need to modify the HTML to add integrity attributes
		// This is more complex and would require HTML parsing
		// For now, we'll just add it as a header
		resp.Header.Set("X-Integrity", integrity)
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SRITransformConfig is the configuration for SRI transform
type SRITransformConfig struct {
	Algorithm          string   `json:"algorithm,omitempty"`             // sha256, sha384 (default), sha512
	ContentTypes       []string `json:"content_types,omitempty"`         // Content types to generate SRI for
	AddIntegrityHeader bool     `json:"add_integrity_header,omitempty"`  // Add Integrity header
	AddIntegrityToHTML bool     `json:"add_integrity_to_html,omitempty"` // Add integrity attributes to HTML (future)
	CacheHashes        bool     `json:"cache_hashes,omitempty"`          // Cache generated hashes
}

// NewSRITransformFromConfig creates a new SRI transform from config
func NewSRITransformFromConfig(cfg SRITransformConfig) (Transformer, error) {
	return NewSRITransform(
		cfg.Algorithm,
		cfg.ContentTypes,
		cfg.AddIntegrityHeader,
		cfg.AddIntegrityToHTML,
		cfg.CacheHashes,
	)
}
