// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// JSONThreatConfig defines structural limits for JSON request bodies.
type JSONThreatConfig struct {
	MaxDepth        int `json:"max_depth"`         // default 20
	MaxKeys         int `json:"max_keys"`          // default 1000
	MaxStringLength int `json:"max_string_length"` // default 200000 (200KB)
	MaxArraySize    int `json:"max_array_size"`    // default 10000
	MaxTotalSize    int `json:"max_total_size"`    // default 10485760 (10MB)
}

// XMLThreatConfig defines structural limits for XML request bodies.
type XMLThreatConfig struct {
	MaxDepth             int `json:"max_depth"`              // default 20
	MaxAttributes        int `json:"max_attributes"`         // default 100
	MaxChildren          int `json:"max_children"`           // default 10000
	EntityExpansionLimit int `json:"entity_expansion_limit"` // default 0 (disabled)
}

// ThreatProtectionConfig holds both JSON and XML threat protection settings.
type ThreatProtectionConfig struct {
	Enabled bool              `json:"enabled"`
	JSON    *JSONThreatConfig `json:"json,omitempty"`
	XML     *XMLThreatConfig  `json:"xml,omitempty"`
}

// DefaultJSONThreatConfig returns safe defaults for JSON threat protection.
func DefaultJSONThreatConfig() *JSONThreatConfig {
	return &JSONThreatConfig{
		MaxDepth:        20,
		MaxKeys:         1000,
		MaxStringLength: 200000, // 200KB
		MaxArraySize:    10000,
		MaxTotalSize:    10485760, // 10MB
	}
}

// DefaultXMLThreatConfig returns safe defaults for XML threat protection.
func DefaultXMLThreatConfig() *XMLThreatConfig {
	return &XMLThreatConfig{
		MaxDepth:             20,
		MaxAttributes:        100,
		MaxChildren:          10000,
		EntityExpansionLimit: 0, // disabled
	}
}

// DefaultThreatProtectionConfig returns a default config with both JSON and XML protection enabled.
func DefaultThreatProtectionConfig() *ThreatProtectionConfig {
	return &ThreatProtectionConfig{
		Enabled: true,
		JSON:    DefaultJSONThreatConfig(),
		XML:     DefaultXMLThreatConfig(),
	}
}

// ThreatProtectionMiddleware creates middleware that validates JSON/XML request bodies
// against structural limits to prevent payload-based attacks.
func ThreatProtectionMiddleware(config *ThreatProtectionConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = DefaultThreatProtectionConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Only validate methods that carry bodies
			if r.Method != http.MethodPost && r.Method != http.MethodPut &&
				r.Method != http.MethodPatch {
				next.ServeHTTP(w, r)
				return
			}

			if r.Body == nil || r.ContentLength == 0 {
				next.ServeHTTP(w, r)
				return
			}

			ct := r.Header.Get("Content-Type")
			ct = strings.ToLower(ct)

			switch {
			case isJSONContentType(ct) && config.JSON != nil:
				if err := validateJSONBody(r, config.JSON); err != nil {
					slog.Debug("JSON threat protection violation",
						"error", err,
						"path", r.URL.Path,
						"method", r.Method,
						"remote_addr", r.RemoteAddr,
					)
					http.Error(w, "Bad Request", http.StatusBadRequest)
					return
				}

			case isXMLContentType(ct) && config.XML != nil:
				if err := validateXMLBody(r, config.XML); err != nil {
					slog.Debug("XML threat protection violation",
						"error", err,
						"path", r.URL.Path,
						"method", r.Method,
						"remote_addr", r.RemoteAddr,
					)
					http.Error(w, "Bad Request", http.StatusBadRequest)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isJSONContentType returns true for JSON content types.
func isJSONContentType(ct string) bool {
	return strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "+json")
}

// isXMLContentType returns true for XML content types.
func isXMLContentType(ct string) bool {
	return strings.Contains(ct, "application/xml") ||
		strings.Contains(ct, "text/xml") ||
		strings.Contains(ct, "+xml")
}

// validateJSONBody reads the request body, validates it against JSON structural limits,
// and restores the body for downstream handlers.
func validateJSONBody(r *http.Request, cfg *JSONThreatConfig) error {
	// Read body with size limit
	maxRead := int64(cfg.MaxTotalSize)
	if maxRead <= 0 {
		maxRead = 10 * 1024 * 1024
	}
	limitedReader := io.LimitReader(r.Body, maxRead+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	// Close original body
	r.Body.Close()

	// Check total size
	if len(body) > cfg.MaxTotalSize {
		return fmt.Errorf("JSON body exceeds maximum size of %d bytes", cfg.MaxTotalSize)
	}

	// Restore body for downstream handlers
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Stream-parse JSON tokens to validate structure
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	depth := 0
	totalKeys := 0
	// arrayCountStack tracks the number of elements at each nested array level.
	// When we enter an array (depth N), we push a counter; on each element we increment;
	// when we leave, we pop. Only array depths have entries; object depths do not push.
	arrayCountStack := make([]int, 0, 16)
	// inArray tracks whether the current nesting level is an array (true) or object (false).
	inArrayStack := make([]bool, 0, 16)

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}

		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				depth++
				if depth > cfg.MaxDepth {
					return fmt.Errorf("JSON nesting depth %d exceeds maximum of %d", depth, cfg.MaxDepth)
				}
				inArrayStack = append(inArrayStack, false)
				// If we are inside a parent array, count this object as an element
				if len(arrayCountStack) > 0 {
					arrayCountStack[len(arrayCountStack)-1]++
					if arrayCountStack[len(arrayCountStack)-1] > cfg.MaxArraySize {
						return fmt.Errorf("JSON array size exceeds maximum of %d", cfg.MaxArraySize)
					}
				}
			case '[':
				depth++
				if depth > cfg.MaxDepth {
					return fmt.Errorf("JSON nesting depth %d exceeds maximum of %d", depth, cfg.MaxDepth)
				}
				inArrayStack = append(inArrayStack, true)
				arrayCountStack = append(arrayCountStack, 0)
				// If we are inside a parent array, count this sub-array as an element
				if len(arrayCountStack) > 1 {
					arrayCountStack[len(arrayCountStack)-2]++
					if arrayCountStack[len(arrayCountStack)-2] > cfg.MaxArraySize {
						return fmt.Errorf("JSON array size exceeds maximum of %d", cfg.MaxArraySize)
					}
				}
			case '}':
				depth--
				if len(inArrayStack) > 0 {
					inArrayStack = inArrayStack[:len(inArrayStack)-1]
				}
			case ']':
				depth--
				if len(inArrayStack) > 0 {
					inArrayStack = inArrayStack[:len(inArrayStack)-1]
				}
				if len(arrayCountStack) > 0 {
					arrayCountStack = arrayCountStack[:len(arrayCountStack)-1]
				}
			}

		case string:
			// A string token can be an object key or a string value.
			// If we are inside an object (top of inArrayStack is false) and the decoder
			// is about to read a value, then this string is a key. We detect this by
			// checking: the current container is an object (not array).
			// json.Decoder returns keys and values alternately for objects; we count
			// all strings inside objects as potential keys for a conservative check.
			if len(inArrayStack) > 0 && !inArrayStack[len(inArrayStack)-1] {
				totalKeys++
				if totalKeys > cfg.MaxKeys {
					return fmt.Errorf("JSON key count %d exceeds maximum of %d", totalKeys, cfg.MaxKeys)
				}
			} else if len(arrayCountStack) > 0 {
				// String value inside array
				arrayCountStack[len(arrayCountStack)-1]++
				if arrayCountStack[len(arrayCountStack)-1] > cfg.MaxArraySize {
					return fmt.Errorf("JSON array size exceeds maximum of %d", cfg.MaxArraySize)
				}
			}

			// Check string length
			if len(v) > cfg.MaxStringLength {
				return fmt.Errorf("JSON string length %d exceeds maximum of %d", len(v), cfg.MaxStringLength)
			}

		case json.Number:
			// Number value inside array counts as element
			if len(arrayCountStack) > 0 && len(inArrayStack) > 0 && inArrayStack[len(inArrayStack)-1] {
				arrayCountStack[len(arrayCountStack)-1]++
				if arrayCountStack[len(arrayCountStack)-1] > cfg.MaxArraySize {
					return fmt.Errorf("JSON array size exceeds maximum of %d", cfg.MaxArraySize)
				}
			}

		case bool:
			// Bool value inside array counts as element
			if len(arrayCountStack) > 0 && len(inArrayStack) > 0 && inArrayStack[len(inArrayStack)-1] {
				arrayCountStack[len(arrayCountStack)-1]++
				if arrayCountStack[len(arrayCountStack)-1] > cfg.MaxArraySize {
					return fmt.Errorf("JSON array size exceeds maximum of %d", cfg.MaxArraySize)
				}
			}

		case nil:
			// Null value inside array counts as element
			if len(arrayCountStack) > 0 && len(inArrayStack) > 0 && inArrayStack[len(inArrayStack)-1] {
				arrayCountStack[len(arrayCountStack)-1]++
				if arrayCountStack[len(arrayCountStack)-1] > cfg.MaxArraySize {
					return fmt.Errorf("JSON array size exceeds maximum of %d", cfg.MaxArraySize)
				}
			}
		}
	}

	return nil
}

// validateXMLBody reads the request body, validates it against XML structural limits,
// and restores the body for downstream handlers.
func validateXMLBody(r *http.Request, cfg *XMLThreatConfig) error {
	// Read body (use a reasonable limit)
	maxRead := int64(10 * 1024 * 1024) // 10MB default for XML
	limitedReader := io.LimitReader(r.Body, maxRead+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	r.Body.Close()

	if int64(len(body)) > maxRead {
		return fmt.Errorf("XML body exceeds maximum size")
	}

	// Check for entity expansion attacks before parsing.
	// The Go xml.Decoder does not expand external entities, but we block
	// DOCTYPE declarations containing ENTITY definitions as a defense-in-depth
	// measure (billion laughs / entity expansion attacks).
	if cfg.EntityExpansionLimit == 0 {
		bodyStr := string(body)
		upperBody := strings.ToUpper(bodyStr)
		if strings.Contains(upperBody, "<!ENTITY") {
			return fmt.Errorf("XML entity declarations are not allowed")
		}
	}

	// Restore body for downstream handlers
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Stream-parse XML tokens to validate structure
	dec := xml.NewDecoder(bytes.NewReader(body))
	// Disable strict mode to prevent the decoder from resolving entities
	dec.Strict = false

	depth := 0
	totalChildren := 0
	entityCount := 0

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// XML parsing error - could be malformed input
			return fmt.Errorf("invalid XML: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth > cfg.MaxDepth {
				return fmt.Errorf("XML nesting depth %d exceeds maximum of %d", depth, cfg.MaxDepth)
			}

			totalChildren++
			if totalChildren > cfg.MaxChildren {
				return fmt.Errorf("XML child element count %d exceeds maximum of %d", totalChildren, cfg.MaxChildren)
			}

			// Check attribute count per element
			if len(t.Attr) > cfg.MaxAttributes {
				return fmt.Errorf("XML element has %d attributes, exceeds maximum of %d", len(t.Attr), cfg.MaxAttributes)
			}

		case xml.EndElement:
			depth--

		case xml.CharData:
			// Track entity expansion by monitoring total character data size.
			// In a billion laughs attack, entity expansion generates massive char data.
			if cfg.EntityExpansionLimit > 0 {
				entityCount += len(t)
				if entityCount > cfg.EntityExpansionLimit {
					return fmt.Errorf("XML entity expansion limit exceeded")
				}
			}

		case xml.Directive:
			// Block DOCTYPE declarations as they can contain entity definitions
			directive := strings.ToUpper(string(t))
			if strings.Contains(directive, "ENTITY") {
				return fmt.Errorf("XML entity declarations are not allowed")
			}
		}
	}

	return nil
}
