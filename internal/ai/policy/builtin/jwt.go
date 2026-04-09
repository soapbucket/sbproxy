package builtin

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// JWTDetector detects leaked JWT tokens in content.
// Config fields:
//   - "mode" (string) - "detect" (default) to flag any JWT, "validate" to also check structure
type JWTDetector struct{}

// JWT pattern: three base64url segments separated by dots.
var jwtRegex = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)

// Detect checks content for JWT tokens.
func (d *JWTDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	mode, _ := toString(config.Config["mode"])
	if mode == "" {
		mode = "detect"
	}

	matches := jwtRegex.FindAllString(content, -1)

	var found []string
	for _, m := range matches {
		if mode == "validate" {
			if isValidJWTStructure(m) {
				found = append(found, m[:20]+"...")
			}
		} else {
			found = append(found, m[:20]+"...")
		}
	}

	if len(found) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("detected %d JWT token(s)", len(found))
	}

	result.Latency = time.Since(start)
	return result, nil
}

// isValidJWTStructure checks if a string has valid JWT structure (3 base64url-decodable parts).
func isValidJWTStructure(token string) bool {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return false
	}

	// Header must decode to valid JSON-like content.
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	// Basic check: header should contain "alg".
	if !strings.Contains(string(header), "alg") {
		return false
	}

	// Payload must be decodable.
	_, err = base64.RawURLEncoding.DecodeString(parts[1])
	return err == nil
}
