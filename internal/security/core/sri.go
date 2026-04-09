// Package security implements security middleware for CORS, CSP, and request validation.
package security

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

const (
	logSender = "security:sri"
)

// Supported hash algorithms for SRI
const (
	// SRIAlgorithmSHA256 is a constant for sri algorithm sha256.
	SRIAlgorithmSHA256 = "sha256"
	// SRIAlgorithmSHA384 is a constant for sri algorithm sha384.
	SRIAlgorithmSHA384 = "sha384"
	// SRIAlgorithmSHA512 is a constant for sri algorithm sha512.
	SRIAlgorithmSHA512 = "sha512"
)

// SRIGenerator generates Subresource Integrity hashes
type SRIGenerator struct {
	algorithm string
}

// NewSRIGenerator creates a new SRI hash generator
func NewSRIGenerator(algorithm string) (*SRIGenerator, error) {
	// Default to sha384 (recommended by W3C)
	if algorithm == "" {
		algorithm = SRIAlgorithmSHA384
	}

	// Validate algorithm
	switch algorithm {
	case SRIAlgorithmSHA256, SRIAlgorithmSHA384, SRIAlgorithmSHA512:
		// Valid
	default:
		return nil, fmt.Errorf("unsupported SRI algorithm: %s (supported: sha256, sha384, sha512)", algorithm)
	}

	return &SRIGenerator{
		algorithm: algorithm,
	}, nil
}

// GenerateHash generates an SRI hash from the provided data
func (g *SRIGenerator) GenerateHash(data []byte) (string, error) {
	var h hash.Hash
	switch g.algorithm {
	case SRIAlgorithmSHA256:
		h = sha256.New()
	case SRIAlgorithmSHA384:
		h = sha512.New384()
	case SRIAlgorithmSHA512:
		h = sha512.New()
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", g.algorithm)
	}

	h.Write(data)
	hashBytes := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hashBytes), nil
}

// GenerateHashFromReader generates an SRI hash from a reader
func (g *SRIGenerator) GenerateHashFromReader(r io.Reader) (string, error) {
	var h hash.Hash
	switch g.algorithm {
	case SRIAlgorithmSHA256:
		h = sha256.New()
	case SRIAlgorithmSHA384:
		h = sha512.New384()
	case SRIAlgorithmSHA512:
		h = sha512.New()
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", g.algorithm)
	}

	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("failed to read data: %w", err)
	}

	hashBytes := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hashBytes), nil
}

// GenerateIntegrityAttribute generates a complete integrity attribute value
// Format: "sha384-<base64-hash>"
func (g *SRIGenerator) GenerateIntegrityAttribute(data []byte) (string, error) {
	hash, err := g.GenerateHash(data)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", g.algorithm, hash), nil
}

// GenerateIntegrityAttributeFromReader generates a complete integrity attribute value from a reader
func (g *SRIGenerator) GenerateIntegrityAttributeFromReader(r io.Reader) (string, error) {
	hash, err := g.GenerateHashFromReader(r)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", g.algorithm, hash), nil
}

// SRIValidator validates Subresource Integrity hashes
type SRIValidator struct {
	knownHashes map[string][]string // resource URL -> list of valid hashes
}

// NewSRIValidator creates a new SRI validator
func NewSRIValidator(knownHashes map[string][]string) *SRIValidator {
	return &SRIValidator{
		knownHashes: knownHashes,
	}
}

// ValidateIntegrity validates an integrity attribute value against known hashes
func (v *SRIValidator) ValidateIntegrity(resourceURL, integrity string) error {
	if integrity == "" {
		return fmt.Errorf("integrity attribute is empty")
	}

	// Parse integrity value (can contain multiple hashes separated by spaces)
	hashes := strings.Fields(integrity)
	if len(hashes) == 0 {
		return fmt.Errorf("no hashes found in integrity attribute")
	}

	// Get known hashes for this resource
	knownHashes, exists := v.knownHashes[resourceURL]
	if !exists {
		return fmt.Errorf("no known hashes for resource: %s", resourceURL)
	}

	// Check if any of the provided hashes match any known hash
	for _, providedHash := range hashes {
		for _, knownHash := range knownHashes {
			if providedHash == knownHash {
				slog.Debug("SRI hash validated",
					"resource", resourceURL,
					"hash", providedHash[:min(20, len(providedHash))]+"...")
				return nil
			}
		}
	}

	return fmt.Errorf("SRI hash validation failed: none of the provided hashes match known hashes for %s", resourceURL)
}

// ValidateResponse validates SRI integrity from an HTTP response
func (v *SRIValidator) ValidateResponse(resp *http.Response) error {
	if resp.Request == nil {
		return fmt.Errorf("response has no request context")
	}

	resourceURL := resp.Request.URL.String()
	integrity := resp.Header.Get("Integrity")
	if integrity == "" {
		// Check for integrity in Link header
		linkHeader := resp.Header.Get("Link")
		if linkHeader != "" {
			integrity = extractIntegrityFromLinkHeader(linkHeader)
		}
	}

	if integrity == "" {
		return fmt.Errorf("no integrity attribute found in response")
	}

	return v.ValidateIntegrity(resourceURL, integrity)
}

// extractIntegrityFromLinkHeader extracts integrity value from Link header
// Format: <url>; rel="preload"; integrity="sha384-..."
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

// AddKnownHash adds a known hash for a resource
func (v *SRIValidator) AddKnownHash(resourceURL, hash string) {
	if v.knownHashes == nil {
		v.knownHashes = make(map[string][]string)
	}
	v.knownHashes[resourceURL] = append(v.knownHashes[resourceURL], hash)
}

// GetKnownHashes returns all known hashes for a resource
func (v *SRIValidator) GetKnownHashes(resourceURL string) []string {
	return v.knownHashes[resourceURL]
}


