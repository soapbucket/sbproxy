// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package fingerprint

import (
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
)

// generateJA3Hash creates a simplified JA3-like hash
// Note: This is a simplified version. Real JA3 requires ClientHello parsing
func GenerateJA3Hash(connState *tls.ConnectionState) string {
	// Pre-allocate builder for better performance
	var builder strings.Builder
	builder.Grow(64) // Estimated size for the fingerprint

	// TLS Version
	builder.WriteString(strconv.Itoa(int(connState.Version)))
	builder.WriteByte(',')

	// Cipher Suite (simplified - real JA3 uses offered suites, not negotiated)
	builder.WriteString(strconv.Itoa(int(connState.CipherSuite)))
	builder.WriteByte(',')

	// Curve ID
	builder.WriteString(strconv.Itoa(int(connState.CurveID)))
	builder.WriteByte(',')

	// Protocol
	builder.WriteString(connState.NegotiatedProtocol)

	fingerprint := builder.String()
	hash := fmt.Sprintf("%x", sha1.Sum([]byte(fingerprint)))[:10]
	return hash
}
