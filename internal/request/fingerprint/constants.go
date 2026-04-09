// Package fingerprint generates TLS and HTTP fingerprints (JA3, JA4) for client identification.
package fingerprint

type contextKey string

const (
	// HeaderFingerprint is the HTTP header name for fingerprint.
	HeaderFingerprint     = "X-Sb-Fingerprint"
	// ContextKeyFingerprint is a constant for context key fingerprint.
	ContextKeyFingerprint = "fingerprint"
	// FingerprintVersion is a constant for fingerprint version.
	FingerprintVersion    = "1.0"

	sbHeaderPrefix = "x-sb"

	// contextKeyConnectionTiming is the typed key for storing ConnectionTiming in Go's context
	contextKeyConnectionTiming contextKey = "conn_timing"
)
