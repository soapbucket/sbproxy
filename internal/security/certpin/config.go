// Package certpin implements TLS certificate pinning verification for upstream connections.
package certpin

// CertificatePinningConfig represents certificate pinning configuration for an origin
type CertificatePinningConfig struct {
	Enabled    bool     `json:"enabled"`
	PinSHA256  string   `json:"pin_sha256"`           // Primary pin (base64-encoded SHA-256 hash of SPKI)
	BackupPins []string `json:"backup_pins"`          // Backup pins for rotation
	PinExpiry  string   `json:"pin_expiry,omitempty"` // Optional expiry date (RFC3339 format)
}



