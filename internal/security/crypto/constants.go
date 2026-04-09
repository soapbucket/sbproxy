// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
package crypto

// Provider represents the encryption provider type
type Provider string

const (
	// ProviderLocal is a constant for provider local.
	ProviderLocal Provider = "local"
	// ProviderGCP is a constant for provider gcp.
	ProviderGCP   Provider = "gcp"
	// ProviderAWS is a constant for provider aws.
	ProviderAWS   Provider = "aws"
)

// Parameter keys for crypto settings
const (
	// Local crypto parameters
	ParamEncryptionKey = "encryption_key"
	// ParamSigningKey is a constant for param signing key.
	ParamSigningKey    = "signing_key"

	// GCP KMS parameters
	ParamProjectID = "project_id"
	// ParamLocation is a constant for param location.
	ParamLocation  = "location"
	// ParamKeyRing is a constant for param key ring.
	ParamKeyRing   = "key_ring"
	// ParamKeyID is a constant for param key id.
	ParamKeyID     = "key_id"

	// AWS KMS parameters
	ParamRegion = "region"
)
