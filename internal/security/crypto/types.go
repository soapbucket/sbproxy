// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
package crypto

// Settings holds configuration parameters for this component.
type Settings struct {
	Driver string            `json:"driver" yaml:"driver" mapstructure:"driver"`
	Params map[string]string `json:"params" yaml:"params" mapstructure:"params"`

	// Observability flags
	EnableMetrics bool `json:"enable_metrics,omitempty" yaml:"enable_metrics" mapstructure:"enable_metrics"`
	EnableTracing bool `json:"enable_tracing,omitempty" yaml:"enable_tracing" mapstructure:"enable_tracing"`
}

// Crypto defines the interface for encryption/decryption and signing/verification operations
type Crypto interface {
	// Encrypt encrypts data using the configured encryption key
	Encrypt([]byte) ([]byte, error)

	// Decrypt decrypts data using the configured encryption key
	Decrypt([]byte) ([]byte, error)

	// EncryptWithContext encrypts data using a derived key based on context (e.g., session ID)
	// This provides better security by ensuring each context uses a unique derived key
	EncryptWithContext(data []byte, context string) ([]byte, error)

	// DecryptWithContext decrypts data using a derived key based on context (e.g., session ID)
	// The context must match the one used during encryption
	DecryptWithContext(data []byte, context string) ([]byte, error)

	// Sign signs data using the configured signing key
	Sign([]byte) ([]byte, error)

	// Verify verifies that data1 was signed with the configured signing key
	Verify([]byte, []byte) (bool, error)

	Driver() string
}
