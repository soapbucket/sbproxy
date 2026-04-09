# Crypto Package

This package provides a unified interface for encryption, decryption, signing, and verification operations across multiple cryptographic backends. It supports both local cryptographic operations and cloud-based key management services.

## Supported Providers

- **Local** - AES-256-GCM encryption with HMAC-SHA256 signing
- **GCP** - Google Cloud KMS for encryption with local signing
- **AWS** - AWS KMS for encryption with local signing

## Features

- **Unified Interface**: Single API for all cryptographic operations
- **Multiple Backends**: Support for local and cloud-based encryption
- **Key Management**: Integration with cloud key management services
- **Signing & Verification**: HMAC-based message authentication
- **Error Handling**: Comprehensive error types for different failure modes
- **Type Safety**: Strong typing with provider-specific configuration
- **Production Ready**: Battle-tested implementations for production use
- **Security Best Practices**: Follows cryptographic best practices and standards

## Quick Start

```go
import "github.com/soapbucket/sbproxy/internal/security/crypto"

// Create local crypto instance
crypto, err := crypto.NewLocalCrypto("base64-encoded-32-byte-key", "base64-encoded-signing-key")
if err != nil {
    log.Fatal(err)
}

// Encrypt data
data := []byte("sensitive information")
encrypted, err := crypto.Encrypt("my-secret", data)
if err != nil {
    log.Fatal(err)
}

// Decrypt data
decrypted, err := crypto.Decrypt("my-secret", encrypted)
if err != nil {
    log.Fatal(err)
}

// Sign data
signature, err := crypto.Sign("my-key", data)
if err != nil {
    log.Fatal(err)
}

// Verify signature
valid, err := crypto.Verify("my-key", data, signature)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Valid signature: %t\n", valid)
```

## Provider-Specific Usage

### Local Provider

```go
// Create with explicit keys
crypto, err := crypto.NewLocalCrypto(secretKey, signingKey)

// Or create with auto-generated keys
crypto, err := crypto.NewLocalCrypto("", "")
```

### GCP Provider

```go
crypto, err := crypto.NewGCPCrypto(&crypto.GCPConfig{
    ProjectID: "my-project",
    Location:  "us-central1",
    KeyRing:   "my-keyring",
    KeyID:     "my-key",
    SigningKey: "base64-encoded-signing-key",
})
```

### AWS Provider

```go
crypto, err := crypto.NewAWSCrypto(&crypto.AWSConfig{
    Region:     "us-east-1",
    KeyID:      "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    SigningKey: "base64-encoded-signing-key",
})
```

## API Reference

### Core Interface

```go
type Crypto interface {
    // Encryption/Decryption
    Encrypt(secret string, data []byte) ([]byte, error)
    Decrypt(secret string, data []byte) ([]byte, error)
    
    // Signing/Verification
    Sign(key string, data []byte) ([]byte, error)
    Verify(key string, data1 []byte, data2 []byte) (bool, error)
}
```

### Specialized Interfaces

```go
// For encryption/decryption only
type Encryptor interface {
    Encrypt(secret string, data []byte) ([]byte, error)
    Decrypt(secret string, data []byte) ([]byte, error)
}

// For signing/verification only
type Signer interface {
    Sign(key string, data []byte) ([]byte, error)
    Verify(key string, data1 []byte, data2 []byte) (bool, error)
}
```

### Provider Types

```go
type Provider string

const (
    ProviderLocal Provider = "local"
    ProviderGCP   Provider = "gcp"
    ProviderAWS   Provider = "aws"
)
```

## Configuration Structures

### GCP Configuration

```go
type GCPConfig struct {
    ProjectID  string // GCP project ID
    Location   string // GCP location (e.g., "us-central1")
    KeyRing    string // GCP key ring name
    KeyID      string // GCP key ID
    SigningKey string // Base64-encoded signing key
}
```

### AWS Configuration

```go
type AWSConfig struct {
    Region     string // AWS region (e.g., "us-east-1")
    KeyID      string // AWS KMS key ID or ARN
    SigningKey string // Base64-encoded signing key
}
```

## Usage Examples

### Basic Encryption/Decryption

```go
// Encrypt sensitive data
userData := map[string]interface{}{
    "user_id": "12345",
    "email":   "user@example.com",
    "role":    "admin",
}

jsonData, _ := json.Marshal(userData)
encrypted, err := crypto.Encrypt("user-secret", jsonData)
if err != nil {
    log.Fatal(err)
}

// Store encrypted data
// ... store encrypted data ...

// Later, decrypt the data
decrypted, err := crypto.Decrypt("user-secret", encrypted)
if err != nil {
    log.Fatal(err)
}

var userData map[string]interface{}
json.Unmarshal(decrypted, &userData)
```

### Message Signing and Verification

```go
// Sign a message
message := []byte("important message")
signature, err := crypto.Sign("message-key", message)
if err != nil {
    log.Fatal(err)
}

// Send message and signature
// ... send message and signature ...

// Verify the signature
valid, err := crypto.Verify("message-key", message, signature)
if err != nil {
    log.Fatal(err)
}

if valid {
    fmt.Println("Message is authentic")
} else {
    fmt.Println("Message has been tampered with")
}
```

### Error Handling

```go
encrypted, err := crypto.Encrypt("secret", data)
if err != nil {
    switch err {
    case crypto.ErrInvalidProvider:
        // Handle invalid provider
    case crypto.ErrEncryptionFailed:
        // Handle encryption failure
    case crypto.ErrMissingKeyID:
        // Handle missing key ID
    default:
        // Handle other errors
    }
}
```

## Security Considerations

### Key Management

- **Local Provider**: Keys are stored in memory and should be generated securely
- **GCP Provider**: Keys are managed by Google Cloud KMS
- **AWS Provider**: Keys are managed by AWS KMS

### Key Generation

```go
import (
    "crypto/rand"
    "encoding/base64"
)

// Generate a 32-byte key for AES-256
key := make([]byte, 32)
rand.Read(key)
secretKey := base64.StdEncoding.EncodeToString(key)

// Generate a signing key
signingKey := make([]byte, 32)
rand.Read(signingKey)
signingKeyB64 := base64.StdEncoding.EncodeToString(signingKey)
```

### Best Practices

1. **Use strong, random keys**: Generate keys using cryptographically secure random number generators
2. **Rotate keys regularly**: Implement key rotation strategies for long-term security
3. **Protect signing keys**: Signing keys should be kept secure and not transmitted
4. **Use appropriate providers**: Choose the provider based on your security and compliance requirements
5. **Handle errors properly**: Always check and handle cryptographic operation errors

## Performance Considerations

- **Local Provider**: Fastest, suitable for single-instance applications
- **GCP Provider**: Good performance with cloud key management
- **AWS Provider**: Good performance with cloud key management
- **Network Latency**: Cloud providers may have network latency for encryption operations

## Testing

```go
// Test with local provider
crypto, err := crypto.NewLocalCrypto("", "")
if err != nil {
    t.Fatal(err)
}

// Test encryption/decryption
data := []byte("test data")
encrypted, err := crypto.Encrypt("secret", data)
if err != nil {
    t.Fatal(err)
}

decrypted, err := crypto.Decrypt("secret", encrypted)
if err != nil {
    t.Fatal(err)
}

if !bytes.Equal(data, decrypted) {
    t.Error("Decrypted data doesn't match original")
}
```

## Migration from Options Package

If you're migrating from the `crypto/options` package, the main differences are:

1. **Direct instantiation**: Use `NewLocalCrypto()`, `NewGCPCrypto()`, `NewAWSCrypto()` instead of settings-based configuration
2. **Simplified API**: Direct method calls instead of driver-based registration
3. **Type safety**: Provider-specific configuration structures instead of generic parameters

The core `Crypto` interface remains the same, so existing code using the interface will work without changes.
