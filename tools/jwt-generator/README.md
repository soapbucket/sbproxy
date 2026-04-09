# JWT Token Generator

A command-line tool for generating JWT tokens for testing authentication in the proxy server.

## Features

- Generate JWT tokens with RSA (RS256, RS384, RS512) or HMAC (HS256) algorithms
- Customizable claims (subject, issuer, audience, email, name, roles, etc.)
- Support for token expiration
- Display public key for verification configuration

## Installation

Build the tool:

```bash
cd tools/jwt-generator
go build -o jwt-generator
```

## Quick Start

Generate a basic JWT token with default values:

```bash
./jwt-generator
```

This creates a token with:
- Algorithm: RS256
- Subject: user123
- Issuer: test-issuer
- Audience: test-audience
- Email: user@example.com
- Name: Test User
- Roles: user, admin
- Expiry: 24 hours

## Usage

### Basic Token Generation

```bash
# Generate token with default settings (RS256)
./jwt-generator

# Generate token with custom subject
./jwt-generator -sub "john.doe"

# Generate token with custom claims
./jwt-generator -sub "alice" -email "alice@example.com" -name "Alice Smith"

# Generate token with specific roles
./jwt-generator -roles "admin,superuser,developer"

# Generate token with no expiry
./jwt-generator -exp 0

# Generate token valid for 1 hour
./jwt-generator -exp 1
```

### Using Different Algorithms

```bash
# RS256 (default)
./jwt-generator -alg RS256

# RS384
./jwt-generator -alg RS384

# RS512
./jwt-generator -alg RS512

# HS256 (requires secret)
./jwt-generator -alg HS256 -secret "your-secret-key"
```

### Using Custom Keys

```bash
# Use custom private key for RSA signing
./jwt-generator -key /path/to/private.pem

# For HMAC, specify secret directly
./jwt-generator -alg HS256 -secret "my-super-secret-key"
```

### Display Public Key

View the public key for JWT verification configuration:

```bash
# Show public key in PEM format
./jwt-generator -show-keys

# Show public key in base64-encoded DER format (recommended for JSON config)
./jwt-generator -show-keys -base64
```

## Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-alg` | `RS256` | JWT signing algorithm (RS256, RS384, RS512, HS256) |
| `-key` | `../../test/certs/jwt_test_private.pem` | Path to RSA private key file |
| `-secret` | - | HMAC secret (required for HS256) |
| `-sub` | `user123` | Subject claim (user ID) |
| `-iss` | `test-issuer` | Issuer claim |
| `-aud` | `test-audience` | Audience claim |
| `-email` | `user@example.com` | Email claim |
| `-name` | `Test User` | Name claim |
| `-roles` | `user,admin` | Comma-separated roles |
| `-userid` | `user123` | User ID claim |
| `-exp` | `24` | Token expiry in hours (0 = no expiry) |
| `-show-keys` | `false` | Display public key and exit |
| `-base64` | `false` | Show keys in base64-encoded DER format (use with `-show-keys`) |

## Examples

### Example 1: Admin User Token

```bash
./jwt-generator \
  -sub "admin-001" \
  -email "admin@company.com" \
  -name "System Admin" \
  -roles "admin,superuser" \
  -exp 12
```

### Example 2: Regular User Token

```bash
./jwt-generator \
  -sub "user-12345" \
  -email "user@example.com" \
  -name "John Doe" \
  -roles "user" \
  -exp 24
```

### Example 3: Service Account Token (No Expiry)

```bash
./jwt-generator \
  -sub "service-api-gateway" \
  -iss "api-gateway-service" \
  -aud "backend-api" \
  -exp 0
```

### Example 4: HMAC Token

```bash
./jwt-generator \
  -alg HS256 \
  -secret "my-hmac-secret-key-must-be-long" \
  -sub "user123" \
  -exp 1
```

## Testing with the Proxy

### 1. Get the Public Key

```bash
# Get base64-encoded key (recommended for JSON config)
./jwt-generator -show-keys -base64
```

Copy the output to use in your proxy configuration.

### 2. Configure Proxy JWT Authentication

In your proxy config, add the JWT auth configuration:

```json
{
  "auth": {
    "type": "jwt",
    "algorithm": "RS256",
    "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy9K8zjDzRWEe89EoOMXdqcsqDEpuT2UXX14CCSMSldYUA3PrRsaiFCle3mEB1eXdv5bs+V5ue6JV0bi2O+7fozLOreTimWz+N2cSyzlzFJsviFIBFIW2CX8WW7+WxlXuAMhpLEx2vhnsQ8VQbpX9qcrLLGT4SCXIda9vkCEgUgzqfDLr7JQAerX88bOm/9aVyfKM8V7dSFj6seHIBtYcuorEYpwQhXiKGWnA7dm5n9eHNT071dF4O9n9ylhs657XIzzwkoQiBt66gItrRvZtP0MQ86vKf68RhVV09G4N+oS94fJvipFrBeM0p45ABXe01kczSREnkmkfJ18TRye7+QIDAQAB",
    "issuer": "test-issuer",
    "audience": "test-audience"
  }
}
```

**Note:** The public key can be provided in either:
- Base64-encoded DER format (recommended, shown above)
- PEM format (with `-----BEGIN PUBLIC KEY-----` headers)

### 3. Generate a Token

```bash
./jwt-generator -iss "test-issuer" -aud "test-audience"
```

### 4. Test with curl

```bash
# Copy the token from the generator output
TOKEN="eyJhbGc..."

# Make authenticated request
curl -H "Authorization: Bearer $TOKEN" https://your-proxy/api/endpoint
```

## RSA Key Pair

The tool uses RSA keys located at:
- Private key: `../../test/certs/jwt_test_private.pem` (2048-bit)
- Public key: `../../test/certs/jwt_test_public.pem`

These keys were generated using:

```bash
# Generate private key
openssl genrsa -out certs/jwt_test_private.pem 2048

# Extract public key
openssl rsa -in certs/jwt_test_private.pem -pubout -out certs/jwt_test_public.pem
```

### Using Your Own Keys

To use your own RSA key pair:

1. Generate a new key pair:
   ```bash
   openssl genrsa -out my_private.pem 2048
   openssl rsa -in my_private.pem -pubout -out my_public.pem
   ```

2. Use the private key with the generator:
   ```bash
   ./jwt-generator -key /path/to/my_private.pem
   ```

3. Configure the public key in your proxy config

## Token Structure

The generated tokens include the following claims:

**Standard Claims (RFC 7519):**
- `sub` - Subject (user identifier)
- `iss` - Issuer
- `aud` - Audience
- `iat` - Issued At (timestamp)
- `nbf` - Not Before (timestamp)
- `exp` - Expiration Time (optional)

**Custom Claims:**
- `email` - User's email address
- `name` - User's full name
- `roles` - Array of user roles
- `user_id` - User identifier (same as subject by default)

## Troubleshooting

### "Failed to read private key"

Make sure the private key file exists and is readable:
```bash
ls -la ../../test/certs/jwt_test_private.pem
```

### "Invalid algorithm"

Supported algorithms are: RS256, RS384, RS512, HS256

### "HMAC secret required"

When using HS256, you must provide a secret:
```bash
./jwt-generator -alg HS256 -secret "your-secret-here"
```

### Token Expired

If your token has expired, generate a new one with a longer expiry:
```bash
./jwt-generator -exp 48  # Valid for 48 hours
```

## Advanced Usage

### Scripting

Generate multiple tokens for different users:

```bash
#!/bin/bash
for user in alice bob charlie; do
  echo "Generating token for $user"
  ./jwt-generator -sub "$user" -email "$user@example.com" -name "$user" > "token_$user.txt"
done
```

### Integration Testing

```bash
# Generate short-lived token for testing
TOKEN=$(./jwt-generator -exp 1 | grep "^eyJ" | head -1)

# Use in tests
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/test
```

## Security Notes

⚠️ **Important Security Considerations:**

1. **Test Keys Only** - The included RSA keys are for testing only. **Never use these keys in production!**

2. **Key Security** - In production:
   - Use strong, randomly generated keys
   - Store keys securely (e.g., AWS KMS, HashiCorp Vault)
   - Rotate keys regularly
   - Never commit private keys to version control

3. **Token Expiry** - Always set appropriate expiration times for tokens

4. **HMAC Secrets** - Use long, random secrets (minimum 256 bits for HS256)

5. **Claims Validation** - Always validate issuer, audience, and expiration in production

## License

Copyright 2026 Soap Bucket LLC. All rights reserved. Proprietary and confidential.

