# JWT Testing Tools - Setup Complete ✅

## Summary

A complete JWT token generation and testing toolkit has been created for the proxy server.

## What Was Created

### 1. RSA Key Pair (for testing only)
**Location:** `certs/`
- `jwt_test_private.pem` - 2048-bit RSA private key
- `jwt_test_public.pem` - Public key for verification

**⚠️ Important:** These keys are for testing only. Never use in production!

### 2. JWT Generator Tool
**Location:** `tools/jwt-generator/`
- Standalone Go application for generating JWT tokens
- Supports RSA (RS256/384/512) and HMAC (HS256) algorithms
- Customizable claims (subject, issuer, audience, email, name, roles, etc.)
- Outputs base64-encoded public keys for configuration

**Build:**
```bash
cd tools/jwt-generator
go build -o jwt-generator
```

### 3. Documentation
- `tools/jwt-generator/README.md` - Complete tool documentation
- `internal/config2/README.md` - Updated with JWT examples using base64 keys
- `internal/config2/fixtures/jwt_tokens.json` - Pre-generated example tokens

## Quick Start

### Generate a Token

```bash
cd tools/jwt-generator

# Basic token generation
./jwt-generator

# Custom claims
./jwt-generator \
  -sub "alice" \
  -email "alice@example.com" \
  -name "Alice Smith" \
  -roles "user,developer" \
  -exp 24
```

### Get Public Key for Config

```bash
# Get base64-encoded public key (recommended)
./jwt-generator -show-keys -base64
```

**Output:**
```
RSA Public Key (Base64-encoded DER format):
===========================================
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy9K8zjDzRWEe89EoOMXd...

Use this in your JWT auth config:
{
  "auth": {
    "type": "jwt",
    "algorithm": "RS256",
    "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy9K8zjDzRWEe89EoOMXd..."
  }
}
```

### Use Token in Requests

```bash
# Generate token and store it
TOKEN=$(./jwt-generator | grep "^eyJ" | head -1)

# Use in API requests
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/test
```

## Configuration Examples

### RSA with Base64-Encoded Key (Recommended)

```json
{
  "routes": [
    {
      "path": "/api/*",
      "auth": {
        "type": "jwt",
        "algorithm": "RS256",
        "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy9K8zjDzRWEe89EoOMXdqcsqDEpuT2UXX14CCSMSldYUA3PrRsaiFCle3mEB1eXdv5bs+V5ue6JV0bi2O+7fozLOreTimWz+N2cSyzlzFJsviFIBFIW2CX8WW7+WxlXuAMhpLEx2vhnsQ8VQbpX9qcrLLGT4SCXIda9vkCEgUgzqfDLr7JQAerX88bOm/9aVyfKM8V7dSFj6seHIBtYcuorEYpwQhXiKGWnA7dm5n9eHNT071dF4O9n9ylhs657XIzzwkoQiBt66gItrRvZtP0MQ86vKf68RhVV09G4N+oS94fJvipFrBeM0p45ABXe01kczSREnkmkfJ18TRye7+QIDAQAB",
        "issuer": "test-issuer",
        "audience": "test-audience"
      },
      "action": {
        "type": "proxy",
        "url": "https://backend.example.com"
      }
    }
  ]
}
```

### HMAC (HS256)

```json
{
  "auth": {
    "type": "jwt",
    "algorithm": "HS256",
    "secret": "your-super-secret-key-at-least-256-bits",
    "issuer": "test-issuer",
    "audience": "test-audience"
  }
}
```

## Features

### Token Generation
- ✅ Multiple algorithms (RS256/384/512, HS256)
- ✅ Customizable claims
- ✅ Configurable expiration
- ✅ Support for roles and custom claims

### Public Key Export
- ✅ PEM format (traditional)
- ✅ Base64-encoded DER format (recommended for JSON)
- ✅ Ready-to-use config snippets

### Performance
- ✅ JWT token caching (30s) for validated tokens
- ✅ Public key caching for improved performance
- ✅ O(1) credential lookups

## Example Tokens

Pre-generated test tokens are available in:
```
internal/config2/fixtures/jwt_tokens.json
```

### Sample Token

**Token:**
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciIsInN1YiI6InVzZXIxMjMiLCJhdWQiOlsidGVzdC1hdWRpZW5jZSJdLCJleHAiOjE3NjIzNTc0MjcsIm5iZiI6MTc2MjI3MTAyNywiaWF0IjoxNzYyMjcxMDI3LCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJuYW1lIjoiVGVzdCBVc2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sInVzZXJfaWQiOiJ1c2VyMTIzIn0.sO3hKW9yWjCBrXjCs3cUfemu-eEEBocVtNZptPG02wbaVkm6EbhqjyTP7OPEf6A-_F66mOoBpWWRZBOEAa_Ouo0Iq3pYsS4jLETyFlp5S5LbMCNXEt71__xyboCVjr8p5zZ3MkvP_E9O5MuXG-Sx2gsZxkPgci_mUP1f2EozEtIvtho67dfD3EhDJrW3QFm-G3F6FM104HxSQrbHw1BxWqait__3JG19NPc-NGREfRgQVHOAZZnGlVAtpe3mTvfbN8GvCw5p8CHns3LD9XUFFd3-Tkvbx67uDc7snrBZxvb6rZoHxx99wgszhj3MGxk6PYQkpyHjptBgmGIsjzCWLw
```

**Claims:**
```json
{
  "iss": "test-issuer",
  "sub": "user123",
  "aud": ["test-audience"],
  "email": "user@example.com",
  "name": "Test User",
  "roles": ["user", "admin"],
  "user_id": "user123"
}
```

## Testing Workflow

### 1. Start Proxy with JWT Auth
```bash
# Configure your proxy with JWT auth (see examples above)
./proxy -config config.json
```

### 2. Generate Test Token
```bash
cd tools/jwt-generator
./jwt-generator -iss "test-issuer" -aud "test-audience"
```

### 3. Test Authentication
```bash
# Copy the token from step 2
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI..."

# Test authenticated endpoint
curl -v -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/test

# Should receive 200 OK with valid token
# Should receive 401 Unauthorized with invalid/missing token
```

## Tool Flags Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-alg` | `RS256` | Algorithm (RS256, RS384, RS512, HS256) |
| `-key` | `../../test/certs/jwt_test_private.pem` | Private key path |
| `-secret` | - | HMAC secret (required for HS256) |
| `-sub` | `user123` | Subject (user ID) |
| `-iss` | `test-issuer` | Issuer |
| `-aud` | `test-audience` | Audience |
| `-email` | `user@example.com` | Email claim |
| `-name` | `Test User` | Name claim |
| `-roles` | `user,admin` | Comma-separated roles |
| `-exp` | `24` | Expiry in hours (0 = no expiry) |
| `-show-keys` | `false` | Show public key and exit |
| `-base64` | `false` | Output base64-encoded DER format |

## Key Format Options

The JWT authentication supports two key formats:

### 1. Base64-Encoded DER (Recommended)
- Compact single-line string
- Easy to store in JSON configuration
- No newline characters to escape
- **Example:** `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC...`

### 2. PEM Format (Traditional)
- Multi-line format with headers
- Requires escaping newlines in JSON (`\n`)
- **Example:** `-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----`

**Recommendation:** Use base64-encoded DER format for cleaner JSON configuration.

## Security Notes

⚠️ **Important Security Considerations:**

1. **Test Keys Only**
   - The included RSA keys are for testing ONLY
   - Generate new keys for each environment
   - Never commit private keys to version control

2. **Production Keys**
   - Use strong, randomly generated keys (2048+ bits)
   - Store keys securely (e.g., AWS KMS, HashiCorp Vault)
   - Rotate keys regularly
   - Use different keys per environment

3. **Token Configuration**
   - Always set appropriate expiration times
   - Validate issuer and audience in production
   - Use HTTPS in production
   - Consider token revocation strategies

4. **HMAC Secrets**
   - Use long, random secrets (minimum 256 bits for HS256)
   - Never share secrets between services
   - Rotate secrets regularly

## Troubleshooting

### "Failed to read private key"
Check that the private key exists:
```bash
ls -la ../../test/certs/jwt_test_private.pem
```

### "Invalid token"
- Check that issuer and audience match your config
- Verify the token hasn't expired
- Ensure you're using the correct algorithm

### "Public key not found"
- Verify the public key is correctly configured
- Check that the key format matches (base64 vs PEM)
- Run `./jwt-generator -show-keys -base64` to get the correct format

## Additional Resources

- Tool README: `tools/jwt-generator/README.md`
- Config2 README: `internal/config2/README.md`
- Example Tokens: `internal/config2/fixtures/jwt_tokens.json`
- JWT Standard: https://jwt.io/introduction

---

**Setup Date:** November 4, 2025
**Tool Version:** 1.0
**Test Environment:** Apple M4 Max, Go 1.21+

