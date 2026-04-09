# Crypto CLI Tool

A command-line tool for encrypting, decrypting, signing, and verifying values using Google Cloud KMS, AWS KMS, or local encryption.

## Installation

```bash
cd tools/crypto
go build -o crypto
```

Or install directly:

```bash
go install github.com/soapbucket/proxy/tools/crypto@latest
```

## Usage

### Generate an Encryption Key

Generate a random 32-byte key for local encryption:

```bash
crypto --generate-key
```

Save the output to an environment variable or use it with the `--encryption-key` flag.

### Encrypt Values

#### Local Encryption

```bash
# Using flag
crypto -c encrypt -p local -v "my-secret-password" --encryption-key "your-base64-key"

# Using environment variable
export CRYPTO_ENCRYPTION_KEY="your-base64-key"
crypto -c encrypt -p local -v "my-secret-password"

# Using stdin
echo "my-secret-password" | crypto -c encrypt -p local --stdin --encryption-key "your-base64-key"
```

#### Google Cloud KMS

```bash
crypto -c encrypt -p gcp -v "my-secret" \
  --gcp-project "my-project" \
  --gcp-location "global" \
  --gcp-keyring "my-keyring" \
  --gcp-key "my-key"

# Or using environment variables
export GCP_PROJECT_ID="my-project"
export GCP_LOCATION="global"
export GCP_KEYRING="my-keyring"
export GCP_KEY_ID="my-key"
crypto -c encrypt -p gcp -v "my-secret"
```

#### AWS KMS

```bash
crypto -c encrypt -p aws -v "my-secret" \
  --aws-region "us-east-1" \
  --aws-key "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"

# Or using environment variables
export AWS_REGION="us-east-1"
export AWS_KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
crypto -c encrypt -p aws -v "my-secret"
```

### Decrypt Values

```bash
# Local
crypto -c decrypt -p local -v "local:ABC123..." --encryption-key "your-base64-key"

# GCP KMS
crypto -c decrypt -p gcp -v "gcp:XYZ789..." \
  --gcp-project "my-project" \
  --gcp-location "global" \
  --gcp-keyring "my-keyring" \
  --gcp-key "my-key"

# AWS KMS
crypto -c decrypt -p aws -v "aws:DEF456..." \
  --aws-region "us-east-1" \
  --aws-key "arn:aws:kms:us-east-1:123456789012:key/..."
```

### Sign Values

Sign values to create cryptographic signatures that can be verified later:

```bash
# Local signing
crypto -c sign -p local -v "my-data-to-sign" --encryption-key "your-base64-key"

# Using environment variable
export CRYPTO_ENCRYPTION_KEY="your-base64-key"
crypto -c sign -p local -v "my-data-to-sign"

# Using stdin
echo "my-data-to-sign" | crypto -c sign -p local --stdin --encryption-key "your-base64-key"

# GCP KMS signing
crypto -c sign -p gcp -v "my-data" \
  --gcp-project "my-project" \
  --gcp-location "global" \
  --gcp-keyring "my-keyring" \
  --gcp-key "my-key"

# AWS KMS signing
crypto -c sign -p aws -v "my-data" \
  --aws-region "us-east-1" \
  --aws-key "arn:aws:kms:us-east-1:123456789012:key/..."
```

### Verify Signatures

Verify that data was signed with the correct key:

```bash
# Local verification
crypto -c verify -p local -v "my-data|<base64-signature>" --encryption-key "your-base64-key"

# Using environment variable
export CRYPTO_ENCRYPTION_KEY="your-base64-key"
crypto -c verify -p local -v "my-data|<base64-signature>"

# Using stdin
echo "my-data|<base64-signature>" | crypto -c verify -p local --stdin --encryption-key "your-base64-key"

# GCP KMS verification
crypto -c verify -p gcp -v "my-data|<base64-signature>" \
  --gcp-project "my-project" \
  --gcp-location "global" \
  --gcp-keyring "my-keyring" \
  --gcp-key "my-key"

# AWS KMS verification
crypto -c verify -p aws -v "my-data|<base64-signature>" \
  --aws-region "us-east-1" \
  --aws-key "arn:aws:kms:us-east-1:123456789012:key/..."
```

The verify command returns `true` if the signature is valid, `false` otherwise.

## Encrypted Value Format

Encrypted values are prefixed with the provider name:

- `local:` - Encrypted with local AES-256-GCM
- `gcp:` - Encrypted with Google Cloud KMS
- `aws:` - Encrypted with AWS KMS

Example:
```
local:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/==
```

## Configuration

### Command-Line Flags

| Flag | Description |
|------|-------------|
| `-c` | Command: `encrypt`, `decrypt`, `sign`, or `verify` |
| `-p` | Provider: `local`, `gcp`, or `aws` |
| `-v` | Value to encrypt/decrypt/sign/verify |
| `--stdin` | Read value from stdin |
| `--generate-key` | Generate a random encryption key |
| `--encryption-key` | Encryption key (base64-encoded for local) |
| `--signing-key` | Signing key (base64-encoded for local, optional) |
| `--gcp-project` | GCP project ID |
| `--gcp-location` | GCP location |
| `--gcp-keyring` | GCP key ring name |
| `--gcp-key` | GCP key ID |
| `--aws-region` | AWS region |
| `--aws-key` | AWS KMS key ID or ARN |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CRYPTO_ENCRYPTION_KEY` | Encryption key (fallback: `CRYPTO_LOCAL_KEY`) |
| `CRYPTO_SIGNING_KEY` | Signing key (optional, uses encryption key if not provided) |
| `GCP_PROJECT_ID` | GCP project ID |
| `GCP_LOCATION` | GCP location |
| `GCP_KEYRING` | GCP key ring |
| `GCP_KEY_ID` | GCP key ID |
| `AWS_REGION` | AWS region |
| `AWS_KMS_KEY_ID` | AWS KMS key ID |

## Examples

### Encrypting Database Credentials

```bash
# Generate a key
CRYPTO_KEY=$(crypto --generate-key)

# Encrypt the database password
DB_PASSWORD=$(crypto -c encrypt -p local -v "super-secret-password" --encryption-key "$CRYPTO_KEY")

# Use in configuration
echo "Database password: $DB_PASSWORD"
```

### Using with Configuration Files

```bash
# Encrypt a value for your config
crypto -c encrypt -p local -v "my-oauth-secret" --encryption-key "$CRYPTO_KEY"

# Output: local:AbCdEfGh...

# Add to your YAML config:
# oauth:
#   client_secret: "local:AbCdEfGh..."
```

### Batch Encryption

```bash
#!/bin/bash
export CRYPTO_ENCRYPTION_KEY="your-base64-key"

# Encrypt multiple values
for secret in "password1" "password2" "api-key"; do
  echo "$secret -> $(echo "$secret" | crypto -c encrypt -p local --stdin)"
done
```

### Signing and Verification Examples

```bash
#!/bin/bash
export CRYPTO_ENCRYPTION_KEY="your-base64-key"

# Sign some data
DATA="important-configuration-data"
SIGNATURE=$(echo "$DATA" | crypto -c sign -p local --stdin)
echo "Data: $DATA"
echo "Signature: $SIGNATURE"

# Verify the signature
VERIFY_INPUT="$DATA|$SIGNATURE"
RESULT=$(echo "$VERIFY_INPUT" | crypto -c verify -p local --stdin)
echo "Verification result: $RESULT"
```

## Security Best Practices

1. **Never commit encryption keys to version control**
2. **Use environment variables or secure key management systems**
3. **Rotate encryption keys regularly**
4. **Use KMS providers (GCP/AWS) in production**
5. **Limit access to encrypted values and keys**
6. **Use separate keys for different environments**

## Integration with Proxy Server

The encrypted values can be used directly in the proxy server configuration files. The server will automatically detect and decrypt values with the appropriate provider prefix.

See the main [Crypto Package README](../../internal/crypto/README.md) for more details on integration.

