# Crypto CLI Tool - Usage Examples

Comprehensive examples for using the crypto command-line tool.

## Table of Contents
- [Setup](#setup)
- [Key Generation](#key-generation)
- [Local Encryption](#local-encryption)
- [GCP KMS](#gcp-kms)
- [AWS KMS](#aws-kms)
- [Batch Operations](#batch-operations)
- [Integration with Configuration](#integration-with-configuration)

## Setup

First, build the tool:

```bash
cd /Users/rick/projects/proxy/tools/crypto
./install.sh

# Or build manually:
go build -o crypto main.go
```

## Key Generation

### Generate a New Encryption Key

```bash
# Generate and display a new key
./crypto --generate-key

# Save to a file
./crypto --generate-key > .encryption-key

# Save to environment variable
export CRYPTO_LOCAL_KEY=$(./crypto --generate-key)
```

## Local Encryption

### Basic Encryption

```bash
# Encrypt a value using command-line flag
./crypto -c encrypt -p local -v "my-secret-password" --local-key "$CRYPTO_LOCAL_KEY"

# Output: local:AbCdEfGhIjKlMnOpQrStUvWxYz==
```

### Using stdin

```bash
# Encrypt from stdin
echo "my-secret" | ./crypto -c encrypt -p local --stdin --local-key "$CRYPTO_LOCAL_KEY"

# Encrypt a file content
cat password.txt | ./crypto -c encrypt -p local --stdin --local-key "$CRYPTO_LOCAL_KEY"
```

### Decryption

```bash
# Decrypt a value
./crypto -c decrypt -p local -v "local:AbCdEfGh..." --local-key "$CRYPTO_LOCAL_KEY"

# Decrypt from stdin
echo "local:AbCdEfGh..." | ./crypto -c decrypt -p local --stdin --local-key "$CRYPTO_LOCAL_KEY"
```

### Environment Variable Configuration

```bash
# Set encryption key in environment
export CRYPTO_LOCAL_KEY="your-base64-key-here"

# Now you can omit the --local-key flag
./crypto -c encrypt -p local -v "my-secret"
./crypto -c decrypt -p local -v "local:AbCdEfGh..."
```

## GCP KMS

### Setup

```bash
# Set GCP credentials
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"

# Configure GCP KMS
export GCP_PROJECT_ID="my-project"
export GCP_LOCATION="global"
export GCP_KEYRING="my-keyring"
export GCP_KEY_ID="my-crypto-key"
```

### Encrypt with GCP KMS

```bash
# Using environment variables
./crypto -c encrypt -p gcp -v "my-secret"

# Using command-line flags
./crypto -c encrypt -p gcp -v "my-secret" \
  --gcp-project "my-project" \
  --gcp-location "global" \
  --gcp-keyring "my-keyring" \
  --gcp-key "my-crypto-key"

# Output: gcp:GcpEncryptedValue==
```

### Decrypt with GCP KMS

```bash
# Using environment variables
./crypto -c decrypt -p gcp -v "gcp:GcpEncryptedValue=="

# Using command-line flags
./crypto -c decrypt -p gcp -v "gcp:GcpEncryptedValue==" \
  --gcp-project "my-project" \
  --gcp-location "global" \
  --gcp-keyring "my-keyring" \
  --gcp-key "my-crypto-key"
```

## AWS KMS

### Setup

```bash
# Configure AWS credentials (or use IAM role)
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"

# Configure KMS key
export AWS_REGION="us-east-1"
export AWS_KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
```

### Encrypt with AWS KMS

```bash
# Using environment variables
./crypto -c encrypt -p aws -v "my-secret"

# Using command-line flags
./crypto -c encrypt -p aws -v "my-secret" \
  --aws-region "us-east-1" \
  --aws-key "arn:aws:kms:us-east-1:123456789012:key/..."

# Output: aws:AwsEncryptedValue==
```

### Decrypt with AWS KMS

```bash
# Using environment variables
./crypto -c decrypt -p aws -v "aws:AwsEncryptedValue=="

# Using command-line flags
./crypto -c decrypt -p aws -v "aws:AwsEncryptedValue==" \
  --aws-region "us-east-1" \
  --aws-key "arn:aws:kms:..."
```

## Batch Operations

### Encrypt Multiple Values

```bash
#!/bin/bash
# encrypt-secrets.sh

export CRYPTO_LOCAL_KEY=$(./crypto --generate-key)
echo "Using key: $CRYPTO_LOCAL_KEY"
echo ""

# Array of secrets to encrypt
declare -A secrets=(
  ["database_password"]="super-secret-db-pass"
  ["api_key"]="sk_live_12345"
  ["oauth_secret"]="oauth-client-secret"
  ["session_key"]="session-secret-key-xyz"
)

# Encrypt each secret
for name in "${!secrets[@]}"; do
  value="${secrets[$name]}"
  encrypted=$(echo "$value" | ./crypto -c encrypt -p local --stdin)
  echo "$name: $encrypted"
done
```

### Decrypt Multiple Values

```bash
#!/bin/bash
# decrypt-secrets.sh

export CRYPTO_LOCAL_KEY="your-encryption-key"

# Read encrypted values from a file
while IFS=': ' read -r name encrypted; do
  decrypted=$(echo "$encrypted" | ./crypto -c decrypt -p local --stdin)
  echo "$name: $decrypted"
done < encrypted-secrets.txt
```

### Rotate Encryption Keys

```bash
#!/bin/bash
# rotate-keys.sh

OLD_KEY="$1"
NEW_KEY=$(./crypto --generate-key)

echo "New key: $NEW_KEY"
echo "Rotating encrypted values..."

# Decrypt with old key and re-encrypt with new key
for encrypted in $(cat encrypted-values.txt); do
  # Decrypt with old key
  plaintext=$(echo "$encrypted" | CRYPTO_LOCAL_KEY="$OLD_KEY" \
    ./crypto -c decrypt -p local --stdin)
  
  # Encrypt with new key
  new_encrypted=$(echo "$plaintext" | CRYPTO_LOCAL_KEY="$NEW_KEY" \
    ./crypto -c encrypt -p local --stdin)
  
  echo "$new_encrypted"
done
```

## Integration with Configuration

### Encrypting YAML Configuration Values

```bash
#!/bin/bash
# encrypt-yaml-values.sh

export CRYPTO_LOCAL_KEY=$(cat .encryption-key)

# Encrypt specific values for YAML config
oauth_secret=$(./crypto -c encrypt -p local -v "my-oauth-secret")
db_password=$(./crypto -c encrypt -p local -v "my-db-password")

# Create YAML config with encrypted values
cat > config.yaml <<EOF
proxy:
  oauth:
    enabled: true
    client_secret: "$oauth_secret"
  
  database:
    dsn: "postgresql://user:$db_password@localhost/db"
EOF

echo "Created config.yaml with encrypted values"
```

### Encrypting JSON Origin Configuration

```bash
#!/bin/bash
# encrypt-origin-config.sh

export CRYPTO_LOCAL_KEY=$(cat .encryption-key)

# Encrypt S3 credentials
s3_key="AKIAIOSFODNN7EXAMPLE"
s3_secret=$(./crypto -c encrypt -p local -v "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

# Create JSON config
cat > origin-config.json <<EOF
{
  "id": "s3-cdn",
  "hostname": "cdn.example.com",
  "type": "storage",
  "config": {
    "kind": "s3",
    "bucket": "my-cdn-bucket",
    "region": "us-east-1",
    "key": "$s3_key",
    "secret": "$s3_secret"
  }
}
EOF

echo "Created origin-config.json with encrypted secret"
```

### Decrypt and Verify Configuration

```bash
#!/bin/bash
# verify-encrypted-config.sh

export CRYPTO_LOCAL_KEY=$(cat .encryption-key)

# Extract encrypted values from config
encrypted_values=$(grep -oE '(local|gcp|aws):[A-Za-z0-9+/=]+' config.yaml)

echo "Verifying encrypted values..."
for value in $encrypted_values; do
  # Try to decrypt
  if decrypted=$(echo "$value" | ./crypto -c decrypt -p local --stdin 2>/dev/null); then
    echo "✓ Successfully decrypted: ${value:0:20}..."
  else
    echo "✗ Failed to decrypt: ${value:0:20}..."
  fi
done
```

## Working with Different Environments

### Development Environment

```bash
# .env.development
export CRYPTO_LOCAL_KEY=$(./crypto --generate-key)

# Encrypt dev secrets
DEV_DB_PASSWORD=$(./crypto -c encrypt -p local -v "dev-password")
DEV_API_KEY=$(./crypto -c encrypt -p local -v "dev-api-key")
```

### Staging Environment

```bash
# .env.staging
export CRYPTO_LOCAL_KEY=$(./crypto --generate-key)

# Use different secrets for staging
STAGING_DB_PASSWORD=$(./crypto -c encrypt -p local -v "staging-password")
STAGING_API_KEY=$(./crypto -c encrypt -p local -v "staging-api-key")
```

### Production Environment (using KMS)

```bash
# .env.production
export GCP_PROJECT_ID="production-project"
export GCP_LOCATION="us-central1"
export GCP_KEYRING="production-keyring"
export GCP_KEY_ID="config-encryption-key"

# Encrypt production secrets with GCP KMS
PROD_DB_PASSWORD=$(./crypto -c encrypt -p gcp -v "prod-password")
PROD_API_KEY=$(./crypto -c encrypt -p gcp -v "prod-api-key")
```

## Pipeline Integration

### CI/CD Pipeline Example

```yaml
# .github/workflows/deploy.yml
name: Deploy with Encrypted Config

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Go
        uses: actions/setup-go@v2
        
      - name: Build crypto tool
        run: |
          cd tools/crypto
          go build -o crypto main.go
      
      - name: Encrypt secrets
        env:
          CRYPTO_LOCAL_KEY: ${{ secrets.CRYPTO_KEY }}
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
          API_KEY: ${{ secrets.API_KEY }}
        run: |
          encrypted_db=$(echo "$DB_PASSWORD" | ./tools/crypto/crypto -c encrypt -p local --stdin)
          encrypted_api=$(echo "$API_KEY" | ./tools/crypto/crypto -c encrypt -p local --stdin)
          
          # Update config with encrypted values
          sed -i "s|DB_PASSWORD_PLACEHOLDER|$encrypted_db|g" config.yaml
          sed -i "s|API_KEY_PLACEHOLDER|$encrypted_api|g" config.yaml
      
      - name: Deploy
        run: |
          # Deploy with encrypted config
          kubectl apply -f config.yaml
```

## Troubleshooting

### Check if a value is encrypted

```bash
if [[ "$value" =~ ^(local|gcp|aws): ]]; then
  echo "Value is encrypted"
else
  echo "Value is plain text"
fi
```

### Verify encryption key works

```bash
test_value="test-123"
encrypted=$(echo "$test_value" | ./crypto -c encrypt -p local --stdin)
decrypted=$(echo "$encrypted" | ./crypto -c decrypt -p local --stdin)

if [ "$decrypted" == "$test_value" ]; then
  echo "✓ Encryption key is working"
else
  echo "✗ Encryption key verification failed"
fi
```

### Debug encryption issues

```bash
# Enable verbose output (if implemented)
export CRYPTO_DEBUG=1

# Try encryption with detailed error output
./crypto -c encrypt -p local -v "test" 2>&1 | tee crypto-debug.log
```

## Best Practices

1. **Always use environment variables for keys in production**
   ```bash
   export CRYPTO_LOCAL_KEY=$(cat /secure/path/encryption-key)
   ```

2. **Never commit encryption keys to version control**
   ```bash
   echo ".encryption-key" >> .gitignore
   echo "*.key" >> .gitignore
   ```

3. **Use different keys for different environments**
   ```bash
   export CRYPTO_LOCAL_KEY_DEV=$(./crypto --generate-key)
   export CRYPTO_LOCAL_KEY_PROD=$(./crypto --generate-key)
   ```

4. **Rotate keys periodically**
   ```bash
   # Every 90 days
   ./rotate-keys.sh "$OLD_KEY"
   ```

5. **Use KMS in production**
   ```bash
   # Prefer GCP or AWS KMS over local encryption in production
   ./crypto -c encrypt -p gcp -v "production-secret"
   ```

6. **Backup encryption keys securely**
   ```bash
   # Store in a password manager or secrets vault
   aws secretsmanager put-secret-value \
     --secret-id crypto-encryption-key \
     --secret-string "$CRYPTO_LOCAL_KEY"
   ```

