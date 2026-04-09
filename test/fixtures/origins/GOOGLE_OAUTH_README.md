# Google OAuth Configuration

This file contains a Google OAuth authentication configuration example with encrypted secrets.

## Configuration Details

- **Client ID**: `781990534849-t6v26s5v7blu48kgkocdluvjv0jvlrhk.apps.googleusercontent.com`
- **Client Secret**: Encrypted using local encryption (see below)
- **Provider**: Google OAuth 2.0
- **Scopes**: `openid`, `profile`, `email`

## Encryption

The secrets in this configuration are encrypted using the local encryption provider. The encrypted values have the `local:` prefix.

### Encryption Key

To decrypt these secrets, you need the encryption key. The key used for encryption was:
```
ErUVizIW93RB9PtcNgZXj7RxTrK7BxOLbrtzlXpbFLI=
```

**Important**: This key must match the `crypto_settings.params.encryption_key` value in your `sb.yml` configuration file.

### Updating the Encryption Key in Config

If you need to use a different encryption key, update `conf/sb.test.yml`:

```yaml
crypto_settings:
  driver: "local"
  params:
    encryption_key: "ErUVizIW93RB9PtcNgZXj7RxTrK7BxOLbrtzlXpbFLI="
```

### Re-encrypting Secrets

If you need to re-encrypt the secrets with a different key:

```bash
# Set your encryption key
export CRYPTO_LOCAL_KEY="your-base64-32-byte-key"

# Encrypt the client secret
echo "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" | \
  tools/crypto/crypto -c encrypt -p local --stdin

# Encrypt the session secret
echo "your-session-secret-32-bytes-long!" | \
  tools/crypto/crypto -c encrypt -p local --stdin
```

## Testing

### 1. Add to /etc/hosts

```bash
127.0.0.1 google-oauth.test
```

### 2. Test OAuth Flow

```bash
# Start OAuth login flow
curl -L "http://google-oauth.test:8080/oauth/login"

# Or access in browser
# http://google-oauth.test:8080/oauth/login
```

### 3. Verify Authentication

After successful OAuth authentication, requests will include user information in headers:
- `X-User-ID`: Google user ID
- `X-User-Email`: User email
- `X-User-Name`: User name

## Google OAuth Setup

To use this configuration, you need to:

1. **Create OAuth Credentials** in Google Cloud Console:
   - Go to https://console.cloud.google.com/apis/credentials
   - Create OAuth 2.0 Client ID
   - Add authorized redirect URIs: `https://google-oauth.test:8443/oauth/callback`

2. **Update Configuration**:
   - Update `client_id` if needed
   - Re-encrypt `client_secret` with your encryption key
   - Update `redirect_url` to match your domain

## Security Notes

- **Never commit unencrypted secrets** to version control
- **Rotate encryption keys** periodically
- **Use environment-specific keys** for different environments
- **Store encryption keys securely** (use secrets management)

