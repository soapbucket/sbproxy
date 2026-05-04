# Web Bot Auth

*Last modified: 2026-04-27*

Cryptographic agent verification under RFC 9421 HTTP Message Signatures and the IETF Web Bot Auth draft. AI agents (crawlers, indexers, research bots) sign each request with an Ed25519 key and advertise the key id in the `Signature-Input` header. The gateway verifies the signature against a directory of agent public keys; only agents with valid signatures pass through. OSS ships the inline directory shape used here; a periodic-refresh JWKS-style directory wires onto the same `Directory` trait. `clock_skew_seconds` bounds replay; `required_components` defaults to `["@method", "@target-uri"]` so a signature that only covers a header cannot be replayed against a different verb or URL.

## Run

```bash
export OPENAI_BOT_PUBKEY=...        # 32-byte ed25519 pubkey, hex or base64
export ANTHROPIC_BOT_PUBKEY=...
export PERPLEXITY_BOT_PUBKEY=...
sb run -c sb.yml
```

The directory is populated from environment variables here. Production deployments typically materialise these from a vault or a hosted directory.

## Try it

```bash
# Unsigned request - 401 with bot_auth: signature required.
curl -i -H 'Host: blog.local' http://127.0.0.1:8080/article
# HTTP/1.1 401 Unauthorized
# bot_auth: signature required
```

```bash
# Signed request from a verified bot - 200. The Signature-Input
# header names the keyid and the covered components; the Signature
# header carries the base64 ed25519 signature. See the bot_auth unit
# tests for the canonical request format.
curl -i -H 'Host: blog.local' \
     -H 'Signature-Input: sig1=("@method" "@target-uri" "@authority");keyid="openai-2026-01";created=1710000000;alg="ed25519"' \
     -H 'Signature: sig1=:BASE64_SIG_BYTES:' \
     http://127.0.0.1:8080/article
```

```bash
# Signature with a keyid not in the directory - 401.
curl -i -H 'Host: blog.local' \
     -H 'Signature-Input: sig1=("@method" "@target-uri");keyid="unknown-key";created=1710000000;alg="ed25519"' \
     -H 'Signature: sig1=:BASE64_SIG_BYTES:' \
     http://127.0.0.1:8080/article
```

## What this exercises

- `authentication.type: bot_auth` - RFC 9421 HTTP Message Signatures verification
- `agents[]` directory entries with `key_id`, `algorithm` (ed25519 or hmac_sha256), and `public_key`
- `required_components` - signed components every accepted signature must cover
- `clock_skew_seconds` - bounds replay tolerance on the `created` parameter

## See also

- [docs/web-bot-auth.md](../../docs/web-bot-auth.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
