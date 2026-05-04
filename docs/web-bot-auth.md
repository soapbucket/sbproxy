# Web Bot Auth
*Last modified: 2026-04-27*

The `bot_auth` provider verifies cryptographically-signed AI agents per the IETF "Web Bot Auth" pattern. AI crawlers sign each request with an Ed25519 key under [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) and advertise their `keyid` in the `Signature-Input` header; the gateway looks up the matching public key in its directory and verifies the signature. Agents that pass come through; everything else gets `401`.

## Wire shape

```
GET /article HTTP/1.1
Host: blog.example.com
User-Agent: GPTBot/1.0
Signature-Input: sig1=("@method" "@target-uri" "@authority");created=1700000000;keyid="openai-2026-01";alg="ed25519"
Signature: sig1=:Tcle5Bn3...:
```

## Configuration

```yaml
authentication:
  type: bot_auth
  clock_skew_seconds: 30
  agents:
    - name: openai-gptbot
      key_id: openai-2026-01
      algorithm: ed25519
      public_key: ${OPENAI_BOT_PUBKEY}
      required_components:
        - "@method"
        - "@target-uri"
        - "@authority"
    - name: anthropic-claudebot
      key_id: anthropic-2026-01
      algorithm: ed25519
      public_key: ${ANTHROPIC_BOT_PUBKEY}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `agents` | list | required, non-empty | Directory of known agents. Each `key_id` must be unique. |
| `clock_skew_seconds` | int | 30 | Tolerance for the `created` / `expires` parameters. |
| `agents[].name` | string | required | Human-readable agent name. Surfaced in logs. |
| `agents[].key_id` | string | required | `keyid` parameter the agent advertises in `Signature-Input`. |
| `agents[].algorithm` | string | required | `ed25519` or `hmac_sha256`. |
| `agents[].public_key` | string | required | Hex- or base64-encoded raw key bytes. |
| `agents[].required_components` | list | `["@method", "@target-uri"]` | Signature components every accepted request must cover. |

## Verdicts

The provider produces one of four verdicts; only the first allows the request:

| Verdict | Action | Cause |
|---------|--------|-------|
| `Verified` | Allow | Signature valid against an agent in the directory. |
| `Missing` | `401` | No `Signature-Input` header. |
| `UnknownAgent` | `401` | `keyid` claimed in `Signature-Input` is not in the directory. |
| `Failed` | `401` | Header parse failure, signature mismatch, expired, or required component missing. |

The denial body is intentionally generic (`bot_auth: signature required` / `bot_auth: verification failed`); detailed reasons land in the structured log under the `sbproxy::auth` target so an operator can see exactly which check failed without leaking the same detail to a probing crawler.

## Required components

By default a verifier accepts a signature that covers `("@method" "@target-uri")`. That alone prevents replay across different routes. Tighten this when the upstream relies on a specific header:

```yaml
required_components:
  - "@method"
  - "@target-uri"
  - "@authority"
  - "content-digest"   # bind the body
  - "x-replay-id"      # caller-supplied nonce
```

A signature that omits any required component fails verification. Components are matched by their RFC 9421 canonical name, lowercased.

## Pairing with AI Crawl Control

`bot_auth` and `ai_crawl_control` (F1.7) compose:

```yaml
origins:
  "blog.example.com":
    action: { type: proxy, url: https://upstream.example }
    authentication: { type: bot_auth, agents: [...] }
    policies:
      - type: ai_crawl_control
        price: 0.001
        valid_tokens: [...]
```

A signed crawler still pays per request unless its `Crawler-Payment` token redeems. An unsigned client never reaches the policy. This gives operators two independent gates: identity (bot_auth) and metering (ai_crawl_control).

## Limitations

- The OSS directory is inline in YAML. Dynamic directory refresh from a hosted JWKS-shaped document is on the roadmap; the same `Directory` trait will back both shapes.
- Verification runs in the synchronous auth phase, before the request body is buffered. Signatures that cover `content-digest` therefore fail when the body is non-empty (the verifier sees an empty body). Track the buffered-body wiring under F1.6.1.
- HTTP/3 / QUIC requests deny by default until the H3 dispatch path is plumbed with the full request shape needed for signature reconstruction.

## See also

- [configuration.md](configuration.md#bot_auth) - schema reference.
- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) - the underlying signature standard.
- `crates/sbproxy-modules/src/auth/bot_auth.rs` - source.
- `examples/91-web-bot-auth/sb.yml` - runnable example.
