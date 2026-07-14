# Getting started: Agent identity issuance and enforcement

*Last modified: 2026-07-09*

## What you will build

A gateway that gives AI agents a verifiable identity and enforces it at the edge. Inbound agents sign each request with an Ed25519 key under RFC 9421 HTTP Message Signatures, and SBproxy verifies the signature against a directory of known agent keys before the request reaches the upstream. You will also publish SBproxy's own signing-key directory so other verifiers can confirm the requests SBproxy signs on the way out.

## Prerequisites

- A shell with `curl`.
- `openssl` (used below to generate an Ed25519 keypair for a test agent).
- An upstream to proxy to. This guide uses `test.sbproxy.dev` as the placeholder upstream, following the repo convention.

## Install

You do not have to compile anything to run SBproxy. One line installs the prebuilt binary on macOS or Linux (the script detects OS and architecture and drops the binary in `~/.local/bin`):

```bash
curl -fsSL https://download.sbproxy.dev | sh
```

Homebrew, Docker, binary downloads, and source builds are in the [runtime manual's installation section](manual.md#1-installation). Run the gateway with a config file:

```bash
sbproxy serve -f sb.yml
```

The same `serve -f <config>` form works for the Docker image (`soapbucket/sbproxy:latest serve -f /etc/sbproxy/sb.yml`).

## Minimal config

Save this as `sb.yml`. The `bot_auth` provider is the enforcement side: it verifies signed agents against the inline `agents` directory. The `web_bot_auth_publish` block is the issuance side: it serves SBproxy's own signing-key directory so verifiers can discover the key SBproxy signs outbound requests with.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/soapbucket/sbproxy/main/schemas/sb-config.schema.json
proxy:
  http_bind_port: 8080

origins:
  "blog.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev

    # Enforcement: verify inbound agent signatures (RFC 9421).
    authentication:
      type: bot_auth
      clock_skew_seconds: 30
      agents:
        - name: openai-gptbot
          key_id: openai-2026-01
          algorithm: ed25519
          # Hex- or base64-encoded raw 32-byte ed25519 public key.
          # Replace with your test agent's real published key below.
          public_key: "0011223344556677889900112233445566778899001122334455667788990011"
          # Every accepted signature must cover these components, so a
          # signature cannot be replayed against a different verb or URL.
          required_components:
            - "@method"
            - "@target-uri"
            - "@authority"

    # Issuance: publish SBproxy's own signing-key directory + agent card.
    # Only the PUBLIC half lives in YAML; keep the private key in a vault.
    web_bot_auth_publish:
      enabled: true
      key_id: "sbproxy-key-2026-05-31"
      public_key_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
      agent_name: "SBproxy"
      directory_url: "https://blog.local/.well-known/http-message-signatures-directory"
      description: "Example SBproxy deployment with outbound Web Bot Auth signing."
      contact_url: "mailto:abuse@example.com"
```

Every key above appears in `schemas/sb-config.schema.json` and in the `examples/web-bot-auth` and `examples/web-bot-auth-publish` configs. To generate a real key for the test agent, create an Ed25519 keypair and paste its public half (hex) into the `public_key` field:

```bash
openssl genpkey -algorithm ed25519 -out openai-bot.pem
openssl pkey -in openai-bot.pem -pubout -outform DER | tail -c 32 | xxd -p -c 64
```

## Run it and expected output

Start the gateway:

```bash
sbproxy serve -f sb.yml
```

Enforcement: an unsigned request is rejected with `401`.

```bash
curl -i -H 'Host: blog.local' http://127.0.0.1:8080/article
# HTTP/1.1 401 Unauthorized
# bot_auth: signature required
```

A request whose `keyid` is not in the directory is also rejected with `401`. The verifier rejects on the directory miss before it even checks the signature math.

```bash
# Signature-Input carries keyid="not-in-directory"
curl -i -H 'Host: blog.local' \
     -H 'Signature-Input: sig1=("@method" "@target-uri" "@authority");created=1700000000;keyid="not-in-directory";alg="ed25519"' \
     -H 'Signature: sig1=:AAAA:' \
     http://127.0.0.1:8080/article
# HTTP/1.1 401 Unauthorized
```

A request signed by the key in the directory passes and is forwarded to the upstream with `200`. Production clients generate the `Signature-Input` and `Signature` headers with an RFC 9421 signer keyed to the private half of the keypair above.

```bash
curl -i -H 'Host: blog.local' \
     -H "Signature-Input: $SIG_INPUT" \
     -H "Signature: $SIG" \
     http://127.0.0.1:8080/article
# HTTP/1.1 200 OK
```

Issuance: fetch the signing-key directory SBproxy publishes. Other verifiers fetch this to discover the key SBproxy signs outbound requests with.

```bash
curl -i -H 'Host: blog.local' \
  http://127.0.0.1:8080/.well-known/http-message-signatures-directory
# HTTP/1.1 200 OK
# content-type: application/http-message-signatures-directory+json
```

The body is a JWKS document with one key entry:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPbqsj1oz3Wm9FTo4Y",
      "kid": "sbproxy-key-2026-05-31",
      "key_ops": ["sign"],
      "tag": "web-bot-auth"
    }
  ]
}
```

The Signature Agent Card is served at the companion well-known path:

```bash
curl -i -H 'Host: blog.local' \
  http://127.0.0.1:8080/.well-known/web-bot-auth/agent-card
# HTTP/1.1 200 OK
```

## You are done when

- An unsigned request to `/article` returns `401` with the body `bot_auth: signature required`.
- A request whose `keyid` is not in the `agents` directory returns `401`.
- A request signed by a directory key returns `200` and reaches the upstream.
- `GET /.well-known/http-message-signatures-directory` returns `200` with `Content-Type: application/http-message-signatures-directory+json` and a JSON body containing a `keys` array whose single entry has `"kid": "sbproxy-key-2026-05-31"`.
- `GET /.well-known/web-bot-auth/agent-card` returns `200` with an `"name": "SBproxy"` body.

## Next steps

- [docs/web-bot-auth.md](web-bot-auth.md) - the `bot_auth` provider reference, verdict table, and the publish-side directory.
- [docs/a2a-gateway.md](a2a-gateway.md) - the `a2a` action for typed AgentCard, capability discovery, and chain-safety policy.
- [docs/agent-skills.md](agent-skills.md) - the Agent Skills v0.2.0 well-known projection with SHA-256 integrity.
- [docs/configuration.md](configuration.md) - the full config schema reference, including the `authentication` block.
