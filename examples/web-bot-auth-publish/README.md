# Web Bot Auth publish: SBproxy as a signing agent

*Last modified: 2026-05-31*

Demonstrates the `web_bot_auth_publish` per-origin config. SBproxy serves its own JWKS-shaped signing-key directory at `/.well-known/http-message-signatures-directory` and a Signature Agent Card discovery doc at `/.well-known/web-bot-auth/agent-card`. Verifiers (Cloudflare, AWS WAF, third-party origins running a Web Bot Auth verifier) fetch the directory to verify the `Signature-Input` + `Signature` headers SBproxy attaches to outbound requests when the corresponding signer is wired upstream.

## Run

```bash
make run CONFIG=examples/web-bot-auth-publish/sb.yml
```

## Try it

Fetch the directory JWKS:

```bash
curl -i -H 'Host: agent.local' \
  http://127.0.0.1:8080/.well-known/http-message-signatures-directory
```

Response body (formatted for readability):

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

Content-Type is `application/http-message-signatures-directory+json` per the Web Bot Auth IETF draft.

Fetch the Signature Agent Card:

```bash
curl -i -H 'Host: agent.local' \
  http://127.0.0.1:8080/.well-known/web-bot-auth/agent-card
```

Response body:

```json
{
  "name": "SBproxy",
  "directory_url": "https://agent.local/.well-known/http-message-signatures-directory",
  "description": "Example SBproxy deployment with outbound Web Bot Auth signing.",
  "contact_url": "mailto:abuse@example.com"
}
```

Disable the publish surface by removing the `web_bot_auth_publish` block; SBproxy then returns 404 on both paths rather than forwarding to the upstream.

## What the secret side looks like

The example only carries the PUBLIC key. The matching private key lives outside YAML; the standard rotation flow is:

1. Generate an Ed25519 keypair in the operator's vault / HSM.
2. Configure the outbound signer (separate follow-up) with the private side.
3. Publish the public half here so verifiers can discover it.
4. To rotate: add the new public key to the `web_bot_auth_publish` block (when multi-key publish ships) alongside the old one, swap the signer, then drop the old key once outstanding signatures have aged out.

The signing primitive that consumes the private side is `sbproxy_middleware::signatures::MessageSignatureSigner`.

## See also

* [docs/web-bot-auth.md](../../docs/web-bot-auth.md) — the buyer-facing Web Bot Auth doc.
* [examples/web-bot-auth/](../web-bot-auth/) — the inbound verify side (SBproxy as the verifier).
