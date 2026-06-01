# content_digest: RFC 9530 request-body verification

*Last modified: 2026-05-31*

Demonstrates the `content_digest` policy on a webhook receiver. The proxy hashes every inbound body and compares the result to the `Content-Digest:` header the sender supplied. Mismatch or missing header (with `on_missing: require`) rejects 400 before forwarding to upstream. Useful for any integrity-critical inbox: webhook receivers, payment callbacks, agent endpoints, audit-ingest paths.

## Run

```bash
make run CONFIG=examples/content-digest/sb.yml
```

## Try it

Compute the digest, then send the body with the matching header:

```bash
BODY='{"event":"order.created","id":"ord-42"}'
DIGEST=$(printf '%s' "$BODY" | openssl dgst -sha256 -binary | openssl base64)

curl -X POST -H 'Host: webhook.example.com' \
  -H "Content-Digest: sha-256=:${DIGEST}:" \
  -H 'Content-Type: application/json' \
  -d "$BODY" \
  http://127.0.0.1:8080/webhook
```

Send the wrong digest or omit it entirely to see the 400:

```bash
# Mismatch.
curl -X POST -H 'Host: webhook.example.com' \
  -H 'Content-Digest: sha-256=:wronghashbase64==:' \
  -H 'Content-Type: application/json' \
  -d "$BODY" \
  http://127.0.0.1:8080/webhook

# Missing header.
curl -X POST -H 'Host: webhook.example.com' \
  -H 'Content-Type: application/json' \
  -d "$BODY" \
  http://127.0.0.1:8080/webhook
```

See [docs/content-digest.md](../../docs/content-digest.md) for the full schema and the `Repr-Digest` fallback.
