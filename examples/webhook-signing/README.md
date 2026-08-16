# Webhook signing

*Last modified: 2026-08-16*

![Webhook signing](../../docs/assets/webhook-signing.gif)

Every lifecycle webhook the proxy fires (`on_request`, `on_response`) carries a structured envelope and, when `secret` is set on the callback, an HMAC-SHA256 signature so the receiver can verify it wasn't forged. Headers on the webhook request include `X-Sbproxy-Event`, `X-Sbproxy-Instance`, `X-Sbproxy-Request-Id`, `X-Sbproxy-Config-Revision`, `X-Sbproxy-Timestamp`, and `X-Sbproxy-Signature: v1=<hex>`. The signature is `HMAC-SHA256(secret, "<timestamp>.<body>")`. Receivers should verify within a fixed time window (e.g. 5 minutes) to reject replays.

## Run

```bash
sbproxy serve -f sb.yml
```

The receiver URL `https://hooks.example.com/sbproxy` is illustrative. Point it at your own server (e.g. RequestBin, ngrok, a Cloud Function) to inspect the envelope and verify the signature.

## Try it

```bash
# Fire a request through the proxy. The receiver gets one POST per request
# at on_request and another at on_response.
curl -s -H 'Host: localhost' http://127.0.0.1:8080/get -o /dev/null

# At your receiver you should see two POSTs. Both carry the same header
# set; the body shape differs between the two events.
#
# Headers (both events):
#   User-Agent: sbproxy/<version>
#   X-Sbproxy-Event: on_request | on_response
#   X-Sbproxy-Instance: sbproxy-host-7c4d8b9a
#   X-Sbproxy-Request-Id: 01j9x4...
#   X-Sbproxy-Config-Revision: a7b3f9c11d80
#   X-Sbproxy-Timestamp: 1714200000
#   X-Sbproxy-Signature: v1=4f1e6c...
#
# on_request body (JSON) - fired before the upstream is contacted, so it
# carries the inbound request shape (method, path, client_ip, headers):
#   {
#     "event":"on_request",
#     "proxy":{"instance_id":"...","version":"...","config_revision":"..."},
#     "request":{"id":"01j9x4...","received_at":"2026-04-25T07:32:00Z"},
#     "origin":{"name":"localhost"},
#     "method":"GET","path":"/get","host":"localhost","client_ip":"127.0.0.1",
#     "headers":{...}
#   }
#
# on_response body (JSON) - fired after the response is ready. It drops
# method/client_ip/headers and adds status and duration_ms instead:
#   {
#     "event":"on_response",
#     "proxy":{"instance_id":"...","version":"...","config_revision":"..."},
#     "request":{"id":"01j9x4...","received_at":"2026-04-25T07:32:00Z"},
#     "origin":{"name":"localhost"},
#     "host":"localhost","path":"/get",
#     "status":200,"duration_ms":153
#   }

# Sample receiver-side verification (Python):
#   import hmac, hashlib
#   ts = headers["X-Sbproxy-Timestamp"]
#   sig = headers["X-Sbproxy-Signature"].split("=", 1)[1]
#   mac = hmac.new(b"shared-webhook-secret-change-me",
#                  f"{ts}.{body.decode()}".encode(),
#                  hashlib.sha256).hexdigest()
#   assert hmac.compare_digest(sig, mac)
#   assert abs(time.time() - int(ts)) < 300   # reject replays
```

## What this exercises

- `on_request` and `on_response` callback lists
- Per-callback `secret` activates HMAC-SHA256 signing
- `X-Sbproxy-Signature: v1=<hex>` envelope
- `X-Sbproxy-Timestamp` for replay protection
- Identifying envelope (`X-Sbproxy-Event`, `X-Sbproxy-Instance`, `X-Sbproxy-Request-Id`, `X-Sbproxy-Config-Revision`)

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
