# Troubleshooting
*Last modified: 2026-04-25*

When something breaks, this is the first place to look. For *why* these things happen, see [architecture.md](architecture.md).

## 404, origin not found

The `Host` header on the request does not match any configured origin.

Check:
- Run `sbproxy validate -c sb.yml` to confirm the config parses.
- Confirm the request's `Host` header matches the origin name exactly, including any port suffix.
- SBproxy uses a bloom filter for fast hostname lookup. If you just added an origin via hot reload, wait a second and retry.

## Hot reload did not pick up changes

Usually one of: file watcher debounce, ConfigMap symlink swap, or a validation failure.

Check:
- A config with a validation error gets logged and rejected. The old config keeps running. Run `sbproxy validate -c sb.yml` to see the error.
- Kubernetes ConfigMaps swap via atomic symlink. The watcher catches this, but detection can lag up to 2 seconds.
- If your editor writes to a temp file and renames, make sure the watcher sees the final filename, not the temp.

## AI requests fail with provider error

Check in order:
1. Confirm the provider API key is set correctly. Check the `api_key` field or the environment variable it references.
2. Run `sbproxy validate -c sb.yml` to confirm the provider block parses correctly.
3. Check the structured log for `provider` and `status_code` fields on the failed request.
4. If using a fallback chain, check that at least one provider in the chain has available capacity. The log will show which provider was attempted last.
5. If the error is "context window exceeded," the requested model does not support the token count in the prompt. Add a model with a larger context window to the provider list.

## Rate limiter rejecting requests unexpectedly

Check:
- The `requests_per_second` limit is per-origin, not global. If you have multiple origins sharing an upstream, each origin has its own counter.
- The default token bucket allows short bursts up to `burst` size. A sustained rate above `requests_per_second` will be rejected once the bucket drains.
- If you are testing with many rapid requests, increase `burst` to permit the test pattern.
- Check the structured log for `policy` and `limit` fields to see which rule triggered.

## Requests are slow

SBproxy adds well under 1 ms of overhead under normal load. If you see more, the cause is almost always upstream or DNS.

1. Check `upstream_latency_ms` in the structured log. If it's high, the upstream is slow, not SBproxy.
2. If `upstream_latency_ms` is low but total latency is high, suspect DNS. SBproxy caches DNS with a 30-second TTL; the first request after a cache miss pays the resolver round trip.
3. Turn on OpenTelemetry tracing (`telemetry` block) to get a per-span breakdown across the phase pipeline.
4. If you have Lua, JavaScript, or CEL configured, set `scripting.timeout_ms` to cap runaway scripts.

## TLS handshake fails

Check:
- For ACME auto-cert, confirm `acme.email` is set and the DNS A/AAAA record points at this server. Let's Encrypt needs a successful HTTP-01 or TLS-ALPN-01 challenge.
- For BYO certificates, check that the cert and key paths are readable by the SBproxy process and the cert chain matches the leaf.
- Run `openssl s_client -servername <host> -connect <host>:443` to see the server's offered chain.
- The TLS layer uses `rustls` with the `ring` crypto provider. TLS 1.3 by default with TLS 1.2 fallback.

## HTTP/3 requests fall back to HTTP/2

Cause: HTTP/3 (QUIC) is UDP-based. Most NATs and corporate firewalls block or rate-limit UDP/443.

Check:
- Confirm UDP/443 is reachable: `nc -u -v -z <host> 443`.
- The browser advertises HTTP/3 support via the `Alt-Svc` header. If the response does not include `Alt-Svc: h3=":443"`, the proxy is not advertising it.
- HTTP/3 must be explicitly enabled in the `proxy.tls.http3` block. It is off by default.

## Structured log fields reference

| Field | Meaning |
|---|---|
| `host` | Origin name matched. |
| `method`, `path`, `status` | Request summary. |
| `upstream_latency_ms` | Time waiting for upstream response. |
| `total_latency_ms` | Full request duration including all middleware. |
| `auth_type` | Auth method applied (`api_key`, `jwt`, etc.). |
| `policy` | Policy that triggered a rejection. |
| `provider` | AI provider selected for this request. |
| `model` | AI model used. |
| `tokens_in`, `tokens_out` | Token counts for AI requests. |
| `cache_status` | `hit`, `miss`, or `stale`. |
| `client_ip` | Resolved client IP after trusted proxy unwrapping. |
