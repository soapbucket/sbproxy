# Troubleshooting
*Last modified: 2026-06-08*

When something breaks, this is the first place to look. For *why* these things happen, see [architecture.md](architecture.md).

## A config setting seems to be ignored

You set a config key and nothing changes, with no error at boot.

The most common cause is a misspelled key or one at the wrong nesting level. The config loader keeps an unrecognized key out of the compiled config and the field falls back to its default, which for a protection usually means off.

Check:
- Compare the key against `schemas/sb-config.schema.json`, which is the generated source of truth for every valid key and its nesting.
- Run `sbproxy validate --config sb.yml` to parse the file offline before serving.
- As a quick test, rename the suspect key to something obviously wrong and confirm the behavior is identical. If it is, the key was never taking effect.

## 404, origin not found

The `Host` header on the request does not match any configured origin.

Check:
- Run `sbproxy validate --config sb.yml` to confirm the config parses.
- Confirm the request's `Host` header matches the origin name exactly, including any port suffix.
- SBproxy uses a bloom filter for fast hostname lookup. If you just added an origin via hot reload, wait a second and retry.

## Hot reload did not pick up changes

Usually one of: file watcher debounce, ConfigMap symlink swap, or a validation failure.

Check:
- A config with a validation error gets logged and rejected. The old config keeps running. Run `sbproxy validate --config sb.yml` to see the error.
- The file watcher reacts to in-place writes. Saves that replace the file by atomic rename (many editors, `sed -i`, and Kubernetes ConfigMap symlink swaps) may not be detected. After a ConfigMap update, send `SIGHUP` or restart the pod to force the reload.
- The `agent_classes`, `agent_detect`, and `tls_fingerprint` installers are applied at startup and are not currently re-applied on reload. Restart the process to pick up changes to those blocks.

## AI requests fail with provider error

Check in order:
1. Confirm the provider API key is set correctly. Check the `api_key` field or the environment variable it references.
2. Run `sbproxy validate --config sb.yml` to confirm the provider block parses correctly.
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

Cause: HTTP/3 is currently disabled until native QUIC support lands in Pingora. The proxy does not start a QUIC listener and does not advertise `Alt-Svc`, so HTTP/2 is the highest version served. Clients that try HTTP/3 fall back to HTTP/2, which is expected.

Check:
- The `proxy.http3` block still parses, but it is inert. Setting `enabled: true` only logs a warning and starts no listener, so the absence of an `Alt-Svc: h3` header on responses is expected.
- If you need a UDP/QUIC path today, terminate HTTP/3 at an upstream edge or CDN and forward HTTP/2 to SBproxy.

## An example docker compose stack will not start

The compose-based examples build the `sbproxy` image from source in the container (`build: ../..`, `Dockerfile.cloudbuild`) and pull base images such as `wiremock/wiremock` from Docker Hub.

Check:
- Look for `pull access denied` or `auth.docker.io ... unexpected EOF` in the compose output. That is a registry-connectivity problem, not an example defect.
- Confirm the daemon is up with `docker info`, and that the host can reach Docker Hub.
- Pre-pull the base images (or build the `sbproxy` image once) so a later `docker compose up` works from cache.

## Build and run quick reference

```bash
# Debug build
make build                          # -> target/debug/sbproxy
# Release build (required by the e2e harness)
cargo build --release -p sbproxy    # -> target/release/sbproxy
# Validate a config offline before serving
sbproxy validate --config ./sb.yml
# Run
./target/release/sbproxy serve -f ./sb.yml
```

## Structured log fields reference

The fields below are the ones most useful when triage-grepping the JSON access log. The canonical, exhaustive schema (with optional fields and stability rules) is [access-log.md](./access-log.md); names here mirror that file exactly.

| Field | Meaning |
|---|---|
| `timestamp` | RFC 3339 UTC time of the log line. |
| `origin` | Origin name matched. |
| `method`, `path`, `status` | Request summary. |
| `latency_ms` | End-to-end request duration, milliseconds. |
| `client_ip` | Resolved client IP after trusted-proxy unwrapping. |
| `request_id`, `trace_id` | Correlation ids; `trace_id` is set when an OTLP exporter is wired. |
| `cache_result` | `hit`, `miss`, `stale`, or `bypass`. |
| `auth_provider` | Auth method that ran (`api_key`, `jwt`, etc.). |
| `policy_action` | When a policy intervened, the action it took. |
| `provider`, `model` | AI-gateway selection for the request (only on AI requests). |
| `tokens_in`, `tokens_out` | Token counts (only on AI requests). |
