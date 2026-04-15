# Troubleshooting

*Last modified: 2026-04-14*

Quick reference for common failure modes. For architecture details that explain
why these failures occur, see [architecture.md](architecture.md).

## Request returns 404 - origin not found

Cause: The `Host` header on the incoming request does not match any configured origin name.

Check:
- Run `sbproxy validate -c sb.yml` to confirm the config parses correctly.
- Confirm the `Host` header in your request matches the origin name exactly, including
  any port suffix.
- SBproxy uses a bloom filter for fast hostname pre-check. If you recently added an
  origin via hot reload, wait one second and retry.

## Hot reload did not apply config changes

Cause: File watcher debounce, symlink swap (Kubernetes ConfigMap), or config validation failure.

Check:
- If the config has a validation error, sbproxy logs the error and keeps the previous config.
  Run `sbproxy validate -c sb.yml` to see the error.
- Kubernetes ConfigMaps use an atomic symlink swap. SBproxy's watcher detects this, but
  the detection can lag by up to 2 seconds.
- If you are editing the file via a tool that writes to a temp file and renames, confirm
  the watcher sees the final filename, not the temp file.

## AI requests fail with provider error

Check in order:
1. Confirm the provider API key is set correctly. Check the `api_key` field or the
   environment variable it references.
2. Run `sbproxy validate -c sb.yml` to confirm the provider block parses correctly.
3. Check the structured log for `provider` and `status_code` fields on the failed request.
4. If using a fallback chain, check that at least one provider in the chain has available
   capacity. The log will show which provider was attempted last.
5. If the error is "context window exceeded," the requested model does not support the
   token count in the prompt. Add a model with a larger context window to the provider list.

## Rate limiter rejecting requests unexpectedly

Check:
- The `requests_per_minute` limit is per-origin, not global. If you have multiple origins
  sharing an upstream, each origin has its own counter.
- The `sliding_window` algorithm uses real wall time. A burst that crosses a minute
  boundary counts against the new window.
- If you are testing with many rapid requests, the `token_bucket` algorithm is more
  permissive of short bursts than `sliding_window`.
- Check the structured log for `policy` and `limit` fields to see which rule triggered.

## Requests are slow - diagnosing latency

SBproxy adds under 1ms of overhead to the request path under normal conditions. If you
are seeing higher latency, the cause is almost always upstream or DNS.

Steps:
1. Check the structured log for `upstream_latency_ms`. If this is high, the issue is
   the upstream service, not sbproxy.
2. If `upstream_latency_ms` is low but total latency is high, check for DNS resolution
   overhead. SBproxy caches DNS with a 30-second TTL by default. If the provider hostname
   is resolving slowly, the first request after a cache miss will be slow.
3. Enable OpenTelemetry tracing (`telemetry` config block) to get per-span latency
   breakdown across the full 18-layer handler chain.
4. If Lua or CEL scripting is configured, add a `scripting.timeout_ms` limit to prevent
   runaway scripts from adding latency.

## Structured log fields reference

| Field | Meaning |
|---|---|
| `host` | Origin name matched |
| `method`, `path`, `status` | Request summary |
| `upstream_latency_ms` | Time waiting for upstream response |
| `total_latency_ms` | Full request duration including all middleware |
| `auth_type` | Auth method applied (`api_key`, `jwt`, etc.) |
| `policy` | Policy that triggered a rejection |
| `provider` | AI provider selected for this request |
| `model` | AI model used |
| `tokens_in`, `tokens_out` | Token counts for AI requests |
| `cache_status` | `hit`, `miss`, or `stale` |
| `client_ip` | Resolved client IP after trusted proxy unwrapping |
