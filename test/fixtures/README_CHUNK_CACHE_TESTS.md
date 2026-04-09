# Chunk Cache Test Suite

## Quick Start

### 1. Add Test Configs

```bash
cd /Users/rick/projects/proxy/test/fixtures
./add_hn_test_configs.sh
```

### 2. Add to /etc/hosts

```bash
sudo tee -a /etc/hosts << EOF
127.0.0.1 hn-signature.test
127.0.0.1 hn-url.test
127.0.0.1 hn-hybrid.test
127.0.0.1 hn-ignore-nocache.test
127.0.0.1 hn-modifiers.test
127.0.0.1 hn-exact.test
127.0.0.1 hn-hash.test
EOF
```

### 3. Reload Proxy

Restart your proxy to load the new configs.

### 4. Run Tests

```bash
cd /Users/rick/projects/proxy/test/fixtures
./test_chunk_cache.sh
```

## Manual Testing

### Test Signature Cache

```bash
# First request (miss)
curl -ksv -H "Host: hn-signature.test" -H "X-Sb-Flags: debug" https://localhost:8443/

# Second request (hit)
curl -ksv -H "Host: hn-signature.test" -H "X-Sb-Flags: debug" https://localhost:8443/

# Look for:
# < x-cache: HIT-SIGNATURE
# < x-sb-cache-key: signature:config:hn-signature:sig:html_doctype_to_body
```

### Test URL Cache

```bash
# First request (miss)
curl -ksv -H "Host: hn-url.test" -H "X-Sb-Flags: debug" https://localhost:8443/

# Second request (hit - fresh)
curl -ksv -H "Host: hn-url.test" -H "X-Sb-Flags: debug" https://localhost:8443/

# Look for:
# < x-cache: HIT
# < x-sb-cache-key: url:https://localhost:8443/

# After TTL expires (5 minutes)
# < x-cache: HIT-STALE
```

### Test Cache Override

```bash
# Test ignoring no-cache
curl -ksv -H "Host: hn-ignore-nocache.test" -H "X-Sb-Flags: debug" \
  -H "Cache-Control: no-cache" https://localhost:8443/

# Should still get: x-cache: HIT-SIGNATURE
```

## Test Configs Overview

| Config | Hostname | Features | Use Case |
|--------|----------|----------|----------|
| **hn-signature** | hn-signature.test | Signature cache only | Test TTFB improvement |
| **hn-url** | hn-url.test | URL cache only | Test complete caching |
| **hn-hybrid** | hn-hybrid.test | Both signature + URL | Test realistic scenario |
| **hn-ignore-nocache** | hn-ignore-nocache.test | Ignores client no-cache | Test override behavior |
| **hn-modifiers** | hn-modifiers.test | Modifies cache headers | Test header manipulation |
| **hn-exact** | hn-exact.test | Exact byte matching | Test signature detection |
| **hn-hash** | hn-hash.test | Hash-based signatures | Test hash matching |

## Cache Header Behavior

### Respecting Cache Headers (Default)

```yaml
chunk_cache:
  ignore_no_cache: false  # Respect client Cache-Control: no-cache
```

**Result**: Client can bypass cache with `Cache-Control: no-cache`

### Ignoring Cache Headers

```yaml
chunk_cache:
  ignore_no_cache: true   # Cache even if client sends no-cache
```

**Result**: Always cache, ignore client directives

### Overriding Upstream Headers

```yaml
response_modifiers:
  - type: "add_header"
    config:
      name: "Cache-Control"
      value: "public, max-age=300"
```

**Result**: Replace upstream `Cache-Control: private` with cacheable directive

## Expected Headers

### HIT-SIGNATURE (Partial/Streaming)
```
x-cache: HIT-SIGNATURE
x-sb-cache-key: signature:config:{id}:sig:{name}
transfer-encoding: chunked  (HTTP/1.1, HTTP/2 only)
```

### HIT (Fresh Complete)
```
x-cache: HIT
x-sb-cache-key: url:https://...
```

### HIT-STALE (Expired Complete)
```
x-cache: HIT-STALE
x-sb-cache-key: url:https://...
```

### MISS
```
(no x-cache header)
```

## Troubleshooting

### No cache headers appearing

**Check**:
1. Is debug flag enabled? `-H "X-Sb-Flags: debug"`
2. Is chunk_cache present in config? (presence enables it)
3. Check proxy logs: `grep 'chunk cache' logs`

### Cache always misses

**Check**:
1. Are you sending `Cache-Control: no-cache`?
2. Is `ignore_no_cache: true` if you want to cache anyway?
3. Check signature patterns match response content

### HTTP/3 errors

**Should be fixed** - ensure you have the latest fixes:
- Logger set on http3.Server
- No Transfer-Encoding header on HTTP/3
- No trailer conversion on HTTP/3

## Performance Benchmarking

```bash
# Benchmark without cache (first request)
ab -n 100 -c 10 -H "Host: hn-signature.test" https://localhost:8443/

# Benchmark with cache (subsequent requests)
ab -n 100 -c 10 -H "Host: hn-signature.test" https://localhost:8443/

# Compare: TTFB should be significantly lower with cache
```

## Documentation

- **Full Testing Guide**: `/docs/CHUNK_CACHE_TESTING_GUIDE.md`
- **Implementation Fixes**: `/docs/CHUNK_CACHE_FLUSHER_FIX.md`
- **Config Schemas**: `/internal/config/chunk_cache.go`

## Support

If you encounter issues:
1. Check proxy logs for errors
2. Enable debug headers
3. Verify config syntax in `chunk_cache_test_configs.json`
4. Test with HTTP/2 first (simpler than HTTP/3)

