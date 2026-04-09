# API Proxy Examples

Configuration examples for sbproxy's reverse proxy features. Each file is a complete, runnable config. All examples proxy to [httpbin.org](https://httpbin.org) so you can test without a real backend.

## Examples

### auth-jwt.yml - JWT Authentication

Validates JWTs using a JWKS endpoint. Works with any OIDC provider (Auth0, Okta, Google, etc.).

```bash
sbproxy serve -f examples/api/auth-jwt.yml

# Without token (returns 401)
curl -v -H "Host: api.example.com" http://localhost:8080/api/users

# With token
curl -H "Host: api.example.com" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8080/api/users
```

### caching-swr.yml - Response Caching with Stale-While-Revalidate

Caches GET responses for 5 minutes. Serves stale content while refreshing in the background.

```bash
sbproxy serve -f examples/api/caching-swr.yml

# First request hits the backend
curl -v -H "Host: api.example.com" http://localhost:8080/get 2>&1 | grep -i "x-cache"

# Second request is served from cache (check X-Cache header)
curl -v -H "Host: api.example.com" http://localhost:8080/get 2>&1 | grep -i "x-cache"

# POST invalidates the cache
curl -X POST -H "Host: api.example.com" http://localhost:8080/post -d "data=test"

# Next GET hits the backend again
curl -v -H "Host: api.example.com" http://localhost:8080/get 2>&1 | grep -i "x-cache"
```

### rate-limiting-redis.yml - Distributed Rate Limiting

Rate limits shared across proxy instances via Redis. Clients get 60 requests per minute.

```bash
# Start Redis first
docker run -d -p 6379:6379 redis:7-alpine

sbproxy serve -f examples/api/rate-limiting-redis.yml

# Send 65 requests rapidly. Requests 61+ return 429.
for i in $(seq 1 65); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Host: api.example.com" http://localhost:8080/get)
  echo "Request $i: $code"
done

# Check rate limit headers
curl -v -H "Host: api.example.com" http://localhost:8080/get 2>&1 | grep -i "ratelimit\|retry-after"
```

### transforms-json.yml - Response Transforms and Header Injection

Strips sensitive fields from responses and adds security headers.

```bash
sbproxy serve -f examples/api/transforms-json.yml

# Check response headers (security headers injected)
curl -v -H "Host: api.example.com" http://localhost:8080/get 2>&1 | grep -i "x-content-type\|x-frame\|strict-transport"

# Check that upstream receives injected headers
curl -s -H "Host: api.example.com" http://localhost:8080/get | python3 -m json.tool
```

### microservice-routing.yml - Path-Based Routing

A single hostname routes to different backends based on URL path. Each sub-route has its own auth and rate limits.

```bash
sbproxy serve -f examples/api/microservice-routing.yml

# Users service
curl -H "Host: api.example.com" http://localhost:8080/api/users

# Orders service
curl -H "Host: api.example.com" http://localhost:8080/api/orders

# Health check (no auth required)
curl -H "Host: api.example.com" http://localhost:8080/health

# Default backend (anything else)
curl -H "Host: api.example.com" http://localhost:8080/anything-else
```

## Documentation

- [Configuration Reference](../../docs/configuration.md)
- [Scripting Reference](../../docs/scripting.md) (CEL/Lua modifiers)
- [Manual](../../docs/manual.md) (deployment, TLS, metrics)
