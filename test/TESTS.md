# Test Origins - curl Commands

This document provides curl commands for testing all configured test origins in the SoapBucket Proxy.

## Prerequisites

1. Ensure the proxy is running on `http://localhost:8080`
2. Ensure the E2E test server is running on `http://localhost:8090`
3. For browser testing, add test hostnames to `/etc/hosts`:
   ```bash
   sudo bash -c 'cat >> /etc/hosts << EOF
   127.0.0.1 basic-proxy.test proxy-headers.test proxy-rewrite.test proxy-query.test
   127.0.0.1 html-transform.test json-transform.test string-replace.test
   127.0.0.1 jwt-auth.test rate-limit.test waf.test security-headers.test
   127.0.0.1 cors.test https-proxy.test forward-rules.test callbacks.test
   127.0.0.1 complex.test google-oauth.test jwt-encrypted.test
   EOF'
   ```

## Basic Proxy Tests

### basic-proxy.test
Basic proxy forwarding without modifications.

```bash
curl -H "Host: basic-proxy.test" http://localhost:8080/
curl -H "Host: basic-proxy.test" http://localhost:8080/test/simple-200
curl -H "Host: basic-proxy.test" http://localhost:8080/test/json-response
```

### proxy-headers.test
Proxy with custom request and response headers.

```bash
curl -H "Host: proxy-headers.test" http://localhost:8080/
curl -v -H "Host: proxy-headers.test" http://localhost:8080/  # View headers
```

### proxy-rewrite.test
Proxy with URL path rewriting.

```bash
curl -H "Host: proxy-rewrite.test" http://localhost:8080/old-api/test
curl -H "Host: proxy-rewrite.test" http://localhost:8080/test  # No rewrite
```

### proxy-query.test
Proxy that adds query parameters.

```bash
curl -H "Host: proxy-query.test" http://localhost:8080/
curl -H "Host: proxy-query.test" "http://localhost:8080/?existing=param"
```

### proxy-conditional.test
Proxy with conditional header modifications.

```bash
curl -H "Host: proxy-conditional.test" http://localhost:8080/api/test
curl -H "Host: proxy-conditional.test" -H "Authorization: Bearer token" http://localhost:8080/admin/test
curl -H "Host: proxy-conditional.test" http://localhost:8080/other
```

## Transform Tests

### html-transform.test
HTML transformation with script injection.

```bash
curl -H "Host: html-transform.test" http://localhost:8080/
```

### html-transform-advanced.test
Advanced HTML transformation with optimization.

```bash
curl -H "Host: html-transform-advanced.test" http://localhost:8080/
```

### html-transform-hn.test
HTML transform for Hacker News.

```bash
curl -H "Host: html-transform-hn.test" http://localhost:8080/
```

### html-transform-example.test
HTML transform for example.com.

```bash
curl -H "Host: html-transform-example.test" http://localhost:8080/
```

### html-transform-techmeme.test
HTML transform for Techmeme.

```bash
curl -H "Host: html-transform-techmeme.test" http://localhost:8080/
```

### html-transform-caching.test
HTML transform with caching enabled.

```bash
curl -H "Host: html-transform-caching.test" http://localhost:8080/
```

### html-transform-fingerprint-caching.test
HTML transform with fingerprint-based caching.

```bash
curl -H "Host: html-transform-fingerprint-caching.test" http://localhost:8080/
```

### json-transform.test
JSON transformation with pretty printing and redaction.

```bash
curl -H "Host: json-transform.test" http://localhost:8080/test/json-response
curl -H "Host: json-transform.test" -H "Content-Type: application/json" \
  -d '{"sensitive":"data","public":"info"}' http://localhost:8080/test/json-response
```

### json-transform-comprehensive.test
Comprehensive JSON transformation.

```bash
curl -H "Host: json-transform-comprehensive.test" http://localhost:8080/test/json-response
```

### string-replace.test
String replacement in HTML/text content.

```bash
curl -H "Host: string-replace.test" http://localhost:8080/
```

### javascript-transform.test
JavaScript transformation.

```bash
curl -H "Host: javascript-transform.test" http://localhost:8080/test.js
curl -H "Host: javascript-transform.test" http://localhost:8080/script.js
```

### javascript-transform-comprehensive.test
Comprehensive JavaScript transformation.

```bash
curl -H "Host: javascript-transform-comprehensive.test" http://localhost:8080/test.js
```

### css-transform.test
CSS transformation.

```bash
curl -H "Host: css-transform.test" http://localhost:8080/style.css
```

### css-transform-comprehensive.test
Comprehensive CSS transformation.

```bash
curl -H "Host: css-transform-comprehensive.test" http://localhost:8080/style.css
```

### template-transform.test
Template transformation.

```bash
curl -H "Host: template-transform.test" http://localhost:8080/
```

### markdown-transform.test
Markdown transformation.

```bash
curl -H "Host: markdown-transform.test" http://localhost:8080/test.md
```

### multiple-transforms.test
Multiple transforms applied in sequence.

```bash
curl -H "Host: multiple-transforms.test" http://localhost:8080/
```

### transform-chain.test
Transform chain testing.

```bash
curl -H "Host: transform-chain.test" http://localhost:8080/
```

## Action Type Tests

### redirect.test
Redirect to another URL.

```bash
curl -L -H "Host: redirect.test" http://localhost:8080/
curl -v -H "Host: redirect.test" http://localhost:8080/test/path?query=value
```

### static.test
Serve static content.

```bash
curl -H "Host: static.test" http://localhost:8080/
```

### graphql.test
GraphQL proxy endpoint.

```bash
curl -H "Host: graphql.test" -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}' http://localhost:8080/graphql
```

### graphql-rate-limit.test
GraphQL with rate limiting.

```bash
curl -H "Host: graphql-rate-limit.test" -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}' http://localhost:8080/graphql
```

### websocket.test
WebSocket proxy (use websocat or similar tool).

```bash
# Note: curl doesn't support WebSocket, use websocat or wscat
# websocat ws://localhost:8080/echo -H "Host: websocket.test"
```

### websocket-pool.test
WebSocket with connection pooling.

```bash
# Use websocat or wscat for WebSocket testing
```

### loadbalancer.test
Load balancer with multiple targets.

```bash
curl -H "Host: loadbalancer.test" http://localhost:8080/
curl -v -H "Host: loadbalancer.test" -H "Cookie: _sb.l=server1" http://localhost:8080/
```

### lb-health.test
Load balancer with health checks.

```bash
curl -H "Host: lb-health.test" http://localhost:8080/
```

### failover-lb.test
Load balancer with failover.

```bash
curl -H "Host: failover-lb.test" http://localhost:8080/
```

## Authentication Tests

### jwt-auth.test
JWT authentication required.

```bash
# Without token (should fail)
curl -H "Host: jwt-auth.test" http://localhost:8080/

# With valid JWT token (generate token with test-secret-key-change-in-production)
# Example token generation (requires jwt tool):
# jwt encode --secret "test-secret-key-change-in-production" --alg HS256 \
#   '{"sub":"user123","email":"user@example.com","iss":"test-issuer","aud":"test-audience"}'
curl -H "Host: jwt-auth.test" \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  http://localhost:8080/
```

### jwt-encrypted.test
JWT with encryption.

```bash
curl -H "Host: jwt-encrypted.test" \
  -H "Authorization: Bearer <ENCRYPTED_JWT_TOKEN>" \
  http://localhost:8080/
```

### jwt-jwks.test
JWT with JWKS validation.

```bash
curl -H "Host: jwt-jwks.test" \
  -H "Authorization: Bearer <JWKS_VALIDATED_TOKEN>" \
  http://localhost:8080/
```

### jwt-claims.test
JWT with claims extraction.

```bash
curl -H "Host: jwt-claims.test" \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  http://localhost:8080/
```

### basic-auth.test
Basic authentication.

```bash
curl -H "Host: basic-auth.test" http://localhost:8080/  # Should fail
curl -u "testuser:testpass" -H "Host: basic-auth.test" http://localhost:8080/
```

### basic-auth-multiple.test
Basic auth with multiple users.

```bash
curl -u "user1:pass1" -H "Host: basic-auth-multiple.test" http://localhost:8080/
curl -u "user2:pass2" -H "Host: basic-auth-multiple.test" http://localhost:8080/
```

### api-key.test
API key authentication.

```bash
curl -H "Host: api-key.test" http://localhost:8080/  # Should fail
curl -H "Host: api-key.test" -H "X-API-Key: test-api-key" http://localhost:8080/
```

### api-key-multiple.test
API key with multiple keys.

```bash
curl -H "Host: api-key-multiple.test" -H "X-API-Key: key1" http://localhost:8080/
curl -H "Host: api-key-multiple.test" -H "X-API-Key: key2" http://localhost:8080/
```

### bearer-token.test
Bearer token authentication.

```bash
curl -H "Host: bearer-token.test" http://localhost:8080/  # Should fail
curl -H "Host: bearer-token.test" -H "Authorization: Bearer test-token" http://localhost:8080/
```

### bearer-token-multiple.test
Bearer token with multiple tokens.

```bash
curl -H "Host: bearer-token-multiple.test" \
  -H "Authorization: Bearer token1" http://localhost:8080/
curl -H "Host: bearer-token-multiple.test" \
  -H "Authorization: Bearer token2" http://localhost:8080/
```

### google-oauth.test
Google OAuth authentication.

```bash
curl -H "Host: google-oauth.test" http://localhost:8080/
```

### multi-auth.test
Multiple authentication methods.

```bash
curl -H "Host: multi-auth.test" -H "X-API-Key: test-key" http://localhost:8080/
curl -u "user:pass" -H "Host: multi-auth.test" http://localhost:8080/
```

### ws-auth.test
WebSocket with authentication.

```bash
# Use websocat with auth headers
```

## Security & Policy Tests

### rate-limit.test
Rate limiting (10 requests per minute).

```bash
# Make multiple requests quickly to trigger rate limit
for i in {1..15}; do
  curl -H "Host: rate-limit.test" http://localhost:8080/
  sleep 0.1
done
```

### rate-limit-strict.test
Strict rate limiting.

```bash
for i in {1..20}; do
  curl -H "Host: rate-limit-strict.test" http://localhost:8080/
done
```

### rate-limit-user.test
Rate limiting per user.

```bash
curl -H "Host: rate-limit-user.test" -H "X-User-ID: user1" http://localhost:8080/
curl -H "Host: rate-limit-user.test" -H "X-User-ID: user2" http://localhost:8080/
```

### progressive-rate-limit.test
Progressive rate limiting.

```bash
for i in {1..30}; do
  curl -H "Host: progressive-rate-limit.test" http://localhost:8080/
done
```

### request-limiting.test
Request size/body limiting.

```bash
curl -H "Host: request-limiting.test" -X POST \
  -d "small payload" http://localhost:8080/
curl -H "Host: request-limiting.test" -X POST \
  -d "$(python3 -c 'print("x" * 10000)')" http://localhost:8080/  # Large payload
```

### waf.test
Web Application Firewall.

```bash
# Normal request
curl -H "Host: waf.test" http://localhost:8080/

# SQL injection attempt (should be blocked)
curl -H "Host: waf.test" "http://localhost:8080/?id=1' OR '1'='1"

# XSS attempt (should be blocked)
curl -H "Host: waf.test" "http://localhost:8080/?q=<script>alert(1)</script>"
```

### waf-multiple.test
WAF with multiple rules.

```bash
curl -H "Host: waf-multiple.test" http://localhost:8080/
curl -H "Host: waf-multiple.test" "http://localhost:8080/?test=UNION SELECT"
```

### security-headers.test
Security headers injection.

```bash
curl -v -H "Host: security-headers.test" http://localhost:8080/  # Check headers
```

### security-headers-comprehensive.test
Comprehensive security headers.

```bash
curl -v -H "Host: security-headers-comprehensive.test" http://localhost:8080/
```

### ip-filter.test
IP filtering (whitelist).

```bash
curl -H "Host: ip-filter.test" http://localhost:8080/
```

### ip-blacklist.test
IP blacklist.

```bash
curl -H "Host: ip-blacklist.test" http://localhost:8080/
```

### geo-blocking.test
Geographic IP blocking.

```bash
curl -H "Host: geo-blocking.test" http://localhost:8080/
```

### csrf.test
CSRF protection.

```bash
curl -H "Host: csrf.test" http://localhost:8080/
curl -H "Host: csrf.test" -X POST http://localhost:8080/
```

### ddos.test
DDoS protection.

```bash
# Rapid requests to test DDoS protection
for i in {1..100}; do
  curl -H "Host: ddos.test" http://localhost:8080/ &
done
wait
```

### threat-detection.test
Threat detection.

```bash
curl -H "Host: threat-detection.test" http://localhost:8080/
```

### bot-detection.test
Bot detection.

```bash
curl -H "Host: bot-detection.test" http://localhost:8080/
curl -H "Host: bot-detection.test" -H "User-Agent: Googlebot" http://localhost:8080/
```

### comprehensive-security.test
Comprehensive security features.

```bash
curl -H "Host: comprehensive-security.test" http://localhost:8080/
```

### sri.test
Subresource Integrity.

```bash
curl -H "Host: sri.test" http://localhost:8080/
```

### certificate-pinning.test
Certificate pinning.

```bash
curl -H "Host: certificate-pinning.test" https://localhost:8443/
```

### certificate-pinning-backup.test
Certificate pinning with backup.

```bash
curl -H "Host: certificate-pinning-backup.test" https://localhost:8443/
```

### certificate-pinning-expired.test
Certificate pinning with expired cert.

```bash
curl -H "Host: certificate-pinning-expired.test" https://localhost:8443/
```

### mtls-proxy.test
Mutual TLS proxy.

```bash
curl --cert client.crt --key client.key \
  -H "Host: mtls-proxy.test" https://localhost:8443/
```

## CORS Tests

### cors.test
CORS headers.

```bash
curl -H "Host: cors.test" -H "Origin: http://example.com" \
  -X OPTIONS http://localhost:8080/
curl -H "Host: cors.test" -H "Origin: http://example.com" \
  http://localhost:8080/
```

### cors-comprehensive.test
Comprehensive CORS configuration.

```bash
curl -H "Host: cors-comprehensive.test" -H "Origin: http://example.com" \
  -X OPTIONS http://localhost:8080/
```

## HTTPS Tests

### https-proxy.test
HTTPS proxy to backend.

```bash
curl -H "Host: https-proxy.test" http://localhost:8080/
```

### https-proxy-bad-cert.test
HTTPS proxy with bad certificate handling.

```bash
curl -H "Host: https-proxy-bad-cert.test" http://localhost:8080/
```

## Forward Rules Tests

### forward-rules.test
Forward rules based on path.

```bash
curl -H "Host: forward-rules.test" http://localhost:8080/
curl -H "Host: forward-rules.test" http://localhost:8080/api/test
```

### forward-rules-api.test
Forward rules API endpoint.

```bash
curl -H "Host: forward-rules-api.test" http://localhost:8080/api/test
```

### forward-rules-complex.test
Complex forward rules.

```bash
curl -H "Host: forward-rules-complex.test" http://localhost:8080/
curl -H "Host: forward-rules-complex.test" http://localhost:8080/api/v1/test
curl -H "Host: forward-rules-complex.test" http://localhost:8080/admin/test
```

### nested-forward.test
Nested forwarding.

```bash
curl -H "Host: nested-forward.test" http://localhost:8080/
```

### conditional-routing.test
Conditional routing.

```bash
curl -H "Host: conditional-routing.test" http://localhost:8080/
curl -H "Host: conditional-routing.test" -H "X-Route: api" http://localhost:8080/
```

### geo-routing.test
Geographic routing.

```bash
curl -H "Host: geo-routing.test" http://localhost:8080/
curl -H "Host: geo-routing.test" -H "CF-IPCountry: US" http://localhost:8080/
curl -H "Host: geo-routing.test" -H "CF-IPCountry: UK" http://localhost:8080/
```

### us-backend.test
US backend endpoint.

```bash
curl -H "Host: us-backend.test" http://localhost:8080/
```

### uk-backend.test
UK backend endpoint.

```bash
curl -H "Host: uk-backend.test" http://localhost:8080/
```

### admin-backend.test
Admin backend.

```bash
curl -H "Host: admin-backend.test" http://localhost:8080/
```

### api-v1-backend.test
API v1 backend.

```bash
curl -H "Host: api-v1-backend.test" http://localhost:8080/
```

### api-v1-router.test
API v1 router.

```bash
curl -H "Host: api-v1-router.test" http://localhost:8080/api/v1/test
```

### api-v2-backend.test
API v2 backend.

```bash
curl -H "Host: api-v2-backend.test" http://localhost:8080/
```

### old-service-backend.test
Old service backend.

```bash
curl -H "Host: old-service-backend.test" http://localhost:8080/
```

### beta-backend.test
Beta backend.

```bash
curl -H "Host: beta-backend.test" http://localhost:8080/
```

### users-service.test
Users service.

```bash
curl -H "Host: users-service.test" http://localhost:8080/
```

### products-service.test
Products service.

```bash
curl -H "Host: products-service.test" http://localhost:8080/
```

### dynamic-backend.test
Dynamic backend selection.

```bash
curl -H "Host: dynamic-backend.test" http://localhost:8080/
```

## Callback Tests

### callbacks.test
HTTP callbacks.

```bash
curl -H "Host: callbacks.test" http://localhost:8080/
```

### callback-onstart.test
On-start callback.

```bash
curl -H "Host: callback-onstart.test" http://localhost:8080/
```

### callback-onsession.test
On-session callback.

```bash
curl -H "Host: callback-onsession.test" http://localhost:8080/
```

### callback-cel.test
CEL expression callback.

```bash
curl -H "Host: callback-cel.test" http://localhost:8080/
```

### callback-lua.test
Lua callback.

```bash
curl -H "Host: callback-lua.test" http://localhost:8080/
```

### callback-jsonpath.test
JSONPath callback.

```bash
curl -H "Host: callback-jsonpath.test" http://localhost:8080/
```

### cel-callback-onstart.test
CEL on-start callback.

```bash
curl -H "Host: cel-callback-onstart.test" http://localhost:8080/
```

### lua-callback-onstart.test
Lua on-start callback.

```bash
curl -H "Host: lua-callback-onstart.test" http://localhost:8080/
```

### cel-callback-session.test
CEL session callback.

```bash
curl -H "Host: cel-callback-session.test" http://localhost:8080/
```

### lua-callback-session.test
Lua session callback.

```bash
curl -H "Host: lua-callback-session.test" http://localhost:8080/
```

### cel-callback-auth.test
CEL auth callback.

```bash
curl -H "Host: cel-callback-auth.test" http://localhost:8080/
```

### lua-callback-auth.test
Lua auth callback.

```bash
curl -H "Host: lua-callback-auth.test" http://localhost:8080/
```

### cel-expression-policy-callback.test
CEL expression policy callback.

```bash
curl -H "Host: cel-expression-policy-callback.test" http://localhost:8080/
```

### lua-expression-policy-callback.test
Lua expression policy callback.

```bash
curl -H "Host: lua-expression-policy-callback.test" http://localhost:8080/
```

### cel-rule-callback-data.test
CEL rule callback with data.

```bash
curl -H "Host: cel-rule-callback-data.test" http://localhost:8080/
```

### lua-rule-callback-data.test
Lua rule callback with data.

```bash
curl -H "Host: lua-rule-callback-data.test" http://localhost:8080/
```

### cel-multiple-callbacks.test
Multiple CEL callbacks.

```bash
curl -H "Host: cel-multiple-callbacks.test" http://localhost:8080/
```

### lua-multiple-callbacks.test
Multiple Lua callbacks.

```bash
curl -H "Host: lua-multiple-callbacks.test" http://localhost:8080/
```

## Cache Tests

### cache-l1.test
L1 (memory) cache.

```bash
curl -H "Host: cache-l1.test" http://localhost:8080/
curl -H "Host: cache-l1.test" http://localhost:8080/  # Should be cached
```

### cache-l2.test
L2 (Redis) cache.

```bash
curl -H "Host: cache-l2.test" http://localhost:8080/
curl -H "Host: cache-l2.test" http://localhost:8080/  # Should be cached
```

### signature-cache.test
Signature-based cache.

```bash
curl -H "Host: signature-cache.test" http://localhost:8080/
curl -H "Host: signature-cache.test" http://localhost:8080/  # Should be cached
```

### cache-signature-detailed.test
Detailed signature cache.

```bash
curl -H "Host: cache-signature-detailed.test" http://localhost:8080/
```

### cache-compress.test
Cache with compression.

```bash
curl -H "Host: cache-compress.test" -H "Accept-Encoding: gzip" http://localhost:8080/
```

### cache-validation.test
Cache validation.

```bash
curl -H "Host: cache-validation.test" http://localhost:8080/
curl -H "Host: cache-validation.test" -H "If-None-Match: <etag>" http://localhost:8080/
```

### cache-etag.test
Cache with ETag support.

```bash
curl -v -H "Host: cache-etag.test" http://localhost:8080/
curl -H "Host: cache-etag.test" -H "If-None-Match: <etag>" http://localhost:8080/
```

### cache-last-modified.test
Cache with Last-Modified support.

```bash
curl -v -H "Host: cache-last-modified.test" http://localhost:8080/
curl -H "Host: cache-last-modified.test" -H "If-Modified-Since: <date>" http://localhost:8080/
```

### cache-vary.test
Cache with Vary header.

```bash
curl -H "Host: cache-vary.test" -H "Accept-Language: en" http://localhost:8080/
curl -H "Host: cache-vary.test" -H "Accept-Language: fr" http://localhost:8080/
```

### cache-no-cache.test
No-cache directive.

```bash
curl -v -H "Host: cache-no-cache.test" http://localhost:8080/
```

### cache-max-age.test
Cache with max-age.

```bash
curl -v -H "Host: cache-max-age.test" http://localhost:8080/
```

### cache-stale-revalidate.test
Stale-while-revalidate cache.

```bash
curl -H "Host: cache-stale-revalidate.test" http://localhost:8080/
```

### cache-per-user.test
Per-user cache.

```bash
curl -H "Host: cache-per-user.test" -H "X-User-ID: user1" http://localhost:8080/
curl -H "Host: cache-per-user.test" -H "X-User-ID: user2" http://localhost:8080/
```

### conditional-cache.test
Conditional caching.

```bash
curl -H "Host: conditional-cache.test" http://localhost:8080/
curl -H "Host: conditional-cache.test" -H "X-No-Cache: true" http://localhost:8080/
```

### smart-cache.test
Smart caching.

```bash
curl -H "Host: smart-cache.test" http://localhost:8080/
```

## Error Pages Tests

### error-pages.test
Custom error pages.

```bash
curl -H "Host: error-pages.test" http://localhost:8080/nonexistent  # 404
curl -H "Host: error-pages.test" http://localhost:8080/error  # 500
```

### error-pages-callbacks.test
Error pages with callbacks.

```bash
curl -H "Host: error-pages-callbacks.test" http://localhost:8080/nonexistent
```

### error-pages-callback-template.test
Error pages with callback templates.

```bash
curl -H "Host: error-pages-callback-template.test" http://localhost:8080/nonexistent
```

### error-pages-callback-base64.test
Error pages with base64 callback.

```bash
curl -H "Host: error-pages-callback-base64.test" http://localhost:8080/nonexistent
```

### error-pages-comprehensive.test
Comprehensive error pages.

```bash
curl -H "Host: error-pages-comprehensive.test" http://localhost:8080/404
curl -H "Host: error-pages-comprehensive.test" http://localhost:8080/500
curl -H "Host: error-pages-comprehensive.test" http://localhost:8080/503
```

### error-pages-content-types.test
Error pages with different content types.

```bash
curl -H "Host: error-pages-content-types.test" -H "Accept: application/json" \
  http://localhost:8080/nonexistent
curl -H "Host: error-pages-content-types.test" -H "Accept: text/html" \
  http://localhost:8080/nonexistent
```

### error-pages-callback-failures.test
Error page callback failures.

```bash
curl -H "Host: error-pages-callback-failures.test" http://localhost:8080/nonexistent
```

### error-pages-static-comprehensive.test
Static error pages.

```bash
curl -H "Host: error-pages-static-comprehensive.test" http://localhost:8080/404
```

## Request/Response Modifiers Tests

### request-modifiers-complex.test
Complex request modifiers.

```bash
curl -H "Host: request-modifiers-complex.test" http://localhost:8080/
curl -H "Host: request-modifiers-complex.test" -X POST \
  -d '{"test":"data"}' http://localhost:8080/
```

### response-modifiers-complex.test
Complex response modifiers.

```bash
curl -v -H "Host: response-modifiers-complex.test" http://localhost:8080/
```

### response-modifier-comprehensive.test
Comprehensive response modifiers.

```bash
curl -v -H "Host: response-modifier-comprehensive.test" http://localhost:8080/
```

### req-resp-modifiers.test
Request and response modifiers.

```bash
curl -v -H "Host: req-resp-modifiers.test" http://localhost:8080/
```

## Advanced Features Tests

### complex.test
Complex configuration with multiple features.

```bash
curl -H "Host: complex.test" http://localhost:8080/
```

### feature-stack.test
Stack of features.

```bash
curl -H "Host: feature-stack.test" \
  -H "Authorization: Bearer feature-test-token" \
  http://localhost:8080/
```

### multi-policy.test
Multiple policies.

```bash
curl -H "Host: multi-policy.test" http://localhost:8080/
```

### expression-policy.test
Expression-based policy.

```bash
curl -H "Host: expression-policy.test" http://localhost:8080/
```

### session-config.test
Session configuration.

```bash
curl -c cookies.txt -H "Host: session-config.test" http://localhost:8080/
curl -b cookies.txt -H "Host: session-config.test" http://localhost:8080/
```

### session-auth-callbacks.test
Session with auth callbacks.

```bash
curl -c cookies.txt -H "Host: session-auth-callbacks.test" http://localhost:8080/
```

### compression.test
Response compression.

```bash
curl -H "Host: compression.test" -H "Accept-Encoding: gzip,deflate" \
  --compressed http://localhost:8080/
```

### streaming.test
Streaming responses.

```bash
curl -H "Host: streaming.test" http://localhost:8080/
```

### encryption.test
Response encryption.

```bash
curl -H "Host: encryption.test" http://localhost:8080/
```

### storage.test
Storage integration.

```bash
curl -H "Host: storage.test" http://localhost:8080/
```

### grpc.test
gRPC proxy.

```bash
# Use grpcurl for gRPC testing
# grpcurl -plaintext -H "Host: grpc.test" localhost:8080 list
```

### webhook.test
Webhook endpoint.

```bash
curl -H "Host: webhook.test" -X POST \
  -H "Content-Type: application/json" \
  -d '{"event":"test"}' http://localhost:8080/webhook
```

### abtest.test
A/B testing.

```bash
curl -H "Host: abtest.test" http://localhost:8080/
curl -H "Host: abtest.test" -H "Cookie: _ab_test_variant=A" http://localhost:8080/
```

### abtest-sessions.test
A/B testing with sessions.

```bash
curl -c cookies.txt -H "Host: abtest-sessions.test" http://localhost:8080/
curl -b cookies.txt -H "Host: abtest-sessions.test" http://localhost:8080/
```

### canary.test
Canary deployment.

```bash
curl -H "Host: canary.test" http://localhost:8080/
```

### content-negotiation.test
Content negotiation.

```bash
curl -H "Host: content-negotiation.test" -H "Accept: application/json" http://localhost:8080/
curl -H "Host: content-negotiation.test" -H "Accept: text/html" http://localhost:8080/
```

## Retry & Circuit Breaker Tests

### retry-config.test
Retry configuration.

```bash
curl -H "Host: retry-config.test" http://localhost:8080/
```

### retry-handler-e2e.test
Retry handler end-to-end.

```bash
curl -H "Host: retry-handler-e2e.test" http://localhost:8080/
```

### retry-handler-success-after-2.test
Retry handler success after 2 attempts.

```bash
curl -H "Host: retry-handler-success-after-2.test" http://localhost:8080/
```

### retry-handler-exhaust.test
Retry handler exhaustion.

```bash
curl -H "Host: retry-handler-exhaust.test" http://localhost:8080/
```

### retry-handler-429.test
Retry handler for 429 responses.

```bash
curl -H "Host: retry-handler-429.test" http://localhost:8080/
```

### circuit-breaker.test
Circuit breaker.

```bash
# Make multiple requests to trigger circuit breaker
for i in {1..20}; do
  curl -H "Host: circuit-breaker.test" http://localhost:8080/
done
```

### timeout-config.test
Timeout configuration.

```bash
curl -H "Host: timeout-config.test" http://localhost:8080/
```

## Request Coalescing Tests

### request-coalescing.test
Request coalescing.

```bash
# Make multiple simultaneous requests
for i in {1..10}; do
  curl -H "Host: request-coalescing.test" http://localhost:8080/ &
done
wait
```

### request-coalescing-method-url.test
Request coalescing by method and URL.

```bash
for i in {1..10}; do
  curl -H "Host: request-coalescing-method-url.test" http://localhost:8080/test &
done
wait
```

### request-coalescing-disabled.test
Request coalescing disabled.

```bash
for i in {1..10}; do
  curl -H "Host: request-coalescing-disabled.test" http://localhost:8080/ &
done
wait
```

## Transport Wrappers Tests

### transport-wrappers-retry.test
Transport wrapper with retry.

```bash
curl -H "Host: transport-wrappers-retry.test" http://localhost:8080/
```

### transport-wrappers-retry-success.test
Transport wrapper retry success.

```bash
curl -H "Host: transport-wrappers-retry-success.test" http://localhost:8080/
```

### transport-wrappers-retry-exhaust.test
Transport wrapper retry exhaustion.

```bash
curl -H "Host: transport-wrappers-retry-exhaust.test" http://localhost:8080/
```

### transport-wrappers-retry-429.test
Transport wrapper retry for 429.

```bash
curl -H "Host: transport-wrappers-retry-429.test" http://localhost:8080/
```

### transport-wrappers-hedging.test
Transport wrapper with hedging.

```bash
curl -H "Host: transport-wrappers-hedging.test" http://localhost:8080/
```

### transport-wrappers-hedging-get.test
Transport wrapper hedging for GET.

```bash
curl -H "Host: transport-wrappers-hedging-get.test" http://localhost:8080/
```

### transport-wrappers-hedging-disabled.test
Transport wrapper hedging disabled.

```bash
curl -H "Host: transport-wrappers-hedging-disabled.test" http://localhost:8080/
```

### transport-wrappers-health-check.test
Transport wrapper health check.

```bash
curl -H "Host: transport-wrappers-health-check.test" http://localhost:8080/
```

### transport-wrappers-health-check-tcp.test
Transport wrapper TCP health check.

```bash
curl -H "Host: transport-wrappers-health-check-tcp.test" http://localhost:8080/
```

### transport-wrappers-health-check-unhealthy.test
Transport wrapper unhealthy health check.

```bash
curl -H "Host: transport-wrappers-health-check-unhealthy.test" http://localhost:8080/
```

### transport-wrappers-combined.test
Combined transport wrappers.

```bash
curl -H "Host: transport-wrappers-combined.test" http://localhost:8080/
```

### transport-wrappers-combined-full.test
Full combined transport wrappers.

```bash
curl -H "Host: transport-wrappers-combined-full.test" http://localhost:8080/
```

## Max Requests Tests

### max-requests-handler-e2e.test
Max requests handler end-to-end.

```bash
curl -H "Host: max-requests-handler-e2e.test" http://localhost:8080/
```

### max-requests-handler-5.test
Max requests handler (5 limit).

```bash
for i in {1..10}; do
  curl -H "Host: max-requests-handler-5.test" http://localhost:8080/
done
```

### max-requests-handler-10.test
Max requests handler (10 limit).

```bash
for i in {1..15}; do
  curl -H "Host: max-requests-handler-10.test" http://localhost:8080/
done
```

### max-requests-handler-with-error-page.test
Max requests handler with error page.

```bash
for i in {1..10}; do
  curl -H "Host: max-requests-handler-with-error-page.test" http://localhost:8080/
done
```

## Matcher Tests

### request-matcher-comprehensive.test
Comprehensive request matcher.

```bash
curl -H "Host: request-matcher-comprehensive.test" http://localhost:8080/
curl -H "Host: request-matcher-comprehensive.test" -H "X-Custom: value" http://localhost:8080/
curl -H "Host: request-matcher-comprehensive.test" -X POST http://localhost:8080/
```

### response-matcher-comprehensive.test
Comprehensive response matcher.

```bash
curl -H "Host: response-matcher-comprehensive.test" http://localhost:8080/
```

## Forwarder Tests

### forwarder-comprehensive.test
Comprehensive forwarder.

```bash
curl -H "Host: forwarder-comprehensive.test" http://localhost:8080/
```

### forwarder-api.test
API forwarder.

```bash
curl -H "Host: forwarder-api.test" http://localhost:8080/api/test
```

### forwarder-admin.test
Admin forwarder.

```bash
curl -H "Host: forwarder-admin.test" http://localhost:8080/admin/test
```

### forwarder-static.test
Static forwarder.

```bash
curl -H "Host: forwarder-static.test" http://localhost:8080/
```

### forwarder-json.test
JSON forwarder.

```bash
curl -H "Host: forwarder-json.test" http://localhost:8080/
```

### forwarder-cel.test
CEL forwarder.

```bash
curl -H "Host: forwarder-cel.test" http://localhost:8080/
```

### forwarder-lua.test
Lua forwarder.

```bash
curl -H "Host: forwarder-lua.test" http://localhost:8080/
```

### forwarder-query.test
Query forwarder.

```bash
curl -H "Host: forwarder-query.test" "http://localhost:8080/?test=value"
```

### forwarder-ip.test
IP-based forwarder.

```bash
curl -H "Host: forwarder-ip.test" http://localhost:8080/
```

## Encoding & Content Type Tests

### encoding-fix.test
Encoding fix.

```bash
curl -H "Host: encoding-fix.test" http://localhost:8080/
```

### encoding-fix-comprehensive.test
Comprehensive encoding fix.

```bash
curl -H "Host: encoding-fix-comprehensive.test" http://localhost:8080/
```

### content-type-fix.test
Content type fix.

```bash
curl -H "Host: content-type-fix.test" http://localhost:8080/
```

### content-type-fix-comprehensive.test
Comprehensive content type fix.

```bash
curl -H "Host: content-type-fix-comprehensive.test" http://localhost:8080/
```

## Request Signing Tests

### request-signing.test
Request signing.

```bash
curl -H "Host: request-signing.test" http://localhost:8080/
```

## Auth + WAF Tests

### auth-waf.test
Authentication with WAF.

```bash
curl -H "Host: auth-waf.test" -H "Authorization: Bearer test-token" http://localhost:8080/
```

### auth-rate-transform.test
Authentication with rate limiting and transforms.

```bash
curl -H "Host: auth-rate-transform.test" \
  -H "Authorization: Bearer test-token" \
  http://localhost:8080/
```

## Notes

- All curl commands assume the proxy is running on `http://localhost:8080`
- For HTTPS endpoints, use `https://localhost:8443`
- Some tests require authentication tokens - generate them according to the test configuration
- WebSocket tests require tools like `websocat` or `wscat` instead of curl
- gRPC tests require `grpcurl` instead of curl
- Rate limiting tests may need multiple rapid requests to trigger limits
- Cache tests should be run twice to verify caching behavior
- Error page tests intentionally request non-existent paths

## Testing Tips

1. **View Response Headers**: Add `-v` flag to see full headers
2. **Follow Redirects**: Add `-L` flag for redirect tests
3. **Save Cookies**: Use `-c cookies.txt` to save cookies, `-b cookies.txt` to send them
4. **POST Requests**: Use `-X POST -d '{"data":"value"}'` for POST requests
5. **JSON Content**: Add `-H "Content-Type: application/json"` for JSON payloads
6. **Compression**: Use `--compressed` with `Accept-Encoding` header for compressed responses

