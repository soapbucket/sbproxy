# Config Field Stability Tiers
*Last modified: 2026-04-17*

Every sb.yml config field is assigned a stability tier. These tiers determine what changes are allowed without a major version bump.

## Tiers

### Stable

Fields marked **stable** are part of the public API. They cannot be renamed, removed, or have their semantics changed without a major version bump (e.g., v1 -> v2). Default values cannot change.

### Beta

Fields marked **beta** may be renamed or have defaults adjusted in minor releases with a deprecation period (at least one minor release with a warning before removal). Behavioral changes are documented in the changelog.

### Alpha

Fields marked **alpha** may change or be removed in any release without deprecation. They are experimental and should not be relied upon in production configs.

## Field Assignments

### Top-Level (Stable)

| Field | Type | Tier | Notes |
|-------|------|------|-------|
| `origins` | map | stable | Origin configuration map |
| `config_version` | int | stable | Schema version (default: 2) |

### Origin Config (Stable)

| Field | Type | Tier | Notes |
|-------|------|------|-------|
| `hostname` | string | stable | Origin hostname |
| `action` | object | stable | Action handler config |
| `authentication` | object | stable | Auth provider config |
| `policies` | array | stable | Policy enforcers |
| `transforms` | array | stable | Response transforms |
| `request_modifiers` | array | stable | Request modification |
| `response_modifiers` | array | stable | Response modification |
| `session` | object | stable | Session config |
| `response_cache` | object | stable | Response caching |
| `forward_rules` | array | stable | Path-based routing |
| `fallback_origin` | object | stable | Graceful degradation |
| `force_ssl` | bool | stable | HTTPS redirect |
| `allowed_methods` | array | stable | HTTP method filter |
| `cors` | object | stable | CORS config |
| `hsts` | object | stable | HSTS config |
| `compression` | object | stable | Compression config |

### Action Types (Stable)

| Type | Tier | Notes |
|------|------|-------|
| `proxy` | stable | Reverse proxy |
| `load_balancer` | stable | Multi-upstream |
| `static` | stable | Static response |
| `redirect` | stable | HTTP redirect |
| `echo` | stable | Request echo |
| `mock` | stable | Mock response |
| `ai_proxy` | stable | AI gateway |
| `websocket` | stable | WebSocket proxy |
| `grpc` | stable | gRPC proxy |
| `graphql` | stable | GraphQL proxy |
| `beacon` | stable | Fire-and-forget |
| `noop` | stable | No-op |
| `storage` | beta | Object storage |
| `a2a` | beta | Agent-to-Agent |

### Auth Types (Stable)

| Type | Tier | Notes |
|------|------|-------|
| `api_key` | stable | API key auth |
| `basic_auth` | stable | HTTP Basic |
| `bearer` | stable | Bearer token |
| `jwt` | stable | JWT validation |
| `digest` | stable | Digest auth |
| `forward_auth` | stable | External auth |
| `noop` | stable | No auth |

### Policy Types (Stable)

| Type | Tier | Notes |
|------|------|-------|
| `rate_limiting` | stable | Token bucket rate limit |
| `ip_filter` | stable | IP allow/blocklist |
| `expression` | stable | CEL expression |
| `waf` | stable | Web Application Firewall |
| `security_headers` | stable | Security response headers |
| `request_limit` | stable | Request size/rate limits |
| `csrf` | stable | CSRF protection |
| `ddos` | stable | DDoS protection |
| `assertion` | stable | Response assertions |
| `sri` | stable | Subresource integrity |

### AI Gateway (Beta)

| Field | Type | Tier | Notes |
|-------|------|------|-------|
| `providers` | array | stable | Provider list |
| `routing.strategy` | string | stable | Routing algorithm |
| `guardrails` | object | beta | Safety pipeline |
| `budget` | object | beta | Cost controls |
| `virtual_keys` | array | beta | API key abstraction |
| `batch` | object | alpha | Batch API |
| `idempotency` | object | alpha | Request dedup |

### Secrets (Beta)

| Field | Type | Tier | Notes |
|-------|------|------|-------|
| `proxy.secrets.backend` | string | beta | Vault backend type |
| `proxy.secrets.map` | map | beta | Logical name to path |
| `proxy.secrets.rotation` | object | beta | Rotation config |

## Versioning Policy

- **Stable** fields follow semver. Breaking changes require a major version bump.
- **Beta** fields get at least one release of deprecation warnings before removal.
- **Alpha** fields may change without notice. Use in production at your own risk.
- New fields start at **alpha** and promote to **beta** after one stable release, then **stable** after broad adoption.
