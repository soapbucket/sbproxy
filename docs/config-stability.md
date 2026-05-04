# Config stability tiers

*Last modified: 2026-04-24*

Stability guarantees for every field in `sb.yml`. Check a field's tier before relying on it in production.

---

## Stability tiers

### `stable`

A `stable` field is part of the committed public API of SBproxy.

- The field name, type, and default value will not change in a minor or patch release.
- Removing or renaming a `stable` field requires a major version bump (e.g. config_version 1 -> 2) and a migration guide.
- Behavioral changes to a `stable` field require at least a minor version bump and a changelog entry.

### `beta`

A `beta` field is functional and tested but may still change.

- Available for production use. Monitor the changelog before upgrading.
- Renames or semantic changes may happen in a minor release with a deprecation notice.
- Beta fields are not silently removed. A one-release deprecation period applies.

### `alpha`

An `alpha` field is experimental.

- May be renamed, restructured, or removed in any release without prior notice.
- Do not depend on `alpha` fields in critical production paths.
- Feedback on alpha fields is welcome and influences their stabilization.

---

## Stabilization rules

1. A field moves from `alpha` to `beta` once its interface is reviewed, it has integration tests, and it has been in at least one release.
2. A field moves from `beta` to `stable` once it has been in production use by at least one internal deployment for one full release cycle without interface changes.
3. Stable fields are never silently removed. The process is: deprecate (add `x-deprecated` annotation in schema), warn in logs, remove in the next major version.

---

## Field stability reference

### Top-level fields

| Field | Type | Stability | Notes |
|---|---|---|---|
| `config_version` | integer | **stable** | Must be 1. Required. |
| `proxy` | object | **stable** | Server configuration block. |
| `origins` | object (map) | **stable** | Map of hostname to origin config. |

### `proxy` - ProxyServerConfig

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `http_bind_port` | integer | 8080 | **stable** | Plain HTTP listener port. |
| `https_bind_port` | integer | - | **stable** | TLS listener port. Optional. |
| `tls_cert_file` | string | - | **stable** | Path to PEM cert for manual TLS. |
| `tls_key_file` | string | - | **stable** | Path to PEM key for manual TLS. |
| `acme` | object | - | **beta** | Automatic TLS via ACME. |
| `http3` | object | - | **alpha** | HTTP/3 (QUIC) listener. |

### `proxy.acme` - AcmeConfig

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `enabled` | boolean | false | **beta** | Activates ACME. |
| `email` | string | "" | **beta** | Contact email for the ACME account. |
| `directory_url` | string | Let's Encrypt prod | **beta** | ACME directory endpoint URL. |
| `challenge_types` | array | `[tls-alpn-01, http-01]` | **beta** | Challenge method preference list. |
| `storage_backend` | string | `redb` | **beta** | Cert persistence backend. |
| `storage_path` | string | `/var/lib/sbproxy/certs` | **beta** | Filesystem path for cert storage. |
| `renew_before_days` | integer | 30 | **beta** | Days before expiry to renew. |

### `proxy.http3` - Http3Config

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `enabled` | boolean | false | **alpha** | Enable QUIC listener. |
| `max_streams` | integer | 100 | **alpha** | Max concurrent QUIC streams per connection. |
| `idle_timeout_secs` | integer | 30 | **alpha** | QUIC idle timeout in seconds. |

### Origin Config (each entry under `origins:`)

| Field | Alias | Type | Default | Stability | Notes |
|---|---|---|---|---|---|
| `action` | - | object | required | **stable** | What the proxy does with requests. |
| `authentication` | `auth` | object | - | **stable** | Auth plugin config. |
| `policies` | - | array | `[]` | **stable** | Policy plugin list. |
| `transforms` | - | array | `[]` | **beta** | Body transform plugin list. |
| `request_modifiers` | - | array | `[]` | **stable** | Request modification steps. |
| `response_modifiers` | - | array | `[]` | **stable** | Response modification steps. |
| `cors` | - | object | - | **stable** | CORS policy. |
| `hsts` | - | object | - | **stable** | HSTS policy. |
| `compression` | - | object | - | **stable** | Response compression. |
| `session_config` | - | object | - | **beta** | Session cookie management. |
| `force_ssl` | - | boolean | false | **stable** | Redirect HTTP to HTTPS. |
| `allowed_methods` | - | array | `[]` (all) | **stable** | HTTP method allowlist. |
| `forward_rules` | - | array | `[]` | **beta** | Conditional routing rules. |
| `fallback_origin` | - | object | - | **beta** | Secondary origin on primary failure. |
| `response_cache` | - | object | - | **beta** | Response caching config. |
| `variables` | - | object | `{}` | **beta** | Named template variables. |
| `on_request` | - | array | `[]` | **alpha** | Request event hook plugins. |
| `on_response` | - | array | `[]` | **alpha** | Response event hook plugins. |
| `bot_detection` | - | object | - | **alpha** | Bot detection config. |
| `threat_protection` | - | object | - | **alpha** | Dynamic threat blocklist config. |
| `rate_limit_headers` | - | object | - | **beta** | Rate limit response header config. |
| `error_pages` | - | object | - | **beta** | Custom error page config. |
| `traffic_capture` | - | object | - | **alpha** | Request mirroring config. |
| `message_signatures` | - | object | - | **alpha** | HTTP message signing config. |

### CORS Config (`cors:`)

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `allowed_origins` | `allow_origins` | array | `[]` | **stable** |
| `allowed_methods` | `allow_methods` | array | `[]` | **stable** |
| `allowed_headers` | `allow_headers` | array | `[]` | **stable** |
| `expose_headers` | - | array | `[]` | **stable** |
| `max_age` | - | integer | - | **stable** |
| `allow_credentials` | - | boolean | false | **stable** |
| `enable` | `enabled` | boolean | - | **stable** |

### HSTS Config (`hsts:`)

| Field | Type | Default | Stability |
|---|---|---|---|
| `max_age` | integer | 31536000 | **stable** |
| `include_subdomains` | boolean | false | **stable** |
| `preload` | boolean | false | **stable** |

### Compression Config (`compression:`)

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `enabled` | `enable` | boolean | true | **stable** |
| `algorithms` | - | array | `[]` | **stable** |
| `min_size` | - | integer | 0 | **stable** |
| `level` | - | integer | - | **beta** |

### Session Config (`session_config:`)

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `cookie_name` | - | string | - | **beta** |
| `max_age` | `cookie_max_age` | integer | - | **beta** |
| `http_only` | - | boolean | false | **beta** |
| `secure` | - | boolean | false | **beta** |
| `same_site` | `cookie_same_site` | string | - | **beta** |
| `allow_non_ssl` | - | boolean | false | **beta** |

### Request Modifier (`request_modifiers[]`)

| Field | Type | Stability | Notes |
|---|---|---|---|
| `headers` | object | **stable** | Header set/add/remove. |
| `url` | object | **stable** | Path rewrite. |
| `query` | object | **stable** | Query param set/add/remove. |
| `method` | string | **stable** | Override HTTP method. |
| `body` | object | **stable** | Body replacement. |
| `lua_script` | string | **beta** | Dynamic modification via Lua. |

### Response Modifier (`response_modifiers[]`)

| Field | Type | Stability | Notes |
|---|---|---|---|
| `headers` | object | **stable** | Header set/add/remove. |
| `status` | object | **stable** | Status code override. |
| `body` | object | **stable** | Body replacement. |
| `lua_script` | string | **beta** | Dynamic modification via Lua. |

### Header Modifiers

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `set` | - | object | `{}` | **stable** |
| `add` | - | object | `{}` | **stable** |
| `remove` | `delete` | array | `[]` | **stable** |

### Path Replace (`url.path.replace`)

| Field | Type | Stability |
|---|---|---|
| `old` | string | **stable** |
| `new` | string | **stable** |

### Query Modifier

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `set` | - | object | `{}` | **stable** |
| `add` | - | object | `{}` | **stable** |
| `remove` | `delete` | array | `[]` | **stable** |

### Body Modifier (request)

| Field | Type | Stability |
|---|---|---|
| `replace` | string | **stable** |
| `replace_json` | any | **stable** |

### Response Body Modifier

| Field | Type | Stability |
|---|---|---|
| `replace` | string | **stable** |
| `replace_json` | any | **stable** |

### Status Override

| Field | Type | Stability |
|---|---|---|
| `code` | integer | **stable** |
| `text` | string | **stable** |
