# Upgrade Guide
*Last modified: 2026-04-24*

## Upgrading between versions

### From v0.x to v1.0

#### Breaking changes

- Security headers policy now uses `headers: [{name, value}]` array format instead of flat `x_frame_options` fields.
- `session_config` renamed to `session`. The old name still works for now.
- `serde_yaml` replaced with `yaml_serde` internally. No user-facing impact.

#### New features

- JavaScript engine (QuickJS) for transforms and WAF rules via `js_script` fields in request/response modifiers.
- ACME auto-cert (Let's Encrypt) via `proxy.acme` config block.
- HTTP/3 (QUIC) support via `proxy.http3` config block.
- Per-origin metrics with 21 metric families and configurable cardinality limiting.
- W3C and B3 distributed tracing header propagation.
- Webhook alerting with configurable channels via `proxy.alerting`.
- Admin stats SPA via `proxy.admin`.
- Per-origin connection pool tuning via `connection_pool`.

#### Config additions

The following top-level `proxy:` sub-keys are new in v1.0:

| Key | Description |
|-----|-------------|
| `proxy.acme` | ACME auto-cert configuration (Let's Encrypt). |
| `proxy.http3` | HTTP/3 QUIC configuration. |
| `proxy.metrics` | Metrics cardinality limits. |
| `proxy.alerting` | Alert notification channels (webhook, log). |
| `proxy.admin` | Embedded stats/logs SPA. |

The following per-origin keys are new in v1.0:

| Key | Description |
|-----|-------------|
| `connection_pool` | Per-origin connection pool tuning. |
| `on_request` | Event hook plugins (alpha). |
| `on_response` | Event hook plugins (alpha). |
| `bot_detection` | Bot traffic detection (alpha). |
| `threat_protection` | Dynamic blocklist integration (alpha). |
| `rate_limit_headers` | Rate limit response header control. |
| `traffic_capture` | Request mirroring (alpha). |
| `message_signatures` | HTTP message signature verification (alpha). |

#### Migration steps

1. Add `config_version: 1` to the top of your `sb.yml`. Required in v1.0.
2. If you use `session_config:`, rename it to `session:`. The alias still works but will be removed in a future release.
3. If you use security headers via flat fields (e.g. `x_frame_options`), move to the `response_modifiers` headers format:

   Before:
   ```yaml
   x_frame_options: DENY
   x_content_type_options: nosniff
   ```

   After:
   ```yaml
   response_modifiers:
     - headers:
         set:
           X-Frame-Options: DENY
           X-Content-Type-Options: nosniff
   ```

4. Validate the config before deploying:

   ```bash
   sbproxy --config sb.yml --validate
   ```

5. Deploy with zero downtime via config hot reload. Send `SIGHUP` to the running process, or use the admin API.
