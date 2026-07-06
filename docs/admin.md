# Admin server

*Last modified: 2026-07-05*

sbproxy has a built-in admin server: a small control-plane HTTP endpoint,
separate from the data plane, for operating a running proxy. It exposes
the current config, health, and metrics, and it manages API keys,
upstream credentials, and prompt versions at runtime. A built-in web UI
(off by default) sits on top of the same endpoints.

The admin server is off unless you enable it, binds loopback only, and
sits behind HTTP Basic auth. Read this page before exposing it anywhere.

## Enabling it

Add an `admin` block under `proxy`:

```yaml
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    port: 9090
    username: admin
    password: change-this
    max_log_entries: 1000
```

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turn the admin server on. |
| `port` | `9090` | Port it binds, on `127.0.0.1` only. |
| `username` / `password` | `admin` / `changeme` | HTTP Basic credentials. Change them. |
| `max_log_entries` | `1000` | Size of the in-memory recent-request ring buffer. |
| `prompt_persistence_path` | unset | redb file that persists prompt-version edits across restarts. |
| `tls` | unset | Serve HTTPS instead of plaintext (see below). |

The server binds `127.0.0.1` and enforces a localhost-only IP allowlist,
so by default it is reachable only from the same host. A per-IP and
global rate limit protects it from a local flood. Reaching it from
another machine currently means fronting it with your own reverse proxy
or an SSH tunnel; a configurable bind and allowlist are on the roadmap
(see "What is not here yet").

## TLS

To serve the admin server (and the UI) over HTTPS, point `tls` at a PEM
certificate chain and its private key:

```yaml
proxy:
  admin:
    enabled: true
    port: 9090
    username: admin
    password: change-this
    tls:
      cert: /etc/sbproxy/admin-cert.pem
      key: /etc/sbproxy/admin-key.pem
```

Both paths are required together. The key may be PKCS#8 or RSA. If the
cert or key cannot be read or parsed, the admin server logs the error
and does not start, rather than fall back to plaintext on a port you
asked to be TLS. With `tls` set, plaintext requests to the port fail;
use `https://`.

A quick self-signed cert for local testing:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout admin-key.pem -out admin-cert.pem -subj "/CN=localhost"
curl -sk -u admin:change-this https://127.0.0.1:9090/metrics
```

## What it can do

Everything below is reachable at `http(s)://127.0.0.1:<port>`. The
probe routes are unauthenticated; the rest need Basic auth.

**Health and readiness (unauthenticated).**

| Method | Path | Returns |
|---|---|---|
| GET | `/healthz` | `{"status":"ok"}` |
| GET | `/health` | Full report: version, build, uptime, per-component checks. |
| GET | `/readyz`, `/livez` | Readiness / liveness, 200 or 503. |

**Config and pipeline.**

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/openapi.json`, `/api/openapi.yaml` | OpenAPI of the live config. |
| GET | `/admin/drift` | On-disk config hash vs the loaded one. |
| POST | `/admin/reload` | Re-read the config file and hot-swap the pipeline. |
| GET | `/api/health/targets` | Per-target health, outlier, and breaker state. |
| GET | `/admin/model-host/status` | Locally served models, VRAM, keep-alive. |

**API keys and upstream credentials.** Full lifecycle over HTTP: create
(the plaintext token is returned once, on creation), list, get, edit
policy and attribution, delete, revoke, block, unblock, and
grace-window rotate.

| Method | Path |
|---|---|
| POST, GET | `/admin/keys` |
| GET, PATCH, DELETE | `/admin/keys/{id}` |
| POST | `/admin/keys/{id}/revoke`, `/block`, `/unblock`, `/rotate` |
| POST, GET | `/admin/credentials` |
| GET, PATCH, DELETE | `/admin/credentials/{id}` |

Key policy covers allowed and blocked models and providers, budgets, PII
rules, principal selectors, route-to-model, injected tools, tags,
tenant, and expiry. Changes take effect without a reload. These keys are
cluster-shared only when the keystore backend is Redis or the mesh tier;
the default embedded and memory backends are per-node. See
[key-management.md](key-management.md).

**Prompts.**

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/prompts` | Runtime prompt-overlay snapshot. |
| POST | `/admin/prompts/{host}/{name}/versions` | Add a prompt version. |
| PUT | `/admin/prompts/{host}/{name}/pin` | Pin the default version. |

**Observability.**

| Method | Path | Returns |
|---|---|---|
| GET | `/metrics` | Prometheus / OpenMetrics text (also on the data-plane port). |
| GET | `/api/requests` | The recent-request ring buffer (in memory). |
| GET | `/api/audit/recent?limit=` | Recent rate-limit budget audit rows. |

Metrics are per-instance: each process exposes only its own counters.
For a cluster, an external Prometheus scrapes every instance and
aggregates with PromQL; the Grafana dashboards in `dashboards/` already
sum across instances. See [observability.md](observability.md).

## The built-in web UI

A Vue single-page app drives the endpoints above (keys and credentials,
config and drift, logs, metrics, prompts, model-host status). It is off
by default and lives behind a cargo feature so the lean binary carries
no front-end assets.

Build and enable it:

```bash
cd ui && npm install && npm run build   # produces ui/dist/
cargo build --release -p sbproxy --features embed-admin-ui
```

Then open `http(s)://127.0.0.1:<port>/admin/ui`. The browser prompts for
the Basic credentials once and reuses them for the API calls. The UI
inherits whatever auth and TLS the admin server is configured with, so
put it behind TLS before using it over anything but loopback.

## Security notes

- Change the default `username` and `password`. The defaults exist for a
  first run, not for anything reachable.
- Keep the server on loopback (the default) unless it is behind TLS and
  something that authenticates callers.
- Basic auth is a single shared credential with no roles. Treat access
  as all-or-nothing for now.

## What is not here yet

The admin server is being built out under one epic. Shipped today:
the endpoints above, TLS, and the embedded UI. Still to come: a
browser session login (so the UI does not rely on the Basic-auth
prompt), role-based access control with an operator identity in the
audit trail, a configurable bind and IP allowlist for remote access
with CORS, a queryable and streamable logs and events API, and config
edits over HTTP beyond whole-file reload.
