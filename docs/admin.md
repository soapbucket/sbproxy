# Admin server

*Last modified: 2026-07-06*

sbproxy has a built-in admin server: a small control-plane HTTP endpoint,
separate from the data plane, for operating a running proxy. It exposes
the current config, health, metrics, and a filterable request log, and it
manages API keys, upstream credentials, prompt versions, and config
edits at runtime. A built-in web UI (off by default) sits on top of the
same endpoints.

The admin server is off unless you enable it, binds loopback only by
default, and authenticates every request. Read this page before exposing
it anywhere.

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
| `port` | `9090` | Port it binds. |
| `username` / `password` | `admin` / `changeme` | The top-level admin's HTTP Basic credentials. Change them. |
| `max_log_entries` | `1000` | Size of the in-memory recent-request ring buffer. |
| `prompt_persistence_path` | unset | redb file that persists prompt-version edits across restarts. |
| `tls` | unset | Serve HTTPS instead of plaintext (see [TLS](#tls)). |
| `bind` | `127.0.0.1` | Address to bind. Set to `0.0.0.0` or an interface for remote admin. |
| `allow_ips` | empty | IP / CIDR allowlist. Empty keeps the loopback-only default. |
| `cors_origins` | empty | Allowed CORS origins for a separately hosted UI. Empty emits no CORS. |
| `operators` | empty | Additional login identities with roles (see [Authentication and roles](#authentication-and-roles)). |

By default the server binds `127.0.0.1` and permits only loopback
clients, so it is reachable only from the same host; a per-IP and global
rate limit protects it from a local flood. To reach it from another
machine, set `bind`, an `allow_ips` allowlist, and `tls` (see [Remote
access and CORS](#remote-access-and-cors)).

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

## Authentication and roles

Every non-probe request authenticates one of two ways:

- **HTTP Basic**, using the top-level `username` / `password`. Best for
  CI and scripts. The top-level admin always has the full `admin` role.
- **A browser session**, for the UI. `POST /admin/login` verifies
  credentials (a Basic header or a JSON `{"username","password"}` body)
  and sets an `HttpOnly`, `SameSite=Strict` session cookie (marked
  `Secure` when TLS is on), returning a CSRF token. `POST /admin/logout`
  revokes it. The signing key is per process, so a restart logs everyone
  out.

Because the cookie is `HttpOnly`, state-changing requests made with a
session must echo the CSRF token in an `X-CSRF-Token` header (a
double-submit an attacker cannot forge). Basic-auth requests are exempt.

Roles (`operators`) give role-based access. Each operator logs in with
its own credentials and gets a role:

```yaml
proxy:
  admin:
    enabled: true
    username: admin
    password: change-this
    operators:
      - username: oncall
        password: rotate-me
        role: read_only   # GET/read endpoints only; mutations return 403
      - username: deployer
        password: rotate-me-too
        role: admin        # every route
```

A `read_only` operator can read config, metrics, logs, and status but
cannot create keys, edit config, reload, or otherwise mutate. Every
authenticated mutation is written to the audit trail (the
`sbproxy::admin::audit` log target) with the operator's identity.

## Remote access and CORS

To operate the admin server from another host, bind a reachable address,
restrict who may connect, and require TLS:

```yaml
proxy:
  admin:
    enabled: true
    bind: 0.0.0.0
    allow_ips: ["10.0.0.0/8", "192.168.1.50"]   # CIDRs or exact IPs
    cors_origins: ["https://admin.example.com"]   # for a separately hosted UI
    tls: { cert: /etc/sbproxy/admin-cert.pem, key: /etc/sbproxy/admin-key.pem }
    username: admin
    password: change-this
```

`allow_ips` matches exact addresses and CIDR networks; leaving it empty
keeps the loopback-only default (never the permit-all path). When
`cors_origins` lists an origin, the server answers preflight `OPTIONS`
and echoes the CORS headers (with credentials) so a browser SPA on that
origin can call the API cross-origin.

## What it can do

Everything below is reachable at `http(s)://<bind>:<port>`. The probe
routes are unauthenticated; the rest need auth (Basic or a session), and
mutations need the `admin` role.

**Health and readiness (unauthenticated).**

| Method | Path | Returns |
|---|---|---|
| GET | `/healthz` | `{"status":"ok"}` |
| GET | `/health` | Full report: version, build, uptime, per-component checks. |
| GET | `/readyz`, `/livez` | Readiness / liveness, 200 or 503. |

**Session.**

| Method | Path | Purpose |
|---|---|---|
| POST | `/admin/login` | Verify credentials, set the session cookie, return a CSRF token. |
| POST | `/admin/logout` | Revoke the session and clear the cookie. |

**Config and pipeline.**

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/openapi.json`, `/api/openapi.yaml` | OpenAPI of the live config. |
| GET | `/admin/config` | Current on-disk YAML plus the loaded revision. |
| PUT | `/admin/config` | Validate, persist, and hot-swap a new config (`?if_match=<rev>` for optimistic concurrency). |
| GET | `/admin/drift` | On-disk config hash vs the loaded one. |
| POST | `/admin/reload` | Re-read the config file and hot-swap the pipeline. |
| GET | `/api/health/targets` | Per-target health, outlier, and breaker state. |
| GET | `/admin/model-host/status` | Locally served models, VRAM, keep-alive. |
| GET | `/admin/cluster/metrics` | Fleet-aggregated metrics (mesh tier; see [observability.md](observability.md)). |

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
| GET | `/api/requests` | Recent-request ring buffer. Filters: `status`, `method`, `path` (substring), `offset`, `limit`. |
| GET | `/api/requests/stream` | Server-Sent-Events tail: a `data:` event per new request. |
| GET | `/api/usage/spend` | Token and USD spend totals from the AI cost metrics. |
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

Then open `http(s)://<bind>:<port>/admin/ui`. The UI logs in through
`POST /admin/login`, stores the returned CSRF token, and sends it on
writes; the session cookie carries the rest. It inherits whatever auth,
roles, and TLS the admin server is configured with, so put it behind TLS
before using it over anything but loopback.

## Security notes

- Change the default `username` and `password`. The defaults exist for a
  first run, not for anything reachable.
- Keep the server on loopback (the default) unless it is behind TLS with
  an `allow_ips` allowlist.
- Give day-to-day operators the `read_only` role and reserve `admin` for
  the accounts that actually change state; every mutation is audited with
  the operator's identity.

## What is not here yet

The admin control-plane epic is complete: authentication (Basic and
browser sessions with CSRF), RBAC, remote bind with an IP allowlist and
CORS, TLS, the queryable and streamable request log, the spend and
config-write endpoints, and the embedded UI are all shipped. Remaining
follow-ups are single-sign-on / external identity providers for
operators, and per-route scopes finer than the `read_only` / `admin`
split.
