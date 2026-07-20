# Admin server

*Last modified: 2026-07-19*

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

Protected control routes authenticate one of two ways. `POST /admin/login`,
`POST /admin/logout`, and `GET /admin/session` run before the general gate so a
browser can establish, revoke, or discover session state; they do not expose
protected control data.

- **HTTP Basic**, using the top-level `username` / `password`. Best for
  CI and scripts. The top-level admin always has the full `admin` role.
- **A browser session**, for the UI. `POST /admin/login` verifies
  credentials (a Basic header or a JSON `{"username","password"}` body)
  and sets an `HttpOnly`, `SameSite=Strict` session cookie (marked
  `Secure` when TLS is on), returning a CSRF token. `POST /admin/logout`
  revokes it. The signing key is per process, so a restart logs everyone
  out.

Because the cookie is `HttpOnly`, protected state-changing requests made with
a session must echo the CSRF token in an `X-CSRF-Token` header (a double-submit
an attacker cannot forge). Basic-auth requests are exempt. Login, logout,
session discovery, and cluster enrollment use their route-specific rules;
logout does not require a CSRF header.

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

A `read_only` operator can read config, metrics, logs, and status but cannot
create keys, edit config, reload, or otherwise mutate. Protected mutations that
pass the general Admin gate emit a structured event on the
`sbproxy::admin::audit` tracing target with the operator's identity. Session
establishment, discovery, and logout use their route-specific behavior.
Persistence depends on the configured tracing sink.

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

Everything below is reachable at `http(s)://<bind>:<port>`. Probe and session
establishment/discovery routes are unauthenticated; protected routes need auth
(top-level Basic or a session), and protected mutations need the `admin` role.
The separate enrollment exception is `POST /admin/cluster/enroll`, which
authenticates an expiring one-time cluster token instead of an existing admin
operator. Full per-route schemas, request/response shapes, and status codes
live in [admin-api-reference.md](admin-api-reference.md); a task-oriented
walkthrough with a curl cookbook lives in
[admin-api-guide.md](admin-api-guide.md). In short, the surface covers:

| Family | Covers |
|---|---|
| Health and readiness | `/healthz`, `/health`, `/readyz`, `/livez` — unauthenticated probes. |
| Session | `/admin/login`, `/admin/logout`, `/admin/session` — browser-session establishment and CSRF. |
| Config and pipeline | `/admin/config`, `/admin/reload`, `/admin/drift`, `/admin/log-level`, `/api/health/targets`, the OpenAPI mirror. |
| API keys and credentials | Full virtual-key and upstream-credential lifecycle: mint, list, edit policy, revoke, block, rotate, delete. |
| Model host | Catalog, desired-state deployments, runtime status, lifecycle (load/stop/reset), the artifact cache, and the local-serving + compression value report. |
| Cluster | Roster and health, signed deployment publication, one-time enrollment, fleet metrics, the replicated-state substrate. |
| AI compression session state | Content-free session metadata, admin-gated content inspection, delete, and bounded purge — see [ai-context-compression.md](ai-context-compression.md). |
| Cache | Response-cache status/purge, semantic-cache decisions, key-policy cache invalidation. |
| Prompts | The runtime prompt-overlay snapshot, versioning, and pinning. |
| Observability | `/metrics`, the request log and its live stream, spend, audit, and rate-limit budget state. |
| Chat playground | Run a real chat completion against any configured AI endpoint from the dashboard. |

Two things worth calling out here because they affect how you read the config
reference below:

- **API keys and upstream credentials** are cluster-shared only when the
  keystore backend is Redis or the mesh tier; the default embedded and memory
  backends are per-node. Key policy takes effect without a reload. See
  [key-management.md](key-management.md).
- **`/admin/config`** reads and writes the raw config text, so
  environment-variable interpolation (`${ENV_VAR}`) and secret-backend
  references are stored and shown exactly as written — a secret is never
  resolved into the saved config or exposed in the editor. See
  [secrets.md](secrets.md).
- **Model host and cluster deployment mutations** are authority-gated:
  `PUT /admin/model-host/deployments` only works under `admin_managed`
  authority (`file_managed` config stays read-only through this API; cluster
  authority instead publishes through `POST /admin/cluster/deployments` on
  the authority node, with verifier nodes read-only). See
  [model-host.md](model-host.md#authenticated-catalog-and-local-deployment-api).

Metrics are per-instance: each process exposes only its own counters. For a
cluster, an external Prometheus scrapes every instance and aggregates with
PromQL; the Grafana dashboards in `dashboards/` already sum across instances.
See [observability.md](observability.md).

## The built-in web UI

A Vue single-page app drives every endpoint above: keys and credentials,
config and drift, logs (with live tail), metrics, spend, AI performance,
guardrails, prompts, a chat playground, the response/semantic cache, model
host management, artifact storage, audit, and the full cluster roster and
health rail. It is off by default and lives behind a cargo feature so the
lean binary carries no front-end assets.

Build and enable it:

```bash
cd ui && npm ci && npm run build   # produces ui/dist/
cargo build --release -p sbproxy --features embed-admin-ui
```

Then open `http(s)://<bind>:<port>/admin/ui/`. The UI logs in through
`POST /admin/login`, stores the returned CSRF token, and sends it on
writes; the session cookie carries the rest. It inherits whatever auth,
roles, and TLS the admin server is configured with, so put it behind TLS
before using it over anything but loopback.

![The admin sign-in form: username and password fields on a plain card](assets/admin-login.png)

![The Overview page: health ok, per-component checks, a request-log count, and the model host section](assets/admin-overview.png)

See [admin-ui.md](admin-ui.md) for a page-by-page reference: what each of
the seventeen pages shows, what it can mutate, and which API paths back it.

## Security notes

- Change the default `username` and `password`. The defaults exist for a
  first run, not for anything reachable.
- Keep the server on loopback (the default) unless it is behind TLS with
  an `allow_ips` allowlist.
- Give day-to-day operators the `read_only` role and reserve `admin` for
  the accounts that actually change state; every mutation emits an audit event
  with the operator's identity.

## What is not here yet

The admin control-plane epic is complete: authentication (Basic and
browser sessions with CSRF), RBAC, remote bind with an IP allowlist and
CORS, TLS, the queryable and streamable request log, the spend and
config-write endpoints, and the embedded UI are all shipped. Remaining
follow-ups are single-sign-on / external identity providers for
operators, and per-route scopes finer than the `read_only` / `admin`
split.

## See also

- [admin-api-guide.md](admin-api-guide.md) - task-oriented walkthrough: login/CSRF, roles, a curl cookbook.
- [admin-api-reference.md](admin-api-reference.md) - every route, every field, every status code.
- [admin-ui.md](admin-ui.md) - the built-in dashboard, page by page.
