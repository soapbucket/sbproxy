# Admin server

*Last modified: 2026-08-13*

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
| `username` / `password` | `admin` / `changeme` | The top-level admin's HTTP Basic credentials. Refused once the surface is reachable off loopback (see below). |
| `max_log_entries` | `1000` | Size of the in-memory recent-request ring buffer. |
| `prompt_persistence_path` | unset | redb file that persists prompt-version edits across restarts. |
| `tls` | unset | Serve HTTPS instead of plaintext (see [TLS](#tls)). |
| `bind` | `127.0.0.1` | Address to bind. Set to `0.0.0.0` or an interface for remote admin. Must be an IP address, not a hostname. |
| `allow_ips` | empty | IP / CIDR allowlist. Empty keeps the loopback-only default. |
| `cors_origins` | empty | Allowed CORS origins for a separately hosted UI. Empty emits no CORS. |
| `operators` | empty | Additional login identities with roles (see [Authentication and roles](#authentication-and-roles)). |

By default the server binds `127.0.0.1` and permits only loopback
clients, so it is reachable only from the same host; a per-IP and global
rate limit protects it from a local flood. To reach it from another
machine, set `bind`, an `allow_ips` allowlist, and `tls` (see [Remote
access and CORS](#remote-access-and-cors)).

### The default credentials are refused off loopback

The credentials default to `admin` / `changeme` so a first run works with
no setup. Those two strings are published in this file, in the config
reference, and in the source, so an admin server carrying them is
authenticated in form only. The admin API mints and revokes API keys,
reads and rewrites `sb.yml`, and drives the model host, so an open one is
not a smaller problem than an open data plane.

`sbproxy validate` and startup therefore reject the default password once
the admin surface is reachable from another host, meaning either of:

- `bind` is not a loopback address (`0.0.0.0`, a LAN interface, a public
  address), or
- `allow_ips` contains an entry outside loopback (`10.0.0.0/8`,
  `192.168.1.50`, `0.0.0.0/0`).

The error names which of the two tripped. Set a real password to clear
it, ideally out of the environment or a secret backend rather than in the
file:

```yaml
proxy:
  admin:
    enabled: true
    bind: 0.0.0.0
    allow_ips: ["10.0.0.0/8"]
    username: admin
    password: ${ADMIN_PASSWORD}
```

Loopback with the defaults stays valid, because that is the first-run and
local-development path: the credentials there guard nothing the local
user does not already have. The check is on the password alone, so a
different `username` does not clear it. An unresolved `${ADMIN_PASSWORD}`
does not clear it either: a reference whose variable is not exported is
rejected on its own, so it never becomes literal login text. See
[secrets.md](secrets.md).

A `bind` value that is not an IP address is also a validation error.
Startup used to fall back to `127.0.0.1` on a value it could not parse,
so a typo in a wide bind looked like it had worked while the server sat
on loopback, which is exactly the wrong conclusion to hand an operator
about what is exposed. Hostnames are not resolved; use an address.

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
its own credentials and gets a role. Operators are config-only: there is
no admin API to create or edit them, and the admin console's Operators
page is read-only. `password_hash` is an HMAC-SHA256 hash, hex-encoded,
computed with `sbproxy admin hash-password`:

```yaml
proxy:
  admin:
    enabled: true
    username: admin
    password: change-this
    operators:
      - username: oncall
        password_hash: ${ONCALL_PASSWORD_HASH}
        role: read_only   # GET/read endpoints only; mutations return 403
      - username: deployer
        password_hash: ${DEPLOYER_PASSWORD_HASH}
        role: admin        # every route
      - username: acme-billing
        password_hash: ${ACME_BILLING_PASSWORD_HASH}
        role: read_only
        tenant: acme       # may read only acme's metered consumption
```

A `read_only` operator can read config, metrics, logs, and status but cannot
create keys, edit config, reload, or otherwise mutate. Protected mutations that
pass the general Admin gate emit a structured event on the
`sbproxy::admin::audit` tracing target with the operator's identity. Session
establishment, discovery, and logout use their route-specific behavior.
Persistence depends on the configured tracing sink.

`tenant` is a separate question from `role`, and both apply. The role says
whether an operator may change anything; `tenant` says whose metered
consumption they may see. Naming one narrows the `/api/meter/*` routes to
that tenant: a request with no `tenant=` parameter resolves to their own,
and one naming anybody else is refused with `403` rather than filtered to
an empty result, because an empty result reads as "that tenant used
nothing" and somebody will believe it. Leaving `tenant` unset is the
default and means the whole deployment. The scope is read from config on
every request, so removing it from an operator takes effect on the next
reload rather than when their session expires. The console's Operators
page shows the scope in force.

The pepper `password_hash` is verified against comes from
`key_management.crypto.pepper` when that's set. Without it, `password_hash`
is hashed against a fixed pepper built into the binary, the same for every
install, so a leaked `password_hash` is crackable offline by anyone with the
source. Pin `key_management.crypto.pepper` in production; it does not
require enabling the rest of `key_management:`.

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
    password: ${ADMIN_PASSWORD}
```

Either of those two lines (a non-loopback `bind`, an off-loopback
`allow_ips` entry) makes the default password a validation error, so a
remote admin server has a real credential by construction. See [The
default credentials are refused off
loopback](#the-default-credentials-are-refused-off-loopback).

`allow_ips` matches exact addresses and CIDR networks; leaving it empty
keeps the loopback-only default (never the permit-all path). That default
lives in the filter itself rather than at its call site, so an empty list
denies every non-loopback peer, and so does a list whose entries are all
unparseable: a typo in the allowlist narrows the surface instead of
opening it. Loopback is matched by asking the address, not by comparing
text, so the IPv4-mapped form a dual-stack listener reports
(`::ffff:127.0.0.1`) is admitted like the `127.0.0.1` it is. When
`cors_origins` lists an origin, the server answers preflight `OPTIONS`
and echoes the CORS headers (with credentials) so a browser SPA on that
origin can call the API cross-origin.

### Docker-published admin ports

Docker port forwarding changes the peer address the container sees. Even when
the host publishes only to loopback, for example
`-p 127.0.0.1:9090:9090`, the request commonly reaches sbproxy from the
Docker bridge gateway rather than from `127.0.0.1`. An empty `allow_ips`
therefore returns `403` by design.

Bind the admin listener inside the container, keep the host publication on
loopback, and allow the exact bridge network used by that container:

```yaml
proxy:
  admin:
    enabled: true
    bind: 0.0.0.0
    port: 9090
    allow_ips: ["172.18.0.0/16"] # example only; inspect your network
    username: admin
    password: ${ADMIN_PASSWORD}
```

Find the real subnet with `docker network inspect <network>` and use the
narrowest CIDR that covers the reported gateway. Do not copy
`172.17.0.0/16` blindly: user-defined networks, Docker Desktop, rootless
Docker, and CI runners can use different ranges. The host-side
`127.0.0.1:9090` publication remains the first exposure boundary;
`allow_ips` is the independent in-container boundary. Because `bind` and the
bridge CIDR are off-loopback from sbproxy's perspective, configure a real
password as shown above.

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
| Health and readiness | `/healthz`, `/health`, `/readyz`, `/livez`. Unauthenticated probes. |
| Session | `/admin/login`, `/admin/logout`, `/admin/session`. Browser-session establishment and CSRF. |
| Config and pipeline | `/admin/config`, `/admin/reload`, `/admin/drift`, `/admin/log-level`, `/api/health/targets`, the OpenAPI mirror. |
| API keys and credentials | Full virtual-key and upstream-credential lifecycle: mint, list, edit policy, revoke, block, rotate, delete. |
| Model host | Catalog, desired-state deployments, runtime status, lifecycle (load/stop/reset), durable operation jobs with SSE progress, the artifact cache, and the local-serving + compression value report. |
| Cluster | Roster and health, signed deployment publication, one-time enrollment, fleet metrics, fleet-wide VRAM aggregation, the replicated-state substrate. |
| AI compression session state | Content-free session metadata, admin-gated content inspection, delete, and bounded purge. See [ai-context-compression.md](ai-context-compression.md). |
| Cache | Response-cache status/purge, semantic-cache decisions, key-policy cache invalidation. |
| Prompts | The runtime prompt-overlay snapshot, versioning, and pinning. |
| Observability | `/metrics`, the request log and its live stream, spend, audit, and rate-limit budget state. |
| Chat playground | Run a chat completion against any configured AI endpoint from the dashboard, either straight against the AI client or impersonating a virtual key through the real request pipeline. |

Two things worth calling out here because they affect how you read the config
reference below:

- **API keys and upstream credentials** are cluster-shared only when the
  keystore backend is Redis or the mesh tier; the default embedded and memory
  backends are per-node. Key policy takes effect without a reload. See
  [key-management.md](key-management.md).
- **`/admin/config`** reads and writes the raw config text, so
  environment-variable interpolation (`${ENV_VAR}`) and secret-backend
  references are stored and shown exactly as written. A secret is never
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

A Vue single-page app drives every endpoint above: a Get Started
onboarding flow, keys and credentials, config and drift, logs (with live
tail), metrics, spend, AI performance, guardrails, prompts, a chat
playground, model-host jobs (with live SSE progress), the response/
semantic cache, model host management, artifact storage, audit, and the
full cluster roster and health rail. It is off by default and lives
behind a cargo feature so the lean binary carries no front-end assets.

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

### New console views

- **Get Started** (`/get-started`) walks through picking and deploying a
  first model, reusing the same deploy flow as the Model host page.
- **Jobs** (`/jobs`) lists durable model-host operation jobs (load,
  evict) and tails one job's progress live, backed by the admin job API's
  SSE stream with `Last-Event-ID` reconnect.
- **Model host** now reports four axes per deployment instead of two:
  desired state, local runtime state, cluster assignment, and live
  replica state.
- The cluster node roster gains a per-replica disclosure: expand a node
  to see the individual model replicas it is currently serving.
- **Chat playground** now dispatches through the real request pipeline:
  pick a virtual key and the console impersonates it, so the request runs
  through key policy, governance, routing, and guardrails exactly like
  that key's own traffic, instead of calling the AI client directly.
  Plain-HTTP AI origins only; an origin requiring TLS is not yet
  supported from the playground. The direct, bypass-everything call is
  still available as its own API route (`POST
  /admin/api/playground/chat`) for scripting.

See [admin-ui.md](admin-ui.md) for a page-by-page reference: what each
page shows, what it can mutate, and which API paths back it.

## Security notes

- Change the default `username` and `password`. The defaults exist for a
  first run, not for anything reachable, and validation refuses the
  default password once `bind` or `allow_ips` makes the surface reachable
  from another host.
- Keep the server on loopback (the default) unless it is behind TLS with
  an `allow_ips` allowlist. Nothing forces TLS on a remote admin bind
  today, so that one is still on you.
- Changing anything under `proxy.admin` needs a process restart, not a
  reload. The admin server reads its whole config once at startup,
  credentials and TLS included, so a rotated password or a swapped
  certificate does not take effect on `SIGHUP` or `POST /admin/reload`.
  `sbproxy plan` classifies `proxy.admin.**` as `restart` for that
  reason.
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
