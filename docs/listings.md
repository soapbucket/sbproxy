# Listings

*Last modified: 2026-05-09*

A `Listing` is a published, versioned view of an existing Resource (an
origin, an MCP server, or a docs surface). Listings live in the same
Repo as the rest of the proxy config, are version-controlled with it,
and are validated through the same `sbproxy plan` pipeline. The
primitive is the foundation the future hosted-Catalog surface and the
Listing-scoped agent-skills extension build on.

## Where Listings live

Drop one YAML file per Listing under a `listings/` directory at the
Repo root, alongside `sb.yml`:

```
my-repo/
  sb.yml
  listings/
    example-api.yaml
    internal-mcp.yaml
```

The loader picks up every `*.yaml` (and `*.yml`) under `listings/` at
config-load time. A missing directory is fine: Repos that have not
adopted the primitive yet load with no Listings registered. The
`sbproxy plan` subcommand discovers the `listings/` directory next to
the YAML it is given, prints a `plan: sbproxy.listings.loaded` line
on stderr with the count, and folds the per-Listing validation
findings into the existing plan stream so an operator sees both the
count and any errors in the same place as the rest of the diff.

## Schema

Every Listing uses the Kubernetes-flavoured manifest shape:

```yaml
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: example-api
  labels:
    team: platform
spec:
  type: api                  # api | mcp | docs (extensible)
  status: published          # draft | published | retired
  resources:
    - ref: origins/api.example.com
      revision:
        mode: pin            # pin | track-branch | tag
        value: "abc1234"
  auth:
    strategies: [api_key, jwt]
  accessPlan:
    free:
      rate: "100/min"
    paid:
      price_micros: 1000
      currency: USD
  publish:
    visibility: public       # public | authenticated | restricted
    docsUrl: "/docs/example-api"
  lifecycle:
    deprecation: null
    sunsetDate: null
```

Field reference:

| Path | Required | Notes |
|------|----------|-------|
| `apiVersion` | yes | Must be `sbproxy.dev/v1`. |
| `kind` | yes | Must be `Listing`. Other manifest kinds in the same `listings/` directory load as errors. |
| `metadata.name` | yes | Unique within a single Repo. The plan path is `listings.<name>`. |
| `metadata.labels` | no | Free-form label map. The OSS proxy does not interpret labels. |
| `spec.type` | yes | One of `api`, `mcp`, `docs`. Other values pass parsing and surface as `unknown-listing-type` warnings so the schema can grow before the validator does. |
| `spec.status` | yes | One of `draft`, `published`, `retired`. Other values surface as `unknown-listing-status` warnings. |
| `spec.resources` | yes | Non-empty. Each entry references a Resource and pins a revision. |
| `spec.resources[].ref` | yes | `<kind>/<name>` form. `origins/<hostname>` is validated against the active config; `mcp/<name>` and `docs/<name>` are accepted with a warning. |
| `spec.resources[].revision.mode` | yes | One of `pin`, `track-branch`, `tag`. See "Pinning modes" below. |
| `spec.resources[].revision.value` | yes | Mode-specific identifier. |
| `spec.auth.strategies` | no | Auth-strategy names, must be compatible with the underlying Resource. |
| `spec.accessPlan.free.rate` | no | Free-form rate string, e.g. `100/min`. Future Catalog surfaces will parse this. |
| `spec.accessPlan.paid.price_micros` | no | Price per call in micro-units of `currency`. |
| `spec.accessPlan.paid.currency` | no | ISO 4217 currency code (free-form today). |
| `spec.publish.visibility` | no | `public`, `authenticated`, or `restricted`. |
| `spec.publish.docsUrl` | no | Path on the public docs site. |
| `spec.lifecycle.deprecation` | no | Free-form deprecation note. |
| `spec.lifecycle.sunsetDate` | no | `YYYY-MM-DD`. Future Catalog surfaces will parse this. |

The schema is additive: future tickets will add fields under `spec.`
(WOR-196 wires per-Listing agent-skills there) without breaking
existing manifests.

## Pinning modes

A published Listing always serves a deterministic revision of its
underlying Resource. The schema offers three pinning strategies; pick
the one that matches how the team manages the Repo.

### `pin`

Pin to a specific commit SHA (full or short form). Deterministic, the
recommended default for Listings advertised on a paid plan.

```yaml
revision:
  mode: pin
  value: "abc1234"
```

Plan-validation rule: the pinned SHA must exist in the Repo. The OSS
proxy ships a no-op resolver that accepts every SHA so the plan
surface stays self-contained; callers that link a real
`RevisionResolver` (the future k8s controller, the hosted-Catalog
surface) get the strict existence check.

### `track-branch`

Track a moving branch. The Listing resolves to whatever the branch
currently points at when the proxy reloads.

```yaml
revision:
  mode: track-branch
  value: main
```

Use this for internal Listings advertised to a single team where
"latest from `main`" is the right answer. Plan-validation rule: the
branch must exist.

### `tag`

Pin to a release tag.

```yaml
revision:
  mode: tag
  value: v1.2.3
```

Use this when the Repo follows a release-tag workflow and the Listing
should track the current release. Plan-validation rule: the tag must
exist.

## Plan-step validation

Listings fold into the existing `sbproxy plan` validation stream. The
findings show up under the same `Validation:` header, with the same
text and JSON formats.

Rules enforced today:

- `orphan-listing-resource` (error): a `resources[].ref` that names
  `origins/<hostname>` not present in the active `sb.yml`.
- `invalid-listing-resource-kind` (error): the ref names a kind other
  than `origins`, `mcp`, or `docs`.
- `invalid-listing-resource-ref` (error): the ref is not in
  `<kind>/<name>` form.
- `forward-compatible-listing-resource` (warn): `mcp/<name>` or
  `docs/<name>` references that the OSS schema does not yet wire up.
- `missing-listing-revision-sha`,
  `missing-listing-revision-branch`,
  `missing-listing-revision-tag` (error): the revision pin does not
  exist in the Repo per the active `RevisionResolver`.
- `listing-auth-mismatch` (error): `spec.auth.strategies` does not
  include the underlying Resource's `authentication.type`.
- `unknown-listing-type` and `unknown-listing-status` (warn):
  forward-compatible warnings so a new value can land in the schema
  before the validator is taught about it.
- `empty-listing-resources` (error): `spec.resources` is empty.
- `duplicate-listing-name` (error): two manifests in the same Repo
  share a `metadata.name`.

Validation failures surface as plan errors, not config-load errors.
The proxy still starts when a Listing is stale; the operator sees the
finding the next time `sbproxy plan` runs against the Repo.

## Relationship to other primitives

- **Origins** (`sb.yml`'s `origins:` map): the Resource layer. A
  Listing references one or more origins via
  `resources[].ref: origins/<hostname>`. The origin's
  `authentication.type` constrains what `spec.auth.strategies` the
  Listing can advertise.
- **Projections** (`docs/llms.md`, robots.txt, RSL): runtime
  surfaces emitted from the live config. Listings are an input to a
  future Catalog projection (out of scope for this PR; tracked under
  WOR-135). The shape lands here so projections can read from a
  stable Listing surface when the work starts.
- **Agent-skills** (WOR-196): a per-Listing extension that lets a
  Listing publish skill manifests scoped to its surface. The schema
  reserves space for `spec.skills[]` so the WOR-196 ticket can land
  without a breaking change here.

## Example

The runnable example in `examples/listing-primitive/` ships:

- `sb.yml` with one origin (`api.example.com`).
- `listings/example.yaml` that publishes the origin as `example-api`,
  pins it to a short commit SHA, and advertises one auth strategy
  (`jwt`).

Run it like any other example:

```bash
make run CONFIG=examples/listing-primitive/sb.yml
```

The Listing is not on the data path in OSS today: it is the input the
hosted-Catalog surface and the agent-skills extension will consume.
