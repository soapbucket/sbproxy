# Listings

*Last modified: 2026-08-02*

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
| `metadata.labels` | no | Free-form label map. The proxy does not interpret labels. |
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

The schema is additive: future work will add fields under `spec.`
(per-Listing agent-skills, etc.) without breaking existing manifests.

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

Plan-validation rule: the pinned SHA must exist in the Repo. The proxy
ships a no-op resolver that accepts every SHA so the plan
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
  `docs/<name>` references that the schema does not yet wire up.
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
  future Catalog projection (out of scope here). The shape lands here
  so projections can read from a stable Listing surface when the
  work starts.
- **Agent-skills**: `spec.skills[]` is shipped. Each entry mirrors
  the top-level `agent_skills:` block (`name`, `type`, `description`,
  `url`, optional `visibility`), and the projection layer serves the
  per-Listing manifest at
  `/.well-known/agent-skills/<listing-name>/index.json` plus a
  Catalog-wide union at `/.well-known/agent-skills/index.json`.
  Plan-time validation enforces four rules:
  `listing-skill-bad-type` (type must be `skill-md` or `archive`),
  `listing-skill-url-out-of-tree` (url must be fully-qualified or
  resolve under `skills/` in the Repo),
  `duplicate-listing-skill-name` (names unique within one Listing),
  and `unknown-listing-skill-visibility` (warns unless `public` or
  `authenticated`).

## Example

![a request proxied through the origin declared by the pinned listing](assets/listing-primitive.gif)

The runnable example in [`examples/listing-primitive/`](../examples/listing-primitive/)
ships two origins and two Listings, so both halves of the surface are
reachable: `listings/example.yaml` publishes `api.example.com` as
`example-api`, pinned to a short SHA and carrying one skill;
`listings/internal-tools.yaml` publishes `internal.example.com` as
`internal-tools`, tracking a branch and advertising the auth strategy
that origin actually accepts. Both origins answer from the proxy itself,
so the example needs no upstream.

```bash
make run CONFIG=examples/listing-primitive/sb.yml
```

### Plan time

`plan` discovers the `listings/` directory beside the config it is given,
prints the load summary on stderr, and folds the per-Listing findings into
the same validation stream as the config diff:

```
plan: sbproxy.listings.loaded count=2 root=examples/listing-primitive
  + origins.api.example.com [reload] origin 'api.example.com' added
  + origins.internal.example.com [reload] origin 'internal.example.com' added

Plan: 2 added, 0 changed, 0 removed. max-blast-radius: reload
```

The rules above are what a wrong manifest runs into. The example keeps a
deliberately broken one outside its own `listings/` directory, and a
script assembles a throwaway Repo from it:

```
plan: sbproxy.listings.loaded count=1 root=/var/folders/fr/xgqsws5d2k5gnxt8w7tnjwsw0000gn/T/tmp.ljaq6ezc4v
  + origins.api.example.com [reload] origin 'api.example.com' added
  + origins.internal.example.com [reload] origin 'internal.example.com' added

Plan: 2 added, 0 changed, 0 removed. max-blast-radius: reload

Validation:
  [ERROR] listings.broken-listing.spec.resources[0].ref (orphan-listing-resource): listing 'broken-listing' references unknown origin 'nope.example.com' (no matching entry under origins.*)
  [ERROR] listings.broken-listing.spec.resources[1].ref (invalid-listing-resource-kind): listing 'broken-listing' references unsupported resource kind in 'service/not-a-kind' (expected origins/, mcp/, or docs/)
  [ERROR] listings.broken-listing.spec.skills[0].url (listing-skill-url-out-of-tree): listing 'broken-listing' skill[0] url '/etc/passwd' must be fully-qualified or resolve to a file under skills/ in the Repo

Validation: 3 error(s), 0 warning(s).
```

### Serve time

Most of a Listing is input for a future Catalog surface: nothing routes on
`accessPlan`, `publish`, or `lifecycle`, and no request is priced or gated
by them. `spec.skills[]` is the exception, and it is on the data path. The
projection layer serves a per-Listing manifest on every origin the Listing
publishes:

```
{
  "$schema": "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
  "entries": [
    {
      "description": "Place an order against the orders API.",
      "digest": "sha256:1e9f1d77a5250c4a31fa862fe0d733ca3893986421ed4367af2a037bb3c7c42c",
      "name": "place-order",
      "type": "skill-md",
      "url": "http://api.example.com/.well-known/agent-skills/example-api/skills/place-order.md"
    }
  ]
}
```

Each artifact body is re-hosted under that same prefix, with the digest the
manifest pinned re-checked on every fetch:

```
HTTP/1.1 200 OK
content-type: text/markdown; charset=utf-8
content-length: 621
Date: Sun, 02 Aug 2026 20:38:53 GMT
Connection: keep-alive

# Place an order

Create an order against the orders API published by the
`example-api` Listing.

## When to use this

The caller has a customer id, one or more line items, and needs
an order record created. Read-only questions about an existing
order belong to the lookup skill, not this one.

## Steps

1. `POST /orders` with a JSON body carrying `customer_id` and
   `items[]`.
2. Read `order_id` out of the 201 response.
3. Poll `GET /orders/{order_id}` until `status` leaves `pending`.

## Limits

The free access plan allows 100 requests per minute. Above that
the gateway answers 429 and the order is not created.
```

A Listing does not advertise onto a hostname it does not publish. The
second origin declares no skills and is named by no Listing that does, so
it has no manifest, and the 404 arrives before that origin's own jwt
authentication runs:

```
HTTP/1.1 404 Not Found
content-type: application/json
content-length: 39
Date: Sun, 02 Aug 2026 20:38:53 GMT
Connection: keep-alive

{"error":"agent-skills not configured"}
```

The Resource itself is served like any other origin:

```
{"service":"orders","note":"the Resource the example-api Listing publishes"}
```
