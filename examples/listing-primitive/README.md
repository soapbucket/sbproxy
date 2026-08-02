# Listing primitive

![Listing primitive](../../docs/assets/listing-primitive.gif)

The runnable half of [docs/listings.md](../../docs/listings.md). A `Listing` is a published, versioned view of an existing Resource. Listings live in `listings/*.yaml` beside `sb.yml`, so they are version-controlled with the Repo and validated through the same `sbproxy plan` pipeline that diffs the config.

Two origins, two Listings, so both halves of the surface are reachable:

| File | Publishes | Pinning | Shows |
|---|---|---|---|
| `listings/example.yaml` | `origins/api.example.com` as `example-api` | `pin` to a short SHA | An access plan, and one `spec.skills[]` entry, which is the part of a Listing that is on the data path |
| `listings/internal-tools.yaml` | `origins/internal.example.com` as `internal-tools` | `track-branch` on `main` | `spec.auth.strategies` matching the Resource's own `authentication.type`, and `status: draft` |

Both origins answer from the proxy itself, so this example needs no upstream and no fixture. The one skill carries its body inline rather than pointing at a file: a relative artifact path resolves against the process working directory rather than against the manifest, and an example that only runs from one directory is a trap. [`examples/agent-skills/`](../agent-skills/) shows the on-disk shape.

## Run

```bash
make run CONFIG=examples/listing-primitive/sb.yml
```

Or under compose, which is what the smoke runner uses:

```bash
cd examples/listing-primitive
docker compose up -d --wait
```

Listings load from the directory holding the served `sb.yml`, which is why compose mounts `listings/` next to the config rather than anywhere else.

## Plan time

`sbproxy plan` discovers the `listings/` directory beside the config it is given, prints a load summary on stderr, and folds every per-Listing finding into the same validation stream as the rest of the diff.

```bash
sbproxy plan -f examples/listing-primitive/sb.yml
```

<!-- CAPTURE: sbproxy plan -f examples/listing-primitive/sb.yml 2>&1 -->

A broken manifest is what makes the rules legible. This script assembles a throwaway Repo from a copy of `sb.yml` plus the deliberately wrong manifest in `invalid/`, because a broken file inside this example's own `listings/` directory would fail the repository's Listing sweep rather than teach anything:

```bash
bash examples/listing-primitive/bin/plan-error.sh
```

<!-- CAPTURE: bash examples/listing-primitive/bin/plan-error.sh -->

Findings are plan errors, not config-load errors. The proxy still starts with a stale Listing; the operator sees the finding the next time `plan` runs.

## Serve time

Most of a Listing is input for a future Catalog surface. `spec.skills[]` is the exception: the projection layer serves a per-Listing manifest on every origin the Listing publishes.

```bash
curl -s -H 'Host: api.example.com' \
  http://127.0.0.1:8080/.well-known/agent-skills/example-api/index.json
```

<!-- CAPTURE: curl -s -H 'Host: api.example.com' http://127.0.0.1:8080/.well-known/agent-skills/example-api/index.json -->

The artifact body is re-hosted under the Listing's own prefix, with the digest the manifest pinned re-checked on every fetch. A body that diverged from its digest returns 503 with an audit event rather than serving bytes nobody vouched for.

```bash
curl -s -D - -H 'Host: api.example.com' \
  http://127.0.0.1:8080/.well-known/agent-skills/example-api/skills/place-order.md
```

<!-- CAPTURE: curl -s -D - -H 'Host: api.example.com' http://127.0.0.1:8080/.well-known/agent-skills/example-api/skills/place-order.md -->

The unprefixed path returns the union of every Listing that publishes this hostname plus any top-level `agent_skills:` entries, deduplicated by name:

```bash
curl -s -H 'Host: api.example.com' http://127.0.0.1:8080/.well-known/agent-skills/index.json
```

<!-- CAPTURE: curl -s -H 'Host: api.example.com' http://127.0.0.1:8080/.well-known/agent-skills/index.json -->

A Listing does not advertise onto an origin it does not name. `internal-tools` declares no skills and `example-api` does not publish `internal.example.com`, so that hostname has no manifest at all:

```bash
curl -s -i -H 'Host: internal.example.com' http://127.0.0.1:8080/.well-known/agent-skills/index.json
```

<!-- CAPTURE: curl -s -i -H 'Host: internal.example.com' http://127.0.0.1:8080/.well-known/agent-skills/index.json -->

That 404 arrives before the origin's jwt authentication runs, which is deliberate: whether a hostname advertises skills is not a secret, and answering 401 would tell a caller that something is there.

The Resource itself is served like any other origin:

```bash
curl -s -H 'Host: api.example.com' http://127.0.0.1:8080/orders
```

<!-- CAPTURE: curl -s -H 'Host: api.example.com' http://127.0.0.1:8080/orders -->

Run the checked smoke cases from the repository root with:

```bash
bash scripts/examples-smoke.sh examples/listing-primitive
```

## What a Listing does not do yet

- **Nothing routes on it.** `accessPlan`, `publish`, and `lifecycle` are recorded and validated, and no request is priced, gated, or rate-limited by them. They are the input a hosted Catalog surface will read.
- **Revision pins are not checked.** The OSS resolver accepts every SHA, branch, and tag, so `missing-listing-revision-*` cannot fire here. A caller that links a real revision resolver, such as a future controller, gets the strict existence check.
- **Only the well-known prefix serves artifacts.** A Listing skill's body is reachable under `/.well-known/agent-skills/<listing>/<path>`. The bare `/skills/...` path is served by the top-level `agent_skills:` block, which is a separate surface.

## Clean up

```bash
docker compose down -v
```

## Read more

- [docs/listings.md](../../docs/listings.md) - the schema, the three pinning modes, and every plan-validation rule
- [docs/agent-skills.md](../../docs/agent-skills.md) - the v0.2.0 discovery projection and its integrity contract
- [examples/agent-skills/](../agent-skills/) - the same projection from the top-level `agent_skills:` block
