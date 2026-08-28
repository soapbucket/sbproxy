# Cache Reserve on object storage

*Last modified: 2026-08-27*

The [cache reserve](../../docs/cache-reserve.md) is the cold tier under
the response cache: entries the hot tier evicts are mirrored into it,
and a hot miss consults it before paying the origin. This example puts
that tier on object storage and seals every entry before it leaves the
process.

One backend covers four providers. `backend: s3` reaches S3 and anything
S3-compatible (MinIO, Cloudflare R2, Backblaze B2, Ceph) through
`endpoint`; `gcs` and `azure` reach the other two clouds; `local` writes
into a directory, which is what the shipped config uses so the
walkthrough runs with nothing installed.

## Run it

```bash
rm -rf /tmp/sbproxy-reserve-objects
head -c 32 /dev/urandom | base64 > /tmp/sbproxy-reserve.key
python3 examples/cache-reserve/fixture.py &
make run CONFIG=examples/cache-reserve-object-store/sb.yml
```

The upstream is the same fixture the
[cache-reserve](../cache-reserve/) example ships. It counts the requests
that actually reached it and returns the count in the body, so
`upstream_hits` is the witness: a number that does not move is proof a
cache tier answered.

## Watch the tiers

```bash
# 1. Miss. No x-sbproxy-cache header, upstream_hits 1.
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a

# 2. Hot hit. x-sbproxy-cache: HIT, upstream_hits still 1.
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a

# 3. A second path fills the one-entry hot tier and evicts /a from it.
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/b

# 4. Reserve hit, served out of object storage and promoted back into
#    the hot tier on the way out. x-sbproxy-cache: HIT-RESERVE,
#    upstream_hits still 1.
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a
```

## What is on the disk

The objects are sealed, so nothing readable is in them:

```bash
ls /tmp/sbproxy-reserve-objects/sbproxy/reserve/
grep -rc upstream_hits /tmp/sbproxy-reserve-objects   # 0
```

Each object name is the hex encoding of the cache key, which is what
keeps a cache key carrying a path and a query string from escaping the
prefix or colliding with another after the object store normalizes it.

Turn `encryption.enabled` off, restart with a clean directory, and the
same `grep` finds the body. That is the point of the setting and it is
worth seeing once.

## Against a real bucket

Two lines:

```yaml
    backend:
      type: object_store
      backend: s3
      bucket: acme-sbproxy-reserve
      region: us-east-1
      prefix: sbproxy/reserve/
```

Drop `path`, which only applies to `local`. Credentials come from the
provider's own environment discovery (`AWS_*`, `GOOGLE_*`, `AZURE_*`),
the same variables the `storage` action reads, so a machine configured
for one is configured for both.

Against MinIO, add `endpoint`:

```bash
docker run --rm -p 9000:9000 -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin quay.io/minio/minio server /data
```

```yaml
      backend: s3
      bucket: reserve
      endpoint: http://127.0.0.1:9000
      region: us-east-1
```

with `AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin` and
`AWS_ALLOW_HTTP=true` in the environment.

## Two things to set before production

**Lower `sample_rate`.** This example mirrors every hot-cache write so
the walkthrough is four requests instead of forty. A paid object store
charges per request, and the reserve is for the long tail rather than
for everything, so `0.05` to `0.1` is the usual range. Raise `min_ttl`
alongside it: an entry that will not outlive a hot eviction window is
not worth an object.

**Set a bucket lifecycle rule.** The proxy runs its own expiry sweep on
a fifteen-minute timer, so a small reserve does expire without any
bucket configuration. But expiry lives inside each object, so the sweep
has to read each candidate and is bounded at 1,000 objects per call:
one bounded pass per interval whatever the reserve holds, which means a
large backlog is worked through over many ticks rather than in one. S3
lifecycle expiration, GCS object lifecycle management, and Azure blob
lifecycle all do the same job on the reserve's prefix for free. The
built-in sweep is the answer for small reserves and for correctness
after a TTL change; it is not the answer at scale.

## Watching it

Five counters, all labeled by `origin`, drawn by the "Cache Reserve
Traffic" and "Cache Reserve Errors" panels on the `SBProxy Overview`
dashboard:

| Metric | What it tells you |
|---|---|
| `sbproxy_cache_reserve_hits_total` | Requests the origin did not serve after the hot cache had already missed. This is the reserve earning its keep |
| `sbproxy_cache_reserve_misses_total` | Both tiers empty |
| `sbproxy_cache_reserve_writes_total` | Entries the sample rate admitted |
| `sbproxy_cache_reserve_evictions_total` | Explicit deletions on mutation |
| `sbproxy_cache_reserve_errors_total` | Operations the backend refused, by `put` / `get` / `delete` |

The last one is the one to alert on. The reserve is best-effort, so
every error is swallowed and the request is served anyway; without that
counter, a reserve failing every write is indistinguishable from a cache
with a poor hit rate. A sustained `put` rate with a healthy `get` rate
is usually expired write credentials or a changed bucket policy.

## See also

- [docs/cache-reserve.md](../../docs/cache-reserve.md) - the full backend and tuning reference.
- [examples/cache-reserve/](../cache-reserve/) - the same walkthrough on the filesystem backend.
- [examples/response-cache-encrypted/](../response-cache-encrypted/) - at-rest encryption on the hot tier.
