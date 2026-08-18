# Storage
*Last modified: 2026-08-18*

Storage means two things in SBproxy, and this page covers both. The `storage` action serves files out of an object store, the way a static-site origin or a bucket-backed CDN path would. Separately, the gateway itself persists state (certificates, cache entries, payment ledgers, config history), and knowing which backend holds what tells you what to back up, what is safe to lose, and where Redis actually becomes a requirement.

## The `storage` action

The `storage` action serves objects from S3, Google Cloud Storage, Azure Blob Storage, or the local filesystem. All four run through one codepath: the backend is constructed once at config load, and each request translates the inbound path into an object key, fetches or HEADs it, and streams the bytes back with `Content-Type`, `Content-Length`, `ETag`, and `Last-Modified` from the object metadata.

```yaml
origins:
  "static.example.com":
    action:
      type: storage
      backend: s3
      bucket: my-static-site
      prefix: public
      region: us-east-1
      index_file: index.html
```

| Field | Type | Default | Description |
|---|---|---|---|
| `backend` | string | required | `s3`, `gcs`, `azure`, or `local`. Anything else is refused at config load. |
| `bucket` | string | unset | Bucket or container name. Required for the three cloud backends. |
| `path` | string | unset | Local filesystem root. Required for `local`; canonicalized at build time, so symlinks in the configured path resolve to their real target before the store is rooted there. |
| `prefix` | string | unset | Key prefix prepended to every request path. |
| `index_file` | string | unset | Object served for paths ending in `/` (for example `index.html`). |
| `region` | string | env | Region override, `s3` only. |
| `endpoint` | string | unset | Endpoint override for S3-compatible stores (MinIO, Cloudflare R2). |

What it serves: `GET` and `HEAD`, with byte-range support (`Range` in, `206 Partial Content` and `Content-Range` out). Any other method gets `405`. A missing object is `404`; a transient backend error is `502`. `path`, `prefix`, and `index_file` all refuse traversal sequences at config load.

**Credentials come from the environment**, using each provider's standard discovery: `AWS_*` for `s3`, `GOOGLE_*` for `gcs`, `AZURE_*` for `azure`. There is no credential field in the action config, so nothing secret lands in `sb.yml`; set the variables before process start, through your platform's secret mechanism.

Because a `storage` origin is a normal origin, everything in the pipeline applies: authentication, policies, transforms, and the response cache compose with it the same way they do with a `proxy` origin.

Runnable at [`examples/storage-action/`](../examples/storage-action/), which uses the `local` backend so it runs with no cloud account, and shows the range, index-file, and 404 behavior with captured output.

## Where the gateway keeps its own state

The house rule for the gateway's own persistence: **redb** for embedded key-value state, **SQLite** for relational state, and **memory / file / memcached / redis** for the response cache. Nothing requires an external database; the embedded defaults carry a single node, and Redis enters only where state must be shared across replicas.

| Surface | Backends | Configured by | Reference |
|---|---|---|---|
| Response cache | `memory` (default), `file`, `memcached`, `redis` | `proxy.response_cache_store` | [configuration.md](configuration.md#choosing-the-backing-store) |
| Cache reserve (cold tier) | `memory`, `filesystem`, `redis` | the `cache_reserve` block | [cache-reserve.md](cache-reserve.md) |
| Shared counters (exact cluster-wide rate limits) | `redis` (the only implemented driver) | `proxy.l2_cache_settings` | [configuration.md](configuration.md#l2_cache_settings) |
| ACME certificate store | `redb` (default), `sqlite`, `file`, `redis`, `s3`, `gcs`, `azure`, `memory` | `acme.storage_backend` + `acme.storage_path` | [configuration.md](configuration.md#acme--auto-tls) |
| Payment settlement ledger and single-serve nonce ledger | SQLite, one shared database | `proxy.payments` | [payment-settlement.md](payment-settlement.md) |
| Config history (durable ring of applied configs) | content-addressed files in a local directory | `proxy.config_history` | [configuration.md](configuration.md#config_history) |
| AI compression session state | `local` (embedded redb), `redis`, or the replicated mesh | the compression `state` block | [ai-context-compression.md](ai-context-compression.md) |
| Admin prompt persistence | redb, optionally sealed with AES-256-GCM | `prompt_persistence_path` + `prompt_persistence_encryption` | [configuration.md](configuration.md) |
| Cluster state (sessions, handoff) | the replicated mesh substrate | `proxy.cluster` | [mesh-replication.md](mesh-replication.md) |

Three properties worth knowing before you plan an installation around this table:

- **The response cache can seal entries at rest.** The optional `encryption` block under `response_cache_store` encrypts headers and bodies with AES-256-GCM before they reach the backing store, which matters once entries land on disk (`file`) or in a shared store (`memcached`, `redis`) that outlives the request. An entry no configured key can open is evicted and reported as a miss, so rotation heals rather than breaks.
- **Local storage paths are subscriber-owned.** `proxy.compression_state` and `proxy.config_history` name directories on the node's own disk, so a config authority cannot set them for a fleet; a distributed payload naming either is rejected whole. See [configuration.md](configuration.md#what-the-subscriber-owns-outright).
- **What to back up.** The ACME store (or you re-issue on restore), the payments database (it is the proof of settlement), and the config-history ring if you rely on it for rollback. Cache tiers are rebuildable by definition and need no backup.

## See also

- [configuration.md#storage](configuration.md#storage) - the `storage` action's field table in the general reference.
- [cache-reserve.md](cache-reserve.md) - the cold tier under the response cache.
- [capacity-planning.md](capacity-planning.md) - what the persistent surfaces cost in memory and disk.
