# Per-tenant response-cache encryption keys

One response-cache store serves every origin in a process. By default one
key seals every origin's entries too, which means the only thing keeping
two tenants apart in the cache is the cache key. This example gives each
tenant its own key.

## What the origin binding buys, separately from the key

Every sealed entry authenticates the origin it was written for. So an
entry sealed for `tenant-a.local` fails to open when read as
`tenant-b.local`, even when both inherit the store-wide key. A mis-scoped
lookup fails the integrity check rather than returning another tenant's
response body, which makes cross-tenant isolation a property of the
stored record instead of a property of the routing table.

That holds whether or not you set per-origin keys.

## What per-origin keys buy on top

Key separation. Under the default `per_origin_keys: inherit`, one leaked
key opens every tenant's entries. Give each tenant its own key and a
leaked key opens one tenant's.

They also make rotation independent: moving `tenant-a.local`'s active key
into its `previous_keys` and naming a new one rotates that tenant alone.

## Modes

| `per_origin_keys` | An origin that caches and declares no key |
|---|---|
| `inherit` (default) | Uses the store-wide `encryption.key`. |
| `required` | Startup fails, naming every origin that is missing one. |

Use `required` when the deployment's threat model needs every tenant to
hold key material nobody else holds. The failure lists all the missing
origins at once rather than one per restart.

## Running it

```bash
for t in store a b; do
  head -c 32 /dev/urandom | base64 > /tmp/sbproxy-cache-$t.key
  chmod 600 /tmp/sbproxy-cache-$t.key
done
make run CONFIG=examples/response-cache-per-origin-keys/sb.yml
```

```bash
# Miss, then hit.
curl -s -D - -o /dev/null -H 'Host: tenant-a.local' \
  http://127.0.0.1:8080/get | grep -i x-sbproxy-cache
curl -s -D - -o /dev/null -H 'Host: tenant-a.local' \
  http://127.0.0.1:8080/get | grep -i x-sbproxy-cache

# Nothing on disk carries a response header or body.
grep -rc 'content-type' /tmp/sbproxy-per-origin-cache/
```

## Things worth knowing before you deploy this

- Every per-origin key is resolved at boot. One that cannot be resolved
  stops startup with an error naming the origin. There is no path that
  degrades to writing that tenant in the clear.
- Declaring a per-origin key while `proxy.response_cache_store.encryption`
  is off is a config error, not a silent no-op.
- Purge is unaffected. It matches on the cache key and never opens a
  value, so a prefix purge still clears entries sealed under keys the
  admin path does not hold.
- Entries written by a build that predates per-origin keys keep opening
  and reseal with the origin bound the next time they are written.

The single-key version of this is
[`../response-cache-encrypted/`](../response-cache-encrypted/).
