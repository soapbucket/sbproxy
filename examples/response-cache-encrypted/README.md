# Encrypted file-backed response cache

*Last modified: 2026-07-23*

The response cache normally lives in the proxy's own memory, so it starts
cold after every restart and no two replicas share it. This example points
it at a directory instead, and seals what lands in that directory.

Two blocks do the work. `proxy.response_cache_store` picks the backing
store for the whole process, and its `encryption` sub-block turns on
AES-256-GCM at rest. The per-origin `response_cache` block is unchanged
from the [response-caching](../response-caching/) example.

## Why encrypt a cache

A response cache holds whatever the upstream returned. On an API gateway
that is account records, tokens in `Set-Cookie`, and anything else the
backend was willing to send an authenticated caller. Once it is on disk it
outlives the process, and anything with filesystem access can read it: a
backup job, a container snapshot, an operator poking around. Encrypting at
rest means the disk copy is only useful to something that also holds the
key.

## What is sealed

Response headers and the response body. The status code, the time the
entry was cached, and its TTL stay readable, because the file backend
needs them to decide whether a record has expired without opening it
first. All three are authenticated, so they can be read but not altered.
Flipping a cached `200` to a `500`, or stretching an entry's TTL to a
year, fails the integrity check and the entry is thrown away.

## Key material

Any secret reference the rest of the config accepts works here: a
`secret://backend/name` or `vault://...` URI against a backend declared
under `proxy.secrets.backends`, a `file:/path` reference, or a
whole-value `${ENV_VAR}`.

```bash
head -c 32 /dev/urandom | base64 > /tmp/sbproxy-response-cache.key
chmod 600 /tmp/sbproxy-response-cache.key
```

Use 32 random bytes, not a passphrase you thought up. The proxy logs a
short fingerprint of the key it loaded so operators can tell two keys
apart, and that fingerprint gives an attacker something to guess against
offline. Against 256 bits of entropy the guessing goes nowhere. Against
`correcthorsebattery` it finishes over a weekend.

The proxy generates no key for you and never runs unencrypted because one
is missing. A key that cannot be resolved, or that resolves to fewer than
16 bytes, stops startup with an error naming the field. A typo therefore
costs you a failed boot rather than a directory full of plaintext you
believed was protected.

`sbproxy validate` checks the shape of the block but does not read secret
backends or the filesystem, which is the same thing it does everywhere
else. A bad key reference surfaces the first time you serve with it.

## Rotation

Move the current reference into `previous_keys` and name the new one as
`key`:

```yaml
encryption:
  enabled: true
  key: "file:/etc/sbproxy/response-cache.key.new"
  previous_keys:
    - "file:/etc/sbproxy/response-cache.key.old"
```

New writes seal under the new key. Existing entries keep opening under the
old one until they are rewritten or expire. Drop the old reference out of
`previous_keys` and its entries are evicted the next time they are read,
which costs one cache miss each and nothing else.

Every entry carries a short identifier for the key that sealed it, so a
read picks the right key directly instead of trying each one.

## Backends

| Backend | Survives a proxy restart | Shared across replicas | Stale-while-revalidate | Prefix purge |
|---|---|---|---|---|
| `memory` | no | no | yes | yes |
| `file` | yes | yes, on a shared directory | yes | no |
| `memcached` | yes, until memcached restarts | yes | no | no |
| `redis` | yes | yes | no | yes |

Encryption works on all four. On `memory` it buys nothing real, since the
plaintext sits in the same process either way; it is allowed so a config
can move between backends without editing the encryption block.

The two `no` columns are not settings you can flip. `file` and
`memcached` hash cache keys, so neither can scan by prefix, which makes
`invalidate_on_mutation` (on by default) a no-op there and leaves entries
to fall out by TTL. And neither `memcached` nor `redis` can hand back an
entry that is past its TTL, so `stale_while_revalidate` never fires on
them.

`memcached` costs a bit more than the table shows. It opens a TCP
connection per operation, and its server default caps a value at 1 MiB,
so a larger response is refused and logged rather than cached. It also
does not dial the server at boot, and neither does `redis`, so a config
compiles and the proxy starts with the server down. You find out on the
first cache read.

## Run

```bash
head -c 32 /dev/urandom | base64 > /tmp/sbproxy-response-cache.key
chmod 600 /tmp/sbproxy-response-cache.key
make run CONFIG=examples/response-cache-encrypted/sb.yml
```

No env vars required. Uses `test.sbproxy.dev` (the echo upstream) for the
upstream call.

## Try it

```bash
curl -s -D - -o /dev/null -H 'Host: cached.local' http://127.0.0.1:8080/get \
  | grep -i x-sbproxy-cache
curl -s -D - -o /dev/null -H 'Host: cached.local' http://127.0.0.1:8080/get \
  | grep -i x-sbproxy-cache
```

The first call prints nothing, because a miss carries no
`x-sbproxy-cache` header. The second prints `x-sbproxy-cache: HIT`.

Then look at what landed on disk. Each entry is one `.cache` file: eight
binary bytes of expiry, which the backend reads to decide whether the
record is stale, then a small JSON wrapper. In that wrapper the header
list is empty and the body is the sealed envelope, so the only things you
can read are the status code and the two timestamps:

```bash
head -c 96 /tmp/sbproxy-response-cache/*.cache
```

Nothing the upstream sent comes back out of it. Pick any string from the
live response and look for it:

```bash
curl -s -H 'Host: cached.local' http://127.0.0.1:8080/get | head -c 200
grep -rc 'content-type' /tmp/sbproxy-response-cache/
```

The count is `0`. Turn encryption off, delete the directory, replay the
two requests, and the same grep starts matching.

## What this exercises

- `proxy.response_cache_store` - process-wide choice of backing store
- `backend.type: file` - one file per entry, keyed by a hash of the cache key
- `encryption.enabled` + `encryption.key` - AES-256-GCM at rest
- `encryption.previous_keys` - rotation without dumping the cache
- `file:` secret references, which resolve with no `proxy.secrets` block

## See also

- [docs/configuration.md](../../docs/configuration.md) - the full `response_cache_store` reference
- [examples/response-caching](../response-caching/) - the same cache with default storage
- [examples/vault-reference](../vault-reference/) - secret references against a real backend
