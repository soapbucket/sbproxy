# Cache Reserve, watched from the outside

The runnable half of [docs/cache-reserve.md](../../docs/cache-reserve.md). The reserve is a cold tier under the per-origin response cache: entries leaving the hot tier land in it, and a hot miss consults it before the request goes to the origin.

The hot tier here holds exactly one entry. That is not a tuning recommendation. It is what makes the reserve observable in four curl commands instead of an eviction window you have to wait out.

Two witnesses, so neither has to be taken on faith. The `x-sbproxy-cache` header names the tier that answered: absent on a miss, `HIT` from the hot tier, `HIT-RESERVE` from the cold tier. The `upstream_hits` counter in the body comes from the demo upstream, which counts only the requests that really reached it.

## Run

```bash
# The tamper-free version of "clean state": the filesystem reserve
# persists, so a rerun against a stale directory starts warm.
rm -rf /tmp/sbproxy-cache-reserve

# The example ships its own upstream. Start it first, then the proxy.
python3 examples/cache-reserve/fixture.py &
make run CONFIG=examples/cache-reserve/sb.yml
```

Or under compose, which is what the smoke runner uses:

```bash
cd examples/cache-reserve
docker compose up -d --wait
```

## Test

Fetch `/a`. Both tiers are empty, so the request reaches the upstream and the counter reads 1:

```bash
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a
```

<!-- CAPTURE: curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a -->

Fetch it again. The hot tier answers:

```bash
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a
```

<!-- CAPTURE: curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a -->

Fetch a second path. The hot tier holds one entry, so caching `/b` pushes `/a` out of it:

```bash
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/b
```

<!-- CAPTURE: curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/b -->

Now fetch `/a` again. The hot tier no longer has it, the reserve does, and `upstream_hits` still reads 1:

```bash
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a
```

<!-- CAPTURE: curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a -->

A reserve hit promotes the entry back into the hot tier on the way out, so the next read is a plain `HIT` rather than another reserve round trip:

```bash
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a
```

<!-- CAPTURE: curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a -->

The reserve is a directory you can look at:

<!-- CAPTURE: find /tmp/sbproxy-cache-reserve -type f | head -10 -->

Run the checked smoke cases from the repository root with:

```bash
bash scripts/examples-smoke.sh examples/cache-reserve
```

## Clean up

```bash
docker compose down -v
rm -rf /tmp/sbproxy-cache-reserve
```

## Read more

- [docs/cache-reserve.md](../../docs/cache-reserve.md) - backends, the admission filter, the request flow, and the tuning table
- [docs/configuration.md](../../docs/configuration.md#response-cache) - the response-cache schema the reserve sits under
