# Cache Reserve, watched from the outside

![Cache Reserve, watched from the outside](../../docs/assets/cache-reserve.gif)

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

```
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.14.4
Date: Sun, 02 Aug 2026 05:24:07 GMT
Content-Type: application/json
Content-Length: 108
X-Sb-Session-Id: 01KZ0EVW9YBRR43X17TBA0SJWB
traceparent: 00-51efa5a4fbe94796a245e0310fa12037-bf4a80c949ec45b7-01
X-Request-Id: 019fc0edf13e75e18b9b48f3e1aa9744
Connection: keep-alive

{"path":"/a","upstream_hits":1,"note":"this number only moves when the request really reached the upstream"}
```

Fetch it again. The hot tier answers:

```bash
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a
```

```
HTTP/1.1 200 OK
server: BaseHTTP/0.6 Python/3.14.4
Date: Sun, 02 Aug 2026 05:24:07 GMT
content-type: application/json
content-length: 108
x-sb-session-id: 01KZ0EVW9YBRR43X17TBA0SJWB
traceparent: 00-51efa5a4fbe94796a245e0310fa12037-bf4a80c949ec45b7-01
x-request-id: 019fc0edf13e75e18b9b48f3e1aa9744
x-sbproxy-cache: HIT
Connection: keep-alive

{"path":"/a","upstream_hits":1,"note":"this number only moves when the request really reached the upstream"}
```

Fetch a second path. The hot tier holds one entry, so caching `/b` pushes `/a` out of it:

```bash
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/b
```

```
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.14.4
Date: Sun, 02 Aug 2026 05:24:07 GMT
Content-Type: application/json
Content-Length: 108
X-Sb-Session-Id: 01KZ0EVWBQY5D219H3Z962BYWW
traceparent: 00-56a21850fa3947668bde37d045e6aa8b-6a92da42134349e7-01
X-Request-Id: 019fc0edf17675119a3d066bdedf0c7f
Connection: keep-alive

{"path":"/b","upstream_hits":1,"note":"this number only moves when the request really reached the upstream"}
```

Now fetch `/a` again. The hot tier no longer has it, the reserve does, and `upstream_hits` still reads 1:

```bash
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a
```

```
HTTP/1.1 200 OK
server: BaseHTTP/0.6 Python/3.14.4
Date: Sun, 02 Aug 2026 05:24:07 GMT
content-type: application/json
content-length: 108
x-sb-session-id: 01KZ0EVW9YBRR43X17TBA0SJWB
traceparent: 00-51efa5a4fbe94796a245e0310fa12037-bf4a80c949ec45b7-01
x-request-id: 019fc0edf13e75e18b9b48f3e1aa9744
x-sbproxy-cache: HIT-RESERVE
Connection: keep-alive

{"path":"/a","upstream_hits":1,"note":"this number only moves when the request really reached the upstream"}
```

A reserve hit promotes the entry back into the hot tier on the way out, so the next read is a plain `HIT` rather than another reserve round trip:

```bash
curl -s -D - -H 'Host: cache.local' http://127.0.0.1:8080/a
```

```
HTTP/1.1 200 OK
server: BaseHTTP/0.6 Python/3.14.4
Date: Sun, 02 Aug 2026 05:24:07 GMT
content-type: application/json
content-length: 108
x-sb-session-id: 01KZ0EVW9YBRR43X17TBA0SJWB
traceparent: 00-51efa5a4fbe94796a245e0310fa12037-bf4a80c949ec45b7-01
x-request-id: 019fc0edf13e75e18b9b48f3e1aa9744
x-sbproxy-cache: HIT
Connection: keep-alive

{"path":"/a","upstream_hits":1,"note":"this number only moves when the request really reached the upstream"}
```

The reserve is a directory you can look at:

```
/tmp/sbproxy-cache-reserve/03/82/a4cdcdc68ba044294c84e79e9566d4e1f1a35e62d7ca1460e5ff7e811685.bin
/tmp/sbproxy-cache-reserve/03/82/a4cdcdc68ba044294c84e79e9566d4e1f1a35e62d7ca1460e5ff7e811685.json
/tmp/sbproxy-cache-reserve/93/1b/35df8920059e57b20d6f509dfcb14f07a252daa60a812856aba070b8baac.json
/tmp/sbproxy-cache-reserve/93/1b/35df8920059e57b20d6f509dfcb14f07a252daa60a812856aba070b8baac.bin
```

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
