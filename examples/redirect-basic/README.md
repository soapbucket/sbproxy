# Plain redirects

*Last modified: 2026-08-20*

The redirect action's simple form: one origin, one target URL, one status code. Every request to the origin gets a `Location` header carrying `url:` exactly as written; the request path is not appended (for per-path mappings, see [bulk-redirects](../bulk-redirects/)). This example ships three origins. `old.example.local` sends everything to the new site's front door with a 301. `search.example.local` does the same but sets `preserve_query: true`, so a saved `?q=` search survives the move. `ingest.example.local` answers 308, which tells the client to repeat the request at the new URL with the same method and body, where a 301 would let it downgrade a POST to a GET.

## Run

```bash
make run CONFIG=examples/redirect-basic/sb.yml
```

## Try it

```bash
# The domain move: whatever path the old link carried, the reply
# points at the new front door.
$ curl -i -H 'Host: old.example.local' http://127.0.0.1:8080/pricing
HTTP/1.1 301 Moved Permanently
location: https://www.example.com/

# preserve_query: the query string rides along to the target.
$ curl -i -H 'Host: search.example.local' 'http://127.0.0.1:8080/results?q=gateway'
HTTP/1.1 301 Moved Permanently
location: https://find.example.com/search?q=gateway

# 308: the client repeats the POST, method and body intact, at the
# new endpoint.
$ curl -i -X POST -d '{"event":"signup"}' \
       -H 'Host: ingest.example.local' http://127.0.0.1:8080/v1/ingest
HTTP/1.1 308 Permanent Redirect
location: https://api.example.com/v2/ingest
```

## What this exercises

- `action.type: redirect` in its single-target form: `url`, `status`, `preserve_query`
- 301 for moved pages, 308 when the method must survive the redirect
- Host-keyed origins: each hostname carries its own target and status

## See also

- [examples/bulk-redirects](../bulk-redirects/) - per-path redirect lists (inline, file, or URL)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
