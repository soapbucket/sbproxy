# JSON field transform

*Last modified: 2026-04-27*

Demonstrates the `json` transform. The upstream is a `static` action that returns a canned post document, so the example runs offline. The transform reshapes the JSON before returning it to the client by renaming `userId` to `author_id`, removing the `body` field, and setting a new `source` field marking the response as proxied. The origin matches the `json.local` Host header on `127.0.0.1:8080`.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Upstream body (what the static action emits internally):
# {"userId":1,"id":1,"title":"first post","body":"this body field is removed by the transform"}

# Client response after the json transform:
$ curl -s -H 'Host: json.local' http://127.0.0.1:8080/posts/1
{"id":1,"title":"first post","author_id":1,"source":"sbproxy"}
```

```bash
# Headers reflect the JSON content type and the transform output
$ curl -sI -H 'Host: json.local' http://127.0.0.1:8080/posts/1
HTTP/1.1 200 OK
content-type: application/json
```

```bash
# Pretty-print to see the field rewrites applied:
$ curl -s -H 'Host: json.local' http://127.0.0.1:8080/posts/1 | jq
{
  "id": 1,
  "title": "first post",
  "author_id": 1,
  "source": "sbproxy"
}
```

## What this exercises

- `json` transform with `rename`, `remove`, and `set` operations on the response body
- `static` action with `json_body` - the upstream is inline so no external service is needed
- Header / body content negotiation: the transform preserves `application/json`

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
