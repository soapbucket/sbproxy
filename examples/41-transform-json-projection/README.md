# JSON projection transform

*Last modified: 2026-04-27*

Demonstrates the `json_projection` transform in whitelist mode. Only the listed fields (`id`, `title`) survive in the response; everything else is dropped. Same shape used by GraphQL field selection or sparse fieldsets. A self-contained `static` action seeds a four-field document so the example works offline. The origin is reached on `127.0.0.1:8080` via the `project.local` Host header.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Upstream body (what the static action emits internally):
# {"userId":1,"id":1,"title":"first post","body":"the body is dropped by the projection"}

# Client response after the projection transform - only id and title survive
$ curl -s -H 'Host: project.local' http://127.0.0.1:8080/posts/1
{"id":1,"title":"first post"}
```

```bash
$ curl -sI -H 'Host: project.local' http://127.0.0.1:8080/posts/1
HTTP/1.1 200 OK
content-type: application/json
```

```bash
$ curl -s -H 'Host: project.local' http://127.0.0.1:8080/posts/1 | jq
{
  "id": 1,
  "title": "first post"
}
```

## What this exercises

- `json_projection` transform with a whitelist `fields` array
- Field-level data-minimisation pattern: drop everything not explicitly named
- `static` action with `json_body` for an offline upstream

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
