# SSE chunking transform

Some backends emit a plain line-oriented body: a log tail, an NDJSON feed, one record per line. A browser that wants to consume that as a live stream expects Server-Sent Events framing instead, where each event is a `data:` line followed by a blank line. The `sse_chunking` transform does that reframing at the edge, so the origin can stay simple and the client still gets an `EventSource`-shaped stream.

This example seeds a three-line body with a static action and reframes it.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

The origin's body is three plain lines. After the transform, each line is a `data:` event separated by a blank line:

```bash
$ curl -s -H 'Host: sse.local' http://127.0.0.1:8080/
data: build started

data: build passed

data: deploy queued

```

Piping the same response through `od -c` shows the framing exactly, each event ending in two newlines:

```
data:   b u i l d   s t a r t e d \n \n
data:   b u i l d   p a s s e d \n \n
data:   d e p l o y   q u e u e d \n \n
```

## What this shows

- Every non-empty line getting the `data: ` prefix and a blank-line separator
- A body that a browser can read with `new EventSource(...)` produced from a plain line feed

`line_prefix` overrides the prefix (default `data: `) for a backend that expects a different field name. Lines that already carry the prefix are left alone, so the transform is safe on a body that is partially SSE already.

## See also

- [docs/transforms.md](../../docs/transforms.md) is the full transform reference.
- [examples/transform-replace-strings](../transform-replace-strings/) is the same self-seeding pattern for a different transform.
