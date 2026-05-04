# Storage action

*Last modified: 2026-04-27*

The `storage` action serves files from object storage backends. It is backed by the `object_store` crate and supports S3, GCS, Azure Blob, and the local filesystem. This example uses the `local` backend pointed at `/tmp/sbproxy-static` so it runs without any cloud setup; production configs swap `local` for `s3` / `gcs` / `azure` and add the corresponding credentials. Features include `GET` and `HEAD` with `content-type`, `content-length`, `etag`, and `last-modified`; range requests (`206 Partial Content` with `content-range`); `index_file` fallback for directory paths; `405` for unsupported methods; and `404` for missing objects.

## Run

```bash
mkdir -p /tmp/sbproxy-static
echo '<h1>hello from storage</h1>' > /tmp/sbproxy-static/index.html
echo 'body { background: #eee; }' > /tmp/sbproxy-static/site.css
sbproxy serve -f sb.yml
```

To switch the example to an S3-style backend, set `AWS_REGION`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY`, then change the action to `backend: s3`, `bucket: <name>`, `prefix: <path>`, `region: <region>`.

## Try it

```bash
# Directory request - index_file fallback resolves to index.html.
curl -s -H 'Host: static.localhost' http://127.0.0.1:8080/
# <h1>hello from storage</h1>
```

```bash
# Direct file request - content-type derived from extension.
curl -i -H 'Host: static.localhost' http://127.0.0.1:8080/site.css
# HTTP/1.1 200 OK
# content-type: text/css
# etag: "..."
```

```bash
# Range request - 206 Partial Content with content-range header.
curl -i -H 'Host: static.localhost' \
     -H 'Range: bytes=0-9' \
     http://127.0.0.1:8080/site.css
# HTTP/1.1 206 Partial Content
# content-range: bytes 0-9/...
```

```bash
# Missing object - 404.
curl -i -H 'Host: static.localhost' http://127.0.0.1:8080/missing
# HTTP/1.1 404 Not Found
```

## What this exercises

- `action.type: storage` with `backend: local` (S3, GCS, Azure are drop-in replacements)
- `index_file` fallback for directory-shaped requests
- Range requests returning `206 Partial Content` with `content-range`
- ETag and Last-Modified headers derived from object metadata
- 404 / 405 responses for missing objects and unsupported methods

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
