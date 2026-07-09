# API key authentication

*Last modified: 2026-07-09*

![API key authentication](../../docs/assets/auth-api-key.gif)

Enforces an API key check before any upstream call. The `api_key` authentication provider compares the value of the configured header (`X-Api-Key`) against the static allowlist `["dev-key-1", "dev-key-2"]`. Requests with a missing or unrecognised key are rejected with 401 inside the proxy; matching requests are forwarded to `test.sbproxy.dev` unchanged. This is the simplest authentication mode in SBproxy and is well suited to internal APIs, demos, and key-per-tenant access patterns.

## Run

```bash
make run CONFIG=examples/auth-api-key/sb.yml
```

No env vars required.

## Try it

Missing key, request is rejected before the upstream is contacted:

```bash
$ curl -i -H 'Host: api.local' http://127.0.0.1:8080/get
HTTP/1.1 401 Unauthorized
content-type: text/plain

unauthorized
```

Valid key, request is forwarded:

```bash
$ curl -i -H 'Host: api.local' -H 'X-Api-Key: dev-key-1' \
       http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json

{"method":"GET","url":"/get","headers":{"host":"test.sbproxy.dev","x-api-key":"dev-key-1",...},"query":{},"timestamp":"2026-07-09T19:29:58.060Z"}
```

Wrong key, also rejected:

```bash
$ curl -i -H 'Host: api.local' -H 'X-Api-Key: not-on-the-list' \
       http://127.0.0.1:8080/get
HTTP/1.1 401 Unauthorized
content-type: text/plain

unauthorized
```

The second valid key works the same way:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' \
       -H 'Host: api.local' -H 'X-Api-Key: dev-key-2' \
       http://127.0.0.1:8080/get
200
```

## What this exercises

- `authentication.type: api_key` - static allowlist of API keys
- `header_name` - name of the request header the key is read from
- `api_keys` - the canonical field name for the allowed key list
- Pre-upstream rejection - 401s never reach the upstream

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
