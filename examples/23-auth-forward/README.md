# Forward auth

*Last modified: 2026-04-27*

Delegates the authentication decision to an external HTTP service. For each inbound request, sbproxy issues a sub-request to the configured URL (`https://httpbin.org/status/200`) using the configured method (`GET`) and a 5,000 ms timeout. If the sub-request returns 200 (`success_status`), the original request is forwarded to the upstream; otherwise it is rejected with the same status the auth service returned. The `headers_to_forward` list copies named headers (`Authorization`, `Cookie`) from the original request into the auth sub-request so the auth service has the context it needs. Swap the URL for `https://httpbin.org/status/401` to see the rejection path.

## Run

```bash
make run CONFIG=examples/23-auth-forward/sb.yml
```

No env vars required. Both the auth service and the upstream are httpbin.

## Try it

Auth service answers 200, request is forwarded:

```bash
$ curl -i -H 'Host: fwd.local' -H 'Authorization: Bearer demo' \
       http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json

{"args":{},"headers":{"Authorization":"Bearer demo","Host":"httpbin.org",...},"url":"https://httpbin.org/get"}
```

Inspect the cost of the auth subrequest in latency:

```bash
$ time curl -s -o /dev/null -H 'Host: fwd.local' -H 'Authorization: Bearer demo' \
       http://127.0.0.1:8080/get

real    0m0.480s
```

The total includes both the auth subrequest to `httpbin.org/status/200` and the forwarded request to `httpbin.org/get`.

To see the rejection path, change `url` in the config to `https://httpbin.org/status/401` and rerun:

```bash
$ curl -i -H 'Host: fwd.local' http://127.0.0.1:8080/get
HTTP/1.1 401 Unauthorized
content-type: text/plain

unauthorized
```

## What this exercises

- `authentication.type: forward_auth` - delegate the decision to an external endpoint
- `url`, `method`, `timeout` - subrequest contract
- `success_status` - status code that means "authenticated"
- `headers_to_forward` - which inbound headers to relay to the auth service

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
