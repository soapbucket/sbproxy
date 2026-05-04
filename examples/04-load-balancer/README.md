# Load balancer (round-robin)

*Last modified: 2026-04-27*

The `load_balancer` action dispatches each request across a pool of upstream targets using the `round_robin` algorithm. Two targets are configured with equal weights. Both point at `httpbin.org` for demonstration, so per-target traffic distribution is not visible from the response body, but the example confirms the pool dispatches successfully and serves 200s on every iteration. In production you would point each target at a distinct replica address.

## Run

```bash
make run CONFIG=examples/04-load-balancer/sb.yml
```

No env vars required.

## Try it

```bash
$ curl -i -H 'Host: api.local' http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json

{"args":{},"headers":{"Host":"httpbin.org",...},"url":"https://httpbin.org/get"}
```

Run a small batch and confirm every request succeeds:

```bash
$ for i in $(seq 1 6); do
    curl -s -o /dev/null -w '%{http_code}\n' \
      -H 'Host: api.local' http://127.0.0.1:8080/get
  done
200
200
200
200
200
200
```

With distinct upstreams, requests 1, 3, 5 would land on target 0 and requests 2, 4, 6 on target 1.

## What this exercises

- `load_balancer` action - target pool with weighted entries
- `algorithm: round_robin` - alternates targets in a fixed order
- `weight` - relative selection weight (equal in this example)

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/routing-strategies.md](../../docs/routing-strategies.md) - load balancer algorithms
