# Edge feature flags, one rule at a time

![Edge feature flags, one rule at a time](../../docs/assets/feature-flags.gif)

The runnable half of [docs/feature-flags.md](../../docs/feature-flags.md). One flag, four rules, and a CEL expression policy that gates a route on it. The bucketing key is the `X-User` header, so every branch of the rule grammar is reachable from a curl command.

The buckets are not guesses. `hash(flag_name | key) % 100` is FNV-1a 64-bit, which means the bucket for a given pair is fixed: same value on every replica, same value after a restart. The keys in `sb.yml` were picked for the bucket they land in, and the comments record it.

The flagged route is served by the proxy itself, so there is nothing to install and no upstream to run.

## Run

```bash
make run CONFIG=examples/feature-flags/sb.yml
```

Or under compose, which is what the smoke runner uses:

```bash
cd examples/feature-flags
docker compose up -d --wait
```

## Test

`alice@acme.io` buckets at 76, well outside the 25% rollout, and is on the allow list:

```bash
curl -i -H 'Host: flags.local' -H 'X-User: alice@acme.io' http://127.0.0.1:8080/checkout
```

```
HTTP/1.1 200 OK
content-type: application/json
content-length: 97
Date: Sun, 02 Aug 2026 05:08:17 GMT
Connection: keep-alive

{"checkout":"new","note":"flag_enabled(\"new-checkout\", X-User) evaluated true for this caller"}  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
```

`carol@acme.io` buckets at 17, inside the rollout, and is on the block list. The block list wins:

```bash
curl -i -H 'Host: flags.local' -H 'X-User: carol@acme.io' http://127.0.0.1:8080/checkout
```

```
HTTP/1.1 403 Forbidden
content-type: application/json
content-length: 54
Date: Sun, 02 Aug 2026 05:08:17 GMT
Connection: keep-alive

{"error":"new-checkout is off for this bucketing key"}  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
```

`mallory@acme.io` is on both lists, which is the collision the rule order exists to settle. Block still wins, so a config typo defaults to safe:

```bash
curl -i -H 'Host: flags.local' -H 'X-User: mallory@acme.io' http://127.0.0.1:8080/checkout
```

```
HTTP/1.1 403 Forbidden
content-type: application/json
content-length: 54
Date: Sun, 02 Aug 2026 05:08:17 GMT
Connection: keep-alive

{"error":"new-checkout is off for this bucketing key"}  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
```

`ken@acme.io` is on no list. Bucket 22 is under the cutoff, so the rollout decides, and it decides the same way every time:

```bash
for i in 1 2 3; do curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Host: flags.local' -H 'X-User: ken@acme.io' http://127.0.0.1:8080/checkout; done
```

```
200
200
200
```

`ivan@acme.io` buckets at 28, over the cutoff, so `default: false` decides:

```bash
curl -i -H 'Host: flags.local' -H 'X-User: ivan@acme.io' http://127.0.0.1:8080/checkout
```

```
HTTP/1.1 403 Forbidden
content-type: application/json
content-length: 54
Date: Sun, 02 Aug 2026 05:08:17 GMT
Connection: keep-alive

{"error":"new-checkout is off for this bucketing key"}  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
```

Send no bucketing key and the expression cannot prove the request is allowed, so it is denied:

```bash
curl -i -H 'Host: flags.local' http://127.0.0.1:8080/checkout
```

```
HTTP/1.1 403 Forbidden
content-type: application/json
content-length: 54
Date: Sun, 02 Aug 2026 05:08:17 GMT
Connection: keep-alive

{"error":"new-checkout is off for this bucketing key"}  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
```

Run the checked smoke cases from the repository root with:

```bash
bash scripts/examples-smoke.sh examples/feature-flags
```

## Pick your own bucket

The bucket for any pair is one function, so you can work out which side of a rollout a key lands on before you ship it:

```bash
python3 -c 'P=0x100000001b3; M=(1<<64)-1; f=lambda s: __import__("functools").reduce(lambda h,b: ((h^b)*P)&M, s, 0xcbf29ce484222325); [print(k, f(b"new-checkout|"+k.encode())%100) for k in ["alice@acme.io","carol@acme.io","mallory@acme.io","ken@acme.io","ivan@acme.io"]]'
```

```
alice@acme.io 76
carol@acme.io 17
mallory@acme.io 6
ken@acme.io 22
ivan@acme.io 28
```

## Clean up

```bash
docker compose down -v
```

## Read more

- [docs/feature-flags.md](../../docs/feature-flags.md) - the rule grammar, the hot-reload contract, and the CEL helper
- [docs/scripting.md](../../docs/scripting.md#3-cel-expressions) - the rest of the CEL surface
