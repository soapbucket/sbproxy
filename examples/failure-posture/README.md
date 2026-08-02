# A failure posture, degrading for real

The runnable half of the posture table in [docs/degradation.md](../../docs/degradation.md). The virtual key store points at a Redis that is deliberately not running, so every key lookup fails the way it would during a real outage, and `key_management.failure_posture` decides what happens to the request.

The config ships `degraded`. The interesting part is what `degraded` does not do: it does not admit the request. It hands the request to the auth the origin already had, and records that the virtual key's policy, budget, and attribution were lost. A caller who cannot satisfy that auth still gets a 401.

Nothing needs installing. The absent Redis is the outage.

## Run

```bash
make run CONFIG=examples/failure-posture/sb.yml
```

Or under compose, which is what the smoke runner uses:

```bash
cd examples/failure-posture
docker compose up -d --wait
```

## Test

A token the origin's own bearer auth knows. The store lookup failed, the posture admitted, and the origin's auth took it from there:

```bash
curl -i -H 'Host: keys.local' \
     -H 'Authorization: Bearer sbp_a1b2c3d4e5f60718_9f3c1d2e4b5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d' \
     http://127.0.0.1:8080/
```

<!-- CAPTURE: curl -i -H 'Host: keys.local' -H 'Authorization: Bearer sbp_a1b2c3d4e5f60718_9f3c1d2e4b5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d' http://127.0.0.1:8080/ -->

The same shape, the same dead store, the same posture, a token the origin does not know:

```bash
curl -i -H 'Host: keys.local' \
     -H 'Authorization: Bearer sbp_0f1e2d3c4b5a6978_1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809' \
     http://127.0.0.1:8080/
```

<!-- CAPTURE: curl -i -H 'Host: keys.local' -H 'Authorization: Bearer sbp_0f1e2d3c4b5a6978_1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809' http://127.0.0.1:8080/ -->

Every admitted request leaves the record that separates `degraded` from `open`:

<!-- CAPTURE: cd examples/failure-posture && docker compose logs sbproxy 2>&1 | grep -m 2 'failure_posture' -->

Run the checked smoke cases from the repository root with:

```bash
bash scripts/examples-smoke.sh examples/failure-posture
```

## Try the default posture

`closed` is the default and the safest answer: it refuses rather than let a governed key go ungoverned. Change one line in `sb.yml`:

```yaml
    failure_posture: closed
```

Restart and send the first request again. It becomes a `503 key store unavailable`, and so does the second. Neither request reaches the origin's auth, because a posture of `closed` decides before that.

`open` admits exactly what `degraded` admits and writes nothing down. That is the reason to prefer `degraded`.

## Clean up

```bash
docker compose down -v
```

## Read more

- [docs/degradation.md](../../docs/degradation.md) - the posture vocabulary and the full dependency matrix
- [docs/key-management.md](../../docs/key-management.md) - the key plane this posture guards
