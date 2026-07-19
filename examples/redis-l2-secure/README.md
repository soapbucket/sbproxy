# Secure Redis L2 development setup

*Last modified: 2026-07-18*

This example runs Redis with a TLS-only listener, required client certificates,
password authentication, and logical database 7. SBproxy verifies the generated
CA, presents its client identity, authenticates as the Redis `default` user, and
uses the service for shared L2 cache state.

> Development only. The generated CA, leaf certificates, private keys, and
> `development-only-password` are short-lived local fixtures. Do not copy them
> into a production deployment or commit anything under `certs/`.

Run every command below from the repository root. You need OpenSSL, Docker with
Compose, curl, and the Rust toolchain.

## Generate the local PKI

Export the fixture password first. The certificate script hashes it into an
ignored Redis ACL file and defaults to the same value when the variable is
unset.

```bash
export REDIS_PASSWORD='development-only-password'
./examples/redis-l2-secure/generate-certs.sh
```

The script creates a development CA, a localhost Redis server identity, an
SBproxy client identity, a second untrusted CA for the negative test, and the
ACL under `examples/redis-l2-secure/certs/`. The directory is ignored by Git.

## Start TLS-only Redis

```bash
REDIS_PASSWORD='development-only-password' \
  docker compose -f examples/redis-l2-secure/docker-compose.yml up -d --wait redis
```

The container publishes its TLS port on `127.0.0.1:6380`. Plaintext Redis is
disabled with `port 0`, and `tls-auth-clients yes` rejects clients that do not
present a certificate signed by the development CA.

Confirm that the authenticated mTLS connection works without placing the
password on the `redis-cli` command line:

```bash
REDIS_PASSWORD='development-only-password' \
  docker compose -f examples/redis-l2-secure/docker-compose.yml exec -T redis \
  sh -ec 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli --tls \
    --cacert /source-certs/ca.pem \
    --cert /source-certs/client.pem \
    --key /source-certs/client.key \
    -h localhost -p 6379 ping'
```

The command prints `PONG`.

## Validate and start SBproxy

Validation reads and checks the DSN and PEM files but does not open a network
connection:

```bash
REDIS_PASSWORD='development-only-password' \
  cargo run -q -p sbproxy -- validate examples/redis-l2-secure/sb.yml
```

Start SBproxy in the first terminal:

```bash
REDIS_PASSWORD='development-only-password' \
  cargo run -q -p sbproxy -- serve -f examples/redis-l2-secure/sb.yml
```

## Prove cache storage in database 7

In a second terminal, send the same cacheable request twice. The first request
loads the response and writes shared state. The second response carries the
cache hit header.

```bash
curl -fsS -D /tmp/sbproxy-redis-l2-first.headers -o /dev/null \
  -H 'Host: redis-l2.local' \
  'http://127.0.0.1:8080/get?redis_l2_secure=cache-proof'

curl -fsS -D /tmp/sbproxy-redis-l2-second.headers -o /dev/null \
  -H 'Host: redis-l2.local' \
  'http://127.0.0.1:8080/get?redis_l2_secure=cache-proof'

grep -i '^x-sbproxy-cache: HIT' /tmp/sbproxy-redis-l2-second.headers
```

Check key counts without printing cache keys or values:

```bash
REDIS_PASSWORD='development-only-password' \
  docker compose -f examples/redis-l2-secure/docker-compose.yml exec -T redis \
  sh -ec '
    export REDISCLI_AUTH="$REDIS_PASSWORD"
    printf "database 7 keys: "
    redis-cli --tls --cacert /source-certs/ca.pem \
      --cert /source-certs/client.pem --key /source-certs/client.key \
      -h localhost -p 6379 -n 7 DBSIZE
    printf "database 0 keys: "
    redis-cli --tls --cacert /source-certs/ca.pem \
      --cert /source-certs/client.pem --key /source-certs/client.key \
      -h localhost -p 6379 -n 0 DBSIZE
  '
```

Database 7 has at least one key after the cache write. Database 0 remains at
zero in a fresh example.

## Prove trust and authentication failures

Stop the running SBproxy process with `Ctrl-C` before each probe. Configuration
still validates because network establishment is intentionally lazy. The first
cache operation triggers the connection failure and falls back to process-local
cache behavior.

Start with the untrusted CA:

```bash
REDIS_PASSWORD='development-only-password' \
REDIS_CA_FILE='examples/redis-l2-secure/certs/wrong-ca.pem' \
  cargo run -q -p sbproxy -- serve -f examples/redis-l2-secure/sb.yml
```

From the second terminal, trigger a new cache operation:

```bash
curl -fsS -o /dev/null -H 'Host: redis-l2.local' \
  'http://127.0.0.1:8080/get?redis_l2_secure=wrong-ca'
```

The first Redis failure produces one content-free warning with `reason="tls"`.
It contains no DSN, endpoint, database, key, value, certificate path, username,
or password.

Stop that process, then start with the wrong password:

```bash
REDIS_PASSWORD='wrong-development-password' \
  cargo run -q -p sbproxy -- serve -f examples/redis-l2-secure/sb.yml
```

Trigger another new cache operation:

```bash
curl -fsS -o /dev/null -H 'Host: redis-l2.local' \
  'http://127.0.0.1:8080/get?redis_l2_secure=wrong-password'
```

The transition warning uses `reason="auth"` and does not include the server's
response text. Repeated failures stay at `DEBUG` until a successful operation
moves the store back to healthy and emits one content-free `INFO` recovery
event.

## Query the Redis L2 metrics

After either negative probe, query all three metric families from the local
metrics endpoint:

```bash
curl -fsS http://127.0.0.1:8080/metrics |
  grep -E '^(# (HELP|TYPE) sbproxy_redis_kv_|sbproxy_redis_kv_)'
```

The output is limited to these families and labels:

| Metric | Labels and allowed values |
|---|---|
| `sbproxy_redis_kv_connections_total` | `result`: `success`, `error` |
| `sbproxy_redis_kv_operation_duration_seconds` | `operation`: `get`, `set`, `set_ttl`, `delete`, `increment`, `lock`, `unlock`, `scan` |
| `sbproxy_redis_kv_operation_errors_total` | `operation` above; `reason`: `pool_timeout`, `connect_timeout`, `command_timeout`, `tls`, `auth`, `transport`, `server`, `protocol` |

The labels never contain an endpoint, tenant, application key, username,
password, or database number. A family appears after the process first records
the corresponding event.

## Stop the example

Stop SBproxy with `Ctrl-C`, then remove the Redis container:

```bash
REDIS_PASSWORD='development-only-password' \
  docker compose -f examples/redis-l2-secure/docker-compose.yml down
```

The generated files remain under the ignored `certs/` directory so you can run
the example again. Re-run `generate-certs.sh` whenever you want fresh fixtures.

## See also

- [Configuration reference](../../docs/configuration.md#redis-integration)
- [Dependency degradation](../../docs/degradation.md#redis-l2-cache-and-cross-replica-state)
- [Troubleshooting](../../docs/troubleshooting.md#redis-shared-state-is-degraded)
- [AI context compression](../../docs/ai-context-compression.md#redis-state)
