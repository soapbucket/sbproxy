# Exposed credentials

*Last modified: 2026-04-27*

When a request carries `Authorization: Basic <base64>` whose password matches the configured exposure list, the proxy stamps the upstream request with an `exposed-credential-check` header (`action: tag`, the default) or rejects the request outright (`action: block`). The OSS provider is `static`: operators ship a list of leaked passwords (or SHA-1 hex hashes) inline in YAML or via `sha1_file`. Hash-only lists keep plaintext passwords out of config, log files, and process memory dumps. The HIBP k-anonymity adapter ships in the enterprise build.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# The canonical "password" is on every leak list. The upstream sees the
# tag header that the proxy stamped.
curl -i -u alice:password -H 'Host: api.local' http://127.0.0.1:8080/get
# HTTP/1.1 200 OK
# (upstream view will include exposed-credential-check: leaked-password)

curl -s -u alice:password -H 'Host: api.local' http://127.0.0.1:8080/get | jq '.headers["Exposed-Credential-Check"]'
# "leaked-password"

# Hash-only entry: SHA-1("hunter2") matches.
curl -s -u alice:hunter2 -H 'Host: api.local' http://127.0.0.1:8080/get | jq '.headers["Exposed-Credential-Check"]'
# "leaked-password"

# Clean credential: no tag header.
curl -s -u alice:'8sQ%2nT9.zR1@p#X' -H 'Host: api.local' http://127.0.0.1:8080/get | jq '.headers["Exposed-Credential-Check"] // "not present"'
# "not present"

# To switch to hard-block, set action: block and the same request becomes:
# HTTP/1.1 403 Forbidden
# {"error":"forbidden","reason":"exposed credential"}
```

## What this exercises

- `policies[].type: exposed_credentials`
- `action: tag` vs `action: block`
- Inline `passwords` and `sha1_hashes` lists
- Detection from `Authorization: Basic` only (other auth schemes pass through)

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
