# HSTS

*Last modified: 2026-04-27*

The `hsts` block on `secure.local` injects a `Strict-Transport-Security` header on every response. `max_age: 31536000` is one year, `include_subdomains: true` extends the policy to every subdomain, and `preload: true` opts the host into the browser preload list (production-grade only after submission to hstspreload.org). Browsers honour HSTS only over HTTPS, but the header is emitted regardless of scheme so you can verify it on plain HTTP locally.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Expect the HSTS header on every response.
curl -sv -H 'Host: secure.local' http://127.0.0.1:8080/get 2>&1 | grep -i 'strict-transport-security'
# < strict-transport-security: max-age=31536000; includeSubDomains; preload

# Drop preload by removing it from the config to land at:
# < strict-transport-security: max-age=31536000; includeSubDomains

# The header is independent of path or method.
curl -sX POST -H 'Host: secure.local' http://127.0.0.1:8080/post -d '' -o /dev/null -D - | grep -i strict-transport-security
# strict-transport-security: max-age=31536000; includeSubDomains; preload
```

## What this exercises

- `hsts.max_age`
- `hsts.include_subdomains`
- `hsts.preload`
- Strict-Transport-Security header injection on every response

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
