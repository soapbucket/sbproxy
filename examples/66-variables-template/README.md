# Variables and templates

*Last modified: 2026-04-27*

The `variables` block declares static, per-origin key-value pairs that the template engine exposes as `{{ variables.<name> }}`. Environment variables surface as `{{ env.<NAME> }}`. This example wires both into request headers (`X-Api-Version`, `X-Region-Label`, `X-Region-Env`, `X-Beta-Api`) so `httpbin.org/headers` echoes them back, demonstrating that interpolation happens at request time. Nested variables (e.g. `feature_flags.beta_api`) are addressable with dot notation.

## Run

```bash
# Export the env var that the {{ env.* }} placeholder reads at config-load.
export DEPLOY_REGION=us-east-1
sb run -c sb.yml
```

## Try it

```bash
# httpbin echoes back the request headers, so you can see the templated values
# the proxy injected.
curl -s -H 'Host: api.local' http://127.0.0.1:8080/headers | jq .headers
# {
#   "Host": "httpbin.org",
#   "X-Api-Version": "v2",
#   "X-Region-Label": "edge",
#   "X-Region-Env": "us-east-1",
#   "X-Beta-Api": "false",
#   ...
# }

# Change DEPLOY_REGION and restart to see {{ env.DEPLOY_REGION }} pick up the new value.
DEPLOY_REGION=eu-west-1 sb run -c sb.yml
```

## What this exercises

- `variables` block on an origin (scalars, nested maps)
- `{{ variables.* }}` interpolation in `request_modifiers`
- `{{ env.* }}` interpolation from process environment
- Dot notation for nested variable access (`feature_flags.beta_api`)

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
