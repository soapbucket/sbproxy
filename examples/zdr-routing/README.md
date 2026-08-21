# AI gateway: ZDR-only provider routing

*Last modified: 2026-08-20*

An AI gateway origin that only routes to providers whose data-handling posture is zero data retention. The `data_posture: require_zdr: true` block filters the provider candidate set before the routing strategy runs, so an ineligible provider is not a fallback, it is not a candidate.

Two origins, because there are two ways the constraint arrives:

- `ai.local` sets the posture on the origin. The `openai` entry qualifies because this deployment declares a signed ZDR agreement on it (`data_posture.zdr: true`); the `mistral` entry does not, because the shipped catalog records no zero-data-retention commitment for it.
- `ai-any.local` sets nothing and routes to `mistral` normally. A caller that sends `x-sbproxy-require-zdr: true` tightens that one request, finds nothing eligible, and is refused with the constraint and the excluded provider named.

The catalog's own `zdr_available` flag is not enough on its own. OpenAI, Anthropic, Azure OpenAI, and Vertex all sell a zero-data-retention agreement and all retain by default; treating "the vendor offers one" as "we have one" would route a `require_zdr` request straight to a stock retaining account. Holding the agreement is your declaration, which is what the `data_posture:` block on the `openai` entry is.

## Run

```bash
export OPENAI_API_KEY=sk-...
export MISTRAL_API_KEY=...
make run CONFIG=examples/zdr-routing/sb.yml
```

Only `OPENAI_API_KEY` is exercised by the served path; the Mistral entry exists to be excluded. Everything captured below runs without either key being real, because the interesting paths all resolve before any upstream is dialed.

## Who is eligible, right now

The admin server reports each provider's declared posture next to its wire format and auth header, and the effective eligible set the filter computes from it:

```console
$ curl -s -u admin:changeme http://127.0.0.1:9090/admin/ai-data-posture | jq '.origins["ai.local"]'
{
  "constraint": "require_zdr",
  "eligible_providers": [
    "openai"
  ],
  "excluded_providers": [
    "mistral"
  ],
  "providers": [
    {
      "auth_header": "Authorization",
      "catalog": {
        "data_region": null,
        "retains_data": true,
        "zdr_available": true
      },
      "effective": {
        "retains_data": false,
        "zdr": true
      },
      "eligible": true,
      "enabled": true,
      "format": "openai",
      "name": "openai",
      "provider_type": "openai"
    },
    {
      "auth_header": "Authorization",
      "catalog": {
        "data_region": null,
        "retains_data": true,
        "zdr_available": false
      },
      "effective": {
        "retains_data": true,
        "zdr": false
      },
      "eligible": false,
      "enabled": true,
      "format": "openai",
      "name": "mistral",
      "provider_type": "mistral"
    }
  ],
  "requirement": {
    "allow_data_collection": true,
    "require_zdr": true
  }
}
```

`catalog` is what the vendor's published terms say about a stock account. `effective` is what this deployment holds after the operator declaration, and is the thing the filter evaluates. The two differing on the `openai` row is the whole point: the catalog says OpenAI retains by default, and the local declaration says this account does not.

A chat request on `ai.local` is then served by `openai` and never reaches `mistral`. That path needs your own key, so it is not captured here:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "What is 2+2?"}]}'
```

## The refusal

On an origin where nothing qualifies, the request fails closed. No upstream is contacted:

```console
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai-any.local' \
    -H 'x-sbproxy-require-zdr: true' \
    -H 'Content-Type: application/json' \
    -d '{"model": "mistral-small-latest", "messages": [{"role": "user", "content": "hi"}]}'
HTTP/1.1 403 Forbidden
content-type: application/json
content-length: 217
Date: Fri, 21 Aug 2026 01:59:36 GMT
Connection: keep-alive

{"error":{"message":"no eligible provider under the data-handling posture constraint (require_zdr); excluded by posture: mistral","request_id":"01a0220b87a57f328f0a89069877266d","type":"no_posture_eligible_provider"}}
```

The refusal is counted and logged, so a fleet that has quietly started denying traffic is visible without reading response bodies:

```console
$ curl -s -u admin:changeme http://127.0.0.1:9090/metrics | grep data_posture
# HELP sbproxy_ai_data_posture_filter_total AI requests whose provider candidate set the data-posture constraint narrowed or refused
# TYPE sbproxy_ai_data_posture_filter_total counter
sbproxy_ai_data_posture_filter_total{constraint="require_zdr",outcome="filtered",tenant="__default__"} 1
sbproxy_ai_data_posture_filter_total{constraint="require_zdr",outcome="refused",tenant="__default__"} 1
```

```
WARN sbproxy_core::server::ai_dispatch: AI proxy: no provider satisfies the data-posture constraint; failing closed
  event="ai.data_posture.refusal" constraint=require_zdr excluded=mistral excluded_count=1
```

## A posture nothing can satisfy is a config error

The runtime refusal above exists for a constraint that arrives per request, which no config check can see coming. An origin whose *own* block excludes every provider it configures is a different thing: a blackholed origin that would boot green and then deny everything it is ever sent. That is refused at load, with the key named. Delete the `data_posture:` override from the `openai` entry and the config stops compiling:

```console
$ sbproxy validate examples/zdr-routing/sb.yml
validate: config 'examples/zdr-routing/sb.yml' compiled, but a module failed to construct (this would fail at boot):
ai `data_posture` (require_zdr) excludes every configured provider (openai, mistral), so this origin could never route a request. Declare the posture you hold on a provider entry (`data_posture.zdr: true` for a signed zero-data-retention agreement, or `data_posture.retains_data: false`), add a provider that satisfies the constraint, or relax the block. The provider catalog records what each vendor's published terms say about a stock account, not what your own agreement says. To constrain a single request instead of the whole origin, send `x-sbproxy-require-zdr: true` or `x-sbproxy-disallow-data-collection: true`.
```

## What this exercises

- `data_posture` with `require_zdr: true` on an `ai_proxy` action - a hard candidate-set filter ahead of every routing strategy, fallback order, cascade tier, race fan-out, and shadow dispatch
- Provider-level `data_posture.zdr: true` - the operator's declaration that a specific deployment operates under a ZDR agreement, which is what makes a retaining vendor eligible
- `x-sbproxy-require-zdr` / `x-sbproxy-disallow-data-collection` - the per-request spelling of the same constraint, which can tighten an origin but never relax it
- Fail-closed refusal naming the constraint and the excluded providers, with no silent reroute to a non-compliant provider
- `GET /admin/ai-data-posture` - the declared posture and the live effective eligible set
- Config-load refusal of a posture no configured provider can satisfy

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - provider data posture section
- [docs/providers.md](../../docs/providers.md) - the catalog's declared postures per provider
- [docs/admin-api-reference.md](../../docs/admin-api-reference.md) - `GET /admin/ai-data-posture`
- [examples/ai-multi-provider/](../ai-multi-provider/) - the unconstrained fallback-chain baseline
