# Provider-key failure fallback

*Last modified: 2026-08-21*

An AI provider entry can name an operator-held credential to retry on when the provider refuses that entry's own key with a `401` or `403`, and can opt out of doing so per entry. One tenant's expired key stops being one tenant's outage, without becoming a silent transfer of their bill onto your account.

The example is self-contained: the "provider" is a local sbproxy fixture that accepts exactly one bearer token, so no real API keys are needed.

## Run

Two processes: the fixture, then the gateway.

```bash
make run CONFIG=examples/tenant-key-fallback/upstream-provider.yml &
make run CONFIG=examples/tenant-key-fallback/sb.yml
```

`acme.local` has a dead `api_key` and a `fallback_credential_id: house-openai`. `globex.local` has a dead `api_key` and `on_key_failure: fail_closed`. The fixture accepts only the token seeded as `house-openai`, so both tenants' own keys are refused and only the posture differs.

## Scenario 1: the fallback serves the request

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: acme.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}' \
  | jq -r '.choices[0].message.content'
```

Output:

```text
Served on the operator's credential.
```

Acme's own key was refused first. The gateway retried the same provider on the operator's credential rather than routing elsewhere, so the model, the base URL, and the price the request was quoted at all stayed the same:

```text
WARN sbproxy_core::server::ai_dispatch: AI proxy: provider refused this entry's key, retrying on the operator's fallback credential provider=openai-acme status=401 credential_id=house-openai
```

One event on the typed feed, whose timestamp will differ from this one:

```bash
jq -c 'select(.event_type == "credential_fallback")' tenant-key-fallback-events.ndjson
```

```json
{"event_type":"credential_fallback","hostname":"acme.local","tenant_id":"acme","timestamp":1700000000000,"data":{"id":"house-openai","op":"credential_fallback","outcome":"engaged","provider":"openai-acme","resource":"credential","status":401}}
```

The credential is named; its material is not, and never is.

## Scenario 2: `fail_closed` returns the rejection

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: globex.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
```

Output:

```text
401
```

No fallback, no event, and no spend on the operator's account. That is what you want wherever the tenant's own key *is* the authorization boundary: a tenant billed on their own key has to find out it stopped working, and a tenant you revoked upstream must not keep serving traffic on yours.

## Which credential paid

The admin request log carries `credential_source` on every row, the outbound counterpart to the inbound `key_mode`:

```bash
curl -s -u admin:admin 'http://127.0.0.1:9090/api/requests?limit=5' \
  | jq -c '.[] | {origin, status, credential_source}'
```

```json
{"origin":"globex.local","status":401,"credential_source":"provider_entry"}
{"origin":"acme.local","status":200,"credential_source":"fallback"}
```

`provider_entry` means the entry's own `api_key` paid, `fallback` means the operator's credential did, and `native_caller` means the caller presented their own provider key and it was forwarded verbatim. A tenant whose `fallback` share is climbing is a tenant whose key is dying.

## Rules worth knowing before you turn it on

* **A caller-owned native credential never falls back.** When the request arrives with `inbound_key_mode: native`, the provider refused *the caller's* key. Spending yours would bill you for their authorization failure and would let a caller you revoked upstream keep working. This is not configurable.
* **Key fallback owns `401` and `403`.** A `429`, a `5xx`, or a timeout stays with the provider failover and `resilience.cooldown_policy`; a different key against a rate-limited provider is still rate limited.
* **One retry per request.** Both credentials refused is terminal, and the auth retry does not spend the availability budget.
* **The credential is resolved per request**, so a rotation lands without a config reload, and a record belonging to a different tenant than the request is refused.
* **An entry with no `fallback_credential_id` behaves as `fail_closed`**, which is why `fallback` is a safe default on a config written before this feature existed. Setting both `fail_closed` and a `fallback_credential_id` is refused at config load.

## Related reading

* [docs/multi-tenant.md](../../docs/multi-tenant.md#when-a-tenants-provider-key-is-refused) for the decision path and the tenant-scope rules.
* [docs/key-management.md](../../docs/key-management.md) for seeding, rotating, and vault-referencing the credential record.
* [docs/events.md](../../docs/events.md) for the `credential_fallback` payload.
