# Temporary budget overrides

*Last modified: 2026-09-05*

A governed key carries a base budget. This example grants a temporary raise
on top of it through the admin API, watches the raised cap admit a request
the base cap refused, and then watches the base cap come back on its own
when the raise expires, with no config edit and nothing to revert.

The mechanic mirrors LiteLLM's `temp_budget_increase`: the raise is a
separate field on the key record, so the durable limit is never edited and
nothing has to be put back. sbproxy stores the raise on the dynamic key
record with its expiry and the grantor's identity, persists it in the key
store across restarts, and evaluates the expiry lazily wherever the budget
is read. An expired raise is simply ignored, whether the process restarted
in the meantime or not.

## The pieces

`sb.yml` seeds one governed key, `seed0001`, whose base budget is 200 total
tokens (`max_budget_tokens: 200`). Small on purpose: the fixture provider
in `fixture.py` bills exactly the token count named in the message body
(`spend=250` bills 250 prompt tokens), so one request exhausts the cap
and the whole walk fits in a minute. A grant takes effect on the next
request because every admin key mutation invalidates the policy cache, and
expiry needs no invalidation at all: the expiry instant rides on the
record and is compared against the clock wherever the budget is read.

The override itself is runtime state, so nothing about it appears in the
config. You will not find a `budget_override:` key in any YAML: grants
happen through `POST /admin/keys/{id}/budget-override` and die by their own
expiry.

## Run it

```bash
export SBPROXY_KEY_PEPPER=a-long-random-server-pepper
export SBPROXY_KEY_MASTER=a-long-random-master-key
python3 examples/temp-budget-override/fixture.py &
make run CONFIG=examples/temp-budget-override/sb.yml
```

## Spend the base budget

The seeded key's bearer token is `sk-seed0001-demo-secret-please-rotate`.
The first request bills 250 tokens. It is admitted, because admission
compares the spend already on the books against the cap and the books are
empty; its settlement then puts the key at 250 of 200:

<!-- CAPTURE: curl -s http://127.0.0.1:8080/v1/chat/completions -H 'Host: ai.local' -H 'Authorization: Bearer sk-seed0001-demo-secret-please-rotate' -H 'Content-Type: application/json' -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"spend=250"}]}' | jq '{model, usage}' -->

```text
{
  "model": "gpt-4o-mini",
  "usage": {
    "prompt_tokens": 250,
    "completion_tokens": 0,
    "total_tokens": 250
  }
}
```

The second identical request finds 250 already spent against a cap of
200, so the budget gate refuses it before anything is dispatched
upstream:

<!-- CAPTURE: curl -is http://127.0.0.1:8080/v1/chat/completions -H 'Host: ai.local' -H 'Authorization: Bearer sk-seed0001-demo-secret-please-rotate' -H 'Content-Type: application/json' -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"spend=250"}]}' | sed -n '1p;/^{/p' -->

```text
HTTP/1.1 402 Payment Required
{"error":{"type":"budget_exceeded","scope":"api_key","message":"token limit exceeded: 250 >= 200"}}
```

## Grant a raise

Launch day. Grant the key 100,000 extra tokens for 60 seconds, with a
reason that lands in the audit trail alongside the grantor:

<!-- CAPTURE: curl -s -u admin:admin -X POST http://127.0.0.1:9090/admin/keys/seed0001/budget-override -H 'Content-Type: application/json' -d '{"max_tokens_increase":100000,"ttl_secs":60,"reason":"launch-day spike"}' | jq '.key | {budget, budget_override, effective_budget}' -->

```text
{
  "budget": {
    "max_tokens": 200
  },
  "budget_override": {
    "max_tokens_increase": 100000,
    "expires_at": "<RFC3339>",
    "granted_by": "admin",
    "granted_at": "<RFC3339>",
    "reason": "launch-day spike"
  },
  "effective_budget": {
    "max_tokens": 100200
  }
}
```

`budget` is the untouched base. `budget_override` carries the raise, who
granted it, and when it ends. `effective_budget` is what the enforcement
path compares spend against right now: base plus raise.

The refused request from a moment ago now clears the raised cap:

<!-- CAPTURE: curl -s http://127.0.0.1:8080/v1/chat/completions -H 'Host: ai.local' -H 'Authorization: Bearer sk-seed0001-demo-secret-please-rotate' -H 'Content-Type: application/json' -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"spend=250"}]}' | jq '{model, usage}' -->

```text
{
  "model": "gpt-4o-mini",
  "usage": {
    "prompt_tokens": 250,
    "completion_tokens": 0,
    "total_tokens": 250
  }
}
```

Any admin read shows the same three fields while the raise is live, and the
console's Keys page renders them as a "raised" badge with a countdown and a
Clear raise action:

<!-- CAPTURE: curl -s -u admin:admin http://127.0.0.1:9090/admin/keys/seed0001 | jq '.key | {budget, budget_override, effective_budget}' -->

```text
{
  "budget": {
    "max_tokens": 200
  },
  "budget_override": {
    "max_tokens_increase": 100000,
    "expires_at": "<RFC3339>",
    "granted_by": "admin",
    "granted_at": "<RFC3339>",
    "reason": "launch-day spike"
  },
  "effective_budget": {
    "max_tokens": 100200
  }
}
```

The grant is in the key audit trail, named after the operator who made it
(`admin` here, because that is who authenticated to the admin API):

<!-- CAPTURE: curl -s -u admin:admin 'http://127.0.0.1:9090/api/audit/events?channel=key&kind=budget_override_grant&limit=1' | jq . -->

```text
[
  {
    "timestamp": "<RFC3339>",
    "channel": "key",
    "kind": "budget_override_grant",
    "actor": "admin",
    "api_key_id": "seed0001",
    "detail": "key: {\"budget_override\":null} -> {\"budget_override\":{\"max_tokens_increase\":100000,\"max_cost_usd_increase\":null,\"expires_at\":\"<RFC3339>\",\"granted_by\":\"admin\",\"reason\":\"launch-day spike\"}}"
  }
]
```

## Let it expire

Wait out the 60-second TTL, then send the same request. The raise is
gone, so the 500 tokens on the books (250 before the grant, 250 under it)
are measured against the base cap again, and nobody had to remember to
revert anything:

<!-- CAPTURE: sleep 62; curl -is http://127.0.0.1:8080/v1/chat/completions -H 'Host: ai.local' -H 'Authorization: Bearer sk-seed0001-demo-secret-please-rotate' -H 'Content-Type: application/json' -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"spend=250"}]}' | sed -n '1p;/^{/p' -->

```text
HTTP/1.1 402 Payment Required
{"error":{"type":"budget_exceeded","scope":"api_key","message":"token limit exceeded: 500 >= 200"}}
```

An admin read now shows the base budget alone. The read is also what
retires the lapsed grant from the record and writes the expiry into the
audit trail, so the trail holds both ends of the raise's life:

<!-- CAPTURE: curl -s -u admin:admin http://127.0.0.1:9090/admin/keys/seed0001 | jq '.key | {budget, budget_override, effective_budget}' -->

```text
{
  "budget": {
    "max_tokens": 200
  },
  "budget_override": null,
  "effective_budget": {
    "max_tokens": 200
  }
}
```

<!-- CAPTURE: curl -s -u admin:admin 'http://127.0.0.1:9090/api/audit/events?channel=key&kind=budget_override_expire&limit=1' | jq . -->

```text
[
  {
    "timestamp": "<RFC3339>",
    "channel": "key",
    "kind": "budget_override_expire",
    "api_key_id": "seed0001",
    "detail": "key: {\"budget_override\":{\"max_tokens_increase\":100000,\"max_cost_usd_increase\":null,\"expires_at\":\"<RFC3339>\",\"granted_by\":\"admin\",\"reason\":\"launch-day spike\"}} -> {\"budget_override\":null}"
  }
]
```

To end a raise early instead of waiting, `DELETE
/admin/keys/seed0001/budget-override` restores the base cap immediately.

See `docs/ai-gateway.md` (the budgets section) for the override lifecycle
and `docs/key-management.md` for the admin API reference.
