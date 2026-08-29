# AI structured-output enforcement

*Last modified: 2026-08-22*

Demonstrates the `ai_schema` transform: validating an AI provider's response body against an operator-supplied schema, with an `on_failure` mode independent of the transform pipeline's shared `failure_posture` axis. `ai_schema` exists alongside `json_schema` ([`transform-json-schema`](../transform-json-schema/)) for the AI-specific case where an operator wants to calibrate a new schema in `warn` mode against live traffic before promoting it to `block`.

Both origins on `127.0.0.1:8080` serve the same body, which is missing the required `choices` key. The difference in what happens is `on_failure` alone:

- `warn-schema.local` (`on_failure: warn`) logs the violated path and forwards the response unchanged.
- `block-schema.local` (`on_failure: block`) refuses the response.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
curl -i -H 'Host: warn-schema.local' http://127.0.0.1:8080/
```

Forwards the (invalid) body with a `200`, and logs a `WARN`-level line naming the violation:

```
WARN sbproxy_modules::transform::ai_schema: transform="ai_schema" on_failure="warn" schema validation failed: missing required property 'choices'
```

```bash
curl -i -H 'Host: block-schema.local' http://127.0.0.1:8080/
```

Refuses the response instead. `fail_on_error: true` (the legacy spelling of `failure_posture: closed`) makes the refusal end the response rather than log-and-continue on the `static` action's own path, matching [`transform-json-schema`](../transform-json-schema/)'s documented refusal shape.

## What this exercises

- `ai_schema` transform with an inline `schema` object
- `on_failure: warn` vs `on_failure: block` on the same invalid body
- `type`, `required`, and `properties` schema checks
- `failure_posture: closed` (via `fail_on_error: true`) enforced on a `static` action

## See also

- [docs/transforms.md](../../docs/transforms.md) - full transform reference, including `ai_schema`
- [docs/ai-gateway.md](../../docs/ai-gateway.md) - AI gateway configuration
- [transform-json-schema](../transform-json-schema/) - the general-purpose JSON Schema transform this complements
