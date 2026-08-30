# Prompt labels: promote a version without touching a caller

*Last modified: 2026-08-29*

A prompt version is immutable and numbered. A label is a movable pointer at one, so a caller ships `support-bot@production` once and never changes it while the operator moves which version that string renders. This is the shape Portkey and Helicone both converged on, and it is a different thing from the pin: a pin is one pointer per prompt, serving callers who name no version at all, so it cannot express staging sitting on version 2 while production is still on version 1. Both are shown here.

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/prompt-labels/sb.yml
```

## Try it

Point `production` at version 1 and `staging` at version 2:

```bash
$ curl -s -u admin:admin -X PUT \
    http://127.0.0.1:9090/admin/prompts/ai.local/support-bot/labels/production \
    -H 'Content-Type: application/json' -d '{"version":"1"}'
{"host":"ai.local","name":"support-bot","label":"production","version":"1"}

$ curl -s -u admin:admin -X PUT \
    http://127.0.0.1:9090/admin/prompts/ai.local/support-bot/labels/staging \
    -H 'Content-Type: application/json' -d '{"version":"2"}'
{"host":"ai.local","name":"support-bot","label":"staging","version":"2"}
```

Call the label rather than the version. This body is what a caller ships:

```bash
$ curl -s http://127.0.0.1:8080/v1/responses \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"prompt":{"id":"support-bot@production"},"input":"my order is late"}' \
  | jq -r '.output[0].content[0].text'
Sorry about that. Can you share the order number?
```

Promote version 2. The caller's body above does not change:

```bash
$ curl -s -u admin:admin -X PUT \
    http://127.0.0.1:9090/admin/prompts/ai.local/support-bot/labels/production \
    -H 'Content-Type: application/json' -d '{"version":"2"}'
{"host":"ai.local","name":"support-bot","label":"production","version":"2"}
```

The same request now renders version 2, which cites a doc link. Nothing on the caller's side moved.

Read the current mapping back:

```bash
$ curl -s -u admin:admin http://127.0.0.1:9090/admin/prompts | jq '.hosts["ai.local"].prompts["support-bot"]'
{
  "default_version": null,
  "effective_version": "2",
  "versions": ["1", "2"],
  "labels": {"production": "2", "staging": "2"}
}
```

## Two refusals worth knowing

Both answer `409`, and both exist because the alternative is a silent change to what a shipped caller renders.

An exact version always wins over a label of the same name, because a reference naming a version has to keep meaning that exact version. So a label named after an existing version would never resolve, and creating one is refused:

```bash
$ curl -s -u admin:admin -X PUT \
    http://127.0.0.1:9090/admin/prompts/ai.local/support-bot/labels/1 \
    -H 'Content-Type: application/json' -d '{"version":"1"}'
{"error":"cannot create label '1': a version of that name already exists, and an exact version always wins at resolution, so the label would never resolve"}
```

The same collision from the other direction matters more. Adding a version called `production` to a prompt that already has a `production` label would silently repoint every caller of that label:

```bash
$ curl -s -u admin:admin -X POST \
    http://127.0.0.1:9090/admin/prompts/ai.local/support-bot/versions \
    -H 'Content-Type: application/json' \
    -d '{"version":"production","template":"..."}'
{"error":"cannot add version 'production': a label of that name already points at version '2'. Rename the version, or remove the label first"}
```

## Removing a label

```bash
$ curl -s -u admin:admin -X DELETE \
    http://127.0.0.1:9090/admin/prompts/ai.local/support-bot/labels/staging
{"host":"ai.local","name":"support-bot","label":"staging","removed":true}
```

A caller still referencing `support-bot@staging` now gets an unknown-version error rather than falling back to the pin. That is deliberate: quietly serving a different prompt to a caller who asked for a specific label is the failure labels exist to prevent.
