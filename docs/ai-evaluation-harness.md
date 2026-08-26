# AI evaluation harness

*Last modified: 2026-08-25*

SBproxy's AI toolkit registers immutable, explicitly versioned datasets and
evaluates already-recorded candidate responses through the authenticated admin
plane. The run is offline: it never sends dataset entries, candidate responses,
or judge material to a model endpoint. This makes the operation reproducible
and keeps provider credentials out of the evaluation contract.

The toolkit is live control-plane state even though evaluation itself is
offline. Configuration seeds datasets into an immutable pipeline generation;
the admin API can add an exact dataset version to that running generation and
retain bounded aggregate results for its tenant/origin scope.

## Configure the runtime

Datasets and bounds live under `proxy.ai_toolkit`. A dataset's `origin` must
name an existing configured origin and its `version` must be non-zero.

<!-- sbproxy-config: examples/ai-evaluation/sb.yml -->
```yaml
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    port: 9090
    username: admin
    password: ${SB_ADMIN_PASSWORD}
  ai_toolkit:
    limits:
      max_datasets: 8
      max_dataset_versions: 4
      max_dataset_versions_total: 32
      max_dataset_entries: 100
      max_dataset_bytes_total: 8388608
      max_evaluation_cases: 100
      evaluation_concurrency: 2
    agents: []
    workflows: []
    datasets: []

origins:
  "ai.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: AI toolkit control-plane scope
```

The same `datasets` list can seed immutable versions at boot:

```yaml
proxy:
  ai_toolkit:
    datasets:
      - origin: ai.local
        name: support-answers
        version: 1
        entries:
          - input: When can I request a refund?
            expected_output: Refunds are available within 30 days.
            metadata: {case: refund-window}
```

Publishing the same `(origin scope, name, version)` twice is refused. A run must
name an exact version; a missing version never falls forward to latest. The
per-dataset version cap remains scoped, while `max_dataset_versions_total` and
`max_dataset_bytes_total` cap all retained dataset versions and serialized
entry arrays across the runtime generation. Registration is atomic: a refused
version does not consume either global budget.

## Register a dataset

The dataset file contains `name`, `version`, and `entries`; the CLI supplies the
scope separately and sends the request to
`POST /admin/ai-toolkit/datasets/register`.

Registration is generation-pinned: a config reload builds a fresh toolkit
runtime from `proxy.ai_toolkit` alone, so datasets registered over this
API, retained experiment summaries, and recorded operation rows all vanish
at the next reload, even one that changes nothing else. Datasets that must
survive reloads belong in the config's `ai_toolkit.datasets:` block, which
re-seeds every generation.

```json
{
  "name": "support-answers",
  "version": 1,
  "entries": [
    {
      "input": "When can I request a refund?",
      "expected_output": "Refunds are available within 30 days.",
      "metadata": {"case": "refund-window"}
    }
  ]
}
```

```bash
sbproxy ai dataset register \
  --origin ai.local \
  --dataset dataset.json
```

## Evaluate recorded responses

Supply one response string per entry in the exact dataset version:

```json
[
  "Refunds are available within 30 days."
]
```

```bash
sbproxy ai evaluate \
  --origin ai.local \
  --dataset support-answers \
  --version 1 \
  --responses responses.json \
  --experiment-id support-v1-run-1 \
  --experiment-name support-v1-baseline \
  --model recorded-model \
  --prompt-version support-v1 \
  --required-keyword refund \
  --min-bytes 1 \
  --max-bytes 512
```

Setting `--min-bytes` or `--max-bytes` adds one inclusive length-range
metric; leaving both unset adds none, so the reported `metric_pass_rate`
covers exactly the metrics you asked for (and is `1.0` when a run
declares no metrics at all). Repeat `--required-keyword` to require
several literal keywords, and use `--json-schema <file>` to validate
structural JSON output. The runtime also
supports bounded regular-expression, JSON-Schema, length-range, and keyword
metric specifications on the admin wire.

Each live command accepts `--admin-url`, `--username`, and `--password`, or the
standard `SB_ADMIN_URL`, `SB_ADMIN_USERNAME`, and `SB_ADMIN_PASSWORD`
environment variables.

### Recorded judge results

An optional offline judge is still offline. Supply one already-recorded judge
JSON response per dataset case, the judge's model label, and at least one exact
criterion:

```bash
sbproxy ai evaluate \
  --origin ai.local \
  --dataset support-answers \
  --version 1 \
  --responses responses.json \
  --experiment-id support-v1-run-2 \
  --experiment-name support-v1-judge \
  --model recorded-model \
  --judge-responses judge-responses.json \
  --judge-model recorded-judge \
  --judge-criterion accuracy \
  --judge-criterion clarity
```

There is no judge endpoint or judge token flag. SBproxy parses and aggregates
the supplied records; it does not call a judge service.

## Result and retention contract

The response contains only aggregate data: experiment and dataset identities,
model and prompt-version metadata, case count, exact-match rate, custom-metric
pass rate, optional judge score, per-criterion means, and a timestamp. Raw
dataset entries, candidate responses, judge responses, and judge reasoning are
not returned or retained in the snapshot.

Request bytes, response bytes, dataset counts and versions, entries per
dataset, cases per run, metric count, judge criteria, concurrent evaluations,
and retained summaries are all bounded. Saturation fails fast. A validation or
limit error leaves the prior registered state unchanged.

## Observability

- `GET /admin/ai-toolkit/snapshot` returns the caller's bounded dataset and
  aggregate experiment inventory.
- `ai_evaluation_operation` carries only the scoped origin, dataset, and
  experiment identifiers, the dataset version, a closed outcome, case count,
  and duration.
- `sbproxy_ai_toolkit_operations_total{capability="evaluation",outcome="..."}`
  counts terminal operations with closed labels.

See [Admin API reference](admin-api-reference.md#ai-toolkit-admin),
[Events](events.md), and [Metrics stability](metrics-stability.md).

## Runnable example

[`examples/ai-evaluation`](../examples/ai-evaluation/) contains a no-Redis
config, dataset, recorded responses, and the complete CLI sequence.
