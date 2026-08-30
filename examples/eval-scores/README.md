# Scores and feedback: record a quality signal against a logged request

*Last modified: 2026-08-29*

An external eval harness, a thumbs up/down widget, or a human reviewer posts an integer score against a request this proxy logged, and the console charts it over time. sbproxy is not an eval framework and ships no scoring logic: something else decides what a score is, and this stores it beside a request id. That boundary is the feature rather than a limitation of it, and it is Helicone's explicit posture. The bounded `-10..10` range is Portkey's, which is what makes scores from two different evaluators comparable on one axis at all.

Nothing about the request's content is stored with a score. A score is an integer, an optional short evaluator label, and a request id.

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/eval-scores/sb.yml
```

## Try it

Make a request and keep its id:

```bash
$ curl -si http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  | grep -i x-request-id
x-request-id: 01J8QF3M2N4P5R6S7T8V9W0X1Y
```

Post a score against it:

```bash
$ curl -s -u admin:admin -X POST \
    http://127.0.0.1:9090/api/requests/01J8QF3M2N4P5R6S7T8V9W0X1Y/scores \
    -H 'Content-Type: application/json' \
    -d '{"score": 8, "label": "helpfulness"}'
{"request_id":"01J8QF3M2N4P5R6S7T8V9W0X1Y","score":8,"label":"helpfulness","recorded_at":"2026-08-29T14:02:11.417Z"}
```

Read them back with per-label aggregates:

```bash
$ curl -s -u admin:admin http://127.0.0.1:9090/api/scores | jq
{
  "scores": [
    {
      "request_id": "01J8QF3M2N4P5R6S7T8V9W0X1Y",
      "score": 8,
      "label": "helpfulness",
      "recorded_at": "2026-08-29T14:02:11.417Z"
    }
  ],
  "aggregates": [
    {"label": "helpfulness", "count": 1, "mean": 8.0, "min": 8, "max": 8}
  ],
  "capacity": 5000,
  "range": {"min": -10, "max": 10}
}
```

Narrow to one request, which is what the console's per-request panel asks for:

```bash
$ curl -s -u admin:admin \
    'http://127.0.0.1:9090/api/scores?request_id=01J8QF3M2N4P5R6S7T8V9W0X1Y' | jq '.aggregates'
[{"label": "helpfulness", "count": 1, "mean": 8.0, "min": 8, "max": 8}]
```

## Out of range is refused, not clamped

```bash
$ curl -s -u admin:admin -X POST \
    http://127.0.0.1:9090/api/requests/01J8QF3M2N4P5R6S7T8V9W0X1Y/scores \
    -H 'Content-Type: application/json' -d '{"score": 87}'
{"error":"score must be between -10 and 10 inclusive","code":"score_out_of_range"}
```

Clamping would make an evaluator accidentally configured for a 0..100 scale look like a stream of perfect tens, which is a worse outcome than an error the operator can see.

## What it costs to keep

Scores live in a bounded in-process ring of 5,000, reported as `capacity` above. This is a console window rather than a datastore: an operator looking at a chart wants the recent slice, and an unbounded ring behind a POST route is a memory-growth path. Every accepted score also emits a structured log line under `sbproxy::admin::scores` carrying the id, the score, and the label, so shipping those to a warehouse is how you keep history.

## Metric

```
sbproxy_feedback_scores_total{label="helpfulness",bucket="positive"}
```

The sign bucket only (`negative`, `neutral`, `positive`). The score itself is not a metric label: it has 21 readings, and one series per reading per evaluator is how a cardinality problem starts. The distribution is in the JSON above, which the console charts.
