# Observability: budget and target health gauges

*Last modified: 2026-08-20*

Two Prometheus gauges on one scrape, each staged so you can watch it move. `sbproxy_target_health_state{origin, target}` is per-target tri-state health on LiteLLM's 0/1/2 deployment-state scale (0 healthy, 1 degraded with the circuit breaker half-open, 2 excluded from selection), sampled at scrape time from the same pipeline walk that renders `GET /api/health/targets`. `sbproxy_ai_budget_utilization_ratio{scope}` is the fraction of a budget scope's cap consumed, republished by the enforcement path after every billing debit; headroom is `1 - sbproxy_ai_budget_utilization_ratio` in PromQL.

The config stages one scenario per family. `lb.local` load-balances across a live local fixture and a port nothing listens on, so the dead target fails its probe and gets excluded. `ai.local` runs a 300-token budget against an OpenAI-shaped fixture that bills exactly the tokens the request asks for (`spend=100` in the message content), so three calls walk the gauge to the cap and the fourth is refused.

## Run

```bash
python3 examples/health-and-budget-gauges/fixture.py &
make run CONFIG=examples/health-and-budget-gauges/sb.yml
```

The fixture serves the load balancer's healthy target on `127.0.0.1:19601` and the OpenAI stub on `127.0.0.1:19603`. Nothing serves `127.0.0.1:19602`; refused connections are the scenario.

## Watch a target get excluded

Scrape right after startup, before the dead target's third consecutive probe failure, and both targets read healthy:

```bash
$ curl -s http://127.0.0.1:8080/metrics | grep '^sbproxy_target_health_state'
sbproxy_target_health_state{origin="lb.local",target="http://127.0.0.1:19601"} 0
sbproxy_target_health_state{origin="lb.local",target="http://127.0.0.1:19602"} 0
```

The probe interval is 2s and `unhealthy_threshold` is 3, and tokio fires the first probe immediately, so the third failure lands roughly 4s after startup. Scrape again and the dead target has moved to 2:

```bash
$ curl -s http://127.0.0.1:8080/metrics | grep '^sbproxy_target_health_state'
sbproxy_target_health_state{origin="lb.local",target="http://127.0.0.1:19601"} 0
sbproxy_target_health_state{origin="lb.local",target="http://127.0.0.1:19602"} 2
```

Traffic keeps flowing the whole time, because 2 means exactly "what `select_target` skips" and the healthy target is still in rotation:

```bash
$ curl -s http://127.0.0.1:8080/anything -H 'Host: lb.local'
{"target": "19601", "ok": true}
```

The value 1 does not appear in this walk; it needs a circuit breaker in half-open, which is a recovery state a two-target demo cannot hold still long enough to scrape reliably. Configure a breaker and kill the fixture mid-traffic to see it.

## Walk the budget gauge to the cap

The gauge has no series until the first debit, which is the honest shape for "nothing has spent anything yet": absent, not zero. Each call bills 100 tokens against the 300-token workspace cap, and the scrape after each call carries the fraction the debit produced:

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o","messages":[{"role":"user","content":"spend=100"}]}' > /dev/null
$ curl -s http://127.0.0.1:8080/metrics | grep '^sbproxy_ai_budget_utilization_ratio'
sbproxy_ai_budget_utilization_ratio{scope="workspace"} 0.3333333333333333
```

Two more of the same call:

```text
sbproxy_ai_budget_utilization_ratio{scope="workspace"} 0.6666666666666666
sbproxy_ai_budget_utilization_ratio{scope="workspace"} 1
```

At 1 the cap is consumed, and the fourth request is refused before dispatch:

```bash
$ curl -s -w '\nHTTP %{http_code}\n' http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o","messages":[{"role":"user","content":"spend=100"}]}'
{"error":{"message":"token limit exceeded: 300 >= 300","scope":"workspace","type":"budget_exceeded"}}
HTTP 402
```

The point of the gauge is that an operator alerts at 0.9 and never meets that 402. The pre-exhaustion alert ships in `dashboards/prometheus/alerts.yml`: `max by (scope) (sbproxy_ai_budget_utilization_ratio) > 0.9`.

## Where these land

Grafana panels for both ship in `dashboards/grafana/`: Target Health State on the origins dashboard, Budget Utilization by Scope on the AI gateway dashboard. The health gauge and `GET /api/health/targets` render from one pipeline walk, so the admin JSON and the Prometheus series always agree about a target; the JSON additionally carries which of the three mechanisms (probe, outlier ejection, circuit breaker) excluded it. The two targets here have distinct URLs, so each `target` label is just the URL. Configure the same URL twice under one origin (a weighted pair, or blue and green behind one address) and both rows take the load balancer's own `url#index` identifier instead, so the ejected one cannot hide behind the healthy one's series. [docs/observability.md](../../docs/observability.md#budget-headroom-and-target-health) has the full mechanism, including why the health gauge is sampled at scrape time while the budget gauge is written at the enforcement path.

Restarting the proxy resets the budget tracker (the demo cap has `period: total`, which never rolls over), so each walk of the ladder wants a fresh process.
