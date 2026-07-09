# SBproxy reference observability stack

*Last modified: 2026-07-09*

A single `docker compose` command boots a complete metrics, logs, and traces stack pre-wired for SBproxy: Prometheus for metrics, Grafana for visualization, Tempo for traces, Loki for logs, Arize Phoenix and Langfuse for LLM-native traces, and an OpenTelemetry collector as the single OTLP ingress. This is the canonical evaluator-friendly stack referenced by the operator runbook (`../../docs/observability.md`) and the local examples smoke runner. Grafana comes up pre-provisioned with the SBproxy dashboards from `../../deploy/dashboards/`: `overview.json`, `per-agent.json`, `policy-triggers.json`, `audit-log.json`, `traces-overview.json`, `boilerplate-stripping.json`, `content-shapes.json`, and `licensing-edits.json`.

## How to run

```bash
docker compose up -d
```

Then open:

- Grafana at http://localhost:3000 (login `admin` / `admin`)
- Prometheus at http://localhost:9090
- Loki ready endpoint at http://localhost:3100/ready
- Tempo (queried via Grafana, no first-class UI)
- Arize Phoenix at http://localhost:6006 (project `SBproxy LLM Traces`)
- Langfuse at http://localhost:3001 (login `admin@sbproxy.local` / `sbproxy-local-admin`, project `SBproxy LLM Traces`)
- MinIO object storage for Langfuse at http://localhost:9092 (console at http://localhost:9093)

SBproxy applies source-side parent-based sampling from `proxy.observability.telemetry.sample_rate` and keeps completed error, over-budget, and slow traces when the matching telemetry thresholds are set. The collector also carries a cost-aware tail-sampling policy (`tail_sampling` in `otel-collector/config.yaml`) as a backend-side mirror. Keep its latency and budget thresholds aligned with `keep_over_budget_usd` / `keep_slower_than_secs`.

Phoenix and Langfuse are enabled by default in the trace pipeline. SBproxy AI spans are fanned out to both backends with no manual attribute remapping:

- Phoenix receives OTLP HTTP with `x-project-name: SBproxy LLM Traces`, so the project appears automatically after the first trace.
- Langfuse is seeded with `LANGFUSE_INIT_*` values on first boot. The collector authenticates with the matching local demo API keys (`lf_pk_sbproxy_reference` / `lf_sk_sbproxy_reference`) using Basic auth.

Verify everything is healthy:

```bash
docker compose ps
```

The infrastructure services should report `healthy`; Tempo, Phoenix, the OTel collector, and the Langfuse web/worker containers may show `running` because they do not declare healthchecks.

## How to point SBproxy at it

Run SBproxy on the host with its normal serve command:

```bash
sbproxy serve -f <config>
```

No extra flags. Both wiring points live in the YAML:

- Metrics: the proxy serves Prometheus `/metrics` on its data-plane listener (`proxy.http_bind_port`, unauthenticated) and on the admin port (`proxy.admin`, behind the admin basic auth). The stack's Prometheus job scrapes the data plane at `host.docker.internal:8080` (see `prometheus/prometheus.yml`); change that target if your `http_bind_port` is not 8080.
- Traces and logs: the OTLP endpoint comes from `proxy.observability.telemetry` in the YAML, pointed at the OTel collector's host port 4327 (mapped to the container's 4317):

```yaml
proxy:
  http_bind_port: 8080
  observability:
    telemetry:
      enabled: true
      endpoint: "http://localhost:4327"   # OTel collector: host 4327 -> container 4317
      transport: grpc
```

On Linux Docker hosts where `host.docker.internal` does not resolve, add `--add-host host.docker.internal:host-gateway` to the Prometheus service or replace the scrape target with the host's LAN IP.

If you instead run SBproxy as a sibling container on the same Compose network, point the Prometheus scrape target at `sbproxy:8080` and set `proxy.observability.telemetry.endpoint` to `http://otel-collector:4317`.

For LLM-native views, enable content capture on the AI origin you are exercising:

```yaml
origins:
  "ai.local":
    action:
      type: ai_proxy
      trace_content: true
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          default_model: gpt-4o-mini
```

Then send live AI traffic through SBproxy:

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Say hello from SBproxy observability."}]
  }'
```

After the collector flushes, Phoenix and Langfuse both show the same generation with prompt, completion, model, provider, token counts, USD cost, TTFT, latency, and status fields populated from SBproxy's `gen_ai.*`, OpenInference `llm.*`, `input.value`, and `output.value` span attributes/events.

## Stopping and resetting

```bash
docker compose down -v
```

The `-v` flag drops the named volumes for Prometheus, Grafana, Tempo, Loki, and Langfuse's Postgres, ClickHouse, MinIO, and Redis storage so the next `up` starts from a blank slate. Omit `-v` to keep dashboards, scraped metrics, trace history, and the seeded Langfuse project across restarts.

## Layout

```
examples/observability-stack/
  docker-compose.yml
  smoke.json
  prometheus/prometheus.yml
  grafana/provisioning/datasources/datasources.yml
  grafana/provisioning/dashboards/dashboards.yml
  tempo/tempo.yaml
  loki/loki-config.yaml
  otel-collector/config.yaml
```

The Grafana dashboards themselves live at `../../deploy/dashboards/` (`overview.json`, `per-agent.json`, `policy-triggers.json`, `audit-log.json`, `traces-overview.json`, `boilerplate-stripping.json`, `content-shapes.json`, `licensing-edits.json`); `docker-compose.yml` mounts that directory into Grafana's provisioning path so they load at startup.

## See also

- `../../docs/observability.md` - operator runbook for metrics, logs, traces, and this stack
- `../../deploy/dashboards/` - the provisioned Grafana dashboard JSON
