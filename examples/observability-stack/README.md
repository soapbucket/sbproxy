# SBproxy reference observability stack

*Last modified: 2026-06-18*

A single `docker compose` command boots a complete metrics, logs, and traces stack pre-wired for SBproxy: Prometheus for metrics, Grafana for visualization, Tempo for traces, Loki for logs, Arize Phoenix and Langfuse for LLM-native traces, and an OpenTelemetry collector as the single OTLP ingress. This is the canonical evaluator-friendly stack referenced by the operator runbook (`docs/observability.md`) and the local examples smoke runner. The real Wave 1 dashboards land in task B1.6 of `../../docs/AIGOVERNANCE-BUILD.md`; an empty placeholder dashboard is provisioned here so Grafana starts cleanly.

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

Run SBproxy on the host with two extra flags:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4327 \
  sbproxy run --config sb.yml --metrics-listen 127.0.0.1:9091
```

The OTLP endpoint targets the OTel collector (host port 4327, mapped to the container's 4317). The metrics listener on `127.0.0.1:9091` is what Prometheus scrapes via `host.docker.internal:9091` (see `prometheus/prometheus.yml`). On Linux Docker hosts where `host.docker.internal` does not resolve, add `--add-host host.docker.internal:host-gateway` to the Prometheus service or replace the scrape target with the host's LAN IP.

If you instead run SBproxy as a sibling container on the same Compose network, drop `host.docker.internal` and target `sbproxy:9091` directly. The `OTEL_EXPORTER_OTLP_ENDPOINT` then becomes `http://otel-collector:4317`.

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
  prometheus/prometheus.yml
  grafana/provisioning/datasources/datasources.yml
  grafana/provisioning/dashboards/dashboards.yml
  grafana/provisioning/dashboards/placeholder.json
  tempo/tempo.yaml
  loki/loki-config.yaml
  otel-collector/config.yaml
```

## See also

- `../../docs/AIGOVERNANCE-BUILD.md` section 4.6, task **B1.11** (this stack)
- `../../docs/AIGOVERNANCE-BUILD.md` section 4.6, task **B1.6** (real Grafana dashboards land here)
- `../../docs/AIGOVERNANCE-BUILD.md` section 15 (observability strategy)
- `../../docs/` (forward-looking; lands in a later wave)
