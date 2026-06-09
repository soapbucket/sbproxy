# SBproxy reference observability stack

*Last modified: 2026-04-30*

A single `docker compose` command boots a complete metrics, logs, and traces stack pre-wired for SBproxy: Prometheus for metrics, Grafana for visualization, Tempo for traces, Loki for logs, and an OpenTelemetry collector as the single OTLP ingress. This is the canonical evaluator-friendly stack referenced by the operator runbook (`docs/observability.md`) and the local examples smoke runner. The real Wave 1 dashboards land in task B1.6 of `../../docs/AIGOVERNANCE-BUILD.md`; an empty placeholder dashboard is provisioned here so Grafana starts cleanly.

## How to run

```bash
docker compose up -d
```

Then open:

- Grafana at http://localhost:3000 (login `admin` / `admin`)
- Prometheus at http://localhost:9090
- Loki ready endpoint at http://localhost:3100/ready
- Tempo (queried via Grafana, no first-class UI)
- Arize Phoenix at http://localhost:6006 (LLM-native trace view: SBproxy AI spans render as full generations with tokens, USD cost, latency, and error status)

The collector applies a cost-aware tail-sampling policy (`tail_sampling` in `otel-collector/config.yaml`): errors and slow traces are always kept, the rest at a configurable base rate. Mirror `keep_over_budget_usd` / `keep_slower_than_secs` from the proxy's telemetry config into that policy.

Langfuse is a second LLM-native backend. Its v3 self-host needs its own multi-service stack (Postgres, ClickHouse, Redis, object store), so it is not embedded here: run it from its own compose and uncomment the `otlphttp/langfuse` exporter in the collector config, pointing it at the Langfuse OTLP endpoint (`/api/public/otel`).

Verify everything is healthy:

```bash
docker compose ps
```

All five services should report `healthy` (or `running` for Tempo and the OTel collector, which do not declare healthchecks).

## How to point SBproxy at it

Run SBproxy on the host with two extra flags:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4327 \
  sbproxy run --config sb.yml --metrics-listen 127.0.0.1:9091
```

The OTLP endpoint targets the OTel collector (host port 4327, mapped to the container's 4317). The metrics listener on `127.0.0.1:9091` is what Prometheus scrapes via `host.docker.internal:9091` (see `prometheus/prometheus.yml`). On Linux Docker hosts where `host.docker.internal` does not resolve, add `--add-host host.docker.internal:host-gateway` to the Prometheus service or replace the scrape target with the host's LAN IP.

If you instead run SBproxy as a sibling container on the same Compose network, drop `host.docker.internal` and target `sbproxy:9091` directly. The `OTEL_EXPORTER_OTLP_ENDPOINT` then becomes `http://otel-collector:4317`.

## Stopping and resetting

```bash
docker compose down -v
```

The `-v` flag drops the four named volumes (`prometheus_data`, `grafana_data`, `tempo_data`, `loki_data`) so the next `up` starts from a blank slate. Omit `-v` to keep dashboards, scraped metrics, and trace history across restarts.

## Layout

```
00-observability-stack/
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
