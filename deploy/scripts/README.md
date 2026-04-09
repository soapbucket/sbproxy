# Scripts Directory Documentation

Scripts for building, testing, and managing the proxy. See [docs/SCRIPTS_AUDIT.md](../../docs/SCRIPTS_AUDIT.md) for full audit.

## Run Tests

| Script | Purpose |
|--------|---------|
| `run-e2e-tests.sh` | **Primary** E2E test runner. Starts services, loads DB, runs smoke tests |
| `test_race.sh` | Race detection for Go tests (macOS warning-safe) |
| `test-acme.sh` | ACME certificate E2E tests with Pebble |

## Start Proxy

| Script | Purpose |
|--------|---------|
| `run_proxy_standalone.sh` | Single container, no dependencies |
| `run_proxy_general.sh` | Proxy + Redis |
| `run_proxy_advanced.sh` | Full stack (Postgres, Redis, observability) |
| `run-docker.sh` | Unified Docker runner (--file-only, --minimal, --acme) |

## Docker Entrypoints (used by Docker)

| Script | Purpose |
|--------|---------|
| `docker-entrypoint.sh` | Proxy container startup |
| `clickhouse-entrypoint.sh` | ClickHouse init |
| `elasticsearch-init.sh` | Elasticsearch index templates |
| `kibana-init.sh` | Kibana dashboards |

## Test Support (used by run-e2e-tests.sh)

| Script | Purpose |
|--------|---------|
| `setup_proxy_certs.sh` | Generate certs for proxy hostnames |
| `copy_config_files.sh` | Copy config to test dir |
| `load_database.sh` | Load fixtures into PostgreSQL |
| `combine-fixtures.sh` | Merge JSON fixtures |
| `populate_from_docker.sh` | Populate DB from Docker |
| `populate_origins.sh` | Populate DB from local |
| `generate_certificates.sh` | Test cert generation |
| `generate_jwt_tokens.sh` | JWT tokens for tests |

## One-Offs (maintenance only)

| Script | Purpose |
|--------|---------|
| `generate_ai_providers.py` | Regenerate `config/ai_providers.yml` when schema changes |
| `download_pricing.sh` | Download LiteLLM model pricing JSON |

## Usage

```bash
# E2E tests (primary entry point)
./scripts/run-e2e-tests.sh

# Start proxy
./scripts/run_proxy_standalone.sh
./scripts/run_proxy_general.sh
./scripts/run_proxy_advanced.sh
./scripts/run-docker.sh up

# Reload database after fixture changes
./scripts/load_database.sh
```
