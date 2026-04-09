# Quick Start Guide

Get up and running with the E2E test suite in 5 minutes.

## 1. Start the E2E Test Environment

From the `test` directory, run the E2E test runner:

```bash
cd proxy/test
../scripts/run-e2e-tests.sh
```

*Note: If you're already in the `proxy` directory, use `cd test` instead.*

This will:
- ✅ Start all Docker services (Proxy, PostgreSQL, Redis, ClickHouse, ELK Stack, Prometheus, Grafana)
- ✅ Wait for services to be healthy
- ✅ Load test fixtures into database
- ✅ Run smoke tests
- ✅ Display service status and endpoints

## 2. Add /etc/hosts Entries

For browser testing, add test hostnames to `/etc/hosts`:

```bash
sudo bash -c 'cat >> /etc/hosts << EOF
127.0.0.1 basic-proxy.test proxy-headers.test proxy-rewrite.test proxy-query.test proxy-conditional.test
127.0.0.1 html-transform.test html-transform-advanced.test json-transform.test string-replace.test
127.0.0.1 redirect.test static.test graphql.test websocket.test websocket-pool.test loadbalancer.test
127.0.0.1 jwt-auth.test rate-limit.test waf.test security-headers.test ip-filter.test cors.test
127.0.0.1 https-proxy.test https-proxy-bad-cert.test forward-rules.test forward-rules-api.test
127.0.0.1 callbacks.test complex.test google-oauth.test jwt-encrypted.test
EOF'
```

## 3. Test It!

```bash
# Basic proxy test
curl -H "Host: basic-proxy.test" http://localhost:8080/

# HTML transform
curl -H "Host: html-transform.test" http://localhost:8080/ | head -20

# Static content
curl -H "Host: static.test" http://localhost:8080/

# With JWT auth (from test directory)
TOKEN=$(jq -r '.tokens.admin.token' fixtures/jwt_tokens.json)
curl -H "Host: jwt-auth.test" \
     -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/test/auth-required
```

## 4. Access Monitoring & Services

### Core Services
- **Proxy HTTP**: http://localhost:8080
- **Proxy HTTPS**: https://localhost:8443
- **Proxy Metrics**: http://localhost:8888/metrics
- **E2E Test Server**: http://localhost:8090

### Monitoring
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/admin)

### Logging
- **ClickHouse**: http://localhost:8123
- **Elasticsearch**: http://localhost:9200
- **Kibana**: http://localhost:5601

### Databases
- **PostgreSQL**: localhost:5433 (proxy/proxy)
- **Redis**: localhost:6380

## 5. Browser Testing

Open in browser:
- http://basic-proxy.test:8080/
- http://static.test:8080/
- http://html-transform.test:8080/

## Common Commands

```bash
# View logs (from proxy/docker directory)
cd ../docker
export ENV_PREFIX="test-"
export ENV_NETWORK="test_net"
docker compose logs -f proxy

# View all service logs
docker compose logs -f

# Restart services
docker compose restart

# Stop everything
docker compose down

# Stop and remove all data
docker compose down -v

# Reload database (from proxy directory)
cd ..
./scripts/load_database.sh
```

## Troubleshooting

**Services not starting?**
```bash
cd ../docker
export ENV_PREFIX="test-"
export ENV_NETWORK="test_net"
docker compose logs
```

**Database not loading?**
```bash
cd ..
./scripts/load_database.sh
```

**Certificates missing?**
```bash
cd ../scripts
./generate_certificates.sh --hostname "localhost" --output-dir ../test/conf/certs
```

**Check service health:**
```bash
cd ../docker
export ENV_PREFIX="test-"
export ENV_NETWORK="test_net"
docker compose ps
```

For more details, see [README.md](README.md).

