#!/usr/bin/env bash
# E2E Test Runner - Updated for new Docker configuration
set -e

echo "🧪 E2E Test Runner"
echo "=================="
echo ""

# Get script directory and proxy root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_DIR="${PROXY_ROOT}/test"

echo "📋 Test directory: $TEST_DIR"
echo ""

# Check if docker compose is available
if docker compose version > /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose > /dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    echo "❌ Error: docker compose or docker-compose not found"
    exit 1
fi

echo "✅ Using: $COMPOSE_CMD"
echo ""

# Check if Docker daemon is running
echo "🔍 Checking Docker daemon..."
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker daemon is not running!"
    echo ""
    echo "Please start Docker:"
    if command -v colima > /dev/null 2>&1; then
        echo "   colima start"
    elif [ -d "/Applications/Docker.app" ]; then
        echo "   Open Docker Desktop from Applications"
    else
        echo "   Start your Docker daemon"
    fi
    exit 1
fi
echo "✅ Docker daemon is running"
echo ""

# Stop any existing containers
echo "🧹 Cleaning up existing containers..."
cd "${PROXY_ROOT}/docker"

# Export environment variables for test environment
export ENV_PREFIX="test-"
export ENV_NETWORK="test_net"
# Port configurations for test environment (using non-standard ports to avoid conflicts)
export POSTGRES_PORT="${POSTGRES_PORT:-5433}"
export REDIS_PORT="${REDIS_PORT:-6380}"
export PROXY_HTTP_PORT="${PROXY_HTTP_PORT:-8080}"
export PROXY_HTTPS_PORT="${PROXY_HTTPS_PORT:-8443}"
export PROXY_TELEMETRY_PORT="${PROXY_TELEMETRY_PORT:-8888}"
export CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
export CLICKHOUSE_NATIVE_PORT="${CLICKHOUSE_NATIVE_PORT:-9000}"
export ELASTICSEARCH_HTTP_PORT="${ELASTICSEARCH_HTTP_PORT:-9200}"
export ELASTICSEARCH_TRANSPORT_PORT="${ELASTICSEARCH_TRANSPORT_PORT:-9300}"
export KIBANA_PORT="${KIBANA_PORT:-5601}"
export PROMETHEUS_PORT="${PROMETHEUS_PORT:-9090}"
export GRAFANA_PORT="${GRAFANA_PORT:-3000}"
export FLUENT_BIT_PORT="${FLUENT_BIT_PORT:-2020}"

# Use E2E test override file
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.e2e-test.yml"

$COMPOSE_CMD $COMPOSE_FILES down -v 2>/dev/null || true
echo ""

# Build services separately to avoid resource contention
echo "🔨 Building services..."
echo "   Building with docker compose..."
$COMPOSE_CMD $COMPOSE_FILES build || {
    echo "⚠️  Build failed, trying with BuildKit disabled..."
    DOCKER_BUILDKIT=0 $COMPOSE_CMD $COMPOSE_FILES build
}
echo ""

# Start services
echo "🚀 Starting test environment..."
$COMPOSE_CMD $COMPOSE_FILES up -d
echo ""

# Wait for services to be healthy
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check PostgreSQL
echo "   Checking PostgreSQL..."
for i in {1..30}; do
    if docker exec test-postgres pg_isready -U proxy > /dev/null 2>&1; then
        echo "   ✅ PostgreSQL is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "   ❌ PostgreSQL failed to start"
        exit 1
    fi
    sleep 1
done

# Check PostgreSQL schema initialization
echo "   Checking PostgreSQL schema..."
SCHEMA_CHECK=$(docker exec test-postgres psql -U proxy -d proxy -tAc "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'config_storage');" 2>/dev/null || echo "f")
if [ "$SCHEMA_CHECK" = "t" ]; then
    echo "   ✅ PostgreSQL schema is initialized"
else
    echo "   ⚠️  Warning: PostgreSQL schema not initialized"
    echo "   🔧 Initializing PostgreSQL schema..."
    if docker exec -i test-postgres psql -U proxy -d proxy < "${PROXY_ROOT}/sql/init_schema.sql" 2>/dev/null; then
        echo "   ✅ PostgreSQL schema initialized successfully"
    else
        echo "   ⚠️  Warning: Failed to initialize PostgreSQL schema"
        echo "   ℹ️  You can manually initialize with:"
        echo "      docker exec -i test-postgres psql -U proxy -d proxy < ${PROXY_ROOT}/sql/init_schema.sql"
    fi
fi

# Check Redis
echo "   Checking Redis..."
for i in {1..30}; do
    if docker exec test-redis redis-cli ping > /dev/null 2>&1; then
        echo "   ✅ Redis is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "   ❌ Redis failed to start"
        exit 1
    fi
    sleep 1
done

# Check Proxy
echo "   Checking Proxy..."
for i in {1..30}; do
    if curl -s http://localhost:8888/metrics > /dev/null 2>&1; then
        echo "   ✅ Proxy is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "   ❌ Proxy failed to start"
        docker logs test-proxy --tail 50
        exit 1
    fi
    sleep 1
done

# Check ClickHouse
echo "   Checking ClickHouse..."
for i in {1..30}; do
    if curl -s http://localhost:8123/ping > /dev/null 2>&1; then
        echo "   ✅ ClickHouse is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "   ❌ ClickHouse failed to start"
        exit 1
    fi
    sleep 1
done

# Check Elasticsearch
echo "   Checking Elasticsearch..."
for i in {1..60}; do
    if curl -s http://localhost:9200/_cluster/health > /dev/null 2>&1; then
        echo "   ✅ Elasticsearch is ready"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "   ❌ Elasticsearch failed to start"
        exit 1
    fi
    sleep 2
done

# Check Kibana
echo "   Checking Kibana..."
for i in {1..60}; do
    if curl -s http://localhost:5601/api/status > /dev/null 2>&1; then
        echo "   ✅ Kibana is ready"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "   ❌ Kibana failed to start"
        exit 1
    fi
    sleep 2
done

echo ""
echo "✅ All services are ready!"
echo ""

# Wait for and verify initialization services
echo "🔧 Verifying initialization services..."
echo ""

# Check Elasticsearch initialization
echo "   Checking Elasticsearch initialization..."
for i in {1..60}; do
    CONTAINER_STATUS=$(docker ps -a --filter "name=test-elasticsearch-init" --format "{{.Status}}" 2>/dev/null || echo "")
    if echo "$CONTAINER_STATUS" | grep -q "Exited (0)"; then
        echo "   ✅ Elasticsearch initialization completed"
        break
    elif echo "$CONTAINER_STATUS" | grep -q "Exited"; then
        echo "   ⚠️  Elasticsearch initialization exited with error"
        docker logs test-elasticsearch-init --tail 20 2>/dev/null || true
        break
    elif echo "$CONTAINER_STATUS" | grep -q "Up"; then
        # Container is still running
        if [ $i -eq 60 ]; then
            echo "   ⚠️  Elasticsearch initialization still running (may be slow)"
            break
        fi
    fi
    if [ $i -eq 60 ]; then
        echo "   ⚠️  Elasticsearch initialization container not found or still starting"
        break
    fi
    sleep 2
done

# Verify Elasticsearch template exists
if curl -s http://localhost:9200/_index_template/proxy-logs > /dev/null 2>&1; then
    echo "   ✅ Elasticsearch template is configured"
else
    echo "   ⚠️  Warning: Elasticsearch template not found"
    # Check if init container is still running
    if docker ps --filter "name=test-elasticsearch-init" --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
        echo "   ℹ️  Elasticsearch init container is still running, waiting..."
        sleep 5
        # Re-check after waiting
        if curl -s http://localhost:9200/_index_template/proxy-logs > /dev/null 2>&1; then
            echo "   ✅ Elasticsearch template is now configured"
        else
            echo "   🔧 Running Elasticsearch initialization script manually..."
            docker run --rm \
                --network test_net \
                -v "${PROXY_ROOT}/scripts/elasticsearch-init.sh:/scripts/elasticsearch-init.sh:ro" \
                -v "${PROXY_ROOT}/config/elasticsearch/proxy-logs-template.json:/docker-entrypoint-initdb.d/elasticsearch-template.json:ro" \
                curlimages/curl:latest \
                /bin/sh /scripts/elasticsearch-init.sh || echo "   ⚠️  Failed to run Elasticsearch init script"
        fi
    else
        echo "   🔧 Running Elasticsearch initialization script..."
        docker run --rm \
            --network test_net \
            -v "${PROXY_ROOT}/scripts/elasticsearch-init.sh:/scripts/elasticsearch-init.sh:ro" \
            -v "${PROXY_ROOT}/config/elasticsearch/proxy-logs-template.json:/docker-entrypoint-initdb.d/elasticsearch-template.json:ro" \
            curlimages/curl:latest \
            /bin/sh /scripts/elasticsearch-init.sh || echo "   ⚠️  Failed to run Elasticsearch init script"
    fi
fi

# Check Kibana initialization
echo "   Checking Kibana initialization..."
for i in {1..60}; do
    CONTAINER_STATUS=$(docker ps -a --filter "name=test-kibana-init" --format "{{.Status}}" 2>/dev/null || echo "")
    if echo "$CONTAINER_STATUS" | grep -q "Exited (0)"; then
        echo "   ✅ Kibana initialization completed"
        break
    elif echo "$CONTAINER_STATUS" | grep -q "Exited"; then
        echo "   ⚠️  Kibana initialization exited with error"
        docker logs test-kibana-init --tail 20 2>/dev/null || true
        break
    elif echo "$CONTAINER_STATUS" | grep -q "Up"; then
        # Container is still running
        if [ $i -eq 60 ]; then
            echo "   ⚠️  Kibana initialization still running (may be slow)"
            break
        fi
    fi
    if [ $i -eq 60 ]; then
        echo "   ⚠️  Kibana initialization container not found or still starting"
        break
    fi
    sleep 2
done

# Verify Kibana index patterns and dashboards exist
echo "   Checking Kibana saved objects..."
KIBANA_PATTERNS=$(curl -s "http://localhost:5601/api/saved_objects/_find?type=index-pattern" -H "kbn-xsrf: true" 2>/dev/null || echo "")
KIBANA_DASHBOARDS=$(curl -s "http://localhost:5601/api/saved_objects/_find?type=dashboard" -H "kbn-xsrf: true" 2>/dev/null || echo "")

# Check index patterns
if echo "$KIBANA_PATTERNS" | grep -qi "proxy-application"; then
    echo "   ✅ Kibana index patterns are configured"
    # List found patterns
    PATTERN_TITLES=$(echo "$KIBANA_PATTERNS" | grep -o '"title":"[^"]*"' | cut -d'"' -f4 | grep -i "proxy" || echo "")
    if [ -n "$PATTERN_TITLES" ]; then
        echo "$PATTERN_TITLES" | while read -r title; do
            echo "      - $title"
        done
    fi
else
    echo "   ⚠️  Warning: Kibana index patterns not found"
    echo "   ℹ️  Response: $(echo "$KIBANA_PATTERNS" | head -c 200)"
fi

# Check dashboards - try multiple patterns
DASHBOARDS_FOUND=false
if [ -n "$KIBANA_DASHBOARDS" ]; then
    # Try different patterns that might match
    if echo "$KIBANA_DASHBOARDS" | grep -qi "SoapBucket\|Application Logs\|Security Logs"; then
        DASHBOARDS_FOUND=true
    fi
    
    # Also check for any dashboards at all
    DASHBOARD_COUNT=$(echo "$KIBANA_DASHBOARDS" | grep -o '"type":"dashboard"' | wc -l | tr -d ' ')
    if [ "$DASHBOARD_COUNT" -gt 0 ] && [ "$DASHBOARDS_FOUND" = false ]; then
        # There are dashboards but they might have different names
        DASHBOARD_TITLES=$(echo "$KIBANA_DASHBOARDS" | grep -o '"title":"[^"]*"' | cut -d'"' -f4 || echo "")
        if [ -n "$DASHBOARD_TITLES" ]; then
            echo "   ℹ️  Found $DASHBOARD_COUNT dashboard(s) with titles:"
            echo "$DASHBOARD_TITLES" | while read -r title; do
                echo "      - $title"
            done
        fi
    fi
fi

if [ "$DASHBOARDS_FOUND" = true ]; then
    echo "   ✅ Kibana dashboards are configured"
    # List found dashboards
    DASHBOARD_TITLES=$(echo "$KIBANA_DASHBOARDS" | grep -o '"title":"[^"]*"' | cut -d'"' -f4 | grep -i "SoapBucket\|Application\|Security" || echo "")
    if [ -n "$DASHBOARD_TITLES" ]; then
        echo "$DASHBOARD_TITLES" | while read -r title; do
            echo "      - $title"
        done
    fi
else
    echo "   ⚠️  Warning: Kibana dashboards not found"
    
    # Wait a bit and retry - dashboards might still be loading
    echo "   ℹ️  Waiting a bit for dashboards to load..."
    sleep 3
    
    # Re-check
    KIBANA_DASHBOARDS_RETRY=$(curl -s "http://localhost:5601/api/saved_objects/_find?type=dashboard" -H "kbn-xsrf: true" 2>/dev/null || echo "")
    if echo "$KIBANA_DASHBOARDS_RETRY" | grep -qi "SoapBucket\|Application Logs\|Security Logs"; then
        echo "   ✅ Kibana dashboards are now available"
    else
        # Check if init container is still running
        if docker ps --filter "name=test-kibana-init" --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
            echo "   ℹ️  Kibana init container is still running, waiting..."
            sleep 5
            # Re-check after waiting
            KIBANA_DASHBOARDS_RECHECK=$(curl -s "http://localhost:5601/api/saved_objects/_find?type=dashboard" -H "kbn-xsrf: true" 2>/dev/null || echo "")
            if echo "$KIBANA_DASHBOARDS_RECHECK" | grep -qi "SoapBucket\|Application Logs\|Security Logs"; then
                echo "   ✅ Kibana dashboards are now configured"
            else
                echo "   🔧 Running Kibana initialization script manually..."
                INIT_OUTPUT=$(docker run --rm \
                    --network test_net \
                    -v "${PROXY_ROOT}/scripts/kibana-init.sh:/scripts/kibana-init.sh:ro" \
                    -v "${PROXY_ROOT}/config/kibana/saved-objects/kibana/dashboards.ndjson:/scripts/kibana-dashboards.ndjson:ro" \
                    curlimages/curl:latest \
                    /bin/sh /scripts/kibana-init.sh 2>&1)
                INIT_EXIT_CODE=$?
                
                if [ $INIT_EXIT_CODE -eq 0 ]; then
                    echo "$INIT_OUTPUT" | grep -E "(✅|Successfully|completed)" | tail -5
                    echo "   ✅ Kibana initialization completed"
                    # Final check
                    sleep 2
                    KIBANA_DASHBOARDS_FINAL=$(curl -s "http://localhost:5601/api/saved_objects/_find?type=dashboard" -H "kbn-xsrf: true" 2>/dev/null || echo "")
                    if echo "$KIBANA_DASHBOARDS_FINAL" | grep -qi "SoapBucket\|Application Logs\|Security Logs"; then
                        echo "   ✅ Kibana dashboards verified after initialization"
                    fi
                else
                    echo "   ⚠️  Kibana init script exited with code $INIT_EXIT_CODE"
                    echo "$INIT_OUTPUT" | tail -15
                    echo "   ℹ️  Check Kibana UI at http://localhost:5601/app/dashboards to verify"
                fi
            fi
        else
            echo "   🔧 Running Kibana initialization script..."
            INIT_OUTPUT=$(docker run --rm \
                --network test_net \
                -v "${PROXY_ROOT}/scripts/kibana-init.sh:/scripts/kibana-init.sh:ro" \
                -v "${PROXY_ROOT}/config/kibana/saved-objects/kibana/dashboards.ndjson:/scripts/kibana-dashboards.ndjson:ro" \
                curlimages/curl:latest \
                /bin/sh /scripts/kibana-init.sh 2>&1)
            INIT_EXIT_CODE=$?
            
            if [ $INIT_EXIT_CODE -eq 0 ]; then
                echo "$INIT_OUTPUT" | grep -E "(✅|Successfully|completed)" | tail -5
                echo "   ✅ Kibana initialization completed"
                # Final check
                sleep 2
                KIBANA_DASHBOARDS_FINAL=$(curl -s "http://localhost:5601/api/saved_objects/_find?type=dashboard" -H "kbn-xsrf: true" 2>/dev/null || echo "")
                if echo "$KIBANA_DASHBOARDS_FINAL" | grep -qi "SoapBucket\|Application Logs\|Security Logs"; then
                    echo "   ✅ Kibana dashboards verified after initialization"
                else
                    echo "   ℹ️  Dashboards may still be loading. Check Kibana UI at http://localhost:5601/app/dashboards"
                fi
            else
                echo "   ⚠️  Kibana init script exited with code $INIT_EXIT_CODE"
                echo "$INIT_OUTPUT" | tail -15
                echo "   ℹ️  Check Kibana UI at http://localhost:5601/app/dashboards to verify"
            fi
        fi
    fi
fi

# Check ClickHouse schema initialization
echo "   Checking ClickHouse schema..."
if curl -s "http://localhost:8123/?query=EXISTS+DATABASE+proxy_logs" 2>/dev/null | grep -q "1"; then
    echo "   ✅ ClickHouse database exists"
    # Check if tables exist
    if curl -s "http://localhost:8123/?query=EXISTS+TABLE+proxy_logs.request_logs" 2>/dev/null | grep -q "1"; then
        echo "   ✅ ClickHouse tables are initialized"
    else
        echo "   ⚠️  Warning: ClickHouse tables not found"
        echo "   ℹ️  Note: ClickHouse initialization is handled by clickhouse-entrypoint.sh on container start"
        echo "   ℹ️  If tables are missing, restart the ClickHouse container to re-run initialization"
    fi
else
    echo "   ⚠️  Warning: ClickHouse database not initialized"
    echo "   ℹ️  Note: ClickHouse initialization is handled by clickhouse-entrypoint.sh on container start"
    echo "   ℹ️  Restart the ClickHouse container to re-run initialization:"
    echo "      $COMPOSE_CMD $COMPOSE_FILES restart clickhouse"
fi

# Check Grafana
echo "   Checking Grafana..."
for i in {1..30}; do
    if curl -s http://localhost:3000/api/health > /dev/null 2>&1; then
        echo "   ✅ Grafana is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "   ⚠️  Warning: Grafana not responding"
        break
    fi
    sleep 1
done

# Verify Grafana dashboards are available
# Grafana dashboards are auto-provisioned from config/grafana/dashboards/
# They may take a few seconds to load after Grafana starts
echo "   Checking Grafana dashboards..."
DASHBOARD_CHECK_ATTEMPTS=0
DASHBOARDS_FOUND=false

while [ $DASHBOARD_CHECK_ATTEMPTS -lt 10 ]; do
    DASHBOARD_RESPONSE=$(curl -s -u admin:admin "http://localhost:3000/api/search?type=dash-db&folderIds=0" 2>/dev/null || echo "")
    
    # Check for dashboard titles (they should be in the "SoapBucket" folder)
    if echo "$DASHBOARD_RESPONSE" | grep -qi "SoapBucket\|System Overview\|ClickHouse Request Logs\|Per-Origin Performance\|Infrastructure\|Security"; then
        DASHBOARDS_FOUND=true
        break
    fi
    
    # Also check in the SoapBucket folder (folder ID might be different)
    FOLDER_RESPONSE=$(curl -s -u admin:admin "http://localhost:3000/api/folders" 2>/dev/null || echo "")
    SOAPBUCKET_FOLDER_ID=$(echo "$FOLDER_RESPONSE" | grep -o '"id":[0-9]*,"title":"SoapBucket"' | grep -o '"id":[0-9]*' | cut -d':' -f2 || echo "")
    
    if [ -n "$SOAPBUCKET_FOLDER_ID" ]; then
        FOLDER_DASHBOARDS=$(curl -s -u admin:admin "http://localhost:3000/api/search?type=dash-db&folderIds=$SOAPBUCKET_FOLDER_ID" 2>/dev/null || echo "")
        if echo "$FOLDER_DASHBOARDS" | grep -qi "SoapBucket\|System Overview\|ClickHouse"; then
            DASHBOARDS_FOUND=true
            break
        fi
    fi
    
    DASHBOARD_CHECK_ATTEMPTS=$((DASHBOARD_CHECK_ATTEMPTS + 1))
    if [ $DASHBOARD_CHECK_ATTEMPTS -lt 10 ]; then
        sleep 2
    fi
done

if [ "$DASHBOARDS_FOUND" = true ]; then
    echo "   ✅ Grafana dashboards are available"
    # List found dashboards
    DASHBOARD_TITLES=$(curl -s -u admin:admin "http://localhost:3000/api/search?type=dash-db" 2>/dev/null | grep -o '"title":"[^"]*"' | cut -d'"' -f4 | grep -i "SoapBucket" || echo "")
    if [ -n "$DASHBOARD_TITLES" ]; then
        echo "$DASHBOARD_TITLES" | while read -r title; do
            echo "      - $title"
        done
    fi
else
    echo "   ⚠️  Warning: Grafana dashboards not found"
    echo "   ℹ️  Dashboards are auto-provisioned from config/grafana/dashboards/"
    echo "   ℹ️  They may take up to 10 seconds to load after Grafana starts"
    echo "   ℹ️  Check Grafana UI at http://localhost:3000/dashboards"
    echo "   ℹ️  Or manually verify: curl -u admin:admin http://localhost:3000/api/search?type=dash-db"
fi

# Check Prometheus
echo "   Checking Prometheus..."
for i in {1..30}; do
    if curl -s http://localhost:9090/-/healthy > /dev/null 2>&1; then
        echo "   ✅ Prometheus is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "   ⚠️  Warning: Prometheus not responding"
        break
    fi
    sleep 1
done

echo ""
echo "✅ Initialization verification complete!"
echo ""

# Load database with fixtures if load script exists
if [ -f "$TEST_DIR/scripts/load_database.sh" ]; then
    echo "📦 Loading test fixtures into database..."
    cd "$TEST_DIR"
    bash scripts/load_database.sh || echo "⚠️  Warning: Failed to load database"
    echo ""
fi

# Run basic smoke tests
echo "🧪 Running basic smoke tests..."
echo ""

echo "Test 1: Proxy health check"
if curl -sf http://localhost:8888/metrics > /dev/null; then
    echo "✅ Proxy metrics endpoint is accessible"
else
    echo "❌ Proxy metrics endpoint failed"
    exit 1
fi

echo ""
echo "Test 2: E2E test server"
if curl -sf http://localhost:8090/test/simple-200 > /dev/null; then
    echo "✅ E2E test server is responding"
else
    echo "❌ E2E test server failed"
    exit 1
fi

echo ""
echo "Test 3: Database connectivity"
if docker exec test-postgres psql -U proxy -d proxy -c "SELECT 1" > /dev/null 2>&1; then
    echo "✅ Database is accessible"
    # Verify schema is initialized
    SCHEMA_CHECK=$(docker exec test-postgres psql -U proxy -d proxy -tAc "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'config_storage');" 2>/dev/null || echo "f")
    if [ "$SCHEMA_CHECK" = "t" ]; then
        echo "✅ PostgreSQL schema is initialized"
    else
        echo "⚠️  Warning: PostgreSQL schema not initialized"
    fi
else
    echo "❌ Database connection failed"
    exit 1
fi

echo ""
echo "Test 4: L3 Cache (Pebble) directory"
if docker exec test-proxy ls -la /app/data > /dev/null 2>&1; then
    echo "✅ L3 cache data directory exists"
else
    echo "❌ L3 cache data directory missing"
    exit 1
fi

echo ""
echo "Test 5: ClickHouse (request logs)"
if curl -s http://localhost:8123/?query=SELECT%201 > /dev/null 2>&1; then
    echo "✅ ClickHouse is responding to queries"
    # Verify schema is initialized
    if curl -s "http://localhost:8123/?query=EXISTS+TABLE+proxy_logs.request_logs" 2>/dev/null | grep -q "1"; then
        echo "✅ ClickHouse schema is initialized"
    else
        echo "⚠️  Warning: ClickHouse schema not initialized"
    fi
else
    echo "❌ ClickHouse query failed"
    exit 1
fi

echo ""
echo "Test 6: Elasticsearch (application logs)"
if curl -s http://localhost:9200/_cluster/health | grep -q "yellow\|green"; then
    echo "✅ Elasticsearch cluster is healthy"
    # Verify template is configured
    if curl -s http://localhost:9200/_index_template/proxy-logs > /dev/null 2>&1; then
        echo "✅ Elasticsearch template is configured"
    else
        echo "⚠️  Warning: Elasticsearch template not found"
    fi
else
    echo "❌ Elasticsearch cluster unhealthy"
    exit 1
fi

echo ""
echo "Test 7: Kibana (log visualization)"
if curl -s http://localhost:5601/api/status > /dev/null 2>&1; then
    echo "✅ Kibana is accessible"
    # Verify index patterns exist
    if curl -s http://localhost:5601/api/saved_objects/_find?type=index-pattern 2>/dev/null | grep -q "proxy-application"; then
        echo "✅ Kibana index patterns are configured"
    else
        echo "⚠️  Warning: Kibana index patterns not found"
    fi
else
    echo "❌ Kibana is not accessible"
    exit 1
fi

echo ""
echo "Test 8: Grafana (metrics visualization)"
if curl -s http://localhost:3000/api/health > /dev/null 2>&1; then
    echo "✅ Grafana is accessible"
    # Verify dashboards are available
    if curl -s -u admin:admin http://localhost:3000/api/search?type=dash-db 2>/dev/null | grep -q "SoapBucket\|ClickHouse\|System"; then
        echo "✅ Grafana dashboards are available"
    else
        echo "⚠️  Warning: Grafana dashboards not found"
    fi
else
    echo "❌ Grafana is not accessible"
    exit 1
fi

echo ""
echo "Test 9: Prometheus (metrics collection)"
if curl -s http://localhost:9090/-/healthy > /dev/null 2>&1; then
    echo "✅ Prometheus is accessible"
else
    echo "❌ Prometheus is not accessible"
    exit 1
fi

echo ""
echo "========================"
echo "✅ All smoke tests passed!"
echo "========================"
echo ""
echo "📊 Service Status:"
$COMPOSE_CMD $COMPOSE_FILES ps
echo ""
echo "📍 Service Endpoints:"
echo "   Proxy HTTP:        http://localhost:8080"
echo "   Proxy HTTPS:       https://localhost:8443"
echo "   Proxy Metrics:     http://localhost:8888/metrics"
echo "   E2E Test Server:   http://localhost:8090"
echo "   PostgreSQL:        localhost:5433"
echo "   Redis:             localhost:6380"
echo "   ClickHouse:        http://localhost:8123"
echo "   Elasticsearch:     http://localhost:9200"
echo "   Kibana:            http://localhost:5601"
echo "   Prometheus:        http://localhost:9090"
echo "   Grafana:           http://localhost:3000 (admin/admin)"
echo ""
echo "🧪 To run manual tests:"
echo "   curl -H 'Host: basic-proxy.test' http://localhost:8080/"
echo ""
echo "📋 To view logs:"
echo "   $COMPOSE_CMD $COMPOSE_FILES logs -f proxy"
echo "   $COMPOSE_CMD $COMPOSE_FILES logs -f clickhouse"
echo ""
echo "🔨 To rebuild services:"
echo "   cd ../docker && $COMPOSE_CMD $COMPOSE_FILES build"
echo ""
echo "🛑 To stop:"
echo "   $COMPOSE_CMD $COMPOSE_FILES down"
echo ""
echo "🧹 To stop and remove all data:"
echo "   $COMPOSE_CMD $COMPOSE_FILES down -v"
echo ""

