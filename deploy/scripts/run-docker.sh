#!/bin/bash
#
# Soapbucket Docker Runner
# ========================
# A unified script to run Docker containers for the Soapbucket project.
#
# Usage:
#   ./run-docker.sh [command] [options]
#
# Commands:
#   up          Start all services (default)
#   down        Stop all services
#   restart     Restart all services
#   logs        View logs (use -f to follow)
#   status      Show container status
#   build       Build the proxy image
#   clean       Stop and remove all containers and volumes
#
# Options:
#   -d, --detach     Run in background (default for 'up')
#   -f, --follow     Follow logs (for 'logs' command)
#   --proxy-only     Start only the proxy service (no observability stack)
#   --minimal        Start proxy with postgres and redis (no observability)
#   --file-only      Start proxy with redis only (for file-based storage, no postgres)
#   --acme           Include Pebble ACME test server
#   --rebuild        Force rebuild before starting
#
# Flag combinations:
#   --file-only              proxy + redis (file storage)
#   --file-only --acme       proxy + redis + pebble
#   --minimal                proxy + postgres + redis
#   --minimal --acme         proxy + postgres + redis + pebble
#   --minimal --file-only    proxy + redis (same as --file-only, postgres skipped)
#   -h, --help       Show this help message
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKER_DIR="${PROXY_DIR}/docker"

# Default environment variables
export ENV_PREFIX="${ENV_PREFIX:-}"
export ENV_NETWORK="${ENV_NETWORK:-proxy_net}"
export POSTGRES_PORT="${POSTGRES_PORT:-5432}"
export REDIS_PORT="${REDIS_PORT:-6379}"
export CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
export CLICKHOUSE_NATIVE_PORT="${CLICKHOUSE_NATIVE_PORT:-9000}"
export ELASTICSEARCH_HTTP_PORT="${ELASTICSEARCH_HTTP_PORT:-9200}"
export ELASTICSEARCH_TRANSPORT_PORT="${ELASTICSEARCH_TRANSPORT_PORT:-9300}"
export KIBANA_PORT="${KIBANA_PORT:-5601}"
export PROMETHEUS_PORT="${PROMETHEUS_PORT:-9090}"
export GRAFANA_PORT="${GRAFANA_PORT:-3000}"
export PROXY_HTTP_PORT="${PROXY_HTTP_PORT:-8080}"
export PROXY_HTTPS_PORT="${PROXY_HTTPS_PORT:-8443}"
export PROXY_TELEMETRY_PORT="${PROXY_TELEMETRY_PORT:-8888}"
export FLUENT_BIT_PORT="${FLUENT_BIT_PORT:-2020}"
export ELASTICSEARCH_HEAP="${ELASTICSEARCH_HEAP:-1g}"
# Storage configuration
export STORAGE_FILE_PATH="${STORAGE_FILE_PATH:-/app/config/sites.json}"
# ACME test server ports
export PEBBLE_ACME_PORT="${PEBBLE_ACME_PORT:-14000}"
export PEBBLE_MGMT_PORT="${PEBBLE_MGMT_PORT:-15000}"
# ACME configuration (set by --acme flag)
export ENABLE_ACME="${ENABLE_ACME:-false}"
export ACME_EMAIL="${ACME_EMAIL:-acme@soapbucket.dev}"
export ACME_DIRECTORY_URL="${ACME_DIRECTORY_URL:-}"
export ACME_INSECURE_SKIP_VERIFY="${ACME_INSECURE_SKIP_VERIFY:-false}"

# Functions
print_header() {
    echo -e "\n${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  🧼 Soapbucket Docker Runner${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}→${NC} $1"
}

print_section() {
    echo -e "\n${BLUE}▸${NC} ${BOLD}$1${NC}"
}

show_help() {
    cat << EOF
${BOLD}Soapbucket Docker Runner${NC}

${BOLD}USAGE:${NC}
    ./run-docker.sh [command] [options]

${BOLD}COMMANDS:${NC}
    up          Start all services (default)
    down        Stop all services
    restart     Restart all services
    logs        View logs (use -f to follow)
    status      Show container status
    build       Build the proxy image only
    clean       Stop and remove all containers and volumes

${BOLD}OPTIONS:${NC}
    -d, --detach     Run in background (default for 'up')
    -f, --follow     Follow logs (for 'logs' command)
    --proxy-only     Start only the proxy service (no deps)
    --minimal        Start proxy with postgres + redis (no observability)
    --file-only      Start proxy with redis only (no postgres, for file storage)
    --acme           Include Pebble ACME test server (https://localhost:14000/dir)
    --rebuild        Force rebuild before starting

${BOLD}FLAG COMBINATIONS:${NC}
    --file-only              proxy + redis (file storage)
    --file-only --acme       proxy + redis + pebble
    --minimal                proxy + postgres + redis
    --minimal --file-only    proxy + redis (postgres skipped when using file storage)
    -h, --help       Show this help message

${BOLD}ENVIRONMENT VARIABLES:${NC}
    PROXY_HTTP_PORT       HTTP port (default: 8080)
    PROXY_HTTPS_PORT      HTTPS port (default: 8443)
    GRAFANA_PORT          Grafana port (default: 3000)
    PROMETHEUS_PORT       Prometheus port (default: 9090)
    KIBANA_PORT           Kibana port (default: 5601)
    STORAGE_FILE_PATH     Path to origins file (default: /app/config/sites.json)
    PEBBLE_ACME_PORT      Pebble ACME server port (default: 14000)

${BOLD}EXAMPLES:${NC}
    ./run-docker.sh                     # Start all services
    ./run-docker.sh up --minimal        # Start minimal stack
    ./run-docker.sh logs -f proxy       # Follow proxy logs
    ./run-docker.sh down                # Stop all services
    ./run-docker.sh clean               # Clean everything
    PROXY_HTTP_PORT=9090 ./run-docker.sh up  # Custom port

${BOLD}SERVICE URLS (after startup):${NC}
    Proxy HTTP:    http://localhost:${PROXY_HTTP_PORT}
    Proxy HTTPS:   https://localhost:${PROXY_HTTPS_PORT}
    Grafana:       http://localhost:${GRAFANA_PORT} (admin/admin)
    Prometheus:    http://localhost:${PROMETHEUS_PORT}
    Kibana:        http://localhost:${KIBANA_PORT}
    ClickHouse:    http://localhost:${CLICKHOUSE_HTTP_PORT}
EOF
}

show_status() {
    print_section "Container Status"
    docker compose -f "${DOCKER_DIR}/docker-compose.yml" ps 2>/dev/null || {
        print_info "No containers running"
    }
}

show_urls() {
    print_section "Service URLs"
    echo -e "    ${GREEN}Proxy HTTP:${NC}    http://localhost:${PROXY_HTTP_PORT}"
    echo -e "    ${GREEN}Proxy HTTPS:${NC}   https://localhost:${PROXY_HTTPS_PORT}"
    echo -e "    ${GREEN}Telemetry:${NC}     http://localhost:${PROXY_TELEMETRY_PORT}/metrics"
    echo -e "    ${GREEN}Grafana:${NC}       http://localhost:${GRAFANA_PORT} (admin/admin)"
    echo -e "    ${GREEN}Prometheus:${NC}    http://localhost:${PROMETHEUS_PORT}"
    echo -e "    ${GREEN}Kibana:${NC}        http://localhost:${KIBANA_PORT}"
    echo -e "    ${GREEN}ClickHouse:${NC}    http://localhost:${CLICKHOUSE_HTTP_PORT}"
}

do_up() {
    local services=""
    local compose_args="-d"
    local rebuild=""
    local no_deps=""
    local profile_args=""
    
    if [ "$REBUILD" = true ]; then
        rebuild="--build"
    fi
    
    if [ "$WITH_ACME" = true ]; then
        profile_args="--profile acme"
        # Enable ACME certificate generation with Pebble
        export ENABLE_ACME="true"
        export ACME_EMAIL="${ACME_EMAIL:-acme@soapbucket.dev}"
        export ACME_DIRECTORY_URL="https://pebble:14000/dir"
        export ACME_INSECURE_SKIP_VERIFY="true"
        print_info "Including Pebble ACME test server (auto-generating certificates)"
    fi
    
    if [ "$PROXY_ONLY" = true ]; then
        services="proxy"
        no_deps="--no-deps"
        print_info "Starting proxy only (no dependencies)"
    elif [ "$FILE_ONLY" = true ]; then
        # FILE_ONLY mode: proxy + redis only (no postgres needed for file storage)
        # This applies whether --minimal is also passed or not
        # For file-only mode, start only redis + e2e-test-server + proxy
        print_info "Starting file-only stack (proxy + redis + e2e-test-server, using sites.json)"
        cd "${DOCKER_DIR}"
        
        # Start Pebble ACME server if requested
        if [ "$WITH_ACME" = true ]; then
            print_info "Starting Pebble ACME test server..."
            if ! docker compose -f docker-compose.yml $profile_args up -d $rebuild pebble; then
                print_error "Failed to start Pebble"
                exit 1
            fi
            # Wait for Pebble to be ready (check from host since container has no shell)
            print_info "Waiting for Pebble to be ready..."
            local pebble_retries=30
            while [ $pebble_retries -gt 0 ]; do
                if curl -sk "https://localhost:${PEBBLE_ACME_PORT}/dir" >/dev/null 2>&1; then
                    print_success "Pebble ACME server is ready"
                    break
                fi
                sleep 1
                pebble_retries=$((pebble_retries - 1))
            done
            if [ $pebble_retries -eq 0 ]; then
                print_error "Pebble failed to become ready"
                docker logs pebble --tail 10
                exit 1
            fi
            # Start challenge test server
            docker compose -f docker-compose.yml $profile_args up -d $rebuild challtestsrv || true
        fi
        
        # Start redis and test server
        print_info "Starting Redis and E2E Test Server..."
        if ! docker compose -f docker-compose.yml $profile_args up -d $rebuild redis e2e-test-server proxy-data-init; then
            print_error "Failed to start dependencies"
            exit 1
        fi
        
        # Wait for redis and test server to be healthy
        print_info "Waiting for dependencies to be ready..."
        local retries=30
        while [ $retries -gt 0 ]; do
            if docker compose -f docker-compose.yml $profile_args ps redis 2>/dev/null | grep -q "healthy" && \
               docker compose -f docker-compose.yml $profile_args ps e2e-test-server 2>/dev/null | grep -q "healthy"; then
                break
            fi
            sleep 1
            retries=$((retries - 1))
        done
        
        if [ $retries -eq 0 ]; then
            print_error "Dependencies failed to become healthy"
            exit 1
        fi
        
        # Start proxy without dependencies
        print_info "Starting proxy..."
        if docker compose -f docker-compose.yml $profile_args up -d --no-deps $rebuild proxy; then
            print_success "Services started successfully"
            print_section "Service URLs (file-only mode)"
            echo -e "    ${GREEN}Proxy HTTP:${NC}    http://localhost:${PROXY_HTTP_PORT}"
            echo -e "    ${GREEN}Proxy HTTPS:${NC}   https://localhost:${PROXY_HTTPS_PORT}"
            echo -e "    ${GREEN}Telemetry:${NC}     http://localhost:${PROXY_TELEMETRY_PORT}/metrics"
            echo -e "    ${GREEN}Storage:${NC}       ${STORAGE_FILE_PATH} (file-based)"
            echo -e "    ${GREEN}Test Backend:${NC}  e2e-test-server:8090"
            if [ "$WITH_ACME" = true ]; then
                echo -e "    ${GREEN}Pebble ACME:${NC}   https://localhost:${PEBBLE_ACME_PORT}/dir"
            fi
        else
            print_error "Failed to start proxy"
            exit 1
        fi
        return 0
    elif [ "$MINIMAL" = true ]; then
        # MINIMAL mode (without --file-only): proxy + postgres + redis + e2e-test-server
        print_info "Starting minimal stack (proxy + postgres + redis + e2e-test-server)"
        cd "${DOCKER_DIR}"
        
        # Start Pebble ACME server if requested
        if [ "$WITH_ACME" = true ]; then
            print_info "Starting Pebble ACME test server..."
            if ! docker compose -f docker-compose.yml $profile_args up -d $rebuild pebble; then
                print_error "Failed to start Pebble"
                exit 1
            fi
            print_info "Waiting for Pebble to be ready..."
            local pebble_retries=30
            while [ $pebble_retries -gt 0 ]; do
                if curl -sk "https://localhost:${PEBBLE_ACME_PORT}/dir" >/dev/null 2>&1; then
                    print_success "Pebble ACME server is ready"
                    break
                fi
                sleep 1
                pebble_retries=$((pebble_retries - 1))
            done
            if [ $pebble_retries -eq 0 ]; then
                print_error "Pebble failed to become ready"
                docker logs pebble --tail 10
                exit 1
            fi
            docker compose -f docker-compose.yml $profile_args up -d $rebuild challtestsrv || true
        fi
        
        # Start dependencies
        print_info "Starting dependency services..."
        if ! docker compose -f docker-compose.yml $profile_args up -d $rebuild postgres redis e2e-test-server proxy-data-init; then
            print_error "Failed to start dependency services"
            exit 1
        fi
        
        # Wait for dependencies to be healthy
        print_info "Waiting for dependency services to be ready..."
        local retries=30
        while [ $retries -gt 0 ]; do
            if docker compose -f docker-compose.yml $profile_args ps postgres 2>/dev/null | grep -q "healthy" && \
               docker compose -f docker-compose.yml $profile_args ps redis 2>/dev/null | grep -q "healthy" && \
               docker compose -f docker-compose.yml $profile_args ps e2e-test-server 2>/dev/null | grep -q "healthy"; then
                break
            fi
            sleep 1
            retries=$((retries - 1))
        done
        
        if [ $retries -eq 0 ]; then
            print_error "Dependency services failed to become healthy"
            exit 1
        fi
        
        # Start proxy without dependencies (skip fluent-bit -> elasticsearch chain)
        print_info "Starting proxy..."
        if docker compose -f docker-compose.yml $profile_args up -d --no-deps $rebuild proxy; then
            print_success "Services started successfully"
            print_section "Service URLs (minimal mode)"
            echo -e "    ${GREEN}Proxy HTTP:${NC}    http://localhost:${PROXY_HTTP_PORT}"
            echo -e "    ${GREEN}Proxy HTTPS:${NC}   https://localhost:${PROXY_HTTPS_PORT}"
            echo -e "    ${GREEN}Telemetry:${NC}     http://localhost:${PROXY_TELEMETRY_PORT}/metrics"
            echo -e "    ${GREEN}PostgreSQL:${NC}    localhost:${POSTGRES_PORT}"
            echo -e "    ${GREEN}Test Backend:${NC}  e2e-test-server:8090"
            if [ "$WITH_ACME" = true ]; then
                echo -e "    ${GREEN}Pebble ACME:${NC}   https://localhost:${PEBBLE_ACME_PORT}/dir"
            fi
        else
            print_error "Failed to start proxy"
            exit 1
        fi
        return 0
    else
        print_info "Starting full stack..."
    fi
    
    cd "${DOCKER_DIR}"
    
    if docker compose -f docker-compose.yml $profile_args up $compose_args $rebuild $no_deps $services; then
        print_success "Services started successfully"
        show_urls
        if [ "$WITH_ACME" = true ]; then
            echo -e "    ${GREEN}Pebble ACME:${NC}   https://localhost:${PEBBLE_ACME_PORT}/dir"
        fi
    else
        print_error "Failed to start services"
        exit 1
    fi
}

do_down() {
    print_info "Stopping all services..."
    cd "${DOCKER_DIR}"
    
    local profile_args=""
    if [ "$WITH_ACME" = true ]; then
        profile_args="--profile acme"
    fi
    
    if docker compose -f docker-compose.yml $profile_args down; then
        print_success "Services stopped"
    else
        print_error "Failed to stop services"
        exit 1
    fi
}

do_restart() {
    print_info "Restarting services..."
    do_down
    do_up
}

do_logs() {
    local follow_flag=""
    local service="$1"
    
    if [ "$FOLLOW" = true ]; then
        follow_flag="-f"
    fi
    
    cd "${DOCKER_DIR}"
    docker compose -f docker-compose.yml logs $follow_flag $service
}

do_build() {
    print_info "Building proxy image..."
    cd "${DOCKER_DIR}"
    
    # Get build metadata
    BUILD_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    if docker compose -f docker-compose.yml build \
        --build-arg BUILD_HASH="$BUILD_HASH" \
        --build-arg BUILD_DATE="$BUILD_DATE" \
        proxy; then
        print_success "Image built successfully"
    else
        print_error "Failed to build image"
        exit 1
    fi
}

do_clean() {
    print_info "Stopping and removing all containers and volumes..."
    cd "${DOCKER_DIR}"
    
    docker compose -f docker-compose.yml down -v --remove-orphans 2>/dev/null || true
    
    # Remove any dangling images
    print_info "Cleaning up dangling images..."
    docker image prune -f 2>/dev/null || true
    
    print_success "Cleanup complete"
}

# Parse arguments
COMMAND=""
FOLLOW=false
PROXY_ONLY=false
MINIMAL=false
FILE_ONLY=false
WITH_ACME=false
REBUILD=false
EXTRA_ARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        up|down|restart|logs|status|build|clean)
            COMMAND="$1"
            shift
            ;;
        -d|--detach)
            # Default behavior for 'up'
            shift
            ;;
        -f|--follow)
            FOLLOW=true
            shift
            ;;
        --proxy-only)
            PROXY_ONLY=true
            shift
            ;;
        --minimal)
            MINIMAL=true
            shift
            ;;
        --file-only)
            FILE_ONLY=true
            shift
            ;;
        --acme)
            WITH_ACME=true
            shift
            ;;
        --rebuild)
            REBUILD=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -*)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
        *)
            EXTRA_ARGS="$EXTRA_ARGS $1"
            shift
            ;;
    esac
done

# Default command is 'up'
COMMAND="${COMMAND:-up}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if docker-compose.yml exists
if [ ! -f "${DOCKER_DIR}/docker-compose.yml" ]; then
    print_error "docker-compose.yml not found at ${DOCKER_DIR}"
    exit 1
fi

print_header

# Execute command
case "$COMMAND" in
    up)
        do_up
        ;;
    down)
        do_down
        ;;
    restart)
        do_restart
        ;;
    logs)
        do_logs $EXTRA_ARGS
        ;;
    status)
        show_status
        ;;
    build)
        do_build
        ;;
    clean)
        do_clean
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac
