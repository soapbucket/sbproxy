#!/bin/bash
# ACME Certificate E2E Testing Script
# Tests ACME certificate issuance using Pebble (Let's Encrypt's test server)
#
# Usage:
#   ./scripts/test-acme.sh          # Run all tests
#   ./scripts/test-acme.sh unit     # Run only unit tests
#   ./scripts/test-acme.sh e2e      # Run only E2E tests with Pebble
#   ./scripts/test-acme.sh cleanup  # Clean up Docker containers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Docker compose file
COMPOSE_FILE="$PROJECT_ROOT/docker/docker-compose.acme-test.yml"

# Pebble ACME directory URL
PEBBLE_ACME_URL="https://localhost:14000/dir"

# Wait timeout for Pebble (seconds)
PEBBLE_WAIT_TIMEOUT=60

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Run unit tests for ACME components
run_unit_tests() {
    log_info "Running ACME unit tests..."
    
    cd "$PROJECT_ROOT"
    
    # Run TLS service tests
    log_info "Testing internal/service (TLS config)..."
    go test -v ./internal/service/... -run "TestGetACMETLSConfig|TestCache" -count=1
    
    # Run ACME cache tests
    log_info "Testing lib/acmecache..."
    go test -v ./lib/acmecache/... -count=1
    
    log_success "Unit tests completed!"
}

# Start Pebble ACME test server
start_pebble() {
    log_info "Starting Pebble ACME test server..."
    
    cd "$PROJECT_ROOT"
    
    # Check if Pebble is already running
    if docker ps --format '{{.Names}}' | grep -q "pebble-acme"; then
        log_warn "Pebble is already running"
        return 0
    fi
    
    # Start Pebble
    docker compose -f "$COMPOSE_FILE" up -d pebble
    
    # Wait for Pebble to be healthy
    log_info "Waiting for Pebble to be ready (timeout: ${PEBBLE_WAIT_TIMEOUT}s)..."
    
    local elapsed=0
    while [ $elapsed -lt $PEBBLE_WAIT_TIMEOUT ]; do
        if curl -sk "$PEBBLE_ACME_URL" > /dev/null 2>&1; then
            log_success "Pebble is ready!"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
        echo -n "."
    done
    
    echo ""
    log_error "Pebble failed to start within ${PEBBLE_WAIT_TIMEOUT}s"
    docker compose -f "$COMPOSE_FILE" logs pebble
    return 1
}

# Stop Pebble
stop_pebble() {
    log_info "Stopping Pebble ACME test server..."
    cd "$PROJECT_ROOT"
    docker compose -f "$COMPOSE_FILE" down -v
    log_success "Pebble stopped"
}

# Run E2E integration tests with Pebble
run_e2e_tests() {
    log_info "Running ACME E2E tests with Pebble..."
    
    cd "$PROJECT_ROOT"
    
    # Ensure Pebble is running
    start_pebble
    
    # Run integration tests
    log_info "Running integration tests..."
    PEBBLE_ACME_URL="$PEBBLE_ACME_URL" \
        go test -tags=integration -v ./internal/service/... -run TestACME -count=1 -timeout 120s
    
    log_success "E2E tests completed!"
}

# Show Pebble logs
show_logs() {
    log_info "Pebble logs:"
    cd "$PROJECT_ROOT"
    docker compose -f "$COMPOSE_FILE" logs pebble
}

# Test ACME directory endpoint
test_pebble_connection() {
    log_info "Testing Pebble ACME directory..."
    
    if curl -sk "$PEBBLE_ACME_URL" | jq . > /dev/null 2>&1; then
        log_success "Pebble ACME directory is accessible"
        curl -sk "$PEBBLE_ACME_URL" | jq .
        return 0
    else
        log_error "Cannot connect to Pebble"
        return 1
    fi
}

# Print usage
usage() {
    echo "ACME Certificate E2E Testing Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  unit       Run unit tests only"
    echo "  e2e        Run E2E tests with Pebble"
    echo "  start      Start Pebble ACME server"
    echo "  stop       Stop Pebble ACME server"
    echo "  logs       Show Pebble logs"
    echo "  test       Test Pebble connection"
    echo "  cleanup    Stop and remove all containers"
    echo "  all        Run all tests (default)"
    echo ""
    echo "Environment Variables:"
    echo "  PEBBLE_ACME_URL   Pebble ACME directory URL (default: $PEBBLE_ACME_URL)"
    echo ""
    echo "Examples:"
    echo "  $0              # Run all tests"
    echo "  $0 unit         # Run only unit tests"
    echo "  $0 e2e          # Run E2E tests with Pebble"
    echo "  $0 start        # Start Pebble for manual testing"
}

# Main entry point
main() {
    local command="${1:-all}"
    
    echo "========================================"
    echo "  ACME Certificate Testing"
    echo "========================================"
    echo ""
    
    case "$command" in
        unit)
            run_unit_tests
            ;;
        e2e)
            run_e2e_tests
            ;;
        start)
            start_pebble
            test_pebble_connection
            log_info "Pebble is running. Use 'PEBBLE_ACME_URL=$PEBBLE_ACME_URL go test -tags=integration ...' to run tests"
            ;;
        stop)
            stop_pebble
            ;;
        logs)
            show_logs
            ;;
        test)
            test_pebble_connection
            ;;
        cleanup)
            stop_pebble
            ;;
        all)
            run_unit_tests
            echo ""
            run_e2e_tests
            echo ""
            stop_pebble
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
    
    echo ""
    echo "========================================"
    echo "  Testing Complete"
    echo "========================================"
}

main "$@"
