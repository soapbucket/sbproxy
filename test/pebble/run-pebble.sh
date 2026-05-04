#!/usr/bin/env bash
# Start/stop Pebble ACME test environment.
#
# Usage:
#   ./run-pebble.sh up      # start containers, wait for readiness
#   ./run-pebble.sh down    # stop and remove containers
#   ./run-pebble.sh status  # check if running

set -euo pipefail
cd "$(dirname "$0")"

case "${1:-up}" in
  up)
    echo "Starting Pebble ACME test server..."
    docker compose up -d

    echo "Waiting for Pebble to be ready..."
    for i in $(seq 1 30); do
      if curl -sk https://localhost:14000/dir >/dev/null 2>&1; then
        echo "Pebble is ready (ACME directory: https://localhost:14000/dir)"
        echo "Challenge test server: http://localhost:8055"

        # Fetch and display Pebble's root CA cert for trust configuration.
        echo ""
        echo "Pebble root CA cert (add to PEBBLE_CA_CERT in tests):"
        curl -sk https://localhost:15000/roots/0 | head -1
        echo "  ... (use full output for test config)"
        exit 0
      fi
      sleep 1
    done
    echo "ERROR: Pebble did not become ready in 30s"
    docker compose logs
    exit 1
    ;;

  down)
    echo "Stopping Pebble..."
    docker compose down
    echo "Done."
    ;;

  status)
    if curl -sk https://localhost:14000/dir >/dev/null 2>&1; then
      echo "Pebble is running"
      curl -sk https://localhost:14000/dir | python3 -m json.tool 2>/dev/null || true
    else
      echo "Pebble is not running"
    fi
    ;;

  *)
    echo "Usage: $0 {up|down|status}"
    exit 1
    ;;
esac
