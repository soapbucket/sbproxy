#!/bin/sh
# Docker entrypoint script to fix permissions and start proxy

set -e

# Fix permissions for data directory if it exists and is mounted
if [ -d "/app/data" ]; then
    # Check if we can write (if not, try to fix permissions)
    if [ ! -w "/app/data" ]; then
        # If running as non-root, try to fix permissions
        # This will only work if the volume allows it
        chmod 755 /app/data 2>/dev/null || true
    fi
fi

# Execute the proxy binary with all arguments
exec /app/proxy "$@"

