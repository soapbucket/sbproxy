#!/bin/bash
set -e

echo "Checking pkg/ has no internal imports..."
if go list -f '{{range .Imports}}{{.}}{{"\n"}}{{end}}' ./pkg/... 2>/dev/null | grep -q "internal/"; then
    echo "FAIL: pkg/ imports internal/"
    exit 1
fi

echo "Checking for banned enterprise dependencies..."
# Use 'go list -deps' to check actually-compiled package dependencies,
# not 'go list -m all' which includes transitive module metadata that
# may never be compiled (e.g., stow's go.mod declares aws-sdk-go even
# though we only use non-AWS storage backends).
DEPS=$(go list -deps ./... 2>/dev/null)
for banned in "aws-sdk-go" "cloud.google.com/go/kms" "cloud.google.com/go/secretmanager" "clickhouse" "tetratelabs/wazero" "oschwald/maxminddb"; do
    if echo "$DEPS" | grep -q "$banned"; then
        echo "FAIL: core depends on $banned"
        exit 1
    fi
done

echo "Import guard: PASS"
