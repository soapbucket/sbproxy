#!/bin/bash

# Script to add HackerNews chunk cache test configs to sites.json
# Usage: ./add_hn_test_configs.sh

SITES_JSON="/Users/rick/projects/soapbucket/proxy/config/sites/sites.json"
TEST_CONFIGS="/Users/rick/projects/proxy/test/fixtures/chunk_cache_test_configs.json"

echo "Adding HackerNews chunk cache test configs to sites.json..."

# Backup original
cp "$SITES_JSON" "${SITES_JSON}.backup.$(date +%Y%m%d_%H%M%S)"
echo "✅ Backup created: ${SITES_JSON}.backup.$(date +%Y%m%d_%H%M%S)"

# Convert test configs array to object with hostname keys, then merge
jq --slurpfile sites "$SITES_JSON" '
  .configs | 
  map({(.hostname): .}) | 
  add as $new_configs |
  $sites[0] + $new_configs
' "$TEST_CONFIGS" > "${SITES_JSON}.tmp"

# Check if jq succeeded
if [ $? -eq 0 ]; then
  mv "${SITES_JSON}.tmp" "$SITES_JSON"
  echo "✅ Successfully added configs to sites.json"
else
  echo "❌ Error processing JSON, backup preserved"
  rm -f "${SITES_JSON}.tmp"
  exit 1
fi

echo "✅ Added configs to sites.json"
echo ""
echo "Test hostnames added:"
echo "  - hn-signature.test"
echo "  - hn-url.test"
echo "  - hn-hybrid.test"
echo "  - hn-ignore-nocache.test"
echo "  - hn-modifiers.test"
echo "  - hn-exact.test"
echo "  - hn-hash.test"
echo ""
echo "Add these to /etc/hosts or DNS:"
echo "  127.0.0.1 hn-signature.test"
echo "  127.0.0.1 hn-url.test"
echo "  127.0.0.1 hn-hybrid.test"
echo "  127.0.0.1 hn-ignore-nocache.test"
echo "  127.0.0.1 hn-modifiers.test"
echo "  127.0.0.1 hn-exact.test"
echo "  127.0.0.1 hn-hash.test"
echo ""
echo "Reload proxy to apply changes"

