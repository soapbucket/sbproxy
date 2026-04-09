#!/bin/bash
# Kibana initialization script
# This script creates default index patterns in Kibana

# Don't exit on error - we want to continue even if some steps fail
set +e

# Wait for Kibana to be ready
echo "Waiting for Kibana to be ready..."
MAX_RETRIES=60
RETRY_COUNT=0

until curl -s http://kibana:5601/api/status | grep -q '"level":"available"'; do
  RETRY_COUNT=$((RETRY_COUNT + 1))
  if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
    echo "Kibana failed to become ready after $MAX_RETRIES attempts"
    exit 1
  fi
  echo "Kibana is not ready yet. Waiting... (attempt $RETRY_COUNT/$MAX_RETRIES)"
  sleep 5
done

echo "Kibana is ready!"

# Function to create index pattern if it doesn't exist
create_index_pattern() {
  local pattern=$1
  local title=$2
  
  echo "Creating index pattern: $pattern"
  
  # Check if index pattern already exists by searching for the exact title
  existing=$(curl -s -X GET "http://kibana:5601/api/saved_objects/_find?type=index-pattern&search=$title" \
    -H "kbn-xsrf: true" | grep -o "\"id\":\"[^\"]*\"" | head -1 | cut -d'"' -f4)
  
  if [ -n "$existing" ]; then
    echo "Index pattern $pattern already exists (id: $existing), skipping..."
    return 0
  fi
  
  # Create index pattern
  response=$(curl -s -X POST "http://kibana:5601/api/saved_objects/index-pattern/$pattern" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "{
      \"attributes\": {
        \"title\": \"$title\",
        \"timeFieldName\": \"@timestamp\"
      }
    }")
  
  if echo "$response" | grep -q '"id"'; then
    echo "Successfully created index pattern: $pattern"
    return 0
  else
    echo "Warning: Failed to create index pattern $pattern: $response"
    return 1
  fi
}

# Create default index patterns
echo "Creating default Kibana index patterns..."

# Create proxy-application-* index pattern
create_index_pattern "proxy-application-pattern" "proxy-application-*"

# Create proxy-security-* index pattern
create_index_pattern "proxy-security-pattern" "proxy-security-*"

# Wait for index patterns to be fully available
echo "Waiting for index patterns to be fully available..."
sleep 3

# Verify index patterns exist before importing dashboards
verify_index_pattern() {
  local pattern_id=$1
  local pattern_title=$2
  
  for i in {1..10}; do
    if curl -s -X GET "http://kibana:5601/api/saved_objects/index-pattern/$pattern_id" \
      -H "kbn-xsrf: true" 2>/dev/null | grep -q '"id"'; then
      echo "✅ Index pattern $pattern_title is available"
      return 0
    fi
    if [ $i -lt 10 ]; then
      sleep 1
    fi
  done
  echo "⚠️  Warning: Index pattern $pattern_title may not be fully available"
  return 1
}

verify_index_pattern "proxy-application-pattern" "proxy-application-*"
verify_index_pattern "proxy-security-pattern" "proxy-security-*"

# Import dashboards if file exists
if [ -f "/scripts/kibana-dashboards.ndjson" ]; then
  echo ""
  echo "Importing Kibana dashboards..."
  
  # Import dashboards with proper error handling
  response=$(curl -s -w "\n%{http_code}" -X POST "http://kibana:5601/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: multipart/form-data" \
    --form file=@/scripts/kibana-dashboards.ndjson 2>&1)
  
  http_code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" = "200" ]; then
    # Check if import was successful
    if echo "$body" | grep -q '"success":true' || echo "$body" | grep -q '"successCount"'; then
      success_count=$(echo "$body" | grep -o '"successCount":[0-9]*' | cut -d':' -f2 || echo "0")
      error_count=$(echo "$body" | grep -o '"errorCount":[0-9]*' | cut -d':' -f2 || echo "0")
      echo "Successfully imported Kibana dashboards (success: $success_count, errors: $error_count)"
      
      # Verify dashboards exist
      echo "Verifying dashboards were imported..."
      dashboards=$(curl -s -X GET "http://kibana:5601/api/saved_objects/_find?type=dashboard" \
        -H "kbn-xsrf: true" | grep -o '"title":"[^"]*"' | cut -d'"' -f4 || echo "")
      
      if echo "$dashboards" | grep -q "SoapBucket Proxy"; then
        echo "✅ Dashboards verified:"
        echo "$dashboards" | grep "SoapBucket Proxy" | sed 's/^/   - /'
      else
        echo "⚠️  Warning: Dashboards may not have been imported correctly"
      fi
    else
      echo "⚠️  Warning: Import response indicates failure: $body"
    fi
  else
    echo "❌ Error: Failed to import dashboards (HTTP $http_code)"
    echo "Response: $body"
  fi
else
  echo "⚠️  Warning: Dashboard file not found at /scripts/kibana-dashboards.ndjson, skipping dashboard import"
fi

# Check if we had any critical failures
if [ $? -ne 0 ]; then
    echo ""
    echo "⚠️  Kibana initialization completed with some warnings"
    exit 1
else
    echo ""
    echo "✅ Kibana initialization completed successfully!"
    exit 0
fi

