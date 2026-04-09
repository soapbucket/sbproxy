#!/bin/bash
# Elasticsearch initialization script
# This script sets up index templates and initial configuration for Elasticsearch

set -e

# Wait for Elasticsearch to be ready
echo "Waiting for Elasticsearch to be ready..."
until curl -s http://elasticsearch:9200/_cluster/health | grep -q '"status":"green"\|"status":"yellow"'; do
  echo "Elasticsearch is not ready yet. Waiting..."
  sleep 5
done

echo "Elasticsearch is ready!"

# Create index template for proxy logs
echo "Creating index template for proxy logs..."
curl -X PUT "http://elasticsearch:9200/_index_template/proxy-logs" \
  -H 'Content-Type: application/json' \
  -d @/docker-entrypoint-initdb.d/elasticsearch-template.json

echo "Index template created successfully!"

# Set up ILM (Index Lifecycle Management) policies
echo "Setting up ILM policies..."
curl -X PUT "http://elasticsearch:9200/_ilm/policy/proxy-logs-policy" \
  -H 'Content-Type: application/json' \
  -d '{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_size": "50GB",
            "max_age": "7d"
          },
          "set_priority": {
            "priority": 100
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "set_priority": {
            "priority": 50
          },
          "forcemerge": {
            "max_num_segments": 1
          },
          "shrink": {
            "number_of_shards": 1
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'

echo "ILM policy created successfully!"
echo "Elasticsearch initialization completed successfully!"

