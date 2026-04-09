#!/bin/bash
set -e

IMAGE_NAME="e2e-test-server"
IMAGE_TAG="${1:-latest}"

echo "🐳 Building Docker image: $IMAGE_NAME:$IMAGE_TAG"
echo "================================================"

# Build the Docker image
docker build -t "$IMAGE_NAME:$IMAGE_TAG" .

echo ""
echo "✅ Docker image built successfully"
echo ""
echo "Run with:"
echo "  docker run -p 8090:8090 -p 8443:8443 -p 8091:8091 -p 8092:8092 $IMAGE_NAME:$IMAGE_TAG"
echo ""
echo "Or with custom config:"
echo "  docker run -p 8090:8090 -v \$(pwd)/my-config.json:/root/test-config.json $IMAGE_NAME:$IMAGE_TAG"

