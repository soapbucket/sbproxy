#!/bin/bash

# Installation script for the crypto CLI tool

set -e

echo "Installing crypto CLI tool..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"

echo "Project root: $PROJECT_ROOT"
echo "Tool directory: $SCRIPT_DIR"

# Check if go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed${NC}"
    echo "Please install Go from https://golang.org/dl/"
    exit 1
fi

echo -e "${GREEN}✓ Go is installed: $(go version)${NC}"

# Navigate to project root to install dependencies
cd "$PROJECT_ROOT"

echo ""
echo "Installing dependencies..."

# Install GCP KMS (optional)
read -p "Install Google Cloud KMS support? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing GCP KMS..."
    go get cloud.google.com/go/kms@latest || echo -e "${YELLOW}Warning: Failed to install GCP KMS${NC}"
    echo -e "${GREEN}✓ GCP KMS support installed${NC}"
fi

# Install AWS KMS (optional)
read -p "Install AWS KMS support? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing AWS KMS..."
    go get github.com/aws/aws-sdk-go-v2/config@latest || echo -e "${YELLOW}Warning: Failed to install AWS SDK${NC}"
    go get github.com/aws/aws-sdk-go-v2/service/kms@latest || echo -e "${YELLOW}Warning: Failed to install AWS KMS${NC}"
    echo -e "${GREEN}✓ AWS KMS support installed${NC}"
fi

# Run go mod tidy
echo ""
echo "Tidying go modules..."
go mod tidy

# Build the tool
echo ""
echo "Building crypto CLI tool..."
cd "$SCRIPT_DIR"
go build -o crypto main.go

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful!${NC}"
    echo ""
    echo "The crypto tool has been built at: $SCRIPT_DIR/crypto"
    echo ""
    echo "To use it from anywhere, you can:"
    echo "  1. Add it to your PATH:"
    echo "     export PATH=\"$SCRIPT_DIR:\$PATH\""
    echo "  2. Or copy it to a location in your PATH:"
    echo "     sudo cp $SCRIPT_DIR/crypto /usr/local/bin/"
    echo "  3. Or create an alias:"
    echo "     alias crypto='$SCRIPT_DIR/crypto'"
    echo ""
    echo "Try it out:"
    echo "  $SCRIPT_DIR/crypto --generate-key"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

