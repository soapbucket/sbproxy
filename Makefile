VERSION_PKG = github.com/soapbucket/sbproxy/internal/version
GIT_HASH    = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE  = $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION     = $(shell cat VERSION 2>/dev/null || echo "0.1.0")
LDFLAGS     = -s -w \
              -X $(VERSION_PKG).Version=$(VERSION) \
              -X $(VERSION_PKG).BuildHash=$(GIT_HASH) \
              -X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

.PHONY: build test test-race lint fmt validate bench check docker docker-up docker-down certs clean help

build: ## Build the sbproxy binary
	go build -ldflags '$(LDFLAGS)' -o bin/sbproxy ./cmd/sbproxy/

test: ## Run all tests
	go test ./... -count=1 -timeout 300s

test-smoke: ## Run fast smoke tests only (< 5s, for CI PRs)
	go test ./internal/config/ -run TestSmoke -count=1 -timeout 30s -v
	go test ./internal/modules/... -count=1 -timeout 30s
	go test ./pkg/... -count=1 -timeout 30s

test-race: ## Run tests with race detector
	go test -race ./... -count=1 -timeout 300s

lint: ## Run golangci-lint
	golangci-lint run ./...

fmt: ## Format code
	gofmt -s -w .

validate: ## Validate proxy config (usage: make validate CONFIG=path/to/sb.yaml)
	go run ./cmd/sbproxy/ validate -c $(CONFIG)

bench: ## Run benchmarks
	go test -bench=Benchmark -benchmem -count=3 ./internal/ai/...

check: ## Run import guard and dependency checks
	@echo "Checking pkg/ has no internal imports..."
	@go list -f '{{range .Imports}}{{.}}{{"\n"}}{{end}}' ./pkg/... 2>/dev/null | grep -q "internal/" && (echo "FAIL: pkg/ imports internal/" && exit 1) || true
	@echo "Import guard: PASS"

docker: ## Build Docker image
	docker build --build-arg VERSION=$(VERSION) --build-arg GIT_HASH=$(GIT_HASH) -t sbproxy:latest .

docker-up: ## Start Docker Compose stack (sbproxy + Pebble ACME + Redis)
	docker compose -f docker/docker-compose.yml up --build -d

docker-down: ## Stop Docker Compose stack
	docker compose -f docker/docker-compose.yml down

certs: ## Generate self-signed dev certificates (CA, server, client)
	@./scripts/generate-certs.sh

clean: ## Remove build artifacts
	rm -rf bin/

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
