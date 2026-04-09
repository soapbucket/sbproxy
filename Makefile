.PHONY: build test test-race lint fmt validate bench clean help

build: ## Build the sbproxy binary
	go build -o bin/sbproxy ./cmd/sbproxy/

test: ## Run tests
	go test ./... -count=1 -timeout 300s

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

clean: ## Remove build artifacts
	rm -rf bin/

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
