# sbproxy - development Makefile
# Copyright (c) 2026 Soap Bucket LLC. Licensed under Apache 2.0.

.DEFAULT_GOAL := help

CARGO       ?= cargo
DOCKER      ?= docker
CONFIG      ?= examples/00-basic-proxy/sb.yml
LOG_LEVEL   ?= info
BIND_PORT   ?= 8080

CYAN  := \033[36m
RESET := \033[0m

.PHONY: help \
        build build-release build-all \
        run run-release \
        test test-all \
        bench \
        fmt fmt-check \
        lint lint-all \
        check \
        clean \
        docker docker-build \
        e2e

# --- Help --------------------------------------------------------------------

help: ## Show this help message
	@echo "sbproxy - development targets"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} \
	     /^[a-zA-Z_-]+:.*?## / {printf "  $(CYAN)%-20s$(RESET) %s\n", $$1, $$2}' \
	     $(MAKEFILE_LIST)
	@echo ""
	@echo "Variables:"
	@echo "  CONFIG     Config path used by run targets (default: $(CONFIG))"
	@echo "  LOG_LEVEL  RUST_LOG filter for run targets (default: $(LOG_LEVEL))"

# --- Build -------------------------------------------------------------------

build: ## Debug build of the sbproxy binary
	$(CARGO) build -p sbproxy

build-release: ## Optimised release build of the sbproxy binary
	$(CARGO) build --release -p sbproxy

build-all: ## Build every crate in the workspace
	$(CARGO) build --workspace

# --- Run ---------------------------------------------------------------------

run: build ## Run the proxy from a debug build with $(CONFIG)
	RUST_LOG=$(LOG_LEVEL) ./target/debug/sbproxy --config $(CONFIG)

run-release: build-release ## Run the proxy from a release build with $(CONFIG)
	RUST_LOG=$(LOG_LEVEL) ./target/release/sbproxy --config $(CONFIG)

# --- Test --------------------------------------------------------------------

test: ## Run unit and integration tests for default members
	$(CARGO) test

test-all: ## Run the full workspace test suite
	$(CARGO) test --workspace

bench: ## Run benchmark suite (cargo bench)
	$(CARGO) bench --workspace

e2e: build ## Run the end-to-end test harness
	cd e2e && ./run-tests.sh

# --- Lint / Format -----------------------------------------------------------

fmt: ## Format every Rust source file
	$(CARGO) fmt --all

fmt-check: ## Verify formatting without modifying files
	$(CARGO) fmt --all -- --check

lint: ## Run clippy with warnings as errors
	$(CARGO) clippy --all-targets -- -D warnings

lint-all: ## Run clippy across the entire workspace
	$(CARGO) clippy --workspace --all-targets -- -D warnings

# --- Aggregate checks --------------------------------------------------------

check: fmt-check lint test ## Run the pre-commit check bundle (format, lint, test)

# --- Docker ------------------------------------------------------------------

docker docker-build: ## Build the proxy container image
	$(DOCKER) build -f Dockerfile.cloudbuild -t sbproxy:dev .

# --- Cleanup -----------------------------------------------------------------

clean: ## Remove build artifacts
	$(CARGO) clean
