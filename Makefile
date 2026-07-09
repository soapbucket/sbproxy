# sbproxy - development Makefile
# Copyright (c) 2026 Soap Bucket LLC. Licensed under Apache 2.0.

.DEFAULT_GOAL := help

CARGO       ?= cargo
DOCKER      ?= docker
KIND        ?= kind
CONFIG      ?= examples/basic-proxy/sb.yml
LOG_LEVEL   ?= info
BIND_PORT   ?= 8080
KIND_CLUSTER ?= sbproxy-smoke
PROXY_IMAGE ?= sbproxy:ci
OPERATOR_IMAGE ?= sbproxy-operator:ci

CYAN  := \033[36m
RESET := \033[0m

.PHONY: help \
        build build-release build-all \
        run run-release \
        test test-all \
        examples-smoke \
        k8s-operator-smoke \
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

examples-smoke: ## Run docker-compose example smoke tests
	bash scripts/examples-smoke.sh

k8s-operator-smoke: ## Run kind-based Kubernetes operator smoke test
	$(CARGO) build --profile release-fast -p sbproxy-k8s-operator -p sbproxy --locked
	test -x target/release-fast/sbproxy
	test -x target/release-fast/sbproxy-k8s-operator
	$(DOCKER) build -t $(PROXY_IMAGE) -f Dockerfile.ci .
	$(DOCKER) build -t $(OPERATOR_IMAGE) -f crates/sbproxy-k8s-operator/Dockerfile.ci .
	$(KIND) create cluster --name $(KIND_CLUSTER) --image kindest/node:v1.30.0 || true
	$(KIND) load docker-image $(PROXY_IMAGE) $(OPERATOR_IMAGE) --name $(KIND_CLUSTER)
	SKIP_KIND_CREATE=1 NO_CLEANUP=1 PROXY_IMAGE=$(PROXY_IMAGE) OPERATOR_IMAGE=$(OPERATOR_IMAGE) \
		bash deploy/helm/sbproxy/test/smoke.sh

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

# --- Cassettes ---------------------------------------------------------------

tapes: build-release ## Record VHS cassettes (docs/tapes/*.tape -> docs/assets/*.gif)
	scripts/record-tapes.sh $(TAPE)

tapes-gen: ## Regenerate per-example tapes from their documented curls
	python3 scripts/gen-example-tapes.py

# --- Docker ------------------------------------------------------------------

docker docker-build: ## Build the proxy container image
	$(DOCKER) build -f Dockerfile.cloudbuild -t sbproxy:dev .

# --- Cleanup -----------------------------------------------------------------

clean: ## Remove build artifacts
	$(CARGO) clean
