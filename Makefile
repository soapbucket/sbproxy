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
        tapes tapes-gen tapes-check \
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
	$(DOCKER) build -t $(PROXY_IMAGE) -f Dockerfile.ci .
	$(DOCKER) build -t $(OPERATOR_IMAGE) -f crates/sbproxy-k8s-operator/Dockerfile.ci .
	$(KIND) create cluster --name $(KIND_CLUSTER) --image kindest/node:v1.30.0 || true
	$(KIND) load docker-image $(PROXY_IMAGE) $(OPERATOR_IMAGE) --name $(KIND_CLUSTER)
	SKIP_KIND_CREATE=1 NO_CLEANUP=1 PROXY_IMAGE=$(PROXY_IMAGE) OPERATOR_IMAGE=$(OPERATOR_IMAGE) \
		bash deploy/helm/sbproxy/test/smoke.sh

bench: ## Run benchmark suite (cargo bench)
	$(CARGO) bench --workspace

# `make e2e` is refused, not repaired and not deleted, and the refusal is
# the load-bearing part.
#
# The target that sat here ran `cd e2e && ./run-tests.sh` and has exited
# 127 on every commit of this repository (WOR-2949). The path is the Go
# tree's layout, carried into d631e1b37 with the rest of this file;
# `e2e/run-tests.sh` exists only on sara/v0.1.2-go-final, which is not an
# ancestor of main. The Rust tree vendors the same catalog one directory
# down, as e2e/conformance/run-tests.sh.
#
# Deleting the rule is worse than leaving it broken. `e2e/` is a real
# directory, so with no rule and no .PHONY entry make finds a file by
# that name, prints "Nothing to be done for `e2e'", and exits 0: someone
# who typed it to run the suite gets a green shell and no tests. 127 at
# least said something was wrong. Hence a phony rule that fails.
#
# The .PHONY entry at the top of this file is what makes it fail. This
# rule has no prerequisites, so dropping `e2e` from that list restores
# the silent exit 0 described above with a one-word edit; the old rule
# was accidentally immune because `e2e: build` named a phony
# prerequisite. Keep the two together.
#
# Not repointed at e2e/conformance/run-tests.sh either. Nothing named
# `make e2e` in docs/, CONTRIBUTING.md, AGENTS.md, CLAUDE.md, or any
# workflow, and `make help` never listed it (its awk pattern is
# `^[a-zA-Z_-]+:`, which no target with a digit matches), which is how a
# target broken since 2026-05-04 went unreported. A working alias would
# be a second spelling with no CI lane behind it for the next reader to
# depend on.
e2e:
	@echo 'make e2e is not supported. The conformance harness runs through' >&2
	@echo 'scripts/run-e2e.sh, which builds the release binary, pins' >&2
	@echo 'SBPROXY_BIN at it, and execs e2e/conformance/run-tests.sh:' >&2
	@echo '' >&2
	@echo '  ./scripts/run-e2e.sh            # the maintained smoke set' >&2
	@echo '  ./scripts/run-e2e.sh --all      # all 93 historical cases' >&2
	@echo '  ./scripts/run-e2e.sh 01 14 37   # specific cases' >&2
	@echo '' >&2
	@echo 'That suite runs locally only: no workflow invokes it, so nothing' >&2
	@echo 'reports when it drifts red. The Rust-native suite under e2e/tests' >&2
	@echo 'is the one CI watches, and the lane that runs per pull request is' >&2
	@echo 'e2e-subset in .github/workflows/ci.yml, not the whole package.' >&2
	@echo 'See e2e/conformance/HOW-TO-RUN.md for the two side by side.' >&2
	@exit 1

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

tapes-check: ## Verify generated tapes, GIF wiring, and doc-generator behavior
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/gen-example-tapes.py --check
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/wire-example-gifs.py --check
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts.tests.test_doc_generators

# --- Docker ------------------------------------------------------------------

docker docker-build: ## Build the proxy container image
	$(DOCKER) build -f Dockerfile.cloudbuild -t sbproxy:dev .

# --- Cleanup -----------------------------------------------------------------

clean: ## Remove build artifacts
	$(CARGO) clean
