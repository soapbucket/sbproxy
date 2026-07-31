# Convenience runner for the ai-rag-local example bundle.
#
# Targets:
#   make up      - start only the deterministic fixture container
#   make run     - build and start the full stack (fixture + gateway)
#   make smoke   - run scripts/examples-smoke.sh against this example
#   make down    - docker compose down -v --remove-orphans
#
# `make smoke` runs the same assertion as the examples-smoke CI lane:
# it reads smoke.json, boots the stack, proves the retrieved refund
# sentence reaches the model, and tears the stack down again.

COMPOSE ?= docker compose

.PHONY: up run smoke down

up:
	$(COMPOSE) up -d --wait rag-fixture

run:
	$(COMPOSE) up -d --wait

smoke:
	cd ../.. && bash scripts/examples-smoke.sh examples/ai-rag-local

down:
	$(COMPOSE) down -v --remove-orphans
