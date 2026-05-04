# Convenience runner for the 33-quote-token-replay-jwks example.
#
# Targets:
#   make up    - docker compose up -d --wait
#   make down  - docker compose down -v --remove-orphans
#   make logs  - tail logs for sbproxy + facilitator + origin
#   make test  - run verify-quote.sh end-to-end
#   make clean - alias for `down`

COMPOSE      ?= docker compose
PROXY_PORT   ?= 8080
ADMIN_PORT   ?= 9090
PROXY_HOST   ?= 127.0.0.1
HOST_HEADER  ?= blog.test.sbproxy.dev

.PHONY: up down logs test clean jwks

up:
	$(COMPOSE) up -d --wait

down:
	$(COMPOSE) down -v --remove-orphans

clean: down

logs:
	$(COMPOSE) logs --tail=200 -f

# `jwks` is a quick liveness probe of the JWKS endpoint. Useful as a
# minimal CI assertion before the full verify-quote.sh runs.
jwks:
	@echo "==> GET /.well-known/sbproxy/quote-keys.json on :$(ADMIN_PORT)"
	@curl -sS http://$(PROXY_HOST):$(ADMIN_PORT)/.well-known/sbproxy/quote-keys.json | head -c 4096

# `test` runs the full verify-quote.sh helper. Requires jq + openssl.
test:
	@./verify-quote.sh
