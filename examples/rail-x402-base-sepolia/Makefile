# Convenience runner for the 30-rail-x402-base-sepolia example.
#
# Targets:
#   make up    - docker compose up -d --wait
#   make down  - docker compose down -v --remove-orphans
#   make logs  - tail logs for sbproxy + facilitator + origin
#   make test  - probe the multi-rail challenge body
#   make clean - alias for `down`

COMPOSE      ?= docker compose
PROXY_PORT   ?= 8080
PROXY_HOST   ?= 127.0.0.1
HOST_HEADER  ?= blog.test.sbproxy.dev

.PHONY: up down logs test clean

up:
	$(COMPOSE) up -d --wait

down:
	$(COMPOSE) down -v --remove-orphans

clean: down

logs:
	$(COMPOSE) logs --tail=200 -f

# `test` issues two probes:
#   1. Browser UA -> 200 (no charge applied to humans).
#   2. GPTBot + Accept-Payment: x402 -> 402 with the multi-rail body.
test:
	@echo "==> 1/2 browser UA on /article (expect 200, never charged)"
	@curl -sS -o /dev/null -w 'browser /article -> %{http_code}\n' \
	  -H 'Host: $(HOST_HEADER)' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
	@echo "==> 2/2 GPTBot + Accept-Payment: x402 on /article (expect 402, multi-rail)"
	@curl -sS -o /dev/null -w 'GPTBot /article -> %{http_code}\n' \
	  -H 'Host: $(HOST_HEADER)' \
	  -H 'User-Agent: GPTBot/1.0' \
	  -H 'Accept-Payment: x402' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
