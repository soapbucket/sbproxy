# Convenience runner for the 31-rail-mpp-stripe-test example.
#
# Targets:
#   make up           - docker compose up -d --wait
#   make up-wiremock  - docker compose --profile wiremock up -d --wait
#   make down         - docker compose down -v --remove-orphans
#   make logs         - tail logs for sbproxy + origin (+ wiremock)
#   make test         - probe the multi-rail challenge body
#   make clean        - alias for `down`

COMPOSE      ?= docker compose
PROXY_PORT   ?= 8080
PROXY_HOST   ?= 127.0.0.1
HOST_HEADER  ?= feed.test.sbproxy.dev

.PHONY: up up-wiremock down logs test clean

up:
	$(COMPOSE) up -d --wait

up-wiremock:
	$(COMPOSE) --profile wiremock up -d --wait

down:
	$(COMPOSE) down -v --remove-orphans

clean: down

logs:
	$(COMPOSE) logs --tail=200 -f

# `test` issues two probes:
#   1. Browser UA -> 200 (no charge applied to humans).
#   2. ClaudeBot + Accept-Payment: mpp -> 402 with the multi-rail body.
test:
	@echo "==> 1/2 browser UA on /feed/articles/2026 (expect 200, never charged)"
	@curl -sS -o /dev/null -w 'browser /feed/.. -> %{http_code}\n' \
	  -H 'Host: $(HOST_HEADER)' \
	  -H 'Accept: text/markdown' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/feed/articles/2026
	@echo "==> 2/2 ClaudeBot + Accept-Payment: mpp on /feed/articles/2026 (expect 402, multi-rail)"
	@curl -sS -o /dev/null -w 'ClaudeBot /feed/.. -> %{http_code}\n' \
	  -H 'Host: $(HOST_HEADER)' \
	  -H 'User-Agent: ClaudeBot/1.0' \
	  -H 'Accept: text/markdown' \
	  -H 'Accept-Payment: mpp' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/feed/articles/2026
