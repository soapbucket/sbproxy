# Convenience runner for the 32-multi-rail-accept-payment example.
#
# Targets:
#   make up    - docker compose up -d --wait
#   make down  - docker compose down -v --remove-orphans
#   make logs  - tail logs for sbproxy + facilitator + origin + wiremock
#   make test  - probe all three negotiation paths
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

# `test` issues three probes covering the full negotiation matrix:
#   1. q-value preference (x402 first).
#   2. q-value preference (mpp first).
#   3. Unknown rail -> 406 fallback.
test:
	@echo "==> 1/3 Accept-Payment: x402;q=1, mpp;q=0.5 (expect 402, x402 first)"
	@curl -sS -o /dev/null -w 'x402>mpp -> %{http_code}\n' \
	  -H 'Host: $(HOST_HEADER)' \
	  -H 'User-Agent: GPTBot/1.0' \
	  -H 'Accept-Payment: x402;q=1, mpp;q=0.5' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
	@echo "==> 2/3 Accept-Payment: mpp;q=1, x402;q=0.5 (expect 402, mpp first)"
	@curl -sS -o /dev/null -w 'mpp>x402 -> %{http_code}\n' \
	  -H 'Host: $(HOST_HEADER)' \
	  -H 'User-Agent: ClaudeBot/1.0' \
	  -H 'Accept-Payment: mpp;q=1, x402;q=0.5' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
	@echo "==> 3/3 Accept-Payment: foo;q=1 (expect 406, no overlap)"
	@curl -sS -o /dev/null -w 'foo only -> %{http_code}\n' \
	  -H 'Host: $(HOST_HEADER)' \
	  -H 'User-Agent: PerplexityBot/1.0' \
	  -H 'Accept-Payment: foo;q=1' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
