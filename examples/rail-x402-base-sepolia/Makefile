# Convenience runner for the rail-x402-base-sepolia example.
#
# Targets:
#   make validate - check the config without resolving a secret
#   make run      - serve the config with the local release binary
#   make test     - probe the three cases from the README
#   make up       - docker compose up -d --wait
#   make down     - docker compose down -v --remove-orphans
#   make logs     - tail every container's log
#   make clean    - alias for `down`

COMPOSE      ?= docker compose
SBPROXY      ?= ../../target/release/sbproxy
CONFIG       ?= sb.yml
PROXY_PORT   ?= 8080
PROXY_HOST   ?= 127.0.0.1
HOST_HEADER  ?= blog.test.sbproxy.dev

.PHONY: validate run up down logs test clean

validate:
	$(SBPROXY) validate -f $(CONFIG)

run:
	$(SBPROXY) serve -f $(CONFIG)

up:
	$(COMPOSE) up -d --wait

down:
	$(COMPOSE) down -v --remove-orphans

clean: down

logs:
	$(COMPOSE) logs --tail=200 -f

# The three cases the README walks through. A reader is never charged, a
# declared crawler gets a price, and a credential the proxy never issued
# buys nothing.
test:
	@echo "==> 1/3 reader on /article (never charged)"
	@curl -sS -o /dev/null -w 'reader   /article -> %{http_code}\n' \
	  -H 'Host: $(HOST_HEADER)' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
	@echo "==> 2/3 GPTBot on /article (expect 402)"
	@curl -sS -o /dev/null -w 'GPTBot   /article -> %{http_code}\n' \
	  -H 'Host: $(HOST_HEADER)' \
	  -H 'User-Agent: GPTBot/1.0' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
	@echo "==> 3/3 GPTBot with an unissued credential (expect 402)"
	@curl -sS -o /dev/null -w 'unissued /article -> %{http_code}\n' \
	  -H 'Host: $(HOST_HEADER)' \
	  -H 'User-Agent: GPTBot/1.0' \
	  -H 'crawler-payment: not-a-token-this-proxy-issued' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
