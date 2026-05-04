# Convenience runner for the 17-markdown-for-agents example bundle.
#
# Targets:
#   make up      - docker compose up -d --wait
#   make down    - docker compose down -v --remove-orphans
#   make logs    - tail logs of the sbproxy service
#   make test    - run a four-leg curl probe (browser HTML, agent
#                  Markdown unpaid, agent Markdown paid, agent HTML
#                  paid)
#   make clean   - alias for `down`
#
# `make test` is also what `scripts/examples-smoke.sh` exercises
# through `smoke.json` when the examples-smoke CI lane runs (B1.8).
# The script reads the bundle's `smoke.json` for the probe URL list,
# so any new endpoint added to this Makefile should also be added
# there.

COMPOSE      ?= docker compose
PROXY_PORT   ?= 8080
PROXY_HOST   ?= 127.0.0.1

.PHONY: up down logs test clean

up:
	$(COMPOSE) up -d --wait

down:
	$(COMPOSE) down -v --remove-orphans

clean: down

logs:
	$(COMPOSE) logs --tail=200 -f

# `test` issues a representative request per matrix leg. It uses
# `curl -w` to print the HTTP code on one line so failures are easy
# to read in CI logs.
test:
	@echo "==> 1/4 browser asks for HTML (expect 200, no charge)"
	@curl -sS -o /dev/null -w 'browser /article -> %{http_code}\n' \
	  -H 'Host: news.localhost' \
	  -H 'Accept: text/html' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
	@echo "==> 2/4 GPTBot asks for Markdown, no token (expect 402)"
	@curl -sS -o /dev/null -w 'GPTBot   /article md -> %{http_code}\n' \
	  -H 'Host: news.localhost' \
	  -H 'User-Agent: GPTBot/1.0' \
	  -H 'Accept: text/markdown' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
	@echo "==> 3/4 GPTBot asks for Markdown + paid token (expect 200, Markdown body)"
	@curl -sS -o /dev/null -w 'GPTBot   /article md+pay -> %{http_code}\n' \
	  -H 'Host: news.localhost' \
	  -H 'User-Agent: GPTBot/1.0' \
	  -H 'Accept: text/markdown' \
	  -H 'crawler-payment: token-md-001' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
	@echo "==> 4/4 GPTBot asks for HTML + paid token (expect 200, HTML body)"
	@curl -sS -o /dev/null -w 'GPTBot   /article html+pay -> %{http_code}\n' \
	  -H 'Host: news.localhost' \
	  -H 'User-Agent: GPTBot/1.0' \
	  -H 'Accept: text/html' \
	  -H 'crawler-payment: token-html-001' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
