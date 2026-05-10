# Convenience runner for the 24-ai-crawl-tiered example bundle.
#
# Targets:
#   make up      - docker compose up -d --wait
#   make down    - docker compose down -v --remove-orphans
#   make logs    - tail logs of the sbproxy + ledger + origin services
#   make test    - run a four-leg curl probe (browser, free preview,
#                  default crawler, paid premium)
#   make clean   - alias for `down`
#
# `make test` is also what `scripts/examples-smoke.sh` exercises through
# `smoke.json` when the examples-smoke CI lane runs (B1.8). The script
# reads the bundle's `smoke.json` for the probe URL list, so any new
# endpoint added to this Makefile should also be added there.

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

# `test` issues a representative request per tier. It uses `curl -w` to
# print the HTTP code + matched tier on one line so failures are easy to
# read in CI logs.
test:
	@echo "==> 1/4 browser UA on /article (expect 200, no charge)"
	@curl -sS -o /dev/null -w 'browser /article -> %{http_code}\n' \
	  -H 'Host: blog.localhost' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
	@echo "==> 2/4 GPTBot on /preview/article (expect 200, free tier)"
	@curl -sS -o /dev/null -w 'GPTBot   /preview -> %{http_code}\n' \
	  -H 'Host: blog.localhost' \
	  -H 'User-Agent: GPTBot/1.0' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/preview/article
	@echo "==> 3/4 GPTBot on /article (expect 402, html tier)"
	@curl -sS -o /dev/null -w 'GPTBot   /article -> %{http_code}\n' \
	  -H 'Host: blog.localhost' \
	  -H 'User-Agent: GPTBot/1.0' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/article
	@echo "==> 4/4 ClaudeBot + paid token on /feed/articles/2026 (expect 200, feed tier)"
	@curl -sS -o /dev/null -w 'ClaudeBot/feed   -> %{http_code}\n' \
	  -H 'Host: blog.localhost' \
	  -H 'User-Agent: ClaudeBot/1.0' \
	  -H 'crawler-payment: token-feed-001' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/feed/articles/2026
