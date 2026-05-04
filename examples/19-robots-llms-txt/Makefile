# Convenience runner for the 19-robots-llms-txt example bundle.
#
# Targets:
#   make up      - docker compose up -d --wait
#   make down    - docker compose down -v --remove-orphans
#   make logs    - tail logs of the sbproxy service
#   make test    - probe each of the three text projections
#   make clean   - alias for `down`

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

# `test` issues one GET per projection. Asserts 200 on each.
test:
	@echo "==> 1/3 robots.txt (expect 200)"
	@curl -sS -o /dev/null -w 'robots.txt    -> %{http_code}\n' \
	  -H 'Host: news.localhost' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/robots.txt
	@echo "==> 2/3 llms.txt (expect 200, YAML-ish header)"
	@curl -sS -o /dev/null -w 'llms.txt      -> %{http_code}\n' \
	  -H 'Host: news.localhost' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/llms.txt
	@echo "==> 3/3 llms-full.txt (expect 200, full priced-route listing)"
	@curl -sS -o /dev/null -w 'llms-full.txt -> %{http_code}\n' \
	  -H 'Host: news.localhost' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/llms-full.txt
