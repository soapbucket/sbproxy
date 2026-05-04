# Convenience runner for the 18-rsl-licensing example bundle.
#
# Targets:
#   make up      - docker compose up -d --wait
#   make down    - docker compose down -v --remove-orphans
#   make logs    - tail logs of the sbproxy service
#   make test    - probe each of the three policy-graph projections
#   make clean   - alias for `down`
#
# `make test` is also what `scripts/examples-smoke.sh` exercises
# through `smoke.json` when the examples-smoke CI lane runs.

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

# `test` issues one GET per projection. xmllint is optional; the
# `make test` target prints whether the document parses but does not
# fail the run when xmllint is absent.
test:
	@echo "==> 1/3 robots.txt (expect 200, RFC 9309 stanzas)"
	@curl -sS -o /dev/null -w 'robots.txt -> %{http_code}\n' \
	  -H 'Host: shop.localhost' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/robots.txt
	@echo "==> 2/3 licenses.xml (expect 200, RSL 1.0 XML)"
	@curl -sS -o /dev/null -w 'licenses.xml -> %{http_code}\n' \
	  -H 'Host: shop.localhost' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/licenses.xml
	@if command -v xmllint >/dev/null 2>&1; then \
	  curl -sS -H 'Host: shop.localhost' http://$(PROXY_HOST):$(PROXY_PORT)/licenses.xml \
	    | xmllint --noout - && echo 'licenses.xml -> well-formed XML' \
	    || echo 'licenses.xml -> XML parse failed' ; \
	else \
	  echo 'licenses.xml -> xmllint not installed, skipping XML well-formedness check' ; \
	fi
	@echo "==> 3/3 tdmrep.json (expect 200, W3C TDMRep JSON)"
	@curl -sS -o /dev/null -w '.well-known/tdmrep.json -> %{http_code}\n' \
	  -H 'Host: shop.localhost' \
	  http://$(PROXY_HOST):$(PROXY_PORT)/.well-known/tdmrep.json
