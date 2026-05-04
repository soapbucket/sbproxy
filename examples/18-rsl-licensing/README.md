# 18 - RSL licensing
*Last modified: 2026-05-02*

Demonstrates the Wave 4 policy-graph projections. A single
`ai_crawl_control` policy plus the per-origin `content_signal` field
drives three machine-readable documents:

| Path                          | Format            | Spec                      |
|-------------------------------|-------------------|---------------------------|
| `/robots.txt`                 | RFC 9309 stanzas  | IETF draft-koster-rep-ai  |
| `/licenses.xml`               | RSL 1.0 XML       | rsl.ai/spec/1.0           |
| `/.well-known/tdmrep.json`    | W3C TDMRep JSON   | w3c.github.io/tdm-reservation-protocol |

All three are derived from the same compiled config, refreshed
atomically on every config reload, and signed with a `doc_hash` audit
event so an operator can trace any change back to the originating
edit.

The example fixes `content_signal: ai-input` so the projected RSL
document asserts inference-only licensing. Switch to `ai-train` to
license training and `search` to license search-index inclusion. An
absent `content_signal` produces a default-deny RSL document
(`<ai-use licensed="false">`) and a `TDM-Reservation: 1` response
header on origin traffic.

## How it composes

| Service     | Image                              | Role                                                          |
|-------------|------------------------------------|---------------------------------------------------------------|
| sbproxy     | built from `Dockerfile.cloudbuild` | Proxy + projection cache. Serves the three policy-graph docs. |

The proxy is the only container. There is no upstream service to
healthcheck.

## How to run

```bash
cd examples/18-rsl-licensing
docker compose up -d --wait
```

Tear down:

```bash
docker compose down -v
```

The `Makefile` wraps the same calls (`make up`, `make down`,
`make logs`, `make test`).

## What to expect

### 1. `/.well-known/tdmrep.json`

The W3C TDMRep declaration for the origin. Parses as JSON; the body
includes the `content_signal` value set in `sb.yml`.

```bash
curl -s -H 'Host: shop.localhost' \
     http://127.0.0.1:8080/.well-known/tdmrep.json | jq .
# {
#   "tdm-reservation": "0",
#   "tdm-policy": "https://shop.localhost/licenses.xml",
#   ...
# }
```

### 2. `/licenses.xml`

The RSL 1.0 license document. Parses as XML; the body contains a
`urn:rsl:1.0:<hostname>:<config_version>` URN and one `<ai-use>`
assertion per `Content-Signal` value.

```bash
curl -s -H 'Host: shop.localhost' \
     http://127.0.0.1:8080/licenses.xml | head -20
# <?xml version="1.0" encoding="UTF-8"?>
# <licenses xmlns="https://rsl.ai/spec/1.0">
#   <license id="urn:rsl:1.0:shop.localhost:42">
#     <ai-use type="inference" licensed="true" />
#     ...
```

If `xmllint` is available, a sanity check that the document is
well-formed:

```bash
curl -s -H 'Host: shop.localhost' \
     http://127.0.0.1:8080/licenses.xml | xmllint --noout -
# (no output means it parsed cleanly)
```

Strict RSL XSD validation is wired into the
`licensing-conformance` CI workflow (B4.5), which fetches the upstream
RSL XSD weekly and runs the e2e schema tests against the projected
document.

### 3. `/robots.txt`

The crawler list with `Content-Signal: ai-input` headers. Per the IETF
draft, AI-aware crawlers honor the per-stanza Allow / Disallow
directives plus the matching pricing tier.

```bash
curl -s -H 'Host: shop.localhost' \
     http://127.0.0.1:8080/robots.txt
# User-agent: GPTBot
# Allow: /
# Allow: /docs/*
# License: /licenses.xml
# ...
```

### 4. Editing the licensing posture

Change `content_signal: ai-input` to `content_signal: ai-train` in
`sb.yml`, then `docker compose restart sbproxy`. The three
projections refresh atomically; `licenses.xml` now declares
`<ai-use type="training" licensed="true" />` and the audit trail logs
one `PolicyProjectionRefresh` event per (hostname, projection_kind).

## How the mapping works

| `content_signal` | `licenses.xml` `<ai-use>`                          |
|------------------|----------------------------------------------------|
| `ai-train`       | `<ai-use type="training" licensed="true" />`       |
| `ai-input`       | `<ai-use type="inference" licensed="true" />`      |
| `search`         | `<ai-use type="search-index" licensed="true" />`   |
| (absent)         | `<ai-use type="training" licensed="false" />` (default-deny) |

Per-tier `citation_required: true` adds a `requires-citation="true"`
attribute to the corresponding RSL `<terms>` element.

## Audit trail

Each projection refresh emits a `PolicyProjectionRefresh` audit event
with:

- `hostname` (e.g. `shop.localhost`)
- `projection_kind` (one of `robots`, `llms`, `llms-full`, `licenses`, `tdmrep`)
- `config_version` (monotonic per reload)
- `doc_hash` (SHA-256 of the rendered body)
- `byte_len`

The Wave 4 `licensing-edits` Grafana dashboard surfaces these events
as a per-projection table.

## Related docs

- `docs/adr-policy-graph-projections.md` - A4.1 projections ADR.
- `docs/adr-content-negotiation-and-pricing.md` - G4.1 content-negotiate ADR.
- `examples/17-markdown-for-agents/` - companion bundle for the Markdown
  projection.
- `examples/19-robots-llms-txt/` - companion bundle for `robots.txt` plus
  `llms.txt` / `llms-full.txt`.
