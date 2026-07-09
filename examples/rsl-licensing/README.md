# RSL licensing
*Last modified: 2026-07-09*

Demonstrates the Wave 4 policy-graph projections. A single
`ai_crawl_control` policy plus the per-origin `content_signal` field
drives three machine-readable documents:

| Path                          | Format            | Spec                      |
|-------------------------------|-------------------|---------------------------|
| `/robots.txt`                 | RFC 9309 stanzas  | IETF draft-koster-rep-ai  |
| `/licenses.xml`               | RSL 1.0 XML       | rslstandard.org/rsl       |
| `/.well-known/tdmrep.json`    | W3C TDMRep JSON   | W3C TDMRep CG-FINAL-tdmrep-20240510 |

All three are derived from the same compiled config, refreshed
atomically on every config reload, and signed with a `doc_hash` audit
event so an operator can trace any change back to the originating
edit.

The example fixes `content_signal: ai-input` so the projected RSL
document asserts inference-only licensing. Switch to `ai-train` to
license training and `search` to license search-index inclusion. An
absent `content_signal` produces no `<permits>` / `<prohibits>`
element under the usage tier (RSL 1.0 is silent-permissive when a
signal is undeclared) and a `TDM-Reservation: 1` response header on
origin traffic.

## How it composes

| Service     | Image                              | Role                                                          |
|-------------|------------------------------------|---------------------------------------------------------------|
| sbproxy     | built from `Dockerfile.cloudbuild` | Proxy + projection cache. Serves the three policy-graph docs. |

The proxy is the only container. There is no upstream service to
healthcheck.

## How to run

```bash
cd examples/rsl-licensing
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

The W3C TDMRep declaration for the origin. Per the W3C TDMRep
CG-FINAL spec, the document is a bare JSON array at the root (no
envelope object), with one entry per priced route. Each entry carries
three hyphenated keys: `location`, `tdm-reservation`, `tdm-policy`.

```bash
curl -s -H 'Host: shop.localhost' \
     http://127.0.0.1:8080/.well-known/tdmrep.json | jq .
# [
#   {
#     "location": "/",
#     "tdm-reservation": 1,
#     "tdm-policy": "https://shop.localhost/licenses.xml"
#   },
#   {
#     "location": "/docs/*",
#     "tdm-reservation": 1,
#     "tdm-policy": "https://shop.localhost/licenses.xml"
#   }
# ]
```

When the origin asserts a recognised `Content-Signal` (`ai-train`,
`ai-input`, or `search`), each priced tier in the policy emits an
entry with `tdm-reservation: 1`. When the signal is absent, the array
is empty and the proxy stamps a `TDM-Reservation: 1` response header
on origin traffic instead.

### 2. `/licenses.xml`

The RSL 1.0 license document. Parses as XML; the root element is
`<rsl xmlns="https://rslstandard.org/rsl">` and wraps the license
body in a `<content url="...">` element scoped to the origin. The
inner `<license>` carries the `urn:rsl:1.0:<hostname>:<config_version>`
URN plus the `<permits>` / `<prohibits>` token lists derived from the
`Content-Signal` value (RSL 1.0 §3.5).

```bash
curl -s -H 'Host: shop.localhost' \
     http://127.0.0.1:8080/licenses.xml
# <?xml version="1.0" encoding="UTF-8"?>
# <rsl xmlns="https://rslstandard.org/rsl" version="1.0">
#   <content url="https://shop.localhost/*">
#     <license urn="urn:rsl:1.0:shop.localhost:42">
#       <origin hostname="shop.localhost" />
#       <permits type="usage">ai-input</permits>
#       <content-signal>ai-input</content-signal>
#     </license>
#   </content>
# </rsl>
```

If `xmllint` is available, a sanity check that the document is
well-formed:

```bash
curl -s -H 'Host: shop.localhost' \
     http://127.0.0.1:8080/licenses.xml | xmllint --noout -
# (no output means it parsed cleanly)
```

The RSL 1.0 spec at https://rslstandard.org/rsl is prose-only; the
RSL Collective does not publish a canonical XSD, so there is no
schema-validation step beyond well-formedness. The projection-engine
snapshot tests in `crates/sbproxy-modules/src/projections/licenses.rs`
pin the byte-for-byte output, so any drift from the canonical wire
shape fails the CI gate.

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
`<permits type="usage">ai-train</permits>` and the audit trail logs
one `PolicyProjectionRefresh` event per (hostname, projection_kind).

## How the mapping works

| `content_signal` | `licenses.xml` element                                       |
|------------------|--------------------------------------------------------------|
| `ai-train`       | `<permits type="usage">ai-train</permits>`                   |
| `ai-input`       | `<permits type="usage">ai-input</permits>`                   |
| `search`         | `<permits type="usage">search</permits>`                     |
| (absent)         | no `<permits>` or `<prohibits>` (RSL is silent-permissive)   |

Switching to the structured `content_signals:` block lets the
operator declare per-token decisions; a `false` value emits
`<prohibits type="usage">token</prohibits>` instead of `<permits>`.
The "prohibits wins" rule in RSL §3.1.1 means a token that ends up
in both lists is treated as prohibited by spec-aware consumers.

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

- `docs/content-for-agents.md` - the four generated projections,
  their refresh-on-reload semantics, and content-shape negotiation.
- `examples/markdown-for-agents/` - companion bundle for the Markdown
  projection.
- `examples/robots-llms-txt/` - companion bundle for `robots.txt` plus
  `llms.txt` / `llms-full.txt`.
