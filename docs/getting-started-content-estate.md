# Getting started: Content estate (HTML-to-markdown / content transformation for agents)

*Last modified: 2026-07-09*

## What you will build

You will put SBproxy in front of an HTML upstream and have it convert each page into clean Markdown before it reaches the client. Agents and LLM pipelines that prefer Markdown get a compact, portable body; the proxy also rewrites the `Content-Type` header so the response is delivered with the right MIME type. This is the foundation for an agent-aware content estate, and the same origin can later negotiate shape per request and price AI crawlers.

## Prerequisites

- `curl` to send test requests.
- An HTML upstream to transform. This guide uses `test.sbproxy.dev`, the public request-inspection service hosted by SoapBucket, so the config is self-contained. Swap the upstream URL for your own HTML site when you are ready.

## Install

One line installs the prebuilt binary on macOS or Linux. The script detects your OS and architecture, fetches the matching release binary, and drops it in `~/.local/bin`:

```bash
curl -fsSL https://download.sbproxy.dev | sh
```

Homebrew, Docker, binary downloads, and source builds are in the [runtime manual's installation section](manual.md#1-installation). Run the gateway against a config file:

```bash
sbproxy serve -f sb.yml
```

## Minimal config

Save this as `sb.yml`. It fronts the HTML page at `test.sbproxy.dev/html`, converts the body to Markdown with ATX-style headings (`#`, `##`, ...), and stamps the Markdown MIME type on the way out. Every key here exists in the config schema and matches the `transform-html-to-markdown` example.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/soapbucket/sbproxy/main/schemas/sb-config.schema.json
proxy:
  http_bind_port: 8080

origins:
  "tomd.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    transforms:
      - type: html_to_markdown
        heading_style: atx
    response_modifiers:
      - headers:
          set:
            Content-Type: text/markdown; charset=utf-8
```

`tomd.local` is the host your client sends; the proxy matches it against `origins:` and forwards to the upstream. The `html_to_markdown` transform does the conversion; the `response_modifiers` block rewrites `Content-Type` so the Markdown body is delivered with the right MIME.

## Run it and expected output

Start the proxy:

```bash
sbproxy serve -f sb.yml
```

The upstream serves HTML:

```bash
curl -s https://test.sbproxy.dev/html | head -5
```

```text
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>test.sbproxy.dev sample</title></head>
<body>
  <h1>Sample HTML</h1>
```

The proxied response is Markdown with ATX headings and the rewritten content type (insignificant whitespace trimmed):

```bash
curl -i -H 'Host: tomd.local' http://127.0.0.1:8080/html
```

```text
HTTP/1.1 200 OK
content-type: text/markdown; charset=utf-8

# Sample HTML

This document exists so sbproxy HTML transforms have a fixed-shape upstream to point at.

- One
- Two
- Three

Visit [sbproxy.dev](https://sbproxy.dev) for docs.
```

Confirm the headings are ATX (leading hashes, not setext underlines):

```bash
curl -s -H 'Host: tomd.local' http://127.0.0.1:8080/html | grep -E '^#'
```

```text
# Sample HTML
```

## You are done when

- `curl -i -H 'Host: tomd.local' http://127.0.0.1:8080/html` returns `HTTP/1.1 200 OK`.
- The response carries `content-type: text/markdown; charset=utf-8`.
- The body starts with an ATX heading line, `# Sample HTML`, and `grep -E '^#'` over the body returns that heading.
- The raw upstream (`curl -s https://test.sbproxy.dev/html`) is still HTML, confirming the proxy did the conversion.

## Next steps

- [docs/content-for-agents.md](content-for-agents.md) for content-shape negotiation, the JSON envelope, `Content-Signal`, and `x-markdown-tokens`.
- [docs/listings.md](listings.md) for serving structured listings to agents.
- [docs/ai-crawl-control.md](ai-crawl-control.md) to price AI crawlers per content shape and tier.
- [docs/configuration.md](configuration.md) for the full origin, transform, and response-modifier schema.
