# Getting started: inbound AI (agents and crawlers that call you)

*Last modified: 2026-08-28*

SBproxy is a reverse proxy that also governs the AI coming *in*: crawlers and agents hitting your APIs and content. Two jobs show up together in production and are documented as separate walkthroughs today. This page stitches them.

## What you will build

1. Content an agent can consume: HTML in, Markdown (or another negotiated shape) out.
2. Identity at the edge: verify RFC 9421-signed agents, and publish discovery documents for a key you hold.

You can run either half alone. Running both is the inbound estate.

## Walkthroughs

Do these in order if you are new to inbound traffic. Each page installs the binary, writes a config, and has a `curl` you can copy.

1. **Shape the body.** [getting-started-content-estate.md](getting-started-content-estate.md) fronts `test.sbproxy.dev/html`, converts the page to Markdown, and stamps the Markdown content type. Runnable twin: [`examples/transform-html-to-markdown/`](../examples/transform-html-to-markdown/). When you later charge crawlers or negotiate `text/markdown` vs HTML per request, start from [content-for-agents.md](content-for-agents.md) and [use-case-meter-crawlers.md](use-case-meter-crawlers.md).
2. **Verify the caller.** [getting-started-agent-identity.md](getting-started-agent-identity.md) checks Ed25519 HTTP Message Signatures against a directory of known agent keys, and shows how to publish a key directory for an SBproxy signing identity. Runnable twin: [`examples/web-bot-auth/`](../examples/web-bot-auth/).

The two jobs do not share a config in this stitch on purpose. `bot_auth` verifies callers. Transforms reshape bodies. Putting them on one origin is a later composition (auth first, then the content transform), not a missing file.

## Where this sits

This is walkthrough 3 of 4. The set:

1. [all-traffic-gateway.md](all-traffic-gateway.md) - API, MCP, and AI on one listener
2. [getting-started-ai-estate.md](getting-started-ai-estate.md) - apps calling models
3. This page - AI that calls you
4. [quickstart-serve.md](quickstart-serve.md) - a model you run
