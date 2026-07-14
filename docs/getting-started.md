# Getting started

*Last modified: 2026-07-14*

This page takes you from nothing installed to a working SBproxy in a few minutes: install the binary, run a config, confirm it's doing what you expect, then branch into whichever feature brought you here. For the pitch and feature tour, see the [README](../README.md); for every `sb.yml` field, see [configuration.md](configuration.md).

## 1. Install

Pick whichever fits your platform:

```bash
# curl (macOS / Linux)
curl -fsSL https://download.sbproxy.dev | sh

# Homebrew (macOS / Linux)
brew tap soapbucket/tap
brew install sbproxy

# Docker
docker pull soapbucket/sbproxy:latest
```

Building from source needs Rust 1.82+:

```bash
git clone https://github.com/soapbucket/sbproxy
cd sbproxy
make build-release
```

Verify the binary is on your `PATH`:

```bash
sbproxy --version
```

Windows binaries, the distroless Docker image layout, and installing to a specific system path are covered in the [runtime manual's install section](manual.md#1-installation).

## 2. Write a config and run it

Every `sb.yml` has two top-level keys: `proxy:` for global listener settings, and `origins:` mapping a hostname to what happens when a request arrives for it. Here's the smallest useful one, reverse-proxying to SBproxy's public HTTP echo service (`test.sbproxy.dev`, similar to httpbin) so there's nothing else to stand up:

```yaml
proxy:
  http_bind_port: 8080

origins:
  "myapp.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
```

Save that as `sb.yml`. `myapp.example.com` is the hostname your client sends in its `Host` header; SBproxy matches it against `origins:` and forwards to the upstream. Use whatever hostname you want here, `example.com` is reserved (RFC 2606), so it never collides with a real domain.

Validate it before starting anything:

```bash
sbproxy validate sb.yml
```

This runs the same schema check the server uses at boot and exits non-zero with the offending field if something's wrong, useful to wire into CI later. Then run it:

```bash
sbproxy sb.yml
```

And in another terminal:

```bash
curl -H "Host: myapp.example.com" http://127.0.0.1:8080/get
```

You should get back the request SBproxy forwarded, echoed as JSON. That's a working reverse proxy.

## 3. If something didn't work

- `sbproxy validate sb.yml` catches most config mistakes before you even start the proxy.
- Wrong status code or no response? Check the [troubleshooting guide](troubleshooting.md), it's organized by symptom (404s, 502s, config edits not taking effect, and more).
- Quick answers to common install and first-run questions are in the [FAQ](faq.md#install--first-run).

## 4. Where to go next

The config above is a bare reverse proxy. Everything else, AI routing, auth, rate limiting, caching, is more `origins:` fields in the same file:

- **Route to an AI model instead of an HTTP backend**: see [Serve your own model](../README.md#serve-your-own-model) in the README for the shortest path, or [ai-gateway.md](ai-gateway.md) for the full provider and routing reference.
- **Solve a specific problem** (auth in front of existing APIs, guardrails, metering AI crawlers, migrating off LiteLLM, ...): the [problem-to-walkthrough table](README.md#solve-a-problem) has a runnable example for each.
- **See every available field**: [configuration.md](configuration.md) is the full `sb.yml` reference; [json-schema.md](json-schema.md) gets you editor autocomplete and inline validation.
- **Tour every feature with copy-paste configs**: [features.md](features.md).
- **Browse runnable examples**: the [`examples/`](../examples/) directory has one directory per feature, each with its own config and README.
- **Deploy to production**: [self-hosting.md](self-hosting.md) for the single-binary shape, [kubernetes.md](kubernetes.md) and [quickstart-operator.md](quickstart-operator.md) for the OSS operator, [sidecar-deployment.md](sidecar-deployment.md) for per-pod sidecars.
- **Contribute or build from source**: [CONTRIBUTING.md](../CONTRIBUTING.md).

For the complete documentation set, start at the [docs index](README.md).
