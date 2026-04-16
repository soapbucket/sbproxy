# README, Documentation & Website Redesign
*Last modified: 2026-04-16*

## Overview

Redesign sbproxy's README, documentation, and website (sbproxy.dev) to be feature-first and technology-agnostic. The goal is to drive interest in the problem space (fragmented traffic layers) and position sbproxy as the unified solution. The cloud site (cloud.sbproxy.dev) handles enterprise sales. sbproxy.dev educates and converts to downloads.

## Core Messaging

**Tagline:** The unified application gateway.

**Subtitle:** Simplify your traffic layer. One gateway for every protocol and provider.

**Narrative:** Teams are running separate tools for reverse proxying, AI traffic, authentication, rate limiting, caching, and observability. Each has its own config, auth model, failure modes, and operational burden. sbproxy replaces that patchwork with one gateway.

**Rules:**
- Never mention implementation technology (no Go, Rust, goroutines, etc.)
- Never name competitors on the marketing site or README
- Lead with outcomes and problems, not features and specs
- Enterprise gets a single tasteful mention linking to cloud.sbproxy.dev

## README Structure

1. **Logo** - centered, dark/light mode support
2. **Tagline + subtitle**
3. **Badge row** - GitHub stars, license, latest release, CI status
4. **Nav links** - Install | Docs | Examples | Community | Cloud
5. **"Why sbproxy"** - 3-4 benefit-driven bullets:
   - "One config file replaces your reverse proxy, AI gateway, and a dozen middleware scripts."
   - "Add AI capabilities to any existing API without changing your backend."
   - "Ship with authentication, rate limiting, and caching already built in."
   - "Reload configuration without dropping a single connection."
6. **Quick start** - install, create minimal config, run. Under 10 lines total.
7. **"What can you build?"** - 3-4 use case cards: reverse proxy, AI gateway, API security layer, protocol bridge
8. **Feature overview** - concise grouped list
9. **Community** - discussions, issues, contributing guide
10. **Enterprise** - single line: "Need managed hosting and advanced analytics? See sbproxy Cloud."

## Website Structure (sbproxy.dev)

### Homepage Flow

1. **Hero** - tagline, subtitle, two CTAs: "Get Started" / "View Docs"
2. **Problem statement** - visual showing fragmentation (4-5 separate tools) vs unified (one gateway). Visual, not wordy.
3. **Use case cards** (3-4) - scenario-driven, not feature-driven:
   - "Route AI traffic across providers"
   - "Protect any API with zero code changes"
   - "Replace your reverse proxy and add intelligence"
   - Each links to a relevant doc or example
4. **Config example** - interactive/tabbed. One YAML file doing what would take 3 tools. The "aha" moment.
5. **Social proof** - GitHub stars, download stats, community size, user logos if available
6. **Comparison section** - "unified vs patchwork" framing. What you need to install/configure with separate tools vs sbproxy. No competitor names.
7. **Getting started CTA** - repeat install commands, low friction
8. **Footer** - Docs, GitHub, Community, single "sbproxy Cloud" link

### Key Changes from Current Site

- Remove all technology mentions
- Replace feature-spec language with outcome language
- Reframe comparison matrix: "unified vs fragmented," not product-vs-product
- Pricing page links out to cloud.sbproxy.dev
- Enterprise section becomes a single mention, not a full page

### Pages

- `/` - Homepage (flow above)
- `/docs` - Documentation landing
- `/docs/:slug` - Documentation pages
- `/compare` - "Unified vs fragmented" comparison (no competitor names)
- Remove `/compare/:slug` individual competitor pages (replaced by unified comparison)
- Remove `/pricing` from this site (lives on cloud.sbproxy.dev)

## Documentation Structure

### 1. Getting Started
- Quick Start
- Core Concepts
- Your First Proxy
- Your First AI Gateway

### 2. Use Case Guides (new - task-oriented)
- Replace your reverse proxy
- Add an AI gateway to your stack
- Secure any API without code changes
- Migrate from other AI gateways
- Migrate from traditional proxies

### 3. Features (reorganized by domain)
- Traffic Management (routing, load balancing, forwarding rules, protocols)
- AI Gateway (providers, routing strategies, guardrails, spend tracking)
- Security (auth, rate limiting, WAF, DDoS, CORS)
- Caching (response cache, semantic cache)
- Observability (logging, metrics, events)
- Scripting (CEL, Lua)

### 4. Reference
- Configuration reference
- API reference
- Provider list
- Examples

### Tone Shift
- Assume the reader knows they have a traffic problem but may not know proxy terminology
- Lead each page with the problem it solves, then show the config
- Enterprise-only features get a small "Cloud" badge inline, no separate section

## Competitive Intelligence Integration

### Positioning Advantages (already have)
- Only unified proxy + AI gateway
- Zero dependencies, single binary
- MCP and A2A support
- 200+ AI providers
- Hot reload without dropped connections

### Feature Gaps to Close (feeds Rust roadmap)
- Deeper semantic caching
- Broader PII detection
- Hierarchical budget controls
- Built-in observability dashboards

### How It Appears on Site
- Comparison page: "unified vs fragmented" table showing what separate tools require
- Feature pages: reference the landscape without naming competitors ("Most AI gateways require a separate reverse proxy. Most reverse proxies don't understand AI traffic.")
- COMPETITORS.md stays internal as a strategy document

## Out of Scope
- No performance benchmarks until we have our own
- No feature claims we can't back up with current codebase
- No competitor names on any public-facing content
- No enterprise docs on sbproxy.dev (lives on cloud site)
