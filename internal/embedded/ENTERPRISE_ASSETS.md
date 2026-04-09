# Embedded Assets: Core vs Enterprise

This file documents which embedded data files are core (required for basic proxy
operation) and which are enterprise-only (needed only for AI gateway, WAF, or
geo-IP features). The split will be enacted in Phase 6.

## Core Assets (required for all builds)

| File                  | Variable        | Purpose                              |
|-----------------------|-----------------|--------------------------------------|
| version.json          | versionJSON     | Build metadata and file checksums    |
| data/ai_providers.yml.gz | aiProvidersGz | Provider endpoint registry (used by proxy action routing) |

## Enterprise Assets (move to enterprise build tag in Phase 6)

| File                         | Variable        | Feature         | Purpose                              |
|------------------------------|-----------------|-----------------|--------------------------------------|
| data/model_pricing.json.gz   | modelPricingGz  | AI budget/cost  | Token pricing catalog for cost routing and budget enforcement |
| data/regexes.yml.gz          | regexesGz       | WAF             | Regular expressions for WAF rule matching |
| data/ipinfo_lite.mmdb.gz     | ipinfoGz        | Geo-IP          | MaxMind-format IP geolocation database |

## Phase 6 Plan

1. Add `//go:build enterprise` tag to a new `embedded_enterprise.go` file.
2. Move the three enterprise embed vars and their ExtractToTemp entries there.
3. Core build gets stub functions that return empty bytes or "not available" errors.
4. ai_providers.yml stays in core because the proxy action type resolver needs it.
