# SBproxy Documentation

*Last modified: 2026-04-12*

Comprehensive documentation for SBproxy.

| Document | Description |
|----------|-------------|
| [Manual](manual.md) | Runtime reference: CLI flags, environment variables, logging, metrics, TLS, health checks, deployment |
| [Configuration](configuration.md) | All configuration options with YAML examples for every action, auth, policy, and transform type |
| [Config Reference](config.md) | Field-level reference for all config options |
| [Architecture](architecture.md) | Package layout, request pipeline, plugin system, caching, event system, performance |
| [Scripting](scripting.md) | CEL and Lua reference with all context variables, functions, and real-world examples |
| [AI Gateway](ai-gateway.md) | Provider setup, routing strategies, streaming, CEL guardrails |
| [Features](features.md) | Complete feature inventory with working examples |
| [Events](events.md) | Event system, subscriber types, filtering |
| [Providers](providers.md) | 203+ supported AI providers with config names, formats, and documentation links |
| [Comparison](comparison.md) | How SBproxy compares to LiteLLM, Kong, Caddy, Traefik, Nginx, Envoy |

## Examples

See the [examples/](../examples/) directory for ready-to-use configuration files.

## SBproxy Cloud

For managed hosting with a dashboard, advanced security, and AI features, visit [www.soapbucket.com](https://www.soapbucket.com).
