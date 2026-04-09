# AI Package: Enterprise Files

Files listed below will move to an enterprise-only build in a future phase.
They are not needed for core proxy operation and depend on enterprise subsystems
(budget enforcement, guardrails, key rotation, RBAC, alerting).

## Root ai/ package - enterprise files

| File                    | Feature            | Reason                                      |
|-------------------------|--------------------|---------------------------------------------|
| health_checker.go       | Provider health    | Monitors AI provider health, enterprise SLA  |
| provider_budget.go      | Budget enforcement | Per-provider budget tracking                  |
| budget_flags.go         | Budget flags       | Feature flags for budget behavior             |
| handler_responses.go    | Response handling  | Enterprise response post-processing           |
| router_complexity.go    | Smart routing      | Complexity-based model selection              |
| mirror.go               | Traffic mirroring  | Dual-write to shadow provider                 |
| key_pool.go             | Key management     | Pool of API keys with rotation                |
| passthrough_config.go   | Passthrough mode   | Enterprise passthrough configuration          |

## ai/alerts/ directory (entire directory)

Enterprise alerting for AI budget, latency, and error thresholds.

## ai/keys/ - enterprise files

| File                    | Feature            | Reason                                      |
|-------------------------|--------------------|---------------------------------------------|
| rotation_subscriber.go  | Key rotation       | Real-time key rotation via pub/sub            |
| guardrails.go           | Key guardrails     | Per-key usage guardrails                      |
| project.go              | Project keys       | Project-scoped key management                 |
| aliases.go              | Key aliases        | Named aliases for key pools                   |

## ai/rbac/ directory (entire directory)

Role-based access control for AI endpoints.

## ai/guardrails/ - enterprise files

| File                    | Feature            | Reason                                      |
|-------------------------|--------------------|---------------------------------------------|
| parallel.go             | Parallel guardrails| Run multiple guardrail checks concurrently   |

## Notes

- Core AI files (budget.go, cel_router.go, compat.go, etc.) stay in internal/ai/.
- The ai/providers/, ai/routing/, ai/cache/ subdirectories need separate analysis
  to determine which files are core vs enterprise.
- Decoupling will use build tags (`//go:build enterprise`) or interface extraction.
