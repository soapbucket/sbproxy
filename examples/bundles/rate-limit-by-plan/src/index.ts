// rate-limit-by-plan: a proposed sbproxy policy bundle.
//
// Design doc: https://app.notion.com/p/3b068ca7910e81f6b086ff1ecf912054 (§5)
// Not runnable against sbproxy today — see examples/bundles/README.md.
//
// Types below match the shape @sbproxy/extension-types would ship
// (generated from crates/sbproxy-plugin/src/{traits,error}.rs). They're
// spelled out inline here since the package doesn't exist yet.

interface PolicyRequest {
  method: string;
  uri: string;
  headers: Record<string, string>;
  origin: string;
}

type PolicyDecision =
  | { kind: "allow" }
  | { kind: "allow_with_headers"; headers: [string, string][] }
  | { kind: "deny"; status: number; message: string };

interface RateLimitByPlanConfig {
  requests_per_minute: number;
  plan_header: string;
}

// Bundles run in a sandboxed engine with no state that survives across
// invocations (the same isolation guarantee sbproxy's built-in Lua/JS
// scripting already gives, per docs/scripting.md's sandbox section) —
// so a real rate limiter needs a host-provided counter (e.g. a future KV
// binding), which isn't part of this proposal yet. This example reads a
// pre-computed request count from a header instead, standing in for
// whatever eventually supplies that number. Swap `readRequestCount` for
// a real counter lookup once one exists.
function readRequestCount(req: PolicyRequest): number {
  const raw = req.headers["x-request-count"];
  const parsed = raw ? Number.parseInt(raw, 10) : 0;
  return Number.isFinite(parsed) ? parsed : 0;
}

export function enforce(req: PolicyRequest, config: RateLimitByPlanConfig): PolicyDecision {
  const plan = req.headers[config.plan_header];
  if (plan === "free" && readRequestCount(req) > config.requests_per_minute) {
    return {
      kind: "deny",
      status: 429,
      message: `plan '${plan}' exceeded ${config.requests_per_minute} requests/minute`,
    };
  }
  return { kind: "allow" };
}
