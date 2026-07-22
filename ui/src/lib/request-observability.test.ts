import { describe, expect, it } from "vitest";

import type { RequestLog } from "../api";
import {
  buildSessionForest,
  discoverPropertyKeys,
  gatewayBadges,
  logGroups,
  matchesProperty,
  restorePropertyColumns,
  requestMatchesFilters,
  sessionCallChain,
  worstStatus,
} from "./request-observability";

function row(overrides: Partial<RequestLog> = {}): RequestLog {
  return {
    timestamp: "2026-07-21T12:00:00.000Z",
    method: "POST",
    path: "/v1/chat/completions",
    status: 200,
    latency_ms: 100,
    ...overrides,
  };
}

describe("worstStatus", () => {
  it("ranks HTTP classes before numeric codes and ignores malformed values", () => {
    expect(
      worstStatus([
        row({ status: 429 }),
        row({ status: 503 }),
        row({ status: 599 }),
        row({ status: undefined, status_code: 302 }),
        row({ status: Number.NaN }),
      ]),
    ).toBe(599);
    expect(worstStatus([row({ status: 204 }), row({ status: 404 })])).toBe(404);
    expect(worstStatus([row({ status: undefined })])).toBeUndefined();
  });
});

describe("buildSessionForest", () => {
  it("rolls up session requests, tokens, cost, duration, and worst status", () => {
    const forest = buildSessionForest([
      row({
        session_id: "root",
        timestamp: "2026-07-21T12:00:00.000Z",
        latency_ms: 500,
        status: 200,
        tokens_in: 10,
        tokens_out: 20,
        cost_usd_micros: 100,
      }),
      row({
        session_id: "root",
        timestamp: "2026-07-21T12:00:02.000Z",
        latency_ms: 750,
        status: 429,
        tokens_in: 30,
        tokens_out: 40,
        cost_usd_micros: 250,
      }),
    ]);

    expect(forest.roots).toHaveLength(1);
    expect(forest.roots[0]).toMatchObject({
      sessionId: "root",
      requestCount: 2,
      tokensIn: 40,
      tokensOut: 60,
      totalTokens: 100,
      costUsdMicros: 350,
      wallClockMs: 2750,
      worstStatus: 429,
      orphaned: false,
    });
  });

  it("builds a stable hierarchy, promotes orphans, and breaks cycles", () => {
    const forest = buildSessionForest([
      row({ session_id: "child", parent_session_id: "root" }),
      row({ session_id: "root" }),
      row({ session_id: "orphan", parent_session_id: "missing" }),
      row({ session_id: "cycle-a", parent_session_id: "cycle-b" }),
      row({ session_id: "cycle-b", parent_session_id: "cycle-a" }),
      row({ session_id: undefined }),
    ]);

    const root = forest.byId.get("root");
    expect(root?.children.map((child) => child.sessionId)).toEqual(["child"]);
    expect(forest.byId.get("orphan")).toMatchObject({ orphaned: true });
    expect(forest.orphans.map((session) => session.sessionId)).toEqual(["orphan"]);
    expect(forest.ungrouped).toHaveLength(1);
    expect(forest.roots.map((session) => session.sessionId)).toEqual([
      "cycle-a",
      "root",
    ]);
    expect(forest.byId.get("cycle-a")?.children.map((child) => child.sessionId)).toEqual([
      "cycle-b",
    ]);
  });
});

describe("sessionCallChain", () => {
  it("sorts valid timestamps oldest first and malformed timestamps last", () => {
    const rows = [
      row({ request_id: "late", session_id: "s", timestamp: "2026-07-21T12:00:02Z" }),
      row({ request_id: "bad", session_id: "s", timestamp: "not-a-time" }),
      row({ request_id: "early", session_id: "s", timestamp: "2026-07-21T12:00:01Z" }),
      row({ request_id: "other", session_id: "other" }),
    ];

    expect(sessionCallChain(rows, "s").map((request) => request.request_id)).toEqual([
      "early",
      "late",
      "bad",
    ]);
  });
});

describe("promoted properties", () => {
  it("discovers sorted keys and matches exact redacted values", () => {
    const rows = [
      row({ properties: { tier: "gold", feature: "assistant" } }),
      row({ properties: { feature: "search" } }),
      row({ properties: undefined }),
    ];

    expect(discoverPropertyKeys(rows)).toEqual(["feature", "tier"]);
    expect(matchesProperty(rows[0], "tier")).toBe(true);
    expect(matchesProperty(rows[0], "tier", "gold")).toBe(true);
    expect(matchesProperty(rows[0], "tier", "Gold")).toBe(false);
    expect(matchesProperty(rows[1], "tier")).toBe(false);
  });
});

describe("requestMatchesFilters", () => {
  it("applies the server snapshot predicate to live rows", () => {
    const request = row({
      method: "post",
      path: "/v1/chat/completions?stream=true",
      status: 503,
      cache_status: "miss",
      retry_count: 2,
      guardrail_action: "block",
      guardrail_category: "pii",
      properties: { tier: "gold" },
    });

    expect(
      requestMatchesFilters(request, {
        method: "POST",
        status: "5xx",
        path: "chat",
        cacheStatus: "miss",
        retried: true,
        guardrailAction: "block",
        guardrailCategory: "pii",
        propertyKey: "tier",
        propertyValue: "gold",
      }),
    ).toBe(true);
    expect(requestMatchesFilters(request, { retried: false })).toBe(false);
  });
});

describe("gatewayBadges", () => {
  it("uses a deterministic causal order", () => {
    expect(
      gatewayBadges(
        row({
          cache_status: "semantic_hit",
          retry_count: 2,
          failover_engaged: true,
          failover_from: "openai",
          failover_to: "anthropic",
          load_balancer_strategy: "lowest_latency",
          load_balancer_target: "anthropic",
          guardrail_action: "block",
          guardrail_category: "pii",
        }),
      ).map((badge) => [badge.kind, badge.label]),
    ).toEqual([
      ["cache", "semantic hit"],
      ["retry", "retry ×2"],
      ["failover", "openai → anthropic"],
      ["balancer", "lowest latency: anthropic"],
      ["guardrail", "blocked: pii"],
    ]);
  });

  it("marks legacy rows neutrally instead of inventing a gateway outcome", () => {
    expect(gatewayBadges(row())).toEqual([
      { kind: "legacy", label: "gateway data unavailable", tone: "neutral" },
    ]);
  });
});

describe("Logs presentation state", () => {
  it("restores only available, unique property columns", () => {
    expect(
      restorePropertyColumns(
        ["feature", "region", "tier"],
        '["tier","missing","tier","feature"]',
      ),
    ).toEqual(["tier", "feature"]);
    expect(restorePropertyColumns(["tier"], "not-json")).toEqual([]);
  });

  it("switches between one request ledger and session sections", () => {
    const requests = [
      row({ request_id: "child", session_id: "child", parent_session_id: "root" }),
      row({ request_id: "root", session_id: "root" }),
      row({ request_id: "none", session_id: undefined }),
    ];

    expect(logGroups(requests, false)).toMatchObject([
      { key: "all", kind: "all", depth: 0, requests },
    ]);
    expect(
      logGroups(requests, true).map((group) => [
        group.kind,
        group.key,
        group.depth,
        group.requests[0]?.request_id,
      ]),
    ).toEqual([
      ["session", "root", 0, "root"],
      ["session", "child", 1, "child"],
      ["ungrouped", "ungrouped", 0, "none"],
    ]);
  });
});
