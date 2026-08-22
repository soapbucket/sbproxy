import { describe, expect, it } from "vitest";

import type { AdminKey, GovernanceCounterSnapshot } from "../api";
import { findFamily, parsePrometheus } from "./metrics";
import {
  budgetBar,
  budgetTone,
  estimateErrorByModel,
  priceCeilingOutcomes,
  priceSourceShares,
  selectCappedKeys,
  utilizationByScope,
} from "./cost-trust";

function families(lines: string[]) {
  return parsePrometheus(lines.join("\n"));
}

describe("priceSourceShares", () => {
  it("divides by the family's own total, not by the request count", () => {
    const f = findFamily(
      families([
        "# TYPE sbproxy_ai_price_source_total counter",
        'sbproxy_ai_price_source_total{source="catalog"} 96',
        'sbproxy_ai_price_source_total{source="fallback"} 4',
      ]),
      "sbproxy_ai_price_source_total",
    );
    const reading = priceSourceShares(f);
    expect(reading?.total).toBe(100);
    const bySource = Object.fromEntries(
      (reading?.shares ?? []).map((s) => [s.source, s]),
    );
    expect(bySource.catalog.share).toBeCloseTo(0.96, 6);
    expect(bySource.fallback.share).toBeCloseTo(0.04, 6);
    // The two sources nothing wrote are still listed, at a true zero,
    // because the family itself was found.
    expect(bySource.rate_card.count).toBe(0);
    expect(bySource.config.share).toBe(0);
  });

  it("keeps a source value this build does not know about", () => {
    const f = findFamily(
      families(['sbproxy_ai_price_source_total{source="ledger"} 10']),
      "sbproxy_ai_price_source_total",
    );
    const reading = priceSourceShares(f);
    expect(reading?.shares.at(-1)).toMatchObject({
      source: "ledger",
      share: 1,
    });
  });

  it("is undefined when the family is absent, not a row of zeros", () => {
    expect(priceSourceShares(undefined)).toBeUndefined();
  });

  it("has no shares before the first price lookup", () => {
    const f = findFamily(
      families(['sbproxy_ai_price_source_total{source="catalog"} 0']),
      "sbproxy_ai_price_source_total",
    );
    expect(priceSourceShares(f)?.shares[0].share).toBeUndefined();
  });
});

describe("priceCeilingOutcomes", () => {
  it("reads all four outcomes and links the refusals to their requests", () => {
    const f = findFamily(
      families([
        'sbproxy_ai_price_ceiling_total{outcome="candidate_excluded"} 1204',
        'sbproxy_ai_price_ceiling_total{outcome="refused"} 3',
      ]),
      "sbproxy_ai_price_ceiling_total",
    );
    const rows = priceCeilingOutcomes(f) ?? [];
    expect(rows.map((r) => r.outcome)).toEqual([
      "candidate_excluded",
      "refused",
      "invalid_header",
      "unsupported_surface",
    ]);
    expect(rows[0].count).toBe(1204);
    expect(rows[1].link).toBe("/logs?status=402");
    expect(rows[3].count).toBe(0);
  });

  it("is undefined when the ceiling has never been configured", () => {
    expect(priceCeilingOutcomes(undefined)).toBeUndefined();
  });
});

describe("estimateErrorByModel", () => {
  // The histogram straddles zero: buckets run -1.0 to +1.0 and the sign
  // says which way the estimator was wrong.
  const signed = [
    "# TYPE sbproxy_ai_token_estimate_error_ratio histogram",
    'sbproxy_ai_token_estimate_error_ratio_bucket{model="gpt-5.2",le="-1.0"} 0',
    'sbproxy_ai_token_estimate_error_ratio_bucket{model="gpt-5.2",le="-0.5"} 0',
    'sbproxy_ai_token_estimate_error_ratio_bucket{model="gpt-5.2",le="-0.25"} 0',
    'sbproxy_ai_token_estimate_error_ratio_bucket{model="gpt-5.2",le="-0.1"} 50',
    'sbproxy_ai_token_estimate_error_ratio_bucket{model="gpt-5.2",le="-0.05"} 100',
    'sbproxy_ai_token_estimate_error_ratio_bucket{model="gpt-5.2",le="0.0"} 100',
    'sbproxy_ai_token_estimate_error_ratio_bucket{model="gpt-5.2",le="+Inf"} 100',
  ];

  it("keeps the sign, so an over-reserving estimator reads negative", () => {
    const rows =
      estimateErrorByModel(
        findFamily(families(signed), "sbproxy_ai_token_estimate_error_ratio"),
      ) ?? [];
    expect(rows).toHaveLength(1);
    expect(rows[0].model).toBe("gpt-5.2");
    expect(rows[0].p50).toBeLessThan(0);
    expect(rows[0].p50).toBeGreaterThanOrEqual(-0.25);
    // Both tails, because over-reserving holds rate-limit headroom the
    // request never used and a p95 near zero says nothing about it.
    expect(rows[0].p05).toBeLessThanOrEqual(rows[0].p50);
    expect(rows[0].p95).toBeGreaterThanOrEqual(rows[0].p50);
    expect(rows[0].samples).toBe(100);
  });

  it("does not interpolate the lowest bucket across zero", () => {
    // Everything landed in the first bucket. Anchoring interpolation at
    // 0, the way the shared histogram helper does, reports a value
    // between 0 and -1 that the estimator never produced.
    const rows =
      estimateErrorByModel(
        findFamily(
          families([
            'sbproxy_ai_token_estimate_error_ratio_bucket{model="m",le="-1.0"} 10',
            'sbproxy_ai_token_estimate_error_ratio_bucket{model="m",le="-0.5"} 10',
            'sbproxy_ai_token_estimate_error_ratio_bucket{model="m",le="+Inf"} 10',
          ]),
          "sbproxy_ai_token_estimate_error_ratio",
        ),
      ) ?? [];
    expect(rows[0].p05).toBe(-1);
    expect(rows[0].p50).toBe(-1);
    expect(rows[0].p95).toBe(-1);
  });

  it("is undefined when no model has a per-model rate limit configured", () => {
    expect(estimateErrorByModel(undefined)).toBeUndefined();
  });
});

describe("budgetBar", () => {
  function snapshot(
    over: Partial<GovernanceCounterSnapshot>,
  ): GovernanceCounterSnapshot {
    return {
      limit: null,
      used: 0,
      reserved: 0,
      remaining: null,
      reset_at_millis: null,
      ...over,
    };
  }

  it("gives money held in reserve its own segment", () => {
    const bar = budgetBar(
      snapshot({
        limit: 200_000_000,
        used: 184_000_000,
        reserved: 12_000_000,
        remaining: 4_000_000,
      }),
    );
    expect(bar?.usedUsd).toBe(184);
    expect(bar?.reservedUsd).toBe(12);
    expect(bar?.remainingUsd).toBe(4);
    // 98% of the cap is committed. Folding the held money away would
    // show 92% while the next request is the one that gets refused.
    expect(bar?.ratio).toBeCloseTo(0.98, 6);
    expect(bar?.tone).toBe("err");
    expect((bar?.usedPct ?? 0) + (bar?.reservedPct ?? 0)).toBeLessThanOrEqual(
      100,
    );
  });

  it("reports no headroom for a key with no dollar cap", () => {
    expect(budgetBar(snapshot({ used: 5_000_000 }))).toBeUndefined();
  });

  it("does not overflow the bar when an approximate backend overshoots", () => {
    const bar = budgetBar(
      snapshot({ limit: 100_000_000, used: 140_000_000, reserved: 0, remaining: 0 }),
    );
    expect(bar?.ratio).toBeCloseTo(1.4, 6);
    expect(bar?.usedPct).toBe(100);
    expect(bar?.reservedPct).toBe(0);
  });

  it("thresholds at 75 and 90 percent", () => {
    expect(budgetTone(0.74)).toBe("ok");
    expect(budgetTone(0.75)).toBe("warn");
    expect(budgetTone(0.9)).toBe("warn");
    expect(budgetTone(0.91)).toBe("err");
  });
});

describe("selectCappedKeys", () => {
  const keys: AdminKey[] = [
    {
      id: "k1",
      name: "prod-agent",
      policy_revision: 1,
      effective_budget: { max_cost_usd: 200 },
    },
    { id: "k2", name: "batch-etl", policy_revision: 1, max_budget_usd: 250 },
    { id: "k3", name: "uncapped", policy_revision: 1 },
    {
      id: "k4",
      name: "zero-cap",
      policy_revision: 1,
      effective_budget: { max_cost_usd: 0 },
    },
  ];

  it("keeps only keys with an enforced dollar cap", () => {
    const selection = selectCappedKeys(keys, undefined);
    expect(selection.rows.map((r) => r.id)).toEqual(["k2", "k1"]);
    expect(selection.orderedBy).toBe("cap");
    expect(selection.total).toBe(2);
    expect(selection.truncated).toBe(false);
  });

  it("orders by this window's spend when the caller knows it", () => {
    const selection = selectCappedKeys(keys, { k1: 184, k2: 88 });
    expect(selection.rows.map((r) => r.id)).toEqual(["k1", "k2"]);
    expect(selection.orderedBy).toBe("spend");
    expect(selection.rows[0].windowSpendUsd).toBe(184);
  });

  it("does not claim a spend order when the spend map joined nothing", () => {
    // The rollup groups by the id the request path stamped and the key
    // list comes from the admin store, so the join can miss entirely.
    // Printing "highest spend in this window first" over a list ordered
    // by cap describes an order the list is not in.
    const selection = selectCappedKeys(keys, { unrelated: 500 });
    expect(selection.orderedBy).toBe("cap");
    expect(selection.rows.map((r) => r.id)).toEqual(["k2", "k1"]);
  });

  it("reports the keys it left out rather than stopping quietly", () => {
    const many: AdminKey[] = Array.from({ length: 34 }, (_, i) => ({
      id: `k${i}`,
      policy_revision: 1,
      effective_budget: { max_cost_usd: 34 - i },
    }));
    const selection = selectCappedKeys(many, undefined);
    expect(selection.rows).toHaveLength(20);
    expect(selection.total).toBe(34);
    expect(selection.truncated).toBe(true);
  });
});

describe("utilizationByScope", () => {
  it("takes the highest single budget in each scope", () => {
    const f = findFamily(
      families([
        'sbproxy_ai_budget_utilization_ratio{scope="api_key"} 0.51',
        'sbproxy_ai_budget_utilization_ratio{scope="api_key"} 0.12',
        'sbproxy_ai_budget_utilization_ratio{scope="workspace"} 0.72',
      ]),
      "sbproxy_ai_budget_utilization_ratio",
    );
    expect(utilizationByScope(f)).toEqual([
      { scope: "workspace", ratio: 0.72, tone: "ok" },
      { scope: "api_key", ratio: 0.51, tone: "ok" },
    ]);
  });

  it("is undefined when no budget is configured anywhere", () => {
    expect(utilizationByScope(undefined)).toBeUndefined();
  });
});
