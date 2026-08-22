import { describe, expect, it } from "vitest";

import type { SpendWindowBucket, SpendWindowResponse } from "../api";
import {
  compareRows,
  costPerMillionTokens,
  cumulative,
  drillDownLink,
  priorWindowRange,
  rebucket,
  rowsByGroup,
  runRate,
  shiftForward,
  spendDelta,
  spendVariance,
  toSeriesPoints,
  tooCoarseForChart,
  topNWithOther,
  unattributedSpend,
  WINDOW_SECS,
} from "./spend-derive";

function bucket(over: Partial<SpendWindowBucket> = {}): SpendWindowBucket {
  return {
    ts_secs: 0,
    group: "",
    requests: 0,
    tokens_in: 0,
    tokens_out: 0,
    cost_usd_micros: 0,
    ok: 0,
    blocked: 0,
    error: 0,
    ...over,
  };
}

function response(
  buckets: SpendWindowBucket[],
  over: Partial<SpendWindowResponse> = {},
): SpendWindowResponse {
  const totals = buckets.reduce(
    (acc, b) => ({
      requests: acc.requests + b.requests,
      tokens_in: acc.tokens_in + b.tokens_in,
      tokens_out: acc.tokens_out + b.tokens_out,
      cost_usd_micros: acc.cost_usd_micros + b.cost_usd_micros,
      ok: acc.ok + b.ok,
      blocked: acc.blocked + b.blocked,
      error: acc.error + b.error,
    }),
    {
      requests: 0,
      tokens_in: 0,
      tokens_out: 0,
      cost_usd_micros: 0,
      ok: 0,
      blocked: 0,
      error: 0,
    },
  );
  return {
    from: 0,
    to: 0,
    group_by: "model",
    bucket_secs: 3600,
    buckets,
    totals,
    property_keys: [],
    ...over,
  };
}

describe("prior window", () => {
  it("is the same length, immediately before the selected one", () => {
    expect(priorWindowRange("24h", 1_000_000)).toEqual({
      from: 1_000_000 - 2 * 86_400,
      to: 1_000_000 - 86_400,
    });
    // The server requires from < to and parses both as Unix seconds.
    const range = priorWindowRange("7d", 1_755_000_000.7);
    expect(range.from).toBeLessThan(range.to);
    expect(Number.isInteger(range.from)).toBe(true);
    expect(range.to - range.from).toBe(WINDOW_SECS["7d"]);
  });
});

describe("spendDelta", () => {
  it("reports the change and its percentage", () => {
    expect(spendDelta(412.9, 349.61).absolute).toBeCloseTo(63.29, 5);
    expect(spendDelta(412.9, 349.61).ratio).toBeCloseTo(0.181, 3);
  });

  it("has no percentage against a prior window of zero", () => {
    // "+100%" and "+Infinity%" are both inventions. The view says the
    // prior window recorded nothing instead.
    expect(spendDelta(50, 0)).toEqual({ absolute: 50, ratio: undefined });
  });
});

describe("runRate", () => {
  const now = 100 * 3600; // an exact hour boundary

  it("averages over the last six complete hours, counting idle hours as zero", () => {
    // Two hours of $6 each inside the six-hour basis: $12 over 6h is
    // $48/day, not the $144/day an average over present buckets gives.
    const rate = runRate(
      response(
        [
          bucket({ ts_secs: now - 6 * 3600, cost_usd_micros: 6_000_000 }),
          bucket({ ts_secs: now - 2 * 3600, cost_usd_micros: 6_000_000 }),
        ],
        { from: now - 86_400, to: now },
      ),
      "24h",
      now,
    );
    expect(rate?.perDay).toBeCloseTo(48, 6);
    expect(rate?.basisSecs).toBe(6 * 3600);
    expect(rate?.overWindow).toBeCloseTo(48, 6);
  });

  it("projects over the selected window, not always over a day", () => {
    const rate = runRate(
      response([bucket({ ts_secs: now - 3600, cost_usd_micros: 6_000_000 })], {
        from: now - 30 * 86_400,
        to: now,
      }),
      "30d",
      now,
    );
    expect(rate?.perDay).toBeCloseTo(24, 6);
    expect(rate?.overWindow).toBeCloseTo(24 * 30, 6);
  });

  it("is undefined when the window is too short to hold the basis", () => {
    // A one hour window cannot support a six hour basis, and a rate from
    // one bucket is noise with a dollar sign on it.
    expect(
      runRate(response([], { from: now - 3600, to: now }), "1h", now),
    ).toBeUndefined();
  });
});

describe("costPerMillionTokens", () => {
  it("blends input and output", () => {
    expect(costPerMillionTokens(3.11, 700_000, 300_000)).toBeCloseTo(3.11, 6);
  });

  it("is undefined rather than zero when no tokens moved", () => {
    expect(costPerMillionTokens(5, 0, 0)).toBeUndefined();
  });
});

describe("unattributedSpend", () => {
  it("counts the empty group key against the window total", () => {
    const res = response([
      bucket({ group: "gpt-5.2", cost_usd_micros: 363_350_000 }),
      bucket({ group: "", cost_usd_micros: 49_550_000 }),
    ]);
    const un = unattributedSpend(res);
    expect(un.usd).toBeCloseTo(49.55, 6);
    expect(un.totalUsd).toBeCloseTo(412.9, 6);
    expect(un.share).toBeCloseTo(0.12, 2);
  });

  it("has no share on an empty window", () => {
    expect(unattributedSpend(response([])).share).toBeUndefined();
  });
});

describe("rowsByGroup and compareRows", () => {
  it("folds buckets per group, highest spend first", () => {
    const rows = rowsByGroup([
      bucket({ ts_secs: 0, group: "a", cost_usd_micros: 1_000_000, requests: 2 }),
      bucket({ ts_secs: 3600, group: "a", cost_usd_micros: 1_000_000, blocked: 1 }),
      bucket({ ts_secs: 0, group: "b", cost_usd_micros: 5_000_000 }),
    ]);
    expect(rows.map((r) => r.group)).toEqual(["b", "a"]);
    expect(rows[1]).toMatchObject({ costUsd: 2, requests: 2, blocked: 1 });
  });

  it("marks a group that only one window saw, instead of a silent zero", () => {
    const now = rowsByGroup([
      bucket({ group: "kept", cost_usd_micros: 4_000_000 }),
      bucket({ group: "new", cost_usd_micros: 1_000_000 }),
    ]);
    const prior = rowsByGroup([
      bucket({ group: "kept", cost_usd_micros: 3_000_000 }),
      bucket({ group: "gone", cost_usd_micros: 2_000_000 }),
    ]);
    const compared = compareRows(now, prior, 5);
    const byGroup = Object.fromEntries(compared.map((r) => [r.group, r]));
    expect(byGroup.kept.vsPrior).toBeCloseTo(1, 6);
    expect(byGroup.kept.presence).toBe("both");
    // A brand new group has no prior value to subtract, so the delta is
    // absent rather than "+$1.00 from nothing".
    expect(byGroup.new.vsPrior).toBeUndefined();
    expect(byGroup.new.presence).toBe("new");
    // A group that stopped keeps its old dollars as a negative delta.
    expect(byGroup.gone.vsPrior).toBeCloseTo(-2, 6);
    expect(byGroup.gone.costUsd).toBe(0);
    expect(byGroup.gone.presence).toBe("gone");
  });
});

describe("topNWithOther", () => {
  it("keeps the folded dollars so the bars still sum to the total", () => {
    const rows = [
      { group: "a", costUsd: 10 },
      { group: "b", costUsd: 8 },
      { group: "c", costUsd: 3 },
      { group: "", costUsd: 2 },
      { group: "e", costUsd: 1 },
    ];
    const items = topNWithOther(rows, 3);
    expect(items.map((i) => i.key)).toEqual(["a", "b", "c", "Other (2 more)"]);
    expect(items[3].value).toBe(3);
    expect(items.reduce((s, i) => s + i.value, 0)).toBe(24);
  });

  it("labels the empty group rather than rendering a blank bar", () => {
    expect(topNWithOther([{ group: "", costUsd: 1 }], 8)[0].key).toBe(
      "(unattributed)",
    );
  });

  it("adds no Other row when everything fits", () => {
    expect(topNWithOther([{ group: "a", costUsd: 1 }], 8)).toHaveLength(1);
  });
});

describe("rebucket", () => {
  function hourly(count: number): SpendWindowBucket[] {
    return Array.from({ length: count }, (_, i) =>
      bucket({ ts_secs: i * 3600, cost_usd_micros: 1_000_000 }),
    );
  }

  it("leaves a 24 hour window alone", () => {
    const out = rebucket(hourly(24), 3600);
    expect(out.foldedSecs).toBe(3600);
    expect(out.points).toHaveLength(24);
  });

  it("folds 168 hourly buckets to 28 six-hour points", () => {
    const out = rebucket(hourly(168), 3600);
    expect(out.foldedSecs).toBe(6 * 3600);
    expect(out.points).toHaveLength(28);
  });

  it("folds 720 hourly buckets to 30 daily points", () => {
    const out = rebucket(hourly(720), 3600);
    expect(out.foldedSecs).toBe(86_400);
    expect(out.points).toHaveLength(30);
  });

  it("preserves the total dollars through the fold", () => {
    const out = rebucket(hourly(168), 3600);
    expect(out.points.reduce((s, p) => s + p.usd, 0)).toBeCloseTo(168, 6);
  });

  it("sums groups that share a timestamp", () => {
    const out = rebucket(
      [
        bucket({ ts_secs: 0, group: "a", cost_usd_micros: 1_000_000 }),
        bucket({ ts_secs: 0, group: "b", cost_usd_micros: 2_000_000 }),
      ],
      3600,
    );
    expect(out.points).toEqual([{ tsSecs: 0, usd: 3 }]);
  });
});

describe("chart shaping", () => {
  it("says when a window is finer than the rollup can bucket", () => {
    expect(tooCoarseForChart("1h", 3600)).toBe(true);
    expect(tooCoarseForChart("24h", 3600)).toBe(false);
  });

  it("accumulates for the burn-down view", () => {
    expect(
      cumulative([
        { tsSecs: 0, usd: 1 },
        { tsSecs: 3600, usd: 2 },
        { tsSecs: 7200, usd: 3 },
      ]).map((p) => p.usd),
    ).toEqual([1, 3, 6]);
  });

  it("shifts the prior series onto the current window's x-axis", () => {
    expect(shiftForward([{ tsSecs: 0, usd: 1 }], "24h")).toEqual([
      { tsSecs: 86_400, usd: 1 },
    ]);
  });

  it("hands the chart milliseconds", () => {
    expect(toSeriesPoints([{ tsSecs: 10, usd: 2 }])).toEqual([
      { t: 10_000, v: 2 },
    ]);
  });
});

describe("spendVariance", () => {
  it("splits a rise into more tokens and a costlier mix", () => {
    // 1M tokens at $0.30/1k prior; 1.1M now at a higher blended rate.
    const v = spendVariance(363.29, 1_100_000, 300, 1_000_000);
    expect(v?.total).toBeCloseTo(63.29, 6);
    expect(v?.volume).toBeCloseTo(30, 6);
    expect(v?.mix).toBeCloseTo(33.29, 6);
    // The two parts always reconstruct the whole change.
    expect((v?.volume ?? 0) + (v?.mix ?? 0)).toBeCloseTo(v?.total ?? 0, 6);
  });

  it("handles a fall as readily as a rise", () => {
    const v = spendVariance(80, 800_000, 100, 1_000_000);
    expect(v?.total).toBeCloseTo(-20, 6);
    expect(v?.volume).toBeCloseTo(-20, 6);
    expect(v?.mix).toBeCloseTo(0, 6);
  });

  it("is suppressed rather than dividing by zero tokens", () => {
    expect(spendVariance(10, 0, 5, 100)).toBeUndefined();
    expect(spendVariance(10, 100, 5, 0)).toBeUndefined();
  });
});

describe("drillDownLink", () => {
  it("links only where the destination shows the filter it applied", () => {
    expect(drillDownLink("origin", "api.example.com")).toBe(
      "/logs?origin=api.example.com",
    );
    expect(drillDownLink("api_key", "key/prod agent")).toBe(
      "/logs?api_key_id=key%2Fprod%20agent",
    );
    // Logs has no model or tenant input, so those go to Reports, which
    // restores both into visible fields and prices each row.
    expect(drillDownLink("model", "gpt-5.2")).toBe(
      "/reports?model=gpt-5.2&group_by=model",
    );
    expect(drillDownLink("tenant", "acme")).toBe(
      "/reports?tenant=acme&group_by=tenant",
    );
    expect(drillDownLink("property:feature", "chat")).toBe(
      "/logs?property_key=feature&property_value=chat",
    );
  });

  it("refuses a link the request ring cannot filter on", () => {
    // A label that looks clickable and lands on an unfiltered page is
    // worse than a plain label.
    for (const dim of ["provider", "team", "project", "agent", "total"]) {
      expect(drillDownLink(dim, "anything")).toBeUndefined();
    }
  });

  it("never links the unattributed segment", () => {
    expect(drillDownLink("model", "")).toBeUndefined();
  });
});
