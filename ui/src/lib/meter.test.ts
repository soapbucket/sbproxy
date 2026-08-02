import { describe, expect, it } from "vitest";

import type {
  MeterCoverage,
  MeterSummary,
  MeterUnitRow,
  MeterVerifyResult,
} from "../api";
import {
  coverageHeadline,
  coverageIsPartial,
  degradedGapCount,
  gapCount,
  gapExplanation,
  groupedTotals,
  meterEmptyState,
  nodeHead,
  nodeTone,
  verifyHeadline,
  verifyTone,
} from "./meter";

function summary(overrides: Partial<MeterSummary> = {}): MeterSummary {
  return {
    schema_version: 1,
    state: "reporting",
    reason: null,
    group_by: "tenant",
    tenant: null,
    gathered_at: "2026-08-01T00:00:00Z",
    attestation: { configured: true, role: "receipt" },
    chain: {
      node_id: "node-a",
      present: true,
      entries: 3,
      head_hash: "a3f19c8b",
      damaged_at_seq: null,
      damage_reason: null,
    },
    coverage: null,
    nodes: [],
    totals: [],
    claims: 3,
    gaps: { total: 0, by_tenant: [], divergence_total: 0 },
    ...overrides,
  };
}

function unit(overrides: Partial<MeterUnitRow> = {}): MeterUnitRow {
  return {
    group: "acme",
    tenant: "acme",
    unit: "search_call",
    source: "route_weight",
    count: 1,
    ...overrides,
  };
}

describe("meterEmptyState", () => {
  it("says attestation is off rather than showing a zero", () => {
    const empty = meterEmptyState(
      summary({
        state: "off",
        reason: "proxy.attestation is not configured on this node",
        attestation: { configured: false },
        chain: null,
      }),
    );

    expect(empty?.kind).toBe("off");
    expect(empty?.title).toBe("Attestation is off");
    expect(empty?.detail).toContain("not configured");
  });

  it("distinguishes a configured-but-idle meter from an off one", () => {
    // The whole point of the state field. Both render no units; only one
    // of them means the operator has something to fix in their config.
    const off = meterEmptyState(summary({ state: "off", reason: null, chain: null }));
    const idle = meterEmptyState(summary({ state: "idle", reason: null }));

    expect(off?.kind).toBe("off");
    expect(idle?.kind).toBe("idle");
    expect(idle?.title).toBe("No receipts recorded yet");
    expect(off?.detail).not.toBe(idle?.detail);
  });

  it("separates a busy chain with nothing for this tenant", () => {
    const empty = meterEmptyState(
      summary({ state: "reporting", tenant: "acme", totals: [] }),
    );

    expect(empty?.kind).toBe("no-tenant-units");
    expect(empty?.title).toBe("No units for acme");
    expect(empty?.detail).toContain("3 entries");
  });

  it("renders nothing when there are units to show", () => {
    expect(meterEmptyState(summary({ totals: [unit()] }))).toBeNull();
    expect(meterEmptyState(null)).toBeNull();
  });
});

describe("coverage", () => {
  const partial: MeterCoverage = {
    complete: false,
    expected: 3,
    answered: ["node-1", "node-2"],
    uncovered: [
      {
        node_id: "node-3",
        gap: "unreachable",
        last_known_seq: 48213,
        last_seen_at: "2026-08-01T00:00:00Z",
      },
    ],
    gathered_at: "2026-08-01T00:01:00Z",
  };

  it("is silent when the fan-out was complete", () => {
    expect(coverageIsPartial({ ...partial, complete: true, uncovered: [] })).toBe(false);
  });

  it("is silent when there is no mesh at all", () => {
    // A single-node deployment has one chain and nothing to be partial
    // about. A banner that is always there stops being read.
    expect(coverageIsPartial(null)).toBe(false);
  });

  it("shows when a node is missing from the total", () => {
    expect(coverageIsPartial(partial)).toBe(true);
    expect(coverageHeadline(partial)).toBe("2 of 3 nodes answered");
    expect(coverageHeadline(null)).toBe("");
  });

  it("explains every gap in words an operator can act on", () => {
    expect(gapExplanation("never_reported")).toContain("never published");
    expect(gapExplanation("stale")).toContain("too long ago");
    expect(gapExplanation("not_live")).toContain("live member");
    expect(gapExplanation("unreachable")).toContain("could not be reached");
    expect(gapExplanation("unreadable")).toContain("could not use");
    expect(gapExplanation(undefined)).toContain("outside the total");
  });
});

describe("groupedTotals", () => {
  it("keeps two provenances of one unit as two rows", () => {
    // 3 counted plus 40 priced is not 43. Folding them would produce one
    // unfalsifiable line where there were two checkable ones.
    const groups = groupedTotals([
      unit({ source: "measured", count: 3 }),
      unit({ source: "route_weight", count: 40 }),
    ]);

    expect(groups).toHaveLength(1);
    expect(groups[0].group).toBe("acme");
    expect(groups[0].rows).toHaveLength(2);
    expect(groups[0].count).toBe(43);
    expect(groups[0].rows.map((row) => row.source)).toEqual([
      "measured",
      "route_weight",
    ]);
  });

  it("keeps tenants apart", () => {
    const groups = groupedTotals([
      unit({ group: "acme", tenant: "acme", count: 2 }),
      unit({ group: "globex", tenant: "globex", count: 5 }),
    ]);

    expect(groups.map((group) => group.group)).toEqual(["acme", "globex"]);
    expect(groups.map((group) => group.count)).toEqual([2, 5]);
  });

  it("returns nothing for no rows", () => {
    expect(groupedTotals([])).toEqual([]);
  });
});

describe("gap markers", () => {
  const gaps = [
    { tenant: "acme", failure_mode: "degraded", count: 3 },
    { tenant: "acme", failure_mode: "open", count: 1 },
  ];

  it("totals every posture and isolates the degraded one", () => {
    expect(gapCount(gaps)).toBe(4);
    expect(degradedGapCount(gaps)).toBe(3);
  });

  it("reads zero when the meter never missed a write", () => {
    expect(gapCount([])).toBe(0);
    expect(degradedGapCount([])).toBe(0);
  });
});

describe("node rows", () => {
  it("reads an uncovered node as an error carrying its last known head", () => {
    const node = {
      node_id: "node-3",
      covered: false,
      local: false,
      gap: "unreachable",
      last_known_seq: 48213,
      last_seen_at: "2026-08-01T00:00:00Z",
    };

    expect(nodeTone(node)).toBe("err");
    expect(nodeHead(node)).toBe(48213);
  });

  it("flags a covered node still sitting on genesis", () => {
    // A chain that has never moved is what a meter that never started
    // looks like, and it is invisible on a flat graph.
    expect(nodeTone({ node_id: "node-1", covered: true, local: true, head_seq: 0 })).toBe(
      "warn",
    );
    expect(
      nodeTone({ node_id: "node-1", covered: true, local: true, head_seq: 12 }),
    ).toBe("ok");
  });

  it("reports no head for a node nobody has ever heard from", () => {
    expect(
      nodeHead({
        node_id: "node-9",
        covered: false,
        local: false,
        gap: "never_reported",
        last_known_seq: null,
      }),
    ).toBeNull();
  });
});

describe("verifyHeadline", () => {
  function result(overrides: Partial<MeterVerifyResult>): MeterVerifyResult {
    return {
      schema_version: 1,
      state: "reporting",
      outcome: "ok",
      node_id: "node-a",
      verified_at: "2026-08-01T00:00:00Z",
      ...overrides,
    };
  }

  it("names the failing index on a tampered chain", () => {
    // A red cross tells an operator nothing. A sequence number tells them
    // which receipt to open.
    const line = verifyHeadline(
      result({
        outcome: "broken",
        broken_seq: 1,
        reason: "entry_hash does not match recomputed digest (tampered event)",
      }),
    );

    expect(line).toContain("sequence 1");
    expect(line).toContain("tampered event");
    expect(verifyTone(result({ outcome: "broken" }))).toBe("err");
  });

  it("reports a clean chain with its length", () => {
    expect(verifyHeadline(result({ outcome: "ok", entries: 4 }))).toContain("4 entries");
    expect(verifyTone(result({ outcome: "ok" }))).toBe("ok");
  });

  it("separates an off meter from an unstarted chain", () => {
    expect(verifyHeadline(result({ outcome: "not_started", state: "off" }))).toContain(
      "attestation is off",
    );
    expect(verifyHeadline(result({ outcome: "not_started", state: "idle" }))).toContain(
      "not been created",
    );
    expect(verifyTone(result({ outcome: "not_started" }))).toBe("warn");
  });

  it("says nothing before a run has happened", () => {
    expect(verifyHeadline(null)).toBe("");
    expect(verifyTone(null)).toBe("neutral");
  });
});
