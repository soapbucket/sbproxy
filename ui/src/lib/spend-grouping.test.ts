import { describe, expect, it } from "vitest";

import { spendGroupOptions } from "./spend-grouping";

describe("spendGroupOptions", () => {
  it("offers every dimension the rollup query accepts", () => {
    // `GroupBy::parse` in usage_rollup.rs takes
    // provider|model|tenant|team|api_key|project|origin|agent|property:<key>|total.
    // A dimension missing here is one the server answers and the page
    // cannot ask for.
    expect(spendGroupOptions([], "total").map((o) => o.value)).toEqual([
      "total",
      "model",
      "provider",
      "tenant",
      "team",
      "project",
      "api_key",
      "origin",
      "agent",
    ]);
  });

  it("adds sorted promoted properties after built-in dimensions", () => {
    const options = spendGroupOptions(["tier", "feature", "tier"], "model");

    expect(options.slice(-2)).toEqual([
      { value: "property:feature", label: "Property: feature", unavailable: false },
      { value: "property:tier", label: "Property: tier", unavailable: false },
    ]);
  });

  it("retains a selected property that is unavailable in the new window", () => {
    const options = spendGroupOptions(["feature"], "property:tier");

    expect(options.at(-1)).toEqual({
      value: "property:tier",
      label: "Property: tier (unavailable in window)",
      unavailable: true,
    });
  });
});
