import { describe, expect, it } from "vitest";

import reportsView from "./ReportsView.vue?raw";

describe("ReportsView", () => {
  it("loads the report on mount through the typed api client", () => {
    expect(reportsView).toContain("api.requestsReport(");
    expect(reportsView).toContain("req.run()");
    expect(reportsView).toContain("onMounted(");
  });

  it("groups by model, key, tenant, and user simultaneously", () => {
    for (const dimension of ["model", "api_key_id", "tenant", "user"]) {
      expect(reportsView).toContain(`value: "${dimension}"`);
    }
    // Multi-select grouping, not a single-dimension picker: the group
    // set is an array that joins into one group_by parameter.
    expect(reportsView).toContain('groupBy.value.join(",")');
  });

  it("serializes filter and grouping state into the URL, so the view is a shareable link", () => {
    expect(reportsView).toContain("filterStateToQuery(");
    expect(reportsView).toContain("filterStateFromQuery(route.query");
    expect(reportsView).toContain("router.replace(");
  });

  it("exports the current filtered view as CSV and JSONL", () => {
    expect(reportsView).toContain('api.requestsExportUrl("csv"');
    expect(reportsView).toContain('api.requestsExportUrl("jsonl"');
  });

  it("renders errors and the empty state through the shared components", () => {
    expect(reportsView).toMatch(/<ErrorState\s+v-if="req\.error\.value"/);
    expect(reportsView).toContain("<EmptyState");
  });

  it("labels unattributed group values instead of rendering blanks", () => {
    expect(reportsView).toContain("(unattributed)");
  });
});
