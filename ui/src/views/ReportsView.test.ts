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

  it("commits filter state before fetching, so a shared link is not narrower than the table", () => {
    // Bound straight to the loader, Refresh fetched with whatever was
    // in the inputs while the address bar still described the old view:
    // an operator narrows to one tenant, copies the link, and the
    // colleague who opens it sees every tenant's spend.
    expect(reportsView).not.toMatch(/@click="req\.run"[^>]*>\s*Refresh/);
    expect(reportsView).toContain('@click="applyFilters">Refresh');
    expect(reportsView).toContain("const appliedFilters = ref<RequestFilters>({})");
    expect(reportsView).toContain("appliedFilters.value = currentFilters();");
    // And the fetch itself reads the committed state, never the refs.
    expect(reportsView).toContain(
      "api.requestsReport(appliedGroupBy.value, appliedFilters.value)",
    );
  });

  it("builds the export links from committed state, never from uncommitted input", () => {
    // Otherwise the table on screen is unfiltered and the downloaded
    // file is not, under a button whose comment says "the current
    // filtered view".
    expect(reportsView).toContain('api.requestsExportUrl("csv", appliedFilters.value)');
    expect(reportsView).toContain('api.requestsExportUrl("jsonl", appliedFilters.value)');
    expect(reportsView).not.toContain('api.requestsExportUrl("csv", currentFilters())');
    expect(reportsView).not.toContain('api.requestsExportUrl("jsonl", currentFilters())');
  });

  it("downloads through the typed client, so a lapsed session is an error and not a file", () => {
    // A bare <a download> never enters request()'s 401 branch: the
    // browser saved {"error":"Unauthorized"} as requests.csv and the
    // console said nothing.
    expect(reportsView).toContain("api.requestsExport(format, appliedFilters.value)");
    expect(reportsView).toContain('@click.prevent="downloadExport(\'csv\')"');
    expect(reportsView).toContain('@click.prevent="downloadExport(\'jsonl\')"');
    expect(reportsView).toContain("exportError");
  });

  it("renders errors and the empty state through the shared components", () => {
    expect(reportsView).toMatch(/<ErrorState\s+v-if="req\.error\.value"/);
    expect(reportsView).toContain("<EmptyState");
  });

  it("labels unattributed group values instead of rendering blanks", () => {
    expect(reportsView).toContain("(unattributed)");
  });
});
