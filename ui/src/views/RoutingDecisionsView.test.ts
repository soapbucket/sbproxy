import { describe, expect, it } from "vitest";

import routingDecisionsView from "./RoutingDecisionsView.vue?raw";

describe("RoutingDecisionsView", () => {
  it("loads the decisions ring on mount through the typed api client", () => {
    expect(routingDecisionsView).toContain("api.routingDecisions(currentFilters())");
    expect(routingDecisionsView).toContain("req.run()");
    expect(routingDecisionsView).toContain("onMounted(");
  });

  it("filters server-side by origin, strategy, model, provider, and time range", () => {
    for (const dimension of [
      "{ origin: fOrigin.value }",
      "{ strategy: fStrategy.value }",
      "{ model: fModel.value }",
      "{ provider: fProvider.value }",
    ]) {
      expect(routingDecisionsView).toContain(dimension);
    }
    // Time range travels as an RFC 3339 `since` derived from a rolling
    // window, so the server does the cut, not the table.
    expect(routingDecisionsView).toContain(
      "since: new Date(Date.now() - windowMs).toISOString()",
    );
  });

  it("renders errors and the two empty states through the shared components", () => {
    expect(routingDecisionsView).toMatch(/<ErrorState\s+v-if="req\.error\.value"/);
    expect(routingDecisionsView).toMatch(
      /<EmptyState\s+v-else-if="!req\.loading\.value && !rows\.length"/,
    );
  });

  it("round-trips every filter dimension through the URL, not three of five", () => {
    // `?provider=anthropic` in a shared link used to be dropped on the
    // floor and the recipient saw every provider; nothing was ever
    // written back, so applying a filter left no link worth sharing.
    expect(routingDecisionsView).toContain("filterStateFromQuery(route.query, FILTER_KEYS)");
    expect(routingDecisionsView).toContain("filterStateToQuery({");
    for (const dimension of ["origin", "strategy", "model", "provider", "window"]) {
      expect(routingDecisionsView).toContain(`"${dimension}",`);
    }
    expect(routingDecisionsView).toContain('@click="applyFilters"');
  });

  it("shows the decision anatomy: candidates in order, the winner, the traversed chain, and the reason", () => {
    expect(routingDecisionsView).toContain("Candidates weighed, in order");
    expect(routingDecisionsView).toContain(
      'candidate.provider === decision.selected_provider',
    );
    expect(routingDecisionsView).toContain("decision.attempted");
    expect(routingDecisionsView).toContain('push("Reason", decision.reason)');
  });

  it("renders the open detail map generically so additive columns need no UI change", () => {
    expect(routingDecisionsView).toContain("function extraDetail(");
    expect(routingDecisionsView).toContain("decision.detail");
  });
});
