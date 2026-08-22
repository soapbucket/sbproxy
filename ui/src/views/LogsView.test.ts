import { describe, expect, it } from "vitest";

import logsView from "./LogsView.vue?raw";

// WOR-2580: an expanded log row offers "Replay in playground" so an
// operator can send a logged request back through the governed
// pipeline. The affordance is admin-gated (the dispatch route refuses
// read_only operators) and only appears on rows the playground can
// actually replay.
describe("LogsView replay affordance", () => {
  it("offers replay from the expanded detail row", () => {
    expect(logsView).toContain("Replay in playground");
    expect(logsView).toContain("replayQueryFor");
  });

  it("hands off to the playground route with the reconstructable fields", () => {
    expect(logsView).toContain("name: 'playground'");
  });

  it("gates the affordance on the admin role, like the content-sample read", () => {
    expect(logsView).toMatch(/isAdmin && (canReplay|replayQueryFor)/);
  });
});

// The Spend view links its breakdown rows and its price-ceiling refusal
// count at this page. A link that arrives here and is dropped on the
// floor lands the operator on an unfiltered log, which reads as "no
// evidence" rather than "the filter was not applied".
describe("LogsView deep-link filters", () => {
  it("restores every filter a Spend drill-down can send", () => {
    for (const key of [
      "route.query.origin",
      "route.query.api_key_id",
      "route.query.status",
      "route.query.property_key",
      "route.query.property_value",
    ]) {
      expect(logsView).toContain(key);
    }
  });

  it("seeds visible inputs, so the operator can see what narrowed the list", () => {
    expect(logsView).toMatch(/v-model="fStatus"/);
    expect(logsView).toMatch(/v-model="fPropertyKey"/);
    expect(logsView).toMatch(/v-model="fPropertyValue"/);
  });
});
