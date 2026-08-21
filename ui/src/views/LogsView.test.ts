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
