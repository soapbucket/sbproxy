import { describe, expect, it } from "vitest";

import playgroundView from "./PlaygroundView.vue?raw";

// WOR-2580: a logged request replays into the playground. The handoff
// arrives as query params (`replay` = request id, plus the metadata the
// ring retains); the view fetches the redacted content sample through
// the same audited admin endpoint any log read uses, and dispatches
// through the governed data-plane route.
describe("PlaygroundView replay handoff", () => {
  it("accepts the replay handoff from the route query", () => {
    expect(playgroundView).toContain("route.query.replay");
    expect(playgroundView).toContain("beginReplay");
  });

  it("reconstructs the body from the audited content-sample read, never elsewhere", () => {
    expect(playgroundView).toContain("api.requestContent(");
    expect(playgroundView).toContain("resolveReplayContent");
  });

  it("replays every captured message through the dispatch body", () => {
    expect(playgroundView).toContain("replayDispatchMessages(");
  });

  it("states which parts could not be reconstructed", () => {
    expect(playgroundView).toContain("replayGaps");
    expect(playgroundView).toContain("replayAvailabilityNotes");
  });

  it("offers a way back to a plain playground form", () => {
    expect(playgroundView).toContain("clearReplay");
  });
});

// WOR-2497 hardened the playground: `/chat` is the ungoverned direct
// engine call, refused without an explicit `bypass_governance: true`.
// The UI, replay included, must only ever use the governed `/dispatch`
// path, where key policy, budgets, routing, and guardrails all run.
describe("PlaygroundView governed dispatch", () => {
  it("dispatches through the governed data-plane route", () => {
    expect(playgroundView).toContain("api.playgroundDispatch(");
  });

  it("never touches the ungoverned chat route or its bypass flag", () => {
    expect(playgroundView).not.toContain("playgroundChat(");
    expect(playgroundView).not.toContain("bypass_governance");
  });
});
