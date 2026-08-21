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

  it("keeps the server's explanation when the content sample cannot be read", () => {
    // `e.message` is the request line and the status code, assembled
    // client-side. The sentence naming which consent flag was missing
    // is in ApiError.body, and this view used to throw it away.
    expect(playgroundView).toContain("sampleError = contentSampleErrorMessage(e);");
    expect(playgroundView).not.toContain("e instanceof Error ? e.message :");
  });

  it("does not clobber a prompt typed while the sample was in flight", () => {
    expect(playgroundView).toContain("if (settled.prompt && !prompt.value)");
  });

  it("drops the captured text when it drops the disclosure that it is redacted", () => {
    // The replay card holds the only note saying the loaded text is
    // the stored redaction; unmounting it while the text stays in the
    // box makes Send dispatch redacted content to a live provider with
    // nothing on screen saying so, as one user message rather than the
    // captured turns, and it bills.
    expect(playgroundView).toMatch(
      /function clearReplay\(\) \{[\s\S]*?prompt\.value = "";[\s\S]*?\}/,
    );
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
