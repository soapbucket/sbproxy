import { describe, expect, it } from "vitest";

import type { ContentSample, RequestLog } from "../api";
import {
  beginReplay,
  replayAvailabilityNotes,
  replayDispatchMessages,
  replayGaps,
  replayQueryFor,
  resolveReplayContent,
} from "./replay";

const aiRow: RequestLog = {
  request_id: "req-1",
  origin: "api.ai.internal",
  model: "gpt-4o-mini",
  provider: "openai",
  api_key_id: "sbk_alpha",
  key_mode: "minted",
};

const sample: ContentSample = {
  request_id: "req-1",
  tenant_id: "default",
  origin: "api.ai.internal",
  model: "gpt-4o-mini",
  captured_at: "2026-08-20T10:00:00Z",
  input_messages: [
    { role: "system", content: "You are terse." },
    { role: "user", content: "First question" },
    { role: "assistant", content: "First answer" },
    { role: "user", content: "Second [redacted] question" },
  ],
  output_text: "Second answer",
};

describe("replayQueryFor", () => {
  it("builds the playground handoff query from an AI log row", () => {
    expect(replayQueryFor(aiRow)).toEqual({
      replay: "req-1",
      origin: "api.ai.internal",
      model: "gpt-4o-mini",
      key: "sbk_alpha",
    });
  });

  it("passes only a minted virtual key, never a native provider key", () => {
    expect(replayQueryFor({ ...aiRow, key_mode: "native" })).toMatchObject({
      replay: "req-1",
    });
    expect(replayQueryFor({ ...aiRow, key_mode: "native" })).not.toHaveProperty(
      "key",
    );
  });

  it("refuses rows the playground cannot replay", () => {
    // Not an AI dispatch: a plain proxied HTTP row.
    expect(
      replayQueryFor({ request_id: "r", origin: "plain.http", method: "GET" }),
    ).toBeNull();
    // No request id to correlate a content sample with.
    expect(replayQueryFor({ origin: "api.ai.internal", model: "m" })).toBeNull();
    // No origin to dispatch against.
    expect(replayQueryFor({ request_id: "r", model: "m" })).toBeNull();
  });

  it("replays a request blocked before a model or provider resolved", () => {
    // A guardrail block or a token-counted refusal is still an AI
    // dispatch, and reproducing it is the point of replay.
    expect(
      replayQueryFor({
        request_id: "r",
        origin: "api.ai.internal",
        guardrail_action: "block",
      }),
    ).toEqual({ replay: "r", origin: "api.ai.internal" });
    expect(
      replayQueryFor({
        request_id: "r",
        origin: "api.ai.internal",
        tokens_in: 12,
      }),
    ).toEqual({ replay: "r", origin: "api.ai.internal" });
  });
});

describe("resolveReplayContent", () => {
  const seed = beginReplay({
    requestId: "req-1",
    origin: "api.ai.internal",
    model: "gpt-4o-mini",
    keyId: "sbk_alpha",
  });

  it("starts pending, with nothing reconstructed yet", () => {
    expect(seed.content).toBe("pending");
    expect(seed.messages).toBeNull();
    expect(seed.prompt).toBe("");
  });

  it("seeds the prompt from the last captured user message, verbatim", () => {
    const draft = resolveReplayContent(seed, sample, null);
    expect(draft.content).toBe("captured");
    expect(draft.prompt).toBe("Second [redacted] question");
    expect(draft.messages).toHaveLength(4);
    expect(draft.messages?.[0]).toEqual({
      role: "system",
      content: "You are terse.",
    });
  });

  it("fills origin and model from the sample when the query lacked them", () => {
    const bare = beginReplay({ requestId: "req-1" });
    const draft = resolveReplayContent(bare, sample, null);
    expect(draft.origin).toBe("api.ai.internal");
    expect(draft.model).toBe("gpt-4o-mini");
  });

  it("never invents content when the sample is missing", () => {
    const draft = resolveReplayContent(seed, null, "no content sample for that request id");
    expect(draft.content).toBe("missing");
    expect(draft.messages).toBeNull();
    expect(draft.prompt).toBe("");
    expect(draft.contentGap).toBe("no content sample for that request id");
  });
});

describe("replayDispatchMessages", () => {
  it("sends a single user message when nothing was captured", () => {
    expect(replayDispatchMessages(null, "hello")).toEqual([
      { role: "user", content: "hello" },
    ]);
    const missing = resolveReplayContent(
      beginReplay({ requestId: "req-1" }),
      null,
      "no sample",
    );
    expect(replayDispatchMessages(missing, "hello")).toEqual([
      { role: "user", content: "hello" },
    ]);
  });

  it("replays every captured message in order, with the edited prompt in the last user slot", () => {
    const draft = resolveReplayContent(
      beginReplay({ requestId: "req-1" }),
      sample,
      null,
    );
    expect(replayDispatchMessages(draft, "edited question")).toEqual([
      { role: "system", content: "You are terse." },
      { role: "user", content: "First question" },
      { role: "assistant", content: "First answer" },
      { role: "user", content: "edited question" },
    ]);
  });

  it("appends a user message when the capture holds none", () => {
    const draft = resolveReplayContent(
      beginReplay({ requestId: "req-1" }),
      {
        ...sample,
        input_messages: [{ role: "system", content: "You are terse." }],
      },
      null,
    );
    expect(replayDispatchMessages(draft, "typed by hand")).toEqual([
      { role: "system", content: "You are terse." },
      { role: "user", content: "typed by hand" },
    ]);
  });
});

describe("replayGaps", () => {
  it("always states that sampling parameters are not retained", () => {
    for (const draft of [
      beginReplay({ requestId: "r" }),
      resolveReplayContent(beginReplay({ requestId: "r" }), sample, null),
      resolveReplayContent(beginReplay({ requestId: "r" }), null, "no sample"),
    ]) {
      expect(replayGaps(draft).join(" ")).toContain(
        "Sampling parameters are not retained",
      );
    }
  });

  it("states the body gap, with the server's reason, when nothing was captured", () => {
    const draft = resolveReplayContent(
      beginReplay({ requestId: "r" }),
      null,
      "capture requires the origin's capture_content flag AND the key policy's allow_content_capture consent",
    );
    const text = replayGaps(draft).join(" ");
    expect(text).toContain("could not be reconstructed");
    expect(text).toContain("allow_content_capture");
  });

  it("states that a captured replay sends redacted text, not the original", () => {
    const draft = resolveReplayContent(beginReplay({ requestId: "r" }), sample, null);
    expect(replayGaps(draft).join(" ")).toContain("redacted");
  });

  it("flags a capture that holds no user message instead of inventing one", () => {
    const draft = resolveReplayContent(
      beginReplay({ requestId: "r" }),
      { ...sample, input_messages: [{ role: "system", content: "s" }] },
      null,
    );
    expect(replayGaps(draft).join(" ")).toContain("no user message");
  });
});

describe("replayAvailabilityNotes", () => {
  const draft = resolveReplayContent(
    beginReplay({
      requestId: "r",
      origin: "gone.origin",
      model: "retired-model",
      keyId: "sbk_gone",
    }),
    null,
    "no sample",
  );

  it("stays quiet while endpoint and key inventories are still loading", () => {
    expect(replayAvailabilityNotes(draft, {})).toEqual([]);
  });

  it("names the origin, key, and model that no longer resolve", () => {
    const notes = replayAvailabilityNotes(draft, {
      origins: ["api.ai.internal"],
      keyIds: ["sbk_alpha"],
      models: ["gpt-4o-mini"],
    }).join(" ");
    expect(notes).toContain("gone.origin");
    expect(notes).toContain("sbk_gone");
    expect(notes).toContain("retired-model");
  });

  it("stays quiet when everything from the log still resolves", () => {
    const live = resolveReplayContent(
      beginReplay({
        requestId: "r",
        origin: "api.ai.internal",
        model: "gpt-4o-mini",
        keyId: "sbk_alpha",
      }),
      null,
      "no sample",
    );
    expect(
      replayAvailabilityNotes(live, {
        origins: ["api.ai.internal"],
        keyIds: ["sbk_alpha"],
        models: ["gpt-4o-mini"],
      }),
    ).toEqual([]);
  });
});
