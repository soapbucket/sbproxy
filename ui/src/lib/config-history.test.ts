import { describe, expect, it } from "vitest";

import { ApiError, type ConfigHistoryEntry } from "../api";
import {
  blastRadiusLabel,
  blastRadiusTone,
  degradedSummary,
  historyStateTone,
  isConfigHistoryDisabled,
} from "./config-history";

describe("config history presentation", () => {
  it("maps every history state to a distinct, correct badge tone", () => {
    expect(historyStateTone("applied")).toBe("ok");
    expect(historyStateTone("good")).toBe("ok");
    expect(historyStateTone("failed")).toBe("err");
    expect(historyStateTone("reverted")).toBe("warn");
  });

  it("escalates blast-radius tone with the size of the change", () => {
    expect(blastRadiusTone("hitless")).toBe("ok");
    expect(blastRadiusTone("reload")).toBe("neutral");
    expect(blastRadiusTone("restart")).toBe("warn");
    expect(blastRadiusTone("breaking")).toBe("err");
    expect(blastRadiusTone(null)).toBe("neutral");
  });

  it("labels a null blast radius as the first revision, not a bare n/a", () => {
    expect(blastRadiusLabel(null)).toBe("first revision");
    expect(blastRadiusLabel("breaking")).toBe("breaking");
  });

  it("summarizes degraded subsystems only when the list is non-empty", () => {
    expect(degradedSummary([])).toBeNull();
    expect(degradedSummary(["cache", "auth"])).toBe("degraded: cache, auth");
  });

  it("recognizes the disabled-feature 404 and nothing else as quiet", () => {
    const disabled = new ApiError(
      404,
      "GET /admin/config/history failed (404)",
      '{"error":"config history is not enabled"}',
    );
    expect(isConfigHistoryDisabled(disabled)).toBe(true);

    // A 404 for an unknown digest on the detail route is a real error,
    // not the disabled-feature state, even though the status matches.
    const unknownDigest = new ApiError(
      404,
      "GET /admin/config/history/deadbeef failed (404)",
      '{"error":"unknown digest"}',
    );
    expect(isConfigHistoryDisabled(unknownDigest)).toBe(false);

    const serverError = new ApiError(500, "GET /admin/config/history failed (500)", "");
    expect(isConfigHistoryDisabled(serverError)).toBe(false);

    // A 503 (the block is enabled but the ring failed to open at boot)
    // is a real error too, not the disabled empty state: an operator
    // whose store broke needs to see that, not a "turn this on" prompt.
    const failedToOpen = new ApiError(
      503,
      "GET /admin/config/history failed (503)",
      '{"error":"config history failed to open at boot: permission denied"}',
    );
    expect(isConfigHistoryDisabled(failedToOpen)).toBe(false);

    expect(isConfigHistoryDisabled(null)).toBe(false);
  });
});

// Exercise the exported type alongside the real API shape, so a schema
// change to ConfigHistoryEntry that this module does not handle fails
// here instead of only at the call site inside ConfigView.
function _typeCheck(entry: ConfigHistoryEntry): void {
  void historyStateTone(entry.state);
  void blastRadiusTone(entry.blast_radius);
  void degradedSummary(entry.degraded);
}
void _typeCheck;
