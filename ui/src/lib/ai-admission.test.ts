import { describe, expect, it } from "vitest";

import {
  AI_ADMISSION_FAMILY,
  admissionOutcomeLabel,
  admissionReasonLabel,
  admissionSummary,
  admissionSurfaceLabel,
} from "./ai-admission";
import { findFamily, parsePrometheus } from "./metrics";

const SCRAPE = [
  "# HELP sbproxy_ai_admission_decisions_total Pre-provider AI gateway admission decisions",
  "# TYPE sbproxy_ai_admission_decisions_total counter",
  'sbproxy_ai_admission_decisions_total{surface="responses",reason="tools_mcp_unsupported",outcome="deny"} 7',
  'sbproxy_ai_admission_decisions_total{surface="responses",reason="store_unsupported",outcome="deny"} 2',
  'sbproxy_ai_admission_decisions_total{surface="messages",reason="malformed_json",outcome="deny"} 3',
  'sbproxy_ai_admission_decisions_total{surface="chat_completions",reason="prompt_render_failed",outcome="deny"} 1',
].join("\n");

function summarize(text: string) {
  return admissionSummary(findFamily(parsePrometheus(text), AI_ADMISSION_FAMILY));
}

describe("admissionSummary", () => {
  it("reads the counter the emitter writes, under its exact name", () => {
    expect(AI_ADMISSION_FAMILY).toBe("sbproxy_ai_admission_decisions_total");
    // `_total` keeps its own name through the parser's suffix folding,
    // so an exact lookup has to find it.
    expect(findFamily(parsePrometheus(SCRAPE), AI_ADMISSION_FAMILY)?.name).toBe(
      AI_ADMISSION_FAMILY,
    );
  });

  it("separates an absent family from a family reading zero", () => {
    // The counter registers on its first increment, so a proxy that has
    // never refused a request before dispatch publishes no family at
    // all. Reporting that as 0 would draw a healthy signal over a
    // measurement nobody has ever taken.
    expect(summarize("")).toBeUndefined();
    expect(admissionSummary(undefined)).toBeUndefined();

    const registeredButUnused = summarize(
      [
        "# TYPE sbproxy_ai_admission_decisions_total counter",
        "# HELP sbproxy_ai_admission_decisions_total Pre-provider AI gateway admission decisions",
      ].join("\n"),
    );
    expect(registeredButUnused).toEqual({
      total: 0,
      denials: 0,
      rows: [],
      bySurface: [],
    });
  });

  it("totals the denials and ranks the rows worst first", () => {
    const summary = summarize(SCRAPE);
    expect(summary?.total).toBe(13);
    expect(summary?.denials).toBe(13);
    expect(summary?.rows.map((r) => [r.reason, r.count])).toEqual([
      ["tools_mcp_unsupported", 7],
      ["malformed_json", 3],
      ["store_unsupported", 2],
      ["prompt_render_failed", 1],
    ]);
  });

  it("keeps the raw label beside the phrase, so the row still joins the metric", () => {
    const worst = summarize(SCRAPE)?.rows[0];
    expect(worst?.surface).toBe("responses");
    expect(worst?.surfaceLabel).toBe("OpenAI Responses");
    expect(worst?.reason).toBe("tools_mcp_unsupported");
    expect(worst?.reasonLabel).toContain("MCP tool block");
    expect(worst?.outcome).toBe("deny");
    expect(worst?.outcomeLabel).toBe("denied");
  });

  it("groups denials by inbound surface, descending", () => {
    expect(summarize(SCRAPE)?.bySurface).toEqual([
      { key: "OpenAI Responses", value: 9 },
      { key: "Anthropic Messages", value: 3 },
      { key: "Chat completions", value: 1 },
    ]);
  });

  it("folds repeated label sets rather than rendering one row each", () => {
    const summary = summarize(
      [
        "# TYPE sbproxy_ai_admission_decisions_total counter",
        'sbproxy_ai_admission_decisions_total{surface="messages",reason="role_missing",outcome="deny"} 2',
        'sbproxy_ai_admission_decisions_total{surface="messages",reason="role_missing",outcome="deny"} 5',
      ].join("\n"),
    );
    expect(summary?.rows).toHaveLength(1);
    expect(summary?.rows[0].count).toBe(7);
  });

  it("counts only denials in the denial total, whatever else the family carries", () => {
    // `outcome` exists so an admit-side counterpart can share the
    // family. An admit must never inflate the refusal count.
    const summary = summarize(
      [
        "# TYPE sbproxy_ai_admission_decisions_total counter",
        'sbproxy_ai_admission_decisions_total{surface="responses",reason="tools_mcp_unsupported",outcome="deny"} 4',
        'sbproxy_ai_admission_decisions_total{surface="responses",reason="admitted",outcome="allow"} 90',
      ].join("\n"),
    );
    expect(summary?.total).toBe(94);
    expect(summary?.denials).toBe(4);
    expect(summary?.bySurface).toEqual([{ key: "OpenAI Responses", value: 4 }]);
  });
});

describe("admission label vocabularies", () => {
  it("names every surface a refusal can arrive on", () => {
    expect(admissionSurfaceLabel("messages")).toBe("Anthropic Messages");
    expect(admissionSurfaceLabel("responses")).toBe("OpenAI Responses");
    expect(admissionSurfaceLabel("chat_completions")).toBe("Chat completions");
  });

  it("names every reason code the emitter can write", () => {
    // The list in docs/decision-records.md for `ai.admission`. A code
    // added on the Rust side without a phrase here still has to read as
    // words, never as a raw enum.
    const codes = [
      "tools_mcp_unsupported",
      "previous_response_id_unsupported",
      "conversation_unsupported",
      "store_unsupported",
      "prompt_object_unresolved",
      "prompt_object_unrenderable",
      "prompt_reference_not_found",
      "prompt_render_failed",
      "malformed_json",
      "body_not_object",
      "role_missing",
      "role_unsupported",
      "malformed_request",
    ];
    const labels = codes.map(admissionReasonLabel);
    for (const [index, code] of codes.entries()) {
      expect(labels[index]).not.toBe(code);
    }
    // Two codes sharing a phrase would make the table lie about which
    // refusal an operator is looking at.
    expect(new Set(labels).size).toBe(codes.length);
  });

  it("names the cardinality limiter's sentinel as the lost label it is", () => {
    // `budget_for_label` in crates/sbproxy-observe/src/cardinality.rs
    // caps `reason` at 8 accepted values against a 13-code vocabulary,
    // keyed on the label name alone with no eviction, so `__other__` is
    // a state this panel reaches and stays in. Prettified it reads
    // "Other", which looks like a refusal reason and is not one.
    expect(admissionReasonLabel("__other__")).toBe(
      "Beyond the label limit, reason not recorded",
    );
    expect(admissionSurfaceLabel("__other__")).toBe(
      "Beyond the label limit, surface not recorded",
    );
    expect(admissionOutcomeLabel("__other__")).toBe("not recorded");
    expect(admissionReasonLabel("__other__")).not.toBe("Other");

    // The count behind the sentinel is real and still belongs in the
    // total, even though the code behind it is gone.
    const summary = summarize(
      [
        "# TYPE sbproxy_ai_admission_decisions_total counter",
        'sbproxy_ai_admission_decisions_total{surface="responses",reason="__other__",outcome="deny"} 12',
      ].join("\n"),
    );
    expect(summary?.denials).toBe(12);
    expect(summary?.rows[0].reason).toBe("__other__");
  });

  it("prettifies an unknown code instead of dropping it", () => {
    expect(admissionSurfaceLabel("audio_transcription")).toBe("Audio transcription");
    expect(admissionReasonLabel("some_future_code")).toBe("Some future code");
    expect(admissionOutcomeLabel("deny")).toBe("denied");
    expect(admissionOutcomeLabel("allow")).toBe("admitted");
    expect(admissionOutcomeLabel("")).toBe("not labeled");
  });
});
