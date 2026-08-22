import { describe, expect, it } from "vitest";

import aiPerformanceView from "./AiPerformanceView.vue?raw";
import { AI_ADMISSION_FAMILY } from "../lib/ai-admission";

describe("AI performance gateway rejection visibility", () => {
  it("uses the dedicated gateway-decision counter", () => {
    expect(aiPerformanceView).toContain("sbproxy_ai_gateway_decisions_total");
    expect(aiPerformanceView).toContain('decision: "rejected"');
    expect(aiPerformanceView).toContain("Gateway rejection rate");
    expect(aiPerformanceView).toContain("Gateway decisions (decision / reason)");
  });

  it("renders for a rejection that never reached a provider", () => {
    expect(aiPerformanceView).toContain("gatewayDecisionTotal.value > 0");
    expect(aiPerformanceView).toContain("rejected before provider dispatch");
  });
});

describe("AI performance pre-provider admission refusals (WOR-2595)", () => {
  it("names the admission counter through the shared module", () => {
    // The console curates families by name, so the name has to be
    // asserted somewhere: a rename in metric_registry.rs would
    // otherwise leave this panel reading "not reported" forever.
    expect(aiPerformanceView).toContain("AI_ADMISSION_FAMILY");
    expect(aiPerformanceView).toContain("admissionSummary");
    expect(aiPerformanceView).toContain("../lib/ai-admission");
    expect(AI_ADMISSION_FAMILY).toBe("sbproxy_ai_admission_decisions_total");
  });

  it("distinguishes an unreported counter from zero refusals", () => {
    expect(aiPerformanceView).toContain("admissionDenials !== undefined");
    expect(aiPerformanceView).toContain("'not reported'");
    expect(aiPerformanceView).toContain("This is not a zero.");
  });

  it("renders the surface and reason as words, not as raw enum text", () => {
    expect(aiPerformanceView).toContain("row.surfaceLabel");
    expect(aiPerformanceView).toContain("row.reasonLabel");
    expect(aiPerformanceView).toContain("row.outcomeLabel");
    // The raw code stays on the row so it still joins the metric.
    expect(aiPerformanceView).toContain("{{ row.surface }}");
    expect(aiPerformanceView).toContain("{{ row.reason }}");
  });

  it("states what the refusal count covers and what it cannot see", () => {
    expect(aiPerformanceView).toContain("Refused before dispatch");
    expect(aiPerformanceView).toContain("before it chose a");
    expect(aiPerformanceView).toContain("model gate, guardrail, budget, or policy");
  });

  it("keeps the page from reading empty when refusals are the only AI activity", () => {
    // A deployment refusing every request at the inbound shim has no
    // attributed requests, no gateway decisions, and no provider rows.
    // Without this clause the page an operator opens to find the
    // refusal renders the empty state instead.
    expect(aiPerformanceView).toMatch(
      /hasAiTraffic = computed\([\s\S]*?\(admissionDenials\.value \?\? 0\) > 0/,
    );
  });
});
