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

describe("AI classifier and quality-routing visibility (WOR-2672)", () => {
  it("shows intent fallback and quality-hook outcomes from live counters", () => {
    expect(aiPerformanceView).toContain(
      "sbproxy_ai_intent_detection_source_total",
    );
    expect(aiPerformanceView).toContain(
      "sbproxy_ai_quality_routing_decisions_total",
    );
    expect(aiPerformanceView).toContain("Intent detection source");
    expect(aiPerformanceView).toContain("Quality-hook routing outcomes");
    expect(aiPerformanceView).toContain('class="sb-mono">heuristic</span>');
    expect(aiPerformanceView).toContain("heuristic_degraded");
  });

  it("explains that hook fallback preserves configured routing", () => {
    expect(aiPerformanceView).toContain("hook_unavailable");
    expect(aiPerformanceView).toContain("preserves the configured router");
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
    //
    // Gated on the family's total, not on the denied slice: the panel
    // renders every row the family carries, so an admit-side series
    // sharing the family (which `admissionSummary` already reads, and
    // which the label exists for) must not leave the empty state drawn
    // over a populated panel.
    expect(aiPerformanceView).toMatch(
      /hasAiTraffic = computed\([\s\S]*?\(admissionTotal\.value \?\? 0\) > 0/,
    );
    expect(aiPerformanceView).not.toContain("(admissionDenials.value ?? 0) > 0");
  });

  it("says the refusals are already inside the gateway rejection count", () => {
    // A shim refusal sets `ctx.ai_surface`, returns 4xx, and reaches the
    // logging phase, so `record_ai_gateway_decision("rejected",
    // "client_error")` fires for the same request that ticked the
    // admission counter. The two tiles sit side by side, so the page has
    // to say the numbers nest rather than sum.
    expect(aiPerformanceView).toContain("not additive with the gateway rejection rate");
    expect(aiPerformanceView).toContain("client_error");
    expect(aiPerformanceView).toContain("not an addition");
  });

  it("prints the counter name from the shared constant, not a second copy", () => {
    // The name appears twice on this page (the lookup and the
    // "not reported" paragraph). A literal in the paragraph would keep
    // reading the old name after a rename that the lookup followed.
    expect(aiPerformanceView).toContain("{{ AI_ADMISSION_FAMILY }}");
    expect(aiPerformanceView).not.toContain(
      '<span class="sb-mono">sbproxy_ai_admission_decisions_total</span>',
    );
  });
});
