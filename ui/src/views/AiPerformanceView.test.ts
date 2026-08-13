import { describe, expect, it } from "vitest";

import aiPerformanceView from "./AiPerformanceView.vue?raw";

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
