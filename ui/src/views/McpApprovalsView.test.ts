import { describe, expect, it } from "vitest";

import mcpApprovalsView from "./McpApprovalsView.vue?raw";

describe("McpApprovalsView", () => {
  it("loads holds through the typed api client and polls", () => {
    expect(mcpApprovalsView).toContain("api.mcpApprovals()");
    expect(mcpApprovalsView).toContain("pollMs: 5_000");
    expect(mcpApprovalsView).toContain("onMounted(() => {");
    expect(mcpApprovalsView).toContain("req.run()");
  });

  it("approves and denies pending holds with the signed-in operator name", () => {
    expect(mcpApprovalsView).toContain("api.approveMcpHold(hold.id, by)");
    expect(mcpApprovalsView).toContain("api.denyMcpHold(hold.id, by)");
    expect(mcpApprovalsView).toContain("Approve");
    expect(mcpApprovalsView).toContain("Deny");
  });

  it("renders errors and the two empty states through the shared components", () => {
    expect(mcpApprovalsView).toMatch(/<ErrorState\s+v-if="req\.error\.value"/);
    expect(mcpApprovalsView).toContain('v-else-if="!req.loading.value && !enabled"');
    expect(mcpApprovalsView).toContain('v-else-if="!req.loading.value && !holds.length"');
  });

  it("documents fail-closed expiry in the page header", () => {
    expect(mcpApprovalsView).toContain("expires fail-closed");
  });
});
