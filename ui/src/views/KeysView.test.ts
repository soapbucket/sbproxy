import { describe, expect, it } from "vitest";

import keysView from "./KeysView.vue?raw";

describe("KeysView policy editing contract", () => {
  it("edits and clears the created key name and expiry", () => {
    expect(keysView).toContain("editForm.name");
    expect(keysView).toContain("editForm.expires_at");
    expect(keysView).toContain("Name");
    expect(keysView).toContain("Expires at (ISO 8601)");
  });

  it("fetches server capabilities and gates every editable control", () => {
    expect(keysView).toContain("api.keyPolicySchema");
    expect(keysView).toContain("supportsPolicyField");
    for (const fieldCall of [
      "supportsPolicyField('display_name', 'name')",
      "supportsPolicyField('expires_at')",
      "supportsPolicyField('allowed_models')",
      "supportsPolicyField('blocked_models')",
      "supportsPolicyField('allowed_providers')",
      "supportsPolicyField('blocked_providers')",
      "supportsPolicyField('allowed_tools')",
      "supportsPolicyField('require_pii_redaction')",
      "supportsPolicyField('route_to_model')",
      "supportsPolicyField('max_requests_per_minute')",
      "supportsPolicyField('max_tokens_per_minute')",
      "supportsPolicyField('priority')",
      "supportsPolicyField('budget', 'max_budget_usd')",
      "supportsPolicyField('budget', 'max_budget_tokens')",
      "supportsPolicyField('project')",
      "supportsPolicyField('user')",
      "supportsPolicyField('tenant_id', 'tenant')",
      "supportsPolicyField('bypass_prompt_injection')",
      "supportsPolicyField('principal_selectors')",
      "supportsPolicyField('inject_tools')",
      "supportsPolicyField('inject_mcp')",
      "supportsPolicyField('metadata')",
      "supportsPolicyField('tags')",
    ]) {
      expect(keysView).toContain(fieldCall);
    }
  });

  it("renders only bounded safe preview evidence", () => {
    expect(keysView).toContain("api.previewKeyPolicy");
    expect(keysView).toContain("Effective policy preview");
    expect(keysView).toContain("preview.policy_version.revision");
    expect(keysView).toContain("preview.policy_version.digest");
    expect(keysView).toContain("preview.decisions");
    expect(keysView).toContain("Preview reflects the saved revision");
    expect(keysView).not.toContain("preview.secret");
    expect(keysView).not.toContain("preview.secret_hash");
    expect(keysView).not.toContain("JSON.stringify(preview");
  });

  it("does not let an older preview request overwrite the selected key", () => {
    expect(keysView).toContain("let previewInvocation = 0");
    expect(keysView).toContain("const invocation = ++previewInvocation");
    expect(keysView).toContain("invocation !== previewInvocation");
  });

  it("shows the server policy revision and explains origin-scoped digests", () => {
    expect(keysView).toContain("Policy revision");
    expect(keysView).toContain("k.policy_revision");
    expect(keysView).toContain("editBaseline.policy_revision");
    expect(keysView).toContain("policy_digest");
    expect(keysView).toContain("digest is origin-scoped");
  });

  it("keeps an immutable baseline and preserves edits across a 409 refetch", () => {
    expect(keysView).toContain("const editBaseline = ref<AdminKey | null>(null)");
    expect(keysView).toContain("e instanceof ApiError && e.status === 409");
    expect(keysView).toContain("pendingLocalPatch.value = patch");
    expect(keysView).toContain("const current = await api.key");
    expect(keysView).toContain("conflictCurrent.value = current");
    expect(keysView).toContain("Your edits are preserved");
  });

  it("requires an explicit rebase or server reload after a conflict", () => {
    expect(keysView).toContain("rebasePreservedEdits");
    expect(keysView).toContain("loadCurrentPolicy");
    expect(keysView).toContain("Rebase preserved edits");
    expect(keysView).toContain("Load current policy");
  });

  it("keeps unrestricted and deny-all caller tool policies distinct", () => {
    expect(keysView).toContain("allowed_tools_mode");
    expect(keysView).toContain("createForm.allowed_tools_mode");
    expect(keysView).toContain("policy.allowed_tools = toList");
    expect(keysView).toContain("Unrestricted");
    expect(keysView).toContain("Use allowlist");
    expect(keysView).toContain("An empty allowlist blocks all caller-supplied tools");
  });

  it("does not read legacy secret or hash fields into rendered state", () => {
    expect(keysView).not.toContain("created?.plaintext");
    expect(keysView).not.toContain("created?.secret");
    expect(keysView).not.toContain("created?.key");
    expect(keysView).not.toContain("secret_hash");
  });

  it("offers only lifecycle actions valid for the server status", () => {
    expect(keysView).toContain("statusOf(k) === 'active'");
    expect(keysView).toContain("statusOf(k) === 'blocked'");
    expect(keysView).toContain("statusOf(k) !== 'revoked'");
  });

  it("loads governed usage for one selected key", () => {
    expect(keysView).toContain("api.keyUsage");
    expect(keysView).toContain("openUsage(k)");
    expect(keysView).toContain("Usage and reservations");
  });

  it("shows every governed dimension with its reservation arithmetic", () => {
    for (const value of [
      "Requests per window",
      "Tokens per window",
      "Token budget",
      "Monetary budget",
      "dimension.snapshot.limit",
      "dimension.snapshot.used",
      "dimension.snapshot.reserved",
      "dimension.snapshot.remaining",
      "dimension.snapshot.reset_at_millis",
      "formatUsageReset(dimension.snapshot.reset_at_millis)",
      'return resetAtMillis === null ? "Never" : formatTime(resetAtMillis)',
    ]) {
      expect(keysView).toContain(value);
    }
    expect(keysView).toContain("formatUsageUnits");
    expect(keysView).toContain("formatUsageLimit");
    expect(keysView).toContain("total_micro_usd");
  });

  it("shows governance backend health and consistency mode", () => {
    expect(keysView).toContain("usage.backend.consistency");
    expect(keysView).toContain("usage.backend.status");
    expect(keysView).toContain("usage.backend.backend");
    expect(keysView).toContain("usage.backend.checked_at_millis");
    expect(keysView).toContain("backendTone");
    expect(keysView).toContain("backendUnhealthy");
    expect(keysView).toContain('role="alert"');
  });

  it("renders a generic error state when governed usage cannot be loaded", () => {
    expect(keysView).toContain("usageError.value = e instanceof ApiError");
    expect(keysView).toContain('v-else-if="usageError"');
    expect(keysView).toContain("Usage unavailable");
  });

  it("does not let a stale usage request overwrite the selected key", () => {
    expect(keysView).toContain("let usageInvocation = 0");
    expect(keysView).toContain("const invocation = ++usageInvocation");
    expect(keysView).toContain("invocation !== usageInvocation");
  });
});
