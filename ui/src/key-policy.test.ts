import { afterEach, describe, expect, expectTypeOf, it, vi } from "vitest";

import {
  api,
  ApiError,
  buildKeyPolicyPatch,
  keyPolicyDraft,
  rebaseKeyPolicyDraft,
  type AdminKey,
  type AdminKeyPolicyPatch,
  type CreatedKey,
  type GovernanceSnapshot,
} from "./api";

function stubFetch(body: unknown, status = 200) {
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("admin key policy mutation contract", () => {
  it("round-trips mutable name and expiry through set, clear, and undo", () => {
    const baseline: AdminKey = {
      key_id: "key-1",
      policy_revision: 7,
      name: "batch writer",
      expires_at: "2026-08-01T00:00:00Z",
    };
    const edited = keyPolicyDraft(baseline);

    expect(edited.name).toBe("batch writer");
    expect(edited.expires_at).toBe("2026-08-01T00:00:00Z");

    edited.name = "interactive writer";
    edited.expires_at = "2026-09-01T00:00:00Z";
    expect(buildKeyPolicyPatch(baseline, edited)).toEqual({
      expected_revision: 7,
      name: "interactive writer",
      expires_at: "2026-09-01T00:00:00Z",
    });

    edited.name = null;
    edited.expires_at = null;
    expect(buildKeyPolicyPatch(baseline, edited)).toEqual({
      expected_revision: 7,
      name: null,
      expires_at: null,
    });

    edited.name = "batch writer";
    edited.expires_at = "2026-08-01T00:00:00Z";
    expect(buildKeyPolicyPatch(baseline, edited)).toEqual({
      expected_revision: 7,
    });
  });

  it("preserves local name and expiry edits while rebasing a conflict", () => {
    const current: AdminKey = {
      key_id: "key-1",
      policy_revision: 12,
      name: "server name",
      expires_at: "2026-12-01T00:00:00Z",
      blocked_models: ["server-block"],
    };

    const rebased = rebaseKeyPolicyDraft(current, {
      expected_revision: 11,
      name: "local name",
      expires_at: null,
    });

    expect(rebased).toMatchObject({
      name: "local name",
      expires_at: null,
      blocked_models: ["server-block"],
    });
    expect(buildKeyPolicyPatch(current, rebased)).toEqual({
      expected_revision: 12,
      name: "local name",
      expires_at: null,
    });
  });

  it("fetches the server policy descriptor instead of assuming capabilities", async () => {
    const descriptor = {
      schema_version: 1,
      fields: [
        {
          wire_name: "display_name",
          mutation: { kind: "patch", fields: ["name"] },
          editor: "text",
          clear_semantics: "null",
          preview_field: "display_name",
          enforcement_proof: "attribution",
        },
        {
          wire_name: "expires_at",
          mutation: { kind: "patch", fields: ["expires_at"] },
          editor: "datetime",
          clear_semantics: "null",
          preview_field: "expires_at",
          enforcement_proof: "lifecycle_gate",
        },
      ],
    };
    const fetchMock = stubFetch(descriptor);

    await expect(
      (
        api as unknown as {
          keyPolicySchema: () => Promise<typeof descriptor>;
        }
      ).keyPolicySchema(),
    ).resolves.toEqual(descriptor);
    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/keys/policy-schema",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("rejects a malformed descriptor before it can enable a control", async () => {
    stubFetch({
      schema_version: 1,
      fields: [
        {
          wire_name: "allowed_models",
          mutation: { kind: "patch", fields: "allowed_models" },
          editor: "model_list",
          clear_semantics: "empty_list",
          preview_field: "allowed_models",
          enforcement_proof: "model_gate",
        },
      ],
    });

    await expect(api.keyPolicySchema()).rejects.toThrow(
      "policy schema",
    );
  });

  it("requests the safe effective-policy preview for exactly one key", async () => {
    const preview = {
      effective_policy: {
        schema_version: 1,
        key_id: "key/a",
        display_name: "writer",
        status: "active",
        tenant_id: "tenant-a",
      },
      policy_version: { revision: 9, digest: "sha256:safe" },
      decisions: {
        allowed: true,
        lifecycle: { allowed: true, reason_code: "active" },
      },
    };
    const fetchMock = stubFetch(preview);

    await expect(
      (
        api as unknown as {
          previewKeyPolicy: (id: string) => Promise<typeof preview>;
        }
      ).previewKeyPolicy("key/a"),
    ).resolves.toEqual(preview);
    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/keys/key%2Fa/effective-policy/preview",
      expect.objectContaining({ method: "POST", body: "{}" }),
    );
  });

  it("drops undeclared preview material before it reaches rendered state", async () => {
    stubFetch({
      effective_policy: {
        schema_version: 1,
        key_id: "key/a",
        display_name: "writer",
        source: "dynamic",
        status: "active",
        expires_at: null,
        tenant_id: "tenant-a",
        secret: "must-not-survive",
        secret_hash: "must-not-survive",
      },
      policy_version: {
        revision: 9,
        digest: "sha256:safe",
        previous_hash: "must-not-survive",
      },
      decisions: {
        allowed: true,
        lifecycle: {
          allowed: true,
          reason_code: "active",
          upstream_credential: "must-not-survive",
        },
        arbitrary: { allowed: true, reason_code: "must-not-survive" },
      },
    });

    const result = await api.previewKeyPolicy("key/a");

    expect(result).toEqual({
      effective_policy: {
        schema_version: 1,
        key_id: "key/a",
        display_name: "writer",
        source: "dynamic",
        status: "active",
        expires_at: null,
        tenant_id: "tenant-a",
      },
      policy_version: { revision: 9, digest: "sha256:safe" },
      decisions: {
        allowed: true,
        lifecycle: { allowed: true, reason_code: "active" },
      },
    });
    expect(JSON.stringify(result)).not.toContain("must-not-survive");
  });

  it("sets every editable policy value without dropping false or empty shapes", () => {
    const baseline: AdminKey = { key_id: "key-1", policy_revision: 3 };
    const draft = keyPolicyDraft(baseline);
    Object.assign(draft, {
      name: "writer",
      expires_at: "2026-12-01T00:00:00Z",
      allowed_models: ["model-a"],
      blocked_models: ["model-b"],
      allowed_providers: ["provider-a"],
      blocked_providers: ["provider-b"],
      allowed_tools: [],
      require_pii_redaction: ["email"],
      route_to_model: "model-a",
      max_requests_per_minute: 60,
      max_tokens_per_minute: 1_000,
      priority: "interactive",
      max_budget_tokens: 50_000,
      max_budget_usd: 25,
      project: "payments",
      user: "checkout",
      tenant_id: "tenant-a",
      bypass_prompt_injection: false,
      principal_selectors: [{ project: "payments" }],
      inject_tools: [],
      inject_mcp: {},
      metadata: {},
      tags: [],
    });

    expect(buildKeyPolicyPatch(baseline, draft)).toEqual({
      expected_revision: 3,
      name: "writer",
      expires_at: "2026-12-01T00:00:00Z",
      allowed_models: ["model-a"],
      blocked_models: ["model-b"],
      allowed_providers: ["provider-a"],
      blocked_providers: ["provider-b"],
      allowed_tools: [],
      require_pii_redaction: ["email"],
      route_to_model: "model-a",
      max_requests_per_minute: 60,
      max_tokens_per_minute: 1_000,
      priority: "interactive",
      max_budget_tokens: 50_000,
      max_budget_usd: 25,
      project: "payments",
      user: "checkout",
      tenant: "tenant-a",
      principal_selectors: [{ project: "payments" }],
      inject_mcp: {},
    });
  });

  it("rejects a PATCH body without expected_revision before fetch", async () => {
    expectTypeOf<{ allowed_models: string[] }>().not.toMatchTypeOf<AdminKeyPolicyPatch>();
    const response: AdminKey = {
      key_id: "key/a",
      policy_revision: 8,
      allowed_models: [],
    };
    const fetchMock = stubFetch(response);

    await expect(
      api.patchKey("key/a", {
        allowed_models: [],
      } as unknown as AdminKeyPolicyPatch),
    ).rejects.toThrow("expected_revision");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("sends a flat PATCH object with the expected revision", async () => {
    const response: AdminKey = {
      key_id: "key/a",
      policy_revision: 8,
      allowed_models: [],
    };
    const fetchMock = stubFetch({ key: response });
    const patch: AdminKeyPolicyPatch = {
      expected_revision: 7,
      allowed_models: [],
      bypass_prompt_injection: false,
    };

    await api.patchKey("key/a", patch);

    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/keys/key%2Fa",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify(patch),
      }),
    );
  });

  it("rejects revision zero before fetch", async () => {
    const fetchMock = stubFetch({});

    await expect(
      api.patchKey("key-1", { expected_revision: 0 }),
    ).rejects.toThrow("at least 1");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("unwraps the key record returned by PATCH", async () => {
    const updated: AdminKey = {
      key_id: "key-1",
      policy_revision: 5,
      project: "updated",
    };
    stubFetch({ key: updated });

    await expect(
      api.patchKey("key-1", {
        expected_revision: 4,
        project: "updated",
      }),
    ).resolves.toEqual(updated);
  });

  it("encodes every displayed field clear without omitting false or empty values", () => {
    const baseline: AdminKey = {
      key_id: "key-1",
      policy_revision: 41,
      policy_digest: "sha256:old",
      name: "payments writer",
      expires_at: "2026-08-01T00:00:00Z",
      allowed_models: ["model-a"],
      blocked_models: ["model-b"],
      allowed_providers: ["provider-a"],
      blocked_providers: ["provider-b"],
      allowed_tools: ["search"],
      require_pii_redaction: ["email"],
      route_to_model: "model-a",
      max_requests_per_minute: 60,
      max_tokens_per_minute: 1_000,
      priority: "interactive",
      budget: { max_tokens: 50_000, max_cost_usd: 25 },
      project: "payments",
      user: "checkout",
      tenant_id: "tenant-a",
      bypass_prompt_injection: true,
      principal_selectors: [{ team: "payments" }],
      inject_tools: [{ type: "function" }],
      inject_mcp: { ref: "toolhub" },
      metadata: { owner: "platform" },
      tags: ["production"],
    };
    const cleared = keyPolicyDraft({
      key_id: "empty",
      policy_revision: 1,
    });

    expect(buildKeyPolicyPatch(baseline, cleared)).toEqual({
      expected_revision: 41,
      name: null,
      expires_at: null,
      allowed_models: [],
      blocked_models: [],
      allowed_providers: [],
      blocked_providers: [],
      allowed_tools: null,
      require_pii_redaction: [],
      route_to_model: null,
      max_requests_per_minute: null,
      max_tokens_per_minute: null,
      priority: null,
      max_budget_tokens: null,
      max_budget_usd: null,
      project: null,
      user: null,
      tenant: null,
      bypass_prompt_injection: false,
      principal_selectors: [],
      inject_tools: [],
      inject_mcp: null,
      metadata: {},
      tags: [],
    });
  });

  it("replaces every editable field and leaves no sticky change after undo", () => {
    const baseline: AdminKey = {
      key_id: "key-1",
      policy_revision: 14,
      name: "writer a",
      expires_at: "2026-08-01T00:00:00Z",
      allowed_models: ["model-a"],
      blocked_models: ["model-b"],
      allowed_providers: ["provider-a"],
      blocked_providers: ["provider-b"],
      allowed_tools: ["search-a"],
      require_pii_redaction: ["email"],
      route_to_model: "model-a",
      max_requests_per_minute: 60,
      max_tokens_per_minute: 1_000,
      priority: "interactive",
      max_budget_tokens: 50_000,
      max_budget_usd: 25,
      project: "project-a",
      user: "user-a",
      tenant_id: "tenant-a",
      bypass_prompt_injection: true,
      principal_selectors: [{ project: "project-a" }],
      inject_tools: [{ type: "function", name: "tool-a" }],
      inject_mcp: { ref: "gateway-a" },
      metadata: { owner: "team-a" },
      tags: ["tag-a"],
    };
    const replacement = keyPolicyDraft(baseline);
    Object.assign(replacement, {
      name: "writer b",
      expires_at: "2026-09-01T00:00:00Z",
      allowed_models: ["model-c"],
      blocked_models: ["model-d"],
      allowed_providers: ["provider-c"],
      blocked_providers: ["provider-d"],
      allowed_tools: ["search-b"],
      require_pii_redaction: ["phone"],
      route_to_model: "model-c",
      max_requests_per_minute: 120,
      max_tokens_per_minute: 2_000,
      priority: "batch",
      max_budget_tokens: 75_000,
      max_budget_usd: 50,
      project: "project-b",
      user: "user-b",
      tenant_id: "tenant-b",
      bypass_prompt_injection: false,
      principal_selectors: [{ project: "project-b" }],
      inject_tools: [{ type: "function", name: "tool-b" }],
      inject_mcp: { ref: "gateway-b" },
      metadata: { owner: "team-b" },
      tags: ["tag-b"],
    });

    expect(buildKeyPolicyPatch(baseline, replacement)).toEqual({
      expected_revision: 14,
      name: "writer b",
      expires_at: "2026-09-01T00:00:00Z",
      allowed_models: ["model-c"],
      blocked_models: ["model-d"],
      allowed_providers: ["provider-c"],
      blocked_providers: ["provider-d"],
      allowed_tools: ["search-b"],
      require_pii_redaction: ["phone"],
      route_to_model: "model-c",
      max_requests_per_minute: 120,
      max_tokens_per_minute: 2_000,
      priority: "batch",
      max_budget_tokens: 75_000,
      max_budget_usd: 50,
      project: "project-b",
      user: "user-b",
      tenant: "tenant-b",
      bypass_prompt_injection: false,
      principal_selectors: [{ project: "project-b" }],
      inject_tools: [{ type: "function", name: "tool-b" }],
      inject_mcp: { ref: "gateway-b" },
      metadata: { owner: "team-b" },
      tags: ["tag-b"],
    });

    Object.assign(replacement, keyPolicyDraft(baseline));
    expect(buildKeyPolicyPatch(baseline, replacement)).toEqual({
      expected_revision: 14,
    });
  });

  it("distinguishes unrestricted tools from an explicit empty allowlist", () => {
    const restricted: AdminKey = {
      key_id: "key-1",
      policy_revision: 5,
      allowed_tools: ["search"],
    };
    const unrestrictedDraft = keyPolicyDraft(restricted);
    unrestrictedDraft.allowed_tools = null;
    expect(buildKeyPolicyPatch(restricted, unrestrictedDraft)).toEqual({
      expected_revision: 5,
      allowed_tools: null,
    });

    const unrestricted: AdminKey = {
      key_id: "key-2",
      policy_revision: 8,
      allowed_tools: null,
    };
    const denyAllDraft = keyPolicyDraft(unrestricted);
    denyAllDraft.allowed_tools = [];
    expect(buildKeyPolicyPatch(unrestricted, denyAllDraft)).toEqual({
      expected_revision: 8,
      allowed_tools: [],
    });
  });

  it("rebases an explicit empty tool allowlist without losing server changes", () => {
    const current: AdminKey = {
      key_id: "key-1",
      policy_revision: 12,
      allowed_tools: ["server-tool"],
      blocked_models: ["server-block"],
    };
    const localPatch: AdminKeyPolicyPatch = {
      expected_revision: 11,
      allowed_tools: [],
    };

    const rebased = rebaseKeyPolicyDraft(current, localPatch);

    expect(rebased.allowed_tools).toEqual([]);
    expect(rebased.blocked_models).toEqual(["server-block"]);
    expect(buildKeyPolicyPatch(current, rebased)).toEqual({
      expected_revision: 12,
      allowed_tools: [],
    });
  });

  it("rebases only local changes onto the current server policy", () => {
    const original: AdminKey = {
      key_id: "key-1",
      policy_revision: 3,
      policy_digest: "sha256:three",
      allowed_models: ["model-a"],
      blocked_models: ["model-b"],
      project: "payments",
      metadata: { owner: "platform" },
    };
    const edited = keyPolicyDraft(original);
    edited.allowed_models = ["model-local"];
    edited.project = null;
    const localPatch = buildKeyPolicyPatch(original, edited);
    const current: AdminKey = {
      key_id: "key-1",
      policy_revision: 4,
      policy_digest: "sha256:four",
      allowed_models: ["model-server"],
      blocked_models: ["model-concurrent"],
      project: "payments",
      metadata: { owner: "new-owner" },
    };

    const rebased = rebaseKeyPolicyDraft(current, localPatch);

    expect(rebased.allowed_models).toEqual(["model-local"]);
    expect(rebased.project).toBeNull();
    expect(rebased.blocked_models).toEqual(["model-concurrent"]);
    expect(rebased.metadata).toEqual({ owner: "new-owner" });
    expect(buildKeyPolicyPatch(current, rebased)).toEqual({
      expected_revision: 4,
      allowed_models: ["model-local"],
      project: null,
    });
  });

  it("fetches one current key for conflict reconciliation", async () => {
    const current: AdminKey = {
      key_id: "key/a",
      policy_revision: 9,
      policy_digest: "sha256:nine",
    };
    const fetchMock = stubFetch({ key: current });

    await expect(api.key("key/a")).resolves.toEqual(current);
    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/keys/key%2Fa",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("decodes one governed key usage snapshot, converting neither tokens nor micro-USD", async () => {
    const snapshot = {
      key_id: "key/a",
      policy_revision: 4,
      requests_per_window: {
        limit: 60,
        used: 12,
        reserved: 3,
        remaining: 45,
        reset_at_millis: 1_700_000_040_000,
      },
      tokens_per_window: {
        limit: 50_000,
        used: 100,
        reserved: 20,
        remaining: 49_880,
        reset_at_millis: 1_700_000_040_000,
      },
      total_tokens: {
        limit: 1_000_000,
        used: 25_000,
        reserved: 5_000,
        remaining: 970_000,
        reset_at_millis: null,
      },
      total_micro_usd: {
        limit: 50_000_000,
        used: 12_345_678,
        reserved: 1_000_000,
        remaining: 36_654_322,
        reset_at_millis: null,
      },
      backend: {
        backend: "redis",
        consistency: "strict",
        status: "healthy",
        checked_at_millis: 1_700_000_000_000,
      },
      secret_hash: "must-not-survive",
    };
    const fetchMock = stubFetch({ usage: snapshot });

    const result = await api.keyUsage("key/a");

    expect(result).toEqual({
      key_id: "key/a",
      policy_revision: 4,
      requests_per_window: snapshot.requests_per_window,
      tokens_per_window: snapshot.tokens_per_window,
      total_tokens: snapshot.total_tokens,
      total_micro_usd: snapshot.total_micro_usd,
      backend: snapshot.backend,
    });
    expect(result.total_micro_usd.used).toBe(12_345_678);
    expect(result.total_tokens.reset_at_millis).toBeNull();
    expect(JSON.stringify(result)).not.toContain("must-not-survive");
    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/keys/key%2Fa/usage",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("treats a null limit and remaining as an unconfigured dimension", async () => {
    stubFetch({
      usage: {
        key_id: "key-1",
        policy_revision: 1,
        requests_per_window: {
          limit: null,
          used: 4,
          reserved: 0,
          remaining: null,
          reset_at_millis: 1_700_000_040_000,
        },
        tokens_per_window: {
          limit: null,
          used: 0,
          reserved: 0,
          remaining: null,
          reset_at_millis: 1_700_000_040_000,
        },
        total_tokens: {
          limit: null,
          used: 0,
          reserved: 0,
          remaining: null,
          reset_at_millis: null,
        },
        total_micro_usd: {
          limit: null,
          used: 0,
          reserved: 0,
          remaining: null,
          reset_at_millis: null,
        },
        backend: {
          backend: "memory",
          consistency: "approximate",
          status: "healthy",
          checked_at_millis: 1_700_000_000_000,
        },
      },
    });

    const result = await api.keyUsage("key-1");

    expect(result.requests_per_window.limit).toBeNull();
    expect(result.requests_per_window.remaining).toBeNull();
  });

  it("surfaces a governance backend outage as a plain ApiError", async () => {
    stubFetch({ error: "governance backend unavailable" }, 503);

    const error = await api.keyUsage("key-1").catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(503);
  });

  it("rejects malformed usage health and accounting counters", async () => {
    stubFetch({
      usage: {
        key_id: "key-1",
        policy_revision: 2,
        requests_per_window: {
          limit: 10,
          used: -1,
          reserved: 0,
          remaining: 11,
          reset_at_millis: 1_700_000_040_000,
        },
        tokens_per_window: {
          limit: null,
          used: 0,
          reserved: 0,
          remaining: null,
          reset_at_millis: 1_700_000_040_000,
        },
        total_tokens: {
          limit: null,
          used: 0,
          reserved: 0,
          remaining: null,
          reset_at_millis: null,
        },
        total_micro_usd: {
          limit: null,
          used: 0,
          reserved: 0,
          remaining: null,
          reset_at_millis: null,
        },
        backend: {
          backend: "redis",
          consistency: "strict",
          status: "offline",
          checked_at_millis: 1_700_000_000_000,
        },
      },
    });

    await expect(api.keyUsage("key-1")).rejects.toThrow("governance usage");
  });

  it("types governance counter snapshots as nullable safe integers", () => {
    const usage: GovernanceSnapshot = {
      key_id: "key-1",
      policy_revision: 1,
      requests_per_window: {
        limit: null,
        used: 0,
        reserved: 0,
        remaining: null,
        reset_at_millis: null,
      },
      tokens_per_window: {
        limit: null,
        used: 0,
        reserved: 0,
        remaining: null,
        reset_at_millis: null,
      },
      total_tokens: {
        limit: null,
        used: 0,
        reserved: 0,
        remaining: null,
        reset_at_millis: null,
      },
      total_micro_usd: {
        limit: null,
        used: 0,
        reserved: 0,
        remaining: null,
        reset_at_millis: null,
      },
      backend: {
        backend: "memory",
        consistency: "approximate",
        status: "healthy",
        checked_at_millis: 1_700_000_000_000,
      },
    };

    expectTypeOf(usage.backend.consistency).toMatchTypeOf<"approximate" | "strict">();
    expectTypeOf(usage.total_micro_usd.limit).toMatchTypeOf<number | null>();
  });

  it("types the copy-once create envelope around the server key record", () => {
    const created: CreatedKey = {
      token: "copy-once-token",
      key: {
        key_id: "key-1",
        policy_revision: 1,
      },
    };

    expectTypeOf(created.key).toEqualTypeOf<AdminKey>();
  });
});
