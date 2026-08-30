import { afterEach, describe, expect, expectTypeOf, it, vi } from "vitest";

import {
  api,
  ApiError,
  setCsrfToken,
  type ClusterDeploymentBundleDraft,
  type DeploymentReplacementRequest,
  type ExtensionInventorySnapshot,
  type ModelDeployment,
  type ModelDeploymentRequest,
} from "./api";

function stubFetch(rawBody: string, status = 200) {
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(rawBody, {
        status,
        headers: { "content-type": "application/json" },
      }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  setCsrfToken(null);
  vi.unstubAllGlobals();
});

describe("admin API JSON integer safety", () => {
  it("rejects an unsafe raw integer token before Response.json can round it", async () => {
    stubFetch(
      '{"schema_version":1,"authority":"admin_managed","read_only":false,"revision":9007199254740993,"content_digest":null,"deployments":{}}',
    );

    await expect(api.modelHostDeployments()).rejects.toThrow(
      "outside JavaScript's safe integer range",
    );
  });

  it("does not mistake an unsafe-looking integer inside a JSON string for a number", async () => {
    stubFetch(
      '{"schema_version":1,"authority":"admin_managed","read_only":false,"revision":7,"content_digest":"9007199254740993","deployments":{}}',
    );

    await expect(api.modelHostDeployments()).resolves.toMatchObject({
      revision: 7,
      content_digest: "9007199254740993",
    });
  });

  it("rejects an unsafe mutation number before fetch or JSON.stringify can send it", async () => {
    const fetchMock = stubFetch(
      '{"schema_version":1,"revision":8,"content_digest":"digest","plan":{"added":[],"changed":[],"removed":[],"preserved":[]}}',
    );
    const request: DeploymentReplacementRequest = {
      expected_revision: Number.MAX_SAFE_INTEGER + 1,
      deployments: {},
    };

    await expect(api.replaceModelHostDeployments(request)).rejects.toThrow(
      "outside JavaScript's safe integer range",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("preserves raw 409 status and error code bodies", async () => {
    const body =
      '{"code":"revision_conflict","error":"conflict","expected_revision":6,"actual_revision":7}';
    stubFetch(body, 409);

    const error = await api
      .replaceModelHostDeployments({ expected_revision: 6, deployments: {} })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 409, body });
  });

  it("preserves exact bounded catalog picker evidence", async () => {
    stubFetch(
      JSON.stringify({
        schema_version: 1,
        catalog_revision: "catalog-v2",
        models: {
          qwen: {
            params: "0.5B",
            license: "Apache-2.0",
            family: "qwen",
            context_length: 32768,
            variants: [
              {
                id: "q4_k_m",
                format: "gguf",
                quant: "Q4_K_M",
                engines: ["llama_cpp"],
                accelerators: ["cpu", "metal"],
                min_memory_bytes: 512000000,
                download_size_bytes: 384000000,
                certification: "local-metal-2026-07",
                stability: "preview",
              },
            ],
          },
        },
      }),
    );

    await expect(api.modelHostCatalog()).resolves.toMatchObject({
      models: {
        qwen: {
          variants: [
            {
              download_size_bytes: 384000000,
              certification: "local-metal-2026-07",
            },
          ],
        },
      },
    });
  });
});

describe("deployment mutation request contracts", () => {
  it("accepts minimal serde-defaulted deployments without materializing defaults", async () => {
    const deployment: ModelDeploymentRequest = {
      model: "qwen2.5-0.5b-instruct",
    };
    expectTypeOf<{ model: string }>().toMatchTypeOf<ModelDeploymentRequest>();
    expectTypeOf<{ model: string }>().not.toMatchTypeOf<ModelDeployment>();
    const request: DeploymentReplacementRequest = {
      expected_revision: null,
      deployments: { "local-qwen": deployment },
    };
    const fetchMock = stubFetch(
      '{"schema_version":1,"revision":1,"content_digest":"digest","plan":{"added":["local-qwen"],"changed":[],"removed":[],"preserved":[]}}',
    );

    await api.replaceModelHostDeployments(request);

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0]).toEqual([
      "/admin/model-host/deployments",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify(request),
      }),
    ]);
  });

  it("uses the same minimal deployment input for signed cluster publication", async () => {
    const draft: ClusterDeploymentBundleDraft = {
      catalog_revision: "catalog-v2",
      revision: 1,
      deployments: {
        "cluster-qwen": { model: "qwen2.5-0.5b-instruct" },
      },
    };
    const fetchMock = stubFetch(
      '{"schema_version":1,"revision":1,"content_digest":"digest","signer_node_id":"authority-a","signer_key_id":"key-a","status":"published"}',
      202,
    );

    await api.publishClusterDeployments(draft);

    expect(fetchMock.mock.calls[0]).toEqual([
      "/admin/cluster/deployments",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(draft),
      }),
    ]);
  });
});

describe("model lifecycle request contracts", () => {
  it("uses canonical deployment IDs for load, stop, and reset", async () => {
    const fetchMock = stubFetch("{}");

    await api.modelHostLoad("local-qwen");
    await api.modelHostStop("local-qwen");
    await api.modelHostReset("local-qwen");

    expect(fetchMock.mock.calls).toEqual([
      [
        "/admin/model-host/load",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ deployment: "local-qwen" }),
        }),
      ],
      [
        "/admin/model-host/stop",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ deployment: "local-qwen" }),
        }),
      ],
      [
        "/admin/model-host/reset",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ deployment: "local-qwen" }),
        }),
      ],
    ]);
  });
});

describe("request observability contracts", () => {
  it("encodes bounded request-ring filters and omits client-only filters", async () => {
    const fetchMock = stubFetch("[]");

    await api.requests({
      method: "POST",
      status: "503",
      path: "/v1/chat?stream=true",
      origin: "public-api",
      guardrailAction: "block",
      guardrailCategory: "pii",
      cacheStatus: "semantic_hit",
      retried: true,
      propertyKey: "customer.tier",
      propertyValue: "gold & beta",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/requests?method=POST&status=503&path=%2Fv1%2Fchat%3Fstream%3Dtrue&guardrail_action=block&guardrail_category=pii&cache_status=semantic_hit&retried=true&property_key=customer.tier&property_value=gold+%26+beta",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("keeps HTTP-class filtering client-side", async () => {
    const fetchMock = stubFetch("[]");

    await api.requests({ status: "5xx" });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/requests",
      expect.objectContaining({ method: "GET" }),
    );
  });

  // WOR-2578: the report and the export ride the same filter surface
  // as the snapshot, so one filter state describes all three.
  it("builds the multi-dimension report path from the shared filter surface", async () => {
    const fetchMock = stubFetch(
      '{"schema_version":1,"group_by":["model"],"rows":[],"totals":{"requests":0,"tokens_in":0,"tokens_out":0,"cost_usd_micros":0}}',
    );

    await api.requestsReport(["model", "api_key_id", "tenant", "user"], {
      model: "claude-sonnet-4",
      tenant: "acme",
      user: "dev@acme.test",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/requests/report?model=claude-sonnet-4&tenant=acme&user=dev%40acme.test&group_by=model%2Capi_key_id%2Ctenant%2Cuser",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("builds export URLs that carry the current filtered view", () => {
    expect(api.requestsExportUrl("csv", { model: "gpt-5", tenant: "acme" })).toBe(
      "/api/requests/export?model=gpt-5&tenant=acme&format=csv",
    );
    expect(api.requestsExportUrl("jsonl")).toBe("/api/requests/export?format=jsonl");
  });

  it("fetches the export through the client so failures reach the error path", async () => {
    const fetchMock = stubFetch("timestamp,origin\n2026-08-20T00:00:00Z,ai.local\n");

    const body = await api.requestsExport("csv", { tenant: "acme" });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/requests/export?tenant=acme&format=csv",
      expect.objectContaining({ method: "GET" }),
    );
    expect(body).toContain("ai.local");
  });

  it("throws an ApiError carrying the server body when the export is refused", async () => {
    stubFetch('{"error":"Unauthorized"}', 401);

    // The bare <a download> this replaced saved that body as
    // `requests.csv` with nothing on screen.
    await expect(api.requestsExport("csv")).rejects.toBeInstanceOf(ApiError);
  });
});

describe("api.routingDecisions (WOR-2575)", () => {
  it("builds the snake_case server-side filter query", async () => {
    const fetchMock = stubFetch("[]");

    await api.routingDecisions({
      origin: "ai-gateway",
      strategy: "fallback_chain",
      provider: "anthropic",
      model: "gpt-5",
      since: "2026-08-20T10:30:00+00:00",
      limit: 50,
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/routing-decisions?origin=ai-gateway&strategy=fallback_chain&provider=anthropic&model=gpt-5&since=2026-08-20T10%3A30%3A00%2B00%3A00&limit=50",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("omits the query string entirely when nothing is filtered", async () => {
    const fetchMock = stubFetch("[]");

    await api.routingDecisions();

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/routing-decisions",
      expect.objectContaining({ method: "GET" }),
    );
  });
});

describe("api.mcpApprovals (WOR-2588)", () => {
  it("lists holds and posts approve/deny on the hold id", async () => {
    const fetchMock = stubFetch('{"enabled":true,"holds":[]}');
    await api.mcpApprovals();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/mcp/approvals",
      expect.objectContaining({ method: "GET" }),
    );
    await api.approveMcpHold("hold_abc", "alice");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/mcp/approvals/hold_abc/approve",
      expect.objectContaining({ method: "POST" }),
    );
    await api.denyMcpHold("hold_abc", "alice");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/mcp/approvals/hold_abc/deny",
      expect.objectContaining({ method: "POST" }),
    );
  });
});

describe("extension inventory contract", () => {
  it("loads the authoritative running snapshot from the authenticated API", async () => {
    const snapshot: ExtensionInventorySnapshot = {
      schema_version: 1,
      scope: {
        mode: "running",
        proxy_version: "0.9.0",
        config_revision: "sha256:config-revision",
      },
      summary: {
        bundles: 2,
        hooks: 2,
        active: 1,
        available: 1,
        failed: 1,
        collisions: 0,
      },
      bundles: [
        {
          id: "request-policy",
          name: "Request policy",
          version: "1.2.0",
          package: "entry.js",
          source: "git",
          runtime: "javascript",
          state: "active",
          hook_ids: ["request-policy:policy:request_policy"],
          load: { phase: "candidate_load", status: "ok", detail: null },
        },
        {
          id: "broken-policy",
          name: "Broken policy",
          version: "0.1.0",
          package: null,
          source: "directory",
          runtime: "javascript",
          state: "failed",
          hook_ids: [],
          load: {
            phase: "manifest",
            status: "failed",
            detail: "hook kind is unsupported",
          },
        },
      ],
      hooks: [
        {
          id: "request-policy:policy:request_policy",
          bundle_id: "request-policy",
          kind: "policy",
          registration: "git",
          dispatch: "chain",
          match_key: "request_policy",
          position: 0,
          state: "active",
          detail: null,
          runtime: "javascript",
          execution: {
            phase: "request",
            body_mode: "none",
            timeout_ms: 25,
            max_buffer_bytes: null,
          },
          capabilities: ["request.headers.read"],
        },
        {
          id: "request-policy:policy:fallback_policy",
          bundle_id: "request-policy",
          kind: "policy",
          registration: "git",
          dispatch: "chain",
          match_key: "fallback_policy",
          position: null,
          state: "available",
          detail: null,
          runtime: "javascript",
          execution: {
            phase: "request",
            body_mode: "none",
            timeout_ms: 25,
            max_buffer_bytes: null,
          },
          capabilities: [],
        },
      ],
      collisions: [],
    };
    const fetchMock = stubFetch(JSON.stringify(snapshot));

    await expect(api.extensions()).resolves.toEqual(snapshot);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/extensions",
      expect.objectContaining({ method: "GET" }),
    );
  });
});

describe("promoted property spend contracts", () => {
  it("decodes available keys and encodes property grouping", async () => {
    const fetchMock = stubFetch(
      JSON.stringify({
        from: 1,
        to: 2,
        group_by: "property:customer.tier",
        bucket_secs: 3600,
        buckets: [],
        totals: {
          requests: 0,
          tokens_in: 0,
          tokens_out: 0,
          cost_usd_micros: 0,
          ok: 0,
          blocked: 0,
          error: 0,
        },
        property_keys: ["customer.tier", "feature"],
      }),
    );

    const result = await api.spendWindow("24h", "property:customer.tier");

    expect(result.property_keys).toEqual(["customer.tier", "feature"]);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/usage/spend?window=24h&group_by=property%3Acustomer.tier",
      expect.objectContaining({ method: "GET" }),
    );
  });
});

describe("alert operations contracts", () => {
  it("decodes the secret-free runtime snapshot", async () => {
    stubFetch(
      JSON.stringify({
        enabled: true,
        authority: "file",
        read_only: true,
        rules: [
          {
            rule: "error_rate_spike",
            description: "Provider error rate",
            thresholds: [0.1, 0.2],
            minimum_samples: 10,
            state: "inactive",
            sample_count: 4,
          },
        ],
        channels: [
          {
            index: 0,
            type: "slack",
            target: "https://hooks.slack.com",
            health: { status: "untested" },
          },
        ],
        history: [],
      }),
    );

    await expect(api.alerts()).resolves.toMatchObject({
      authority: "file",
      read_only: true,
      rules: [{ minimum_samples: 10, state: "inactive" }],
      channels: [{ target: "https://hooks.slack.com" }],
    });
  });

  it("sends the browser CSRF token on targeted channel tests", async () => {
    const fetchMock = stubFetch('{"status":"accepted"}', 202);
    setCsrfToken("csrf-alert-test");

    await api.testAlertChannel(3);

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/alerts/test",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ "X-CSRF-Token": "csrf-alert-test" }),
        body: JSON.stringify({ channel_index: 3 }),
      }),
    );
  });
});

describe("api.auditChain (WOR-2579)", () => {
  it("builds the snake_case chain query with the paging cursor", async () => {
    const fetchMock = stubFetch('{"channels":[],"entries":[]}');

    await api.auditChain({
      channel: "security",
      actor: "203.0.113.9",
      since: "2026-08-20T10:30:00.000Z",
      beforeSeq: 42,
      limit: 50,
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/audit/chain?channel=security&actor=203.0.113.9&since=2026-08-20T10%3A30%3A00.000Z&before_seq=42&limit=50",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("keeps a zero cursor: seq 0 is a real position, not a missing one", async () => {
    const fetchMock = stubFetch('{"channels":[],"entries":[]}');

    await api.auditChain({ channel: "admin", beforeSeq: 0 });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/audit/chain?channel=admin&before_seq=0",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("omits the query string entirely when nothing is filtered", async () => {
    const fetchMock = stubFetch('{"channels":[],"entries":[]}');

    await api.auditChain();

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/audit/chain",
      expect.objectContaining({ method: "GET" }),
    );
  });
});

describe("admin client marker (WOR-2688)", () => {
  it("marks a read as this app's own so the server can drop the Basic challenge", async () => {
    const fetchMock = stubFetch("[]");

    await api.keys();

    // The header is what tells `basic_challenge_for_request` server-side
    // that a 401 here must not carry `WWW-Authenticate`, which is what
    // opens the browser's native credential dialog over the console.
    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/keys",
      expect.objectContaining({
        headers: expect.objectContaining({ "X-Requested-With": "XMLHttpRequest" }),
      }),
    );
  });

  it("marks a mutation, alongside the CSRF token rather than instead of it", async () => {
    setCsrfToken("csrf-token");
    const fetchMock = stubFetch('{"level":"debug"}');

    await api.setLogLevel("debug");

    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/log-level",
      expect.objectContaining({
        headers: expect.objectContaining({
          "X-Requested-With": "XMLHttpRequest",
          "X-CSRF-Token": "csrf-token",
        }),
      }),
    );
  });

  it("marks a raw-body write too: the config editor is a fetch like any other", async () => {
    const fetchMock = stubFetch("saved");

    await api.putConfig("proxy: {}\n");

    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/config",
      expect.objectContaining({
        headers: expect.objectContaining({ "X-Requested-With": "XMLHttpRequest" }),
      }),
    );
  });
});
