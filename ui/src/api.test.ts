import { afterEach, describe, expect, expectTypeOf, it, vi } from "vitest";

import {
  api,
  ApiError,
  setCsrfToken,
  type ClusterDeploymentBundleDraft,
  type DeploymentReplacementRequest,
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
