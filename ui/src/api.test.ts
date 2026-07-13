import { afterEach, describe, expect, expectTypeOf, it, vi } from "vitest";

import {
  api,
  ApiError,
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
