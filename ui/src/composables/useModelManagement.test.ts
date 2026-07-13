import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("vue", async () => {
  const actual = await vi.importActual<typeof import("vue")>("vue");
  return { ...actual, onMounted: vi.fn() };
});

import {
  api,
  ApiError,
  type CatalogResponse,
  type ClusterDeploymentAuthority,
  type ClusterDeploymentDocument,
  type ClusterStatusResponse,
  type DeploymentDocument,
  type DeploymentRuntimeState,
  type DeploymentRuntimeStatus,
  type ModelHostStatus,
} from "../api";
import { deploymentDefaults } from "../lib/model-management";
import { useModelManagement } from "./useModelManagement";

function ownRecord<T>(entries: ReadonlyArray<readonly [string, T]>): Record<string, T> {
  const record = Object.create(null) as Record<string, T>;
  for (const [key, value] of entries) record[key] = value;
  return record;
}

function catalog(revision = "catalog-v1"): CatalogResponse {
  return {
    schema_version: 1,
    catalog_revision: revision,
    models: {
      model: {
        params: "1B",
        license: "Apache-2.0",
        family: "fixture",
        context_length: 4096,
        variants: [
          {
            id: "q4",
            format: "gguf",
            quant: "Q4",
            engines: ["llama_cpp"],
            accelerators: ["cpu"],
            min_memory_bytes: 1,
            download_size_bytes: 1,
            certification: "fixture",
            stability: "stable",
          },
        ],
      },
    },
  };
}

function document(
  authority: DeploymentDocument["authority"] = "admin_managed",
  readOnly = false,
  revision: number | null = 1,
  deployments: DeploymentDocument["deployments"] = ownRecord([]),
): DeploymentDocument {
  return {
    schema_version: 1,
    authority,
    read_only: readOnly,
    revision,
    content_digest: null,
    deployments,
  };
}

function runtime(
  deployment: string,
  state: DeploymentRuntimeState,
): DeploymentRuntimeStatus {
  return {
    deployment,
    generation: 1,
    state,
    active_requests: 0,
    queued_requests: 0,
    engine: null,
    driver_availability: null,
    artifact_digest: null,
    selected_devices: [],
    memory: null,
    port: null,
    reason_code: null,
    job_id: null,
    last_error: null,
  };
}

function status(deployments: DeploymentRuntimeStatus[] = []): ModelHostStatus {
  return { runtime_revision: 1, deployments, local_serving: { ready: true } };
}

function authority(
  activeRevision: number | null = 7,
  readOnly = false,
  configured = true,
): ClusterDeploymentAuthority {
  return {
    configured,
    read_only: readOnly,
    verifying_key_id: "key-a",
    active_revision: activeRevision,
    active_content_digest: activeRevision === null ? null : "a".repeat(64),
    signer_node_id: configured ? "authority-a" : null,
  };
}

function clusterStatus(
  deploymentAuthority: ClusterDeploymentAuthority = authority(),
): ClusterStatusResponse {
  return { deployment_authority: deploymentAuthority } as ClusterStatusResponse;
}

function bundle(revision = 7): ClusterDeploymentDocument {
  return {
    schema_version: 1,
    bundle: {
      schema_version: 1,
      catalog_revision: "catalog-v1",
      revision,
      deployments: ownRecord([]),
      content_digest: "a".repeat(64),
    },
    signer_node_id: "authority-a",
    signer_key_id: "key-a",
    read_only: false,
  };
}

function mockReads(input: {
  status?: ModelHostStatus | Error;
  catalog?: CatalogResponse | Error;
  document?: DeploymentDocument | Error;
  clusterStatus?: ClusterStatusResponse | Error;
  bundle?: ClusterDeploymentDocument | Error;
  metrics?: string | Error;
} = {}) {
  const value = <T>(candidate: T | Error | undefined, fallback: T) =>
    candidate instanceof Error
      ? Promise.reject(candidate)
      : Promise.resolve(candidate ?? fallback);
  vi.spyOn(api, "modelHostStatus").mockImplementation(() =>
    value(input.status, status()),
  );
  vi.spyOn(api, "modelHostCatalog").mockImplementation(() =>
    value(input.catalog, catalog()),
  );
  vi.spyOn(api, "modelHostDeployments").mockImplementation(() =>
    value(input.document, document()),
  );
  vi.spyOn(api, "clusterStatus").mockImplementation(() =>
    value(input.clusterStatus, clusterStatus()),
  );
  vi.spyOn(api, "clusterDeployments").mockImplementation(() =>
    value(input.bundle, bundle()),
  );
  vi.spyOn(api, "metrics").mockImplementation(() =>
    value(input.metrics, ""),
  );
}

async function loadProof(management: ReturnType<typeof useModelManagement>) {
  await Promise.all([
    management.statusReq.run(),
    management.catalogReq.run(),
    management.deploymentsReq.run(),
    management.clusterStatusReq.run(),
    management.clusterBundleReq.run(),
  ]);
}

function formValue(deploymentId = "new-deployment") {
  return {
    deploymentId,
    deployment: deploymentDefaults("model", "q4"),
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useModelManagement orchestration", () => {
  it("refreshes independent resources and requires current catalog and management proof", async () => {
    mockReads({ catalog: new ApiError(503, "catalog unavailable") });
    const management = useModelManagement();

    const refreshing = management.refresh();
    expect(refreshing).toBeInstanceOf(Promise);
    await refreshing;

    expect(management.status.value).toEqual(status());
    expect(management.deploymentDocument.value).toEqual(document());
    expect(management.catalogReq.error.value?.status).toBe(503);
    expect(management.canMutate.value).toBe(false);

    vi.mocked(api.modelHostCatalog).mockResolvedValueOnce(catalog());
    await management.catalogReq.run();
    expect(management.canMutate.value).toBe(true);

    vi.mocked(api.modelHostCatalog).mockRejectedValueOnce(
      new ApiError(503, "fresh catalog failed"),
    );
    await management.catalogReq.run();
    expect(management.catalog.value?.catalog_revision).toBe("catalog-v1");
    expect(management.catalogReq.succeeded.value).toBe(false);
    expect(management.canMutate.value).toBe(false);
  });

  it("keeps the newest composable response when deferred catalog requests resolve in reverse", async () => {
    mockReads();
    const first = deferred<CatalogResponse>();
    const second = deferred<CatalogResponse>();
    vi.mocked(api.modelHostCatalog)
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    const management = useModelManagement();

    const older = management.catalogReq.run();
    const newer = management.catalogReq.run();
    second.resolve(catalog("newest"));
    await newer;
    first.resolve(catalog("older"));
    await older;

    expect(management.catalog.value?.catalog_revision).toBe("newest");
    expect(management.catalogReq.succeeded.value).toBe(true);
  });

  it("accepts an explicit initial signed-bundle 404 only with fresh null authority revision", async () => {
    mockReads({
      document: document("cluster_authority", true),
      clusterStatus: clusterStatus(authority(null)),
      bundle: new ApiError(404, "no active bundle", "not published"),
    });
    const management = useModelManagement();
    await loadProof(management);

    expect(management.clusterBundleReq.error.value?.status).toBe(404);
    expect(management.canMutate.value).toBe(true);

    vi.mocked(api.clusterStatus).mockRejectedValueOnce(
      new ApiError(503, "authority refresh failed"),
    );
    await management.clusterStatusReq.run();
    expect(management.clusterAuthority.value?.active_revision).toBeNull();
    expect(management.canMutate.value).toBe(false);
  });

  it("gives errors precedence over a retained cluster bundle", async () => {
    mockReads({ document: document("cluster_authority", true) });
    const management = useModelManagement();
    await loadProof(management);
    expect(management.canMutate.value).toBe(true);

    vi.mocked(api.clusterDeployments).mockRejectedValueOnce(
      new ApiError(503, "bundle refresh failed"),
    );
    await management.clusterBundleReq.run();

    expect(management.clusterBundle.value).toEqual(bundle());
    expect(management.clusterBundleReq.succeeded.value).toBe(false);
    expect(management.canMutate.value).toBe(false);
  });

  it.each([
    document("file_managed", true),
    document("admin_managed", true),
    document("cluster_authority", true),
  ])("never calls a mutation API in a read-only mode", async (readOnlyDocument) => {
    const cluster =
      readOnlyDocument.authority === "cluster_authority"
        ? clusterStatus(authority(7, true))
        : clusterStatus();
    mockReads({ document: readOnlyDocument, clusterStatus: cluster });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockResolvedValue({} as never);
    const publish = vi
      .spyOn(api, "publishClusterDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);

    management.openAddDeployment();
    await management.saveDeployment(formValue());

    expect(management.editor.value).toBeNull();
    expect(replace).not.toHaveBeenCalled();
    expect(publish).not.toHaveBeenCalled();
  });

  it("sends an exact immutable complete-map local request from a null initial revision", async () => {
    const special = deploymentDefaults("model", "q4");
    const desired = ownRecord([["__proto__", special]]);
    mockReads({ document: document("admin_managed", false, null, desired) });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openAddDeployment();

    const operation = management.saveDeployment(formValue("added"));
    expect(operation).toBeInstanceOf(Promise);
    await operation;

    expect(replace).toHaveBeenCalledTimes(1);
    const request = replace.mock.calls[0][0];
    expect(request.expected_revision).toBeNull();
    expect(Object.keys(request.deployments).sort()).toEqual(["__proto__", "added"]);
    expect(Object.hasOwn(request.deployments, "__proto__")).toBe(true);
    expect(request.deployments["__proto__"]).not.toBe(special);
    expect(request.deployments["__proto__"].required_labels).not.toBe(
      special.required_labels,
    );
    expect(request.deployments["__proto__"].spread_by).not.toBe(
      special.spread_by,
    );
  });

  it("sends the exact next signed cluster revision and complete map", async () => {
    const existing = deploymentDefaults("model", "q4");
    mockReads({
      document: document(
        "cluster_authority",
        true,
        7,
        ownRecord([["existing", existing]]),
      ),
    });
    const publish = vi
      .spyOn(api, "publishClusterDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openAddDeployment();

    await management.saveDeployment(formValue("added"));

    expect(publish).toHaveBeenCalledTimes(1);
    expect(publish).toHaveBeenCalledWith({
      catalog_revision: "catalog-v1",
      revision: 8,
      deployments: {
        added: formValue("added").deployment,
        existing,
      },
    });
  });

  it("preserves raw 409 state and the operator draft before a successful proof reload", async () => {
    mockReads({ document: document("admin_managed", false, 4) });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockRejectedValueOnce(
        new ApiError(409, "revision conflict", '{"error":"raw conflict"}'),
      )
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openAddDeployment();

    const reloaded = deferred<DeploymentDocument>();
    vi.mocked(api.modelHostDeployments).mockReturnValueOnce(reloaded.promise);
    const saving = management.saveDeployment(formValue("draft-id"));
    await Promise.resolve();
    await Promise.resolve();

    expect(management.conflict.value).toEqual(
      expect.objectContaining({
        status: 409,
        body: '{"error":"raw conflict"}',
        comparison: null,
      }),
    );
    expect(management.editor.value).not.toBeNull();
    expect(management.conflictRetryAllowed.value).toBe(false);

    reloaded.resolve(document("admin_managed", false, 5));
    await saving;
    expect(management.conflict.value?.currentRevision).toBe(5);
    expect(management.conflict.value?.comparison).not.toBeNull();
    expect(management.conflictRetryAllowed.value).toBe(true);
    await management.retryConflict();
    expect(replace).toHaveBeenCalledTimes(2);
  });

  it("keeps raw conflict without a current-map claim when any proof reload fails", async () => {
    mockReads({ document: document("admin_managed", false, 4) });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockRejectedValueOnce(
        new ApiError(409, "revision conflict", "raw local conflict"),
      )
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openAddDeployment();
    vi.mocked(api.modelHostDeployments).mockRejectedValueOnce(
      new ApiError(503, "reload failed", "reload body"),
    );

    await management.saveDeployment(formValue("draft-id"));

    expect(management.editor.value).not.toBeNull();
    expect(management.conflict.value).toEqual(
      expect.objectContaining({
        status: 409,
        body: "raw local conflict",
        currentDeployments: null,
        comparison: null,
        reloadError: expect.stringMatching(/reload/i),
      }),
    );
    expect(management.canMutate.value).toBe(false);
    expect(management.conflictRetryAllowed.value).toBe(false);

    await management.retryConflict();
    expect(replace).toHaveBeenCalledTimes(1);

    vi.mocked(api.modelHostCatalog).mockResolvedValueOnce(catalog());
    vi.mocked(api.modelHostDeployments).mockResolvedValueOnce(
      document("admin_managed", false, 5),
    );
    await Promise.all([
      management.catalogReq.run(),
      management.deploymentsReq.run(),
    ]);
    expect(management.canMutate.value).toBe(true);
    await management.saveDeployment(formValue("draft-id"));
    expect(replace).toHaveBeenCalledTimes(1);
  });

  it.each<DeploymentRuntimeState>(["stopped", "ready"])(
    "requires a fresh lifecycle snapshot with retained %s state but allows a fresh absent runtime row",
    async (retainedState) => {
    const desired = ownRecord([
      ["remove-me", deploymentDefaults("model", "q4")],
    ]);
    mockReads({
      document: document("admin_managed", false, 1, desired),
      status: status([runtime("remove-me", retainedState)]),
    });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);

    vi.mocked(api.modelHostStatus).mockRejectedValueOnce(
      new ApiError(503, "runtime refresh failed"),
    );
    await management.statusReq.run();
    await management.removeDeployment(management.rows.value[0]);
    expect(replace).not.toHaveBeenCalled();
    expect(management.banner.value?.text).toMatch(/refresh runtime/i);

    vi.mocked(api.modelHostStatus).mockResolvedValueOnce(status([]));
    await management.statusReq.run();
    await management.removeDeployment(management.rows.value[0]);
    expect(replace).toHaveBeenCalledTimes(1);
    },
  );

  it("blocks removal when the first lifecycle status request is unavailable", async () => {
    const desired = ownRecord([
      ["remove-me", deploymentDefaults("model", "q4")],
    ]);
    mockReads({
      document: document("admin_managed", false, 1, desired),
      status: new ApiError(503, "runtime unavailable"),
    });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);

    await management.removeDeployment(management.rows.value[0]);

    expect(replace).not.toHaveBeenCalled();
    expect(management.banner.value?.text).toMatch(/refresh runtime/i);
  });

  it("requires every cluster authority proof to reload before comparing a conflict", async () => {
    mockReads({ document: document("cluster_authority", true, 7) });
    const publish = vi
      .spyOn(api, "publishClusterDeployments")
      .mockRejectedValueOnce(
        new ApiError(409, "cluster conflict", "raw cluster conflict"),
      )
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openAddDeployment();
    vi.mocked(api.clusterDeployments).mockRejectedValueOnce(
      new ApiError(503, "bundle reload failed"),
    );

    await management.saveDeployment(formValue("cluster-draft"));

    expect(management.conflict.value).toEqual(
      expect.objectContaining({
        status: 409,
        body: "raw cluster conflict",
        currentDeployments: null,
        comparison: null,
        reloadError: expect.stringMatching(/signed bundle reload failed/i),
      }),
    );
    expect(management.conflictRetryAllowed.value).toBe(false);
    await management.retryConflict();
    expect(publish).toHaveBeenCalledTimes(1);
  });

  it("describes read-only, missing, unconfigured, and verifying ownership truthfully", async () => {
    mockReads({ document: document("admin_managed", true) });
    const management = useModelManagement();
    await loadProof(management);
    expect(management.authorityDescription.value).toMatch(/cannot change/i);
    expect(management.authorityDescription.value).not.toMatch(/owns and can replace/i);

    vi.mocked(api.modelHostDeployments).mockResolvedValueOnce(
      document("cluster_authority", true),
    );
    vi.mocked(api.clusterStatus).mockRejectedValueOnce(
      new ApiError(503, "authority unavailable"),
    );
    await Promise.all([
      management.deploymentsReq.run(),
      management.clusterStatusReq.run(),
    ]);
    expect(management.authorityDescription.value).toMatch(/not been verified/i);
    expect(management.authorityDescription.value).not.toMatch(/this authority node signs/i);

    vi.mocked(api.clusterStatus).mockResolvedValueOnce(
      clusterStatus(authority(null, false, false)),
    );
    await management.clusterStatusReq.run();
    expect(management.authorityDescription.value).toMatch(/no cluster deployment authority/i);

    vi.mocked(api.clusterStatus).mockResolvedValueOnce(
      clusterStatus(authority(7, true, true)),
    );
    await management.clusterStatusReq.run();
    expect(management.authorityDescription.value).toMatch(/verifies signed/i);
    expect(management.authorityDescription.value).toMatch(/configured authority node signs/i);
  });

  it("catches mutation failures without rejecting the returned operation", async () => {
    mockReads();
    vi.spyOn(api, "replaceModelHostDeployments").mockRejectedValueOnce(
      new ApiError(500, "save failed"),
    );
    const management = useModelManagement();
    await loadProof(management);
    management.openAddDeployment();

    await expect(management.saveDeployment(formValue())).resolves.toBeUndefined();
    expect(management.mutationError.value).toMatch(/server returned an error/i);
  });
});
