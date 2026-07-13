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
  type ModelDeployment,
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

function bundle(
  revision = 7,
  deployments: ClusterDeploymentDocument["bundle"]["deployments"] = ownRecord([]),
): ClusterDeploymentDocument {
  return {
    schema_version: 1,
    bundle: {
      schema_version: 1,
      catalog_revision: "catalog-v1",
      revision,
      deployments,
      content_digest: "a".repeat(64),
    },
    signer_node_id: "authority-a",
    signer_key_id: "key-a",
    read_only: false,
  };
}

const CLUSTER_SNAPSHOT_MISMATCHES: ReadonlyArray<{
  name: string;
  mutate: (
    clusterAuthority: ClusterDeploymentAuthority,
    clusterBundle: ClusterDeploymentDocument,
  ) => void;
}> = [
  {
    name: "revision",
    mutate: (_clusterAuthority, clusterBundle) => {
      clusterBundle.bundle.revision = 8;
    },
  },
  {
    name: "content digest",
    mutate: (_clusterAuthority, clusterBundle) => {
      clusterBundle.bundle.content_digest = "b".repeat(64);
    },
  },
  {
    name: "signer node",
    mutate: (_clusterAuthority, clusterBundle) => {
      clusterBundle.signer_node_id = "authority-b";
    },
  },
  {
    name: "signing key",
    mutate: (_clusterAuthority, clusterBundle) => {
      clusterBundle.signer_key_id = "key-b";
    },
  },
  {
    name: "catalog revision",
    mutate: (_clusterAuthority, clusterBundle) => {
      clusterBundle.bundle.catalog_revision = "catalog-v2";
    },
  },
];

const CONFLICT_PROOF_CHANGES: ReadonlyArray<{
  name: string;
  mutate: (current: DeploymentDocument) => void;
}> = [
  {
    name: "revision",
    mutate: (current) => {
      current.revision = 6;
    },
  },
  {
    name: "content digest",
    mutate: (current) => {
      current.content_digest = "b".repeat(64);
    },
  },
  {
    name: "deployment map",
    mutate: (current) => {
      current.deployments = ownRecord([
        ["concurrent", deploymentDefaults("model", "q4")],
      ]);
    },
  },
];

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

async function createRemovalConflict() {
  const desired = ownRecord([
    ["remove-me", deploymentDefaults("model", "q4")],
  ]);
  mockReads({
    document: document("admin_managed", false, 4, desired),
    status: status([runtime("remove-me", "stopped")]),
  });
  const replace = vi
    .spyOn(api, "replaceModelHostDeployments")
    .mockRejectedValueOnce(
      new ApiError(409, "revision conflict", "raw removal conflict"),
    )
    .mockResolvedValue({} as never);
  const management = useModelManagement();
  await loadProof(management);
  vi.mocked(api.modelHostDeployments).mockResolvedValueOnce(
    document("admin_managed", false, 5, desired),
  );
  await management.removeDeployment(management.rows.value[0]);
  return { management, replace };
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

  it("does not expose a retained signer after a fresh no-active-bundle proof", async () => {
    mockReads({ document: document("cluster_authority", true) });
    const management = useModelManagement();
    await loadProof(management);

    expect(management.coherentClusterBundle.value?.signer_node_id).toBe(
      "authority-a",
    );
    vi.mocked(api.clusterStatus).mockResolvedValueOnce(
      clusterStatus(authority(null)),
    );
    vi.mocked(api.clusterDeployments).mockRejectedValueOnce(
      new ApiError(404, "no active bundle", "not published"),
    );

    await Promise.all([
      management.clusterStatusReq.run(),
      management.clusterBundleReq.run(),
    ]);

    expect(management.clusterBundle.value?.signer_node_id).toBe("authority-a");
    expect(management.initialClusterBundleAbsent.value).toBe(true);
    expect(management.coherentClusterBundle.value).toBeNull();
  });

  it("publishes revision one from an empty global map after a fresh initial bundle 404", async () => {
    const localOnly = deploymentDefaults("model", "q4");
    mockReads({
      document: document(
        "cluster_authority",
        true,
        99,
        ownRecord([["local-only", localOnly]]),
      ),
      clusterStatus: clusterStatus(authority(null)),
      bundle: new ApiError(404, "no active bundle", "not published"),
    });
    const publish = vi
      .spyOn(api, "publishClusterDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openAddDeployment();

    await management.saveDeployment(formValue("first-global"));

    expect(publish).toHaveBeenCalledWith({
      catalog_revision: "catalog-v1",
      revision: 1,
      deployments: {
        "first-global": formValue("first-global").deployment,
      },
    });
  });

  it.each(CLUSTER_SNAPSHOT_MISMATCHES)(
    "blocks signed publication when the fresh cluster $name does not agree",
    async ({ mutate }) => {
      const activeAuthority = authority();
      const activeBundle = bundle();
      mutate(activeAuthority, activeBundle);
      mockReads({
        document: document("cluster_authority", true),
        clusterStatus: clusterStatus(activeAuthority),
        bundle: activeBundle,
      });
      const publish = vi
        .spyOn(api, "publishClusterDeployments")
        .mockResolvedValue({} as never);
      const management = useModelManagement();
      await loadProof(management);

      expect(management.canMutate.value).toBe(false);
      management.openAddDeployment();
      await management.saveDeployment(formValue("must-not-publish"));
      expect(publish).not.toHaveBeenCalled();
    },
  );

  it("blocks a deferred cross-resource snapshot that resolves to different active revisions", async () => {
    mockReads({ document: document("cluster_authority", true) });
    const publish = vi
      .spyOn(api, "publishClusterDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    expect(management.canMutate.value).toBe(true);

    const nextStatus = deferred<ClusterStatusResponse>();
    const staleBundle = deferred<ClusterDeploymentDocument>();
    vi.mocked(api.clusterStatus).mockReturnValueOnce(nextStatus.promise);
    vi.mocked(api.clusterDeployments).mockReturnValueOnce(staleBundle.promise);
    const statusRefresh = management.clusterStatusReq.run();
    const bundleRefresh = management.clusterBundleReq.run();

    nextStatus.resolve(clusterStatus(authority(8)));
    await statusRefresh;
    expect(management.canMutate.value).toBe(false);
    staleBundle.resolve(bundle(7));
    await bundleRefresh;

    expect(management.canMutate.value).toBe(false);
    management.openAddDeployment();
    await management.saveDeployment(formValue("must-not-publish"));
    expect(publish).not.toHaveBeenCalled();
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
    {
      label: "authority",
      authorityReadOnly: true,
      bundleReadOnly: false,
    },
    {
      label: "bundle",
      authorityReadOnly: false,
      bundleReadOnly: true,
    },
    {
      label: "authority and bundle",
      authorityReadOnly: true,
      bundleReadOnly: true,
    },
  ])(
    "keeps a verified signed bundle visible when $label is read-only without allowing publication",
    async ({ authorityReadOnly, bundleReadOnly }) => {
      const desired = deploymentDefaults("model", "q4");
      const activeBundle = bundle(
        7,
        ownRecord([["signed-readonly", desired]]),
      );
      activeBundle.read_only = bundleReadOnly;
      mockReads({
        document: document(
          "cluster_authority",
          true,
          7,
          ownRecord([["projection-only", deploymentDefaults("model", "q4")]]),
        ),
        clusterStatus: clusterStatus(authority(7, authorityReadOnly)),
        bundle: activeBundle,
        status: status([runtime("signed-readonly", "stopped")]),
      });
      const publish = vi
        .spyOn(api, "publishClusterDeployments")
        .mockResolvedValue({} as never);
      const management = useModelManagement();
      await loadProof(management);

      expect(management.coherentClusterBundle.value).toBe(activeBundle);
      expect(Object.keys(management.canonicalDesiredDeployments.value ?? {})).toEqual([
        "signed-readonly",
      ]);
      expect(management.rows.value).toEqual([
        expect.objectContaining({
          deploymentId: "signed-readonly",
          desired,
          runtime: expect.objectContaining({ state: "stopped" }),
        }),
      ]);
      expect(management.effectiveDesiredRevision.value).toBe(7);
      expect(management.effectiveDesiredContentDigest.value).toBe(
        "a".repeat(64),
      );
      expect(management.coherentClusterBundle.value?.signer_node_id).toBe(
        "authority-a",
      );
      expect(management.canMutate.value).toBe(false);

      management.openEditDeployment(management.rows.value[0]);
      await management.removeDeployment(management.rows.value[0]);

      expect(management.editor.value).toBeNull();
      expect(publish).not.toHaveBeenCalled();
    },
  );

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
    const signedExisting = deploymentDefaults("model", "q4");
    const projectionOnly = deploymentDefaults("model", "q4");
    mockReads({
      document: document(
        "cluster_authority",
        true,
        7,
        ownRecord([["projection-only", projectionOnly]]),
      ),
      bundle: bundle(7, ownRecord([["signed-existing", signedExisting]])),
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
        "signed-existing": signedExisting,
      },
    });
  });

  it("rejects an add that collides with a signed deployment hidden from the local projection", async () => {
    const hidden = deploymentDefaults("model", "q4");
    mockReads({
      document: document("cluster_authority", true, 7, ownRecord([])),
      bundle: bundle(7, ownRecord([["hidden-signed", hidden]])),
    });
    const publish = vi
      .spyOn(api, "publishClusterDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openAddDeployment();

    await management.saveDeployment(formValue("hidden-signed"));

    expect(publish).not.toHaveBeenCalled();
    expect(management.mutationError.value).toEqual(
      expect.stringMatching(/already exists/i),
    );
  });

  it("seeds a signed cluster edit from the canonical bundle instead of a stale row", async () => {
    const signed: ModelDeployment = {
      ...deploymentDefaults("model", "q4"),
      replicas: 3,
      required_labels: ownRecord([["zone", "west"]]),
      spread_by: ["zone"],
      pull: "on_boot",
      warm: true,
      keep_alive_secs: 600,
      max_concurrency: 4,
    };
    const projection: ModelDeployment = {
      ...signed,
      replicas: 1,
      required_labels: ownRecord([["zone", "stale"]]),
      spread_by: [],
      pull: "manual",
      warm: false,
      keep_alive_secs: 5,
      max_concurrency: 1,
    };
    mockReads({
      document: document(
        "cluster_authority",
        true,
        7,
        ownRecord([["shared", projection]]),
      ),
      bundle: bundle(7, ownRecord([["shared", signed]])),
    });
    const management = useModelManagement();
    await loadProof(management);

    management.openEditDeployment({
      deploymentId: "shared",
      desired: projection,
      runtime: null,
    });

    expect(management.editor.value?.initialDeployment).toEqual(signed);
  });

  it("preserves signed fields while applying the intended edit", async () => {
    const signed: ModelDeployment = {
      ...deploymentDefaults("model", "q4"),
      replicas: 3,
      required_labels: ownRecord([["zone", "west"]]),
      spread_by: ["zone"],
      pull: "on_boot",
      warm: true,
      keep_alive_secs: 600,
      max_concurrency: 4,
      max_queue_depth: 64,
      queue_timeout_ms: 5_000,
    };
    const projection: ModelDeployment = {
      ...signed,
      replicas: 1,
      required_labels: ownRecord([["zone", "stale"]]),
      spread_by: [],
      pull: "manual",
      warm: false,
      keep_alive_secs: 5,
      max_concurrency: 1,
      max_queue_depth: 2,
      queue_timeout_ms: 100,
    };
    mockReads({
      document: document(
        "cluster_authority",
        true,
        7,
        ownRecord([["shared", projection]]),
      ),
      bundle: bundle(7, ownRecord([["shared", signed]])),
    });
    const publish = vi
      .spyOn(api, "publishClusterDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openEditDeployment({
      deploymentId: "shared",
      desired: projection,
      runtime: null,
    });
    const seed = management.editor.value?.initialDeployment;
    expect(seed).not.toBeNull();
    expect(seed).not.toBeUndefined();
    if (!seed) return;

    await management.saveDeployment({
      deploymentId: "shared",
      deployment: { ...seed, replicas: 4 },
    });

    expect(publish).toHaveBeenCalledTimes(1);
    expect(publish.mock.calls[0][0].deployments.shared).toEqual({
      ...signed,
      replicas: 4,
    });
  });

  it("blocks a signed edit when the canonical deployment changes after refresh", async () => {
    const deploymentId = "__proto__";
    const opened: ModelDeployment = {
      ...deploymentDefaults("model", "q4"),
      required_labels: ownRecord([["zone", "west"]]),
      replicas: 2,
    };
    const changed: ModelDeployment = {
      ...opened,
      required_labels: ownRecord([["zone", "east"]]),
      warm: true,
    };
    mockReads({
      document: document("cluster_authority", true, 7),
      bundle: bundle(7, ownRecord([[deploymentId, opened]])),
    });
    const publish = vi
      .spyOn(api, "publishClusterDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    const row = management.rows.value.find(
      (candidate) => candidate.deploymentId === deploymentId,
    );
    expect(row).toBeDefined();
    if (!row) return;
    management.openEditDeployment(row);

    vi.mocked(api.clusterStatus).mockResolvedValueOnce(
      clusterStatus(authority(8)),
    );
    vi.mocked(api.clusterDeployments).mockResolvedValueOnce(
      bundle(8, ownRecord([[deploymentId, changed]])),
    );
    await Promise.all([
      management.clusterStatusReq.run(),
      management.clusterBundleReq.run(),
    ]);

    await management.saveDeployment({
      deploymentId,
      deployment: { ...opened, replicas: 3 },
    });

    expect(publish).not.toHaveBeenCalled();
    expect(management.editor.value).not.toBeNull();
    expect(management.mutationError.value).toMatch(
      /changed or disappeared.*reopen/i,
    );
  });

  it("blocks a local edit when the canonical deployment disappears after refresh", async () => {
    const opened = deploymentDefaults("model", "q4");
    mockReads({
      document: document(
        "admin_managed",
        false,
        7,
        ownRecord([["edit-me", opened]]),
      ),
    });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openEditDeployment(management.rows.value[0]);

    vi.mocked(api.modelHostDeployments).mockResolvedValueOnce(
      document("admin_managed", false, 8, ownRecord([])),
    );
    await management.deploymentsReq.run();

    await management.saveDeployment({
      deploymentId: "edit-me",
      deployment: { ...opened, replicas: 2 },
    });

    expect(replace).not.toHaveBeenCalled();
    expect(management.editor.value).not.toBeNull();
    expect(management.mutationError.value).toMatch(
      /changed or disappeared.*reopen/i,
    );
  });

  it("preserves unrelated signed changes when the edited deployment baseline is unchanged", async () => {
    const deploymentId = "__proto__";
    const opened: ModelDeployment = {
      ...deploymentDefaults("model", "q4"),
      required_labels: ownRecord([
        ["zone", "west"],
        ["tier", "gpu"],
      ]),
    };
    const semanticallyUnchanged: ModelDeployment = {
      ...opened,
      required_labels: ownRecord([
        ["tier", "gpu"],
        ["zone", "west"],
      ]),
    };
    const unrelated = deploymentDefaults("model", "q4");
    mockReads({
      document: document("cluster_authority", true, 7),
      bundle: bundle(7, ownRecord([[deploymentId, opened]])),
    });
    const publish = vi
      .spyOn(api, "publishClusterDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    const row = management.rows.value.find(
      (candidate) => candidate.deploymentId === deploymentId,
    );
    expect(row).toBeDefined();
    if (!row) return;
    management.openEditDeployment(row);

    vi.mocked(api.clusterStatus).mockResolvedValueOnce(
      clusterStatus(authority(8)),
    );
    vi.mocked(api.clusterDeployments).mockResolvedValueOnce(
      bundle(
        8,
        ownRecord([
          [deploymentId, semanticallyUnchanged],
          ["unrelated", unrelated],
        ]),
      ),
    );
    await Promise.all([
      management.clusterStatusReq.run(),
      management.clusterBundleReq.run(),
    ]);

    const edited = { ...opened, replicas: 2 };
    await management.saveDeployment({ deploymentId, deployment: edited });

    expect(publish).toHaveBeenCalledTimes(1);
    const request = publish.mock.calls[0][0];
    expect(request.revision).toBe(9);
    expect(Object.keys(request.deployments).sort()).toEqual([
      "__proto__",
      "unrelated",
    ]);
    expect(Object.hasOwn(request.deployments, deploymentId)).toBe(true);
    expect(request.deployments[deploymentId]).toEqual(edited);
    expect(request.deployments.unrelated).toEqual(unrelated);
  });

  it("blocks an edit when desired-state authority mode changes after opening", async () => {
    const opened = deploymentDefaults("model", "q4");
    mockReads({
      document: document(
        "admin_managed",
        false,
        7,
        ownRecord([["edit-me", opened]]),
      ),
    });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockResolvedValue({} as never);
    const publish = vi
      .spyOn(api, "publishClusterDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openEditDeployment(management.rows.value[0]);

    vi.mocked(api.modelHostDeployments).mockResolvedValueOnce(
      document("cluster_authority", true, 8),
    );
    vi.mocked(api.clusterStatus).mockResolvedValueOnce(
      clusterStatus(authority(8)),
    );
    vi.mocked(api.clusterDeployments).mockResolvedValueOnce(
      bundle(8, ownRecord([["edit-me", opened]])),
    );
    await Promise.all([
      management.deploymentsReq.run(),
      management.clusterStatusReq.run(),
      management.clusterBundleReq.run(),
    ]);

    await management.saveDeployment({
      deploymentId: "edit-me",
      deployment: { ...opened, replicas: 2 },
    });

    expect(replace).not.toHaveBeenCalled();
    expect(publish).not.toHaveBeenCalled();
    expect(management.editor.value).not.toBeNull();
    expect(management.mutationError.value).toMatch(
      /authority changed.*reopen/i,
    );
  });

  it("builds rows from the signed desired map plus the local runtime union", async () => {
    const signed = deploymentDefaults("model", "q4");
    const projection = deploymentDefaults("model", "q4");
    mockReads({
      document: document(
        "cluster_authority",
        true,
        7,
        ownRecord([["projection-only", projection]]),
      ),
      bundle: bundle(7, ownRecord([["signed-only", signed]])),
      status: status([runtime("runtime-only", "ready")]),
    });
    const management = useModelManagement();
    await loadProof(management);

    expect(management.rows.value.map((row) => row.deploymentId)).toEqual([
      "runtime-only",
      "signed-only",
    ]);
    expect(management.rows.value[0]).toEqual(
      expect.objectContaining({ desired: null, runtime: expect.any(Object) }),
    );
    expect(management.rows.value[1]).toEqual(
      expect.objectContaining({ desired: signed, runtime: null }),
    );
    const effective = management as typeof management & {
      effectiveDesiredRevision?: { value: number | null | undefined };
      effectiveDesiredContentDigest?: { value: string | null | undefined };
    };
    expect(effective.effectiveDesiredRevision?.value).toBe(7);
    expect(effective.effectiveDesiredContentDigest?.value).toBe(
      "a".repeat(64),
    );
  });

  it("keeps initial no-bundle desired state empty and prototype safe", async () => {
    const projection = deploymentDefaults("model", "q4");
    mockReads({
      document: document(
        "cluster_authority",
        true,
        99,
        ownRecord([["projection-only", projection]]),
      ),
      clusterStatus: clusterStatus(authority(null)),
      bundle: new ApiError(404, "no active bundle", "not published"),
      status: status([runtime("runtime-only", "stopped")]),
    });
    const management = useModelManagement();
    await loadProof(management);

    expect(management.rows.value.map((row) => row.deploymentId)).toEqual([
      "runtime-only",
    ]);
    const desired = (
      management as typeof management & {
        canonicalDesiredDeployments?: {
          value: Readonly<Record<string, ModelDeployment>> | null;
        };
      }
    ).canonicalDesiredDeployments?.value;
    expect(desired).toBeDefined();
    if (!desired) return;
    expect(Object.keys(desired)).toEqual([]);
    expect(Object.getPrototypeOf(desired)).toBeNull();
    const effective = management as typeof management & {
      effectiveDesiredRevision?: { value: number | null | undefined };
      effectiveDesiredContentDigest?: { value: string | null | undefined };
    };
    expect(effective.effectiveDesiredRevision?.value).toBeNull();
    expect(effective.effectiveDesiredContentDigest?.value).toBeNull();
  });

  it("does not publish removal for a projection-only target absent from the signed map", async () => {
    const projection = deploymentDefaults("model", "q4");
    const signed = deploymentDefaults("model", "q4");
    mockReads({
      document: document(
        "cluster_authority",
        true,
        7,
        ownRecord([["projection-only", projection]]),
      ),
      bundle: bundle(7, ownRecord([["signed-only", signed]])),
      status: status([]),
    });
    const publish = vi
      .spyOn(api, "publishClusterDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);

    await management.removeDeployment({
      deploymentId: "projection-only",
      desired: projection,
      runtime: null,
    });

    expect(publish).not.toHaveBeenCalled();
  });

  it("requires the latest successful lifecycle response to contain the canonical deployments array", async () => {
    const desired = ownRecord([
      ["remove-me", deploymentDefaults("model", "q4")],
    ]);
    mockReads({
      document: document("admin_managed", false, 1, desired),
      status: { runtime_revision: 1, local_serving: { ready: true } },
    });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);

    expect(management.runtimeStatusCurrent.value).toBe(false);
    await management.removeDeployment(management.rows.value[0]);
    expect(replace).not.toHaveBeenCalled();

    vi.mocked(api.modelHostStatus).mockResolvedValueOnce(status([]));
    await management.statusReq.run();
    expect(management.runtimeStatusCurrent.value).toBe(true);
    await management.removeDeployment(management.rows.value[0]);
    expect(replace).toHaveBeenCalledTimes(1);
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

  it("blocks conflict retry when its edited deployment changed during reload", async () => {
    const opened = deploymentDefaults("model", "q4");
    const changed = { ...opened, warm: true };
    mockReads({
      document: document(
        "admin_managed",
        false,
        4,
        ownRecord([["edit-me", opened]]),
      ),
    });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockRejectedValueOnce(
        new ApiError(409, "revision conflict", "raw edit conflict"),
      )
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openEditDeployment(management.rows.value[0]);
    vi.mocked(api.modelHostDeployments).mockResolvedValueOnce(
      document(
        "admin_managed",
        false,
        5,
        ownRecord([["edit-me", changed]]),
      ),
    );

    await management.saveDeployment({
      deploymentId: "edit-me",
      deployment: { ...opened, replicas: 2 },
    });
    expect(management.conflictRetryAllowed.value).toBe(true);

    await management.retryConflict();

    expect(replace).toHaveBeenCalledTimes(1);
    expect(management.editor.value).not.toBeNull();
    expect(management.mutationError.value).toMatch(
      /changed or disappeared.*reopen/i,
    );
  });

  it("blocks Add conflict retry when the target ID appears during reload", async () => {
    const deploymentId = "__proto__";
    const concurrent = deploymentDefaults("model", "q4");
    mockReads({ document: document("admin_managed", false, 4) });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockRejectedValueOnce(
        new ApiError(409, "revision conflict", "raw Add collision"),
      )
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openAddDeployment();
    vi.mocked(api.modelHostDeployments).mockResolvedValueOnce(
      document(
        "admin_managed",
        false,
        5,
        ownRecord([[deploymentId, concurrent]]),
      ),
    );

    await management.saveDeployment(formValue(deploymentId));
    expect(management.conflictRetryAllowed.value).toBe(true);
    expect(
      Object.hasOwn(
        management.canonicalDesiredDeployments.value ?? {},
        deploymentId,
      ),
    ).toBe(true);

    await management.retryConflict();

    expect(replace).toHaveBeenCalledTimes(1);
    expect(management.editor.value).not.toBeNull();
    expect(management.conflict.value?.body).toBe("raw Add collision");
    expect(management.mutationError.value).toMatch(
      /already exists.*(?:reopen|another deployment ID)/i,
    );
  });

  it("blocks rename conflict retry when the target ID appears during reload", async () => {
    const originalDeploymentId = "edit-me";
    const targetDeploymentId = "constructor";
    const opened = deploymentDefaults("model", "q4");
    const concurrent = { ...opened, warm: true };
    mockReads({
      document: document(
        "admin_managed",
        false,
        4,
        ownRecord([[originalDeploymentId, opened]]),
      ),
    });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockRejectedValueOnce(
        new ApiError(409, "revision conflict", "raw rename collision"),
      )
      .mockResolvedValue({} as never);
    const management = useModelManagement();
    await loadProof(management);
    management.openEditDeployment(management.rows.value[0]);
    vi.mocked(api.modelHostDeployments).mockResolvedValueOnce(
      document(
        "admin_managed",
        false,
        5,
        ownRecord([
          [originalDeploymentId, opened],
          [targetDeploymentId, concurrent],
        ]),
      ),
    );

    await management.saveDeployment({
      deploymentId: targetDeploymentId,
      deployment: { ...opened, replicas: 2 },
    });
    expect(management.conflictRetryAllowed.value).toBe(true);
    expect(
      Object.hasOwn(
        management.canonicalDesiredDeployments.value ?? {},
        targetDeploymentId,
      ),
    ).toBe(true);

    await management.retryConflict();

    expect(replace).toHaveBeenCalledTimes(1);
    expect(management.editor.value).not.toBeNull();
    expect(management.conflict.value?.body).toBe("raw rename collision");
    expect(management.mutationError.value).toMatch(
      /already exists.*(?:reopen|another deployment ID)/i,
    );
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

  it("invalidates an admin conflict when reload changes authority to signed cluster publication", async () => {
    mockReads({ document: document("admin_managed", false, 4) });
    const replace = vi
      .spyOn(api, "replaceModelHostDeployments")
      .mockRejectedValueOnce(
        new ApiError(409, "revision conflict", "raw admin conflict"),
      );
    const management = useModelManagement();
    await loadProof(management);
    management.openAddDeployment();
    vi.mocked(api.modelHostDeployments).mockResolvedValueOnce(
      document("cluster_authority", true, 7),
    );

    await management.saveDeployment(formValue("admin-draft"));

    expect(management.editor.value).not.toBeNull();
    expect(management.conflict.value).toEqual(
      expect.objectContaining({
        body: "raw admin conflict",
        comparison: null,
        reloadError: expect.stringMatching(/authority changed.*reopen/i),
      }),
    );
    expect(management.conflictRetryAllowed.value).toBe(false);
    await management.retryConflict();
    expect(replace).toHaveBeenCalledTimes(1);
  });

  it("invalidates a signed cluster conflict when reload changes authority to local admin", async () => {
    mockReads({ document: document("cluster_authority", true, 7) });
    const publish = vi
      .spyOn(api, "publishClusterDeployments")
      .mockRejectedValueOnce(
        new ApiError(409, "revision conflict", "raw cluster conflict"),
      );
    const management = useModelManagement();
    await loadProof(management);
    management.openAddDeployment();
    vi.mocked(api.modelHostDeployments).mockResolvedValueOnce(
      document("admin_managed", false, 8),
    );

    await management.saveDeployment(formValue("cluster-draft"));

    expect(management.editor.value).not.toBeNull();
    expect(management.conflict.value).toEqual(
      expect.objectContaining({
        body: "raw cluster conflict",
        comparison: null,
        reloadError: expect.stringMatching(/authority changed.*reopen/i),
      }),
    );
    expect(management.conflictRetryAllowed.value).toBe(false);
    await management.retryConflict();
    expect(publish).toHaveBeenCalledTimes(1);
  });

  it.each(CONFLICT_PROOF_CHANGES)(
    "invalidates a conflict comparison after a page refresh changes its $name proof",
    async ({ mutate }) => {
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
      vi.mocked(api.modelHostDeployments).mockResolvedValueOnce(
        document("admin_managed", false, 5),
      );
      await management.saveDeployment(formValue("draft-id"));
      expect(management.conflictRetryAllowed.value).toBe(true);

      const changed = document("admin_managed", false, 5);
      mutate(changed);
      vi.mocked(api.modelHostDeployments).mockResolvedValueOnce(changed);
      await management.refresh();

      expect(management.canMutate.value).toBe(true);
      expect(management.conflictRetryAllowed.value).toBe(false);
      await management.retryConflict();
      await management.saveDeployment(formValue("draft-id"));
      expect(replace).toHaveBeenCalledTimes(1);
    },
  );

  it.each<DeploymentRuntimeState>(["ready", "preparing", "draining"])(
    "refreshes lifecycle proof and blocks a removal conflict retry when state becomes %s",
    async (blockedState) => {
      const { management, replace } = await createRemovalConflict();
      expect(management.conflictRetryAllowed.value).toBe(true);
      vi.mocked(api.modelHostStatus).mockResolvedValueOnce(
        status([runtime("remove-me", blockedState)]),
      );

      await management.retryConflict();

      expect(replace).toHaveBeenCalledTimes(1);
      expect(management.banner.value?.text).toMatch(/stop this deployment/i);
    },
  );

  it("blocks a removal conflict retry after a noncanonical compatibility status success", async () => {
    const { management, replace } = await createRemovalConflict();
    vi.mocked(api.modelHostStatus).mockResolvedValueOnce({
      runtime_revision: 2,
      local_serving: { ready: true },
    });

    await management.retryConflict();

    expect(replace).toHaveBeenCalledTimes(1);
    expect(management.banner.value?.text).toMatch(/refresh runtime/i);
  });

  it("blocks a removal conflict retry when the lifecycle refresh fails", async () => {
    const { management, replace } = await createRemovalConflict();
    vi.mocked(api.modelHostStatus).mockRejectedValueOnce(
      new ApiError(503, "runtime refresh failed"),
    );

    await management.retryConflict();

    expect(replace).toHaveBeenCalledTimes(1);
    expect(management.banner.value?.text).toMatch(/refresh runtime/i);
  });

  it.each<DeploymentRuntimeState | null>([
    "stopped",
    "configured",
    "failed",
    null,
  ])(
    "allows a removal conflict retry only after a fresh canonical %s lifecycle result",
    async (allowedState) => {
      const { management, replace } = await createRemovalConflict();
      const statusCallsBeforeRetry = vi.mocked(api.modelHostStatus).mock.calls
        .length;
      vi.mocked(api.modelHostStatus).mockResolvedValueOnce(
        status(
          allowedState === null
            ? []
            : [runtime("remove-me", allowedState)],
        ),
      );

      await management.retryConflict();

      expect(replace).toHaveBeenCalledTimes(2);
      expect(
        vi.mocked(api.modelHostStatus).mock.invocationCallOrder[
          statusCallsBeforeRetry
        ],
      ).toBeLessThan(replace.mock.invocationCallOrder[1]);
    },
  );

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
