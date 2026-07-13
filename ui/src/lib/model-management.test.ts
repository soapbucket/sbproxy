import { describe, expect, it } from "vitest";

import type {
  CatalogEntry,
  CatalogResponse,
  ClusterDeploymentAuthority,
  DeploymentDocument,
  DeploymentRuntimeState,
  ModelDeployment,
} from "../api";
import {
  applyDeploymentChange,
  authorityLabel,
  buildDeploymentMutation,
  createDeploymentConflictState,
  deploymentRows,
  deploymentRemovalGuard,
  deployableCatalogEntries,
  deployableCatalogVariants,
  deploymentDefaults,
  deploymentFormDefaults,
  deploymentFormFromDeployment,
  deploymentMutationMode,
  nextClusterRevision,
  parseDeploymentForm,
} from "./model-management";

function catalogEntry(overrides: Partial<CatalogEntry> = {}): CatalogEntry {
  return {
    params: "0.5B",
    license: "Apache-2.0",
    family: "qwen2.5",
    context_length: 32_768,
    variants: [
      {
        id: "q4_k_m",
        format: "gguf",
        quant: "Q4_K_M",
        engines: ["llama_cpp"],
        accelerators: ["cpu", "metal"],
        min_memory_bytes: 512_000_000,
        download_size_bytes: 384_000_000,
        certification: "local-metal-2026-07",
        stability: "preview",
      },
    ],
    ...overrides,
  };
}

function deploymentDocument(
  authority: DeploymentDocument["authority"],
  read_only: boolean,
): DeploymentDocument {
  return {
    schema_version: 1,
    authority,
    read_only,
    revision: null,
    content_digest: null,
    deployments: {},
  };
}

function clusterAuthority(
  read_only: boolean,
  configured = true,
): ClusterDeploymentAuthority {
  return {
    configured,
    read_only,
    verifying_key_id: "key-a",
    active_revision: 7,
    active_content_digest: "a".repeat(64),
    signer_node_id: "authority-a",
  };
}

describe("model management presentation", () => {
  it("labels every persistent desired-state authority", () => {
    expect(authorityLabel("file_managed")).toBe("File managed");
    expect(authorityLabel("admin_managed")).toBe("Admin managed");
    expect(authorityLabel("cluster_authority")).toBe("Cluster authority");
  });

  it("selects only the mutation path owned by the active authority", () => {
    expect(
      deploymentMutationMode(
        deploymentDocument("file_managed", false),
        clusterAuthority(false),
      ),
    ).toBe("read_only");
    expect(
      deploymentMutationMode(
        deploymentDocument("admin_managed", false),
        null,
      ),
    ).toBe("local_put");
    expect(
      deploymentMutationMode(
        deploymentDocument("admin_managed", true),
        null,
      ),
    ).toBe("read_only");
    expect(
      deploymentMutationMode(
        deploymentDocument("cluster_authority", true),
        clusterAuthority(false),
      ),
    ).toBe("signed_cluster_post");
    expect(
      deploymentMutationMode(
        deploymentDocument("cluster_authority", true),
        clusterAuthority(true),
      ),
    ).toBe("read_only");
    expect(
      deploymentMutationMode(
        deploymentDocument("cluster_authority", true),
        clusterAuthority(false, false),
      ),
    ).toBe("read_only");
  });

  it("computes the next safe cluster revision", () => {
    expect(nextClusterRevision(null)).toBe(1);
    expect(nextClusterRevision(7)).toBe(8);
    expect(nextClusterRevision(Number.MAX_SAFE_INTEGER)).toBeNull();
    expect(nextClusterRevision(-1)).toBeNull();
  });

  it("keeps preview entries with exact deployable variants and filters incomplete entries", () => {
    const catalog: CatalogResponse = {
      schema_version: 1,
      catalog_revision: "catalog-v2",
      models: {
        "preview-ready": catalogEntry(),
        "no-accelerator": catalogEntry({
          variants: [
            {
              ...catalogEntry().variants[0],
              accelerators: [],
            },
          ],
        }),
        "no-engine": catalogEntry({
          variants: [
            {
              ...catalogEntry().variants[0],
              engines: [],
            },
          ],
        }),
        "no-variant": catalogEntry({ variants: [] }),
      },
    };

    expect(deployableCatalogEntries(catalog).map(({ id }) => id)).toEqual([
      "preview-ready",
    ]);
    expect(
      deployableCatalogVariants(catalog.models["preview-ready"]).map(
        (variant) => variant.id,
      ),
    ).toEqual(["q4_k_m"]);
  });

  it("creates a complete deployment using the backend-safe defaults", () => {
    expect(deploymentDefaults("qwen2.5-0.5b-instruct", "q4_k_m")).toEqual({
      model: "qwen2.5-0.5b-instruct",
      variant: "q4_k_m",
      heterogeneous_variants: false,
      replicas: 1,
      required_labels: {},
      spread_by: [],
      pull: "on_demand",
      warm: false,
      keep_alive_secs: null,
      max_concurrency: null,
      max_queue_depth: 128,
      queue_timeout_ms: 30_000,
      engine: "auto",
      rollout: "rolling",
    });
  });

  it("creates an operator draft from backend-safe defaults", () => {
    expect(
      deploymentFormDefaults(
        "local-qwen",
        "qwen2.5-0.5b-instruct",
        "q4_k_m",
      ),
    ).toEqual({
      deploymentId: "local-qwen",
      model: "qwen2.5-0.5b-instruct",
      variant: "q4_k_m",
      heterogeneousVariants: false,
      replicas: "1",
      requiredLabels: "",
      spreadBy: "",
      pull: "on_demand",
      warm: false,
      keepAliveSecs: "",
      maxConcurrency: "",
      maxQueueDepth: "128",
      queueTimeoutMs: "30000",
      engine: "auto",
      rollout: "rolling",
      licenseAcknowledged: false,
    });
  });

  it("round-trips an existing deployment into an editable form draft", () => {
    const deployment = {
      ...deploymentDefaults("qwen2.5-0.5b-instruct", null),
      heterogeneous_variants: true,
      replicas: 2,
      required_labels: { pool: "gpu", zone: "west" },
      spread_by: ["zone", "rack"],
      pull: "on_boot" as const,
      warm: true,
      keep_alive_secs: 600,
      max_concurrency: 4,
      max_queue_depth: 64,
      queue_timeout_ms: 5000,
      engine: "vllm" as const,
      rollout: "recreate" as const,
    };

    expect(deploymentFormFromDeployment("cluster-qwen", deployment)).toEqual(
      expect.objectContaining({
        deploymentId: "cluster-qwen",
        variant: "",
        heterogeneousVariants: true,
        replicas: "2",
        requiredLabels: "pool=gpu\nzone=west",
        spreadBy: "zone\nrack",
        keepAliveSecs: "600",
        maxConcurrency: "4",
        maxQueueDepth: "64",
        queueTimeoutMs: "5000",
        licenseAcknowledged: false,
      }),
    );
  });

  it("parses trimmed placement and admission fields into a complete deployment", () => {
    const draft = deploymentFormDefaults(
      " local-qwen ",
      "qwen2.5-0.5b-instruct",
      "q4_k_m",
    );
    Object.assign(draft, {
      replicas: "2",
      requiredLabels: " pool = gpu \nzone=west ",
      spreadBy: "zone, rack",
      keepAliveSecs: "600",
      maxConcurrency: "4",
      maxQueueDepth: "64",
      queueTimeoutMs: "5000",
      licenseAcknowledged: true,
    });

    expect(
      parseDeploymentForm(draft, {
        requireLicenseAcknowledgement: true,
        existingDeploymentIds: [],
      }),
    ).toEqual({
      errors: {},
      value: {
        deploymentId: "local-qwen",
        deployment: {
          ...deploymentDefaults("qwen2.5-0.5b-instruct", "q4_k_m"),
          replicas: 2,
          required_labels: { pool: "gpu", zone: "west" },
          spread_by: ["zone", "rack"],
          keep_alive_secs: 600,
          max_concurrency: 4,
          max_queue_depth: 64,
          queue_timeout_ms: 5000,
        },
      },
    });
  });

  it("rejects unsafe identifiers, duplicates, invalid automatic replicas, and missing acknowledgement", () => {
    const draft = deploymentFormDefaults(
      "bad/id",
      "qwen2.5-0.5b-instruct",
      null,
    );
    draft.replicas = "2";

    const result = parseDeploymentForm(draft, {
      requireLicenseAcknowledgement: true,
      existingDeploymentIds: ["bad/id"],
    });

    expect(result.value).toBeNull();
    expect(result.errors).toMatchObject({
      deploymentId: expect.stringContaining("letters, numbers"),
      variant: expect.stringContaining("exact variant"),
      licenseAcknowledged: expect.stringContaining("license"),
    });
  });

  it.each<DeploymentRuntimeState>(["ready", "preparing", "draining"])(
    "blocks persistent removal while runtime state is %s",
    (state) => {
      expect(deploymentRemovalGuard(state)).toEqual({
        allowed: false,
        reason:
          "Stop this deployment before removing it from desired state.",
      });
    },
  );

  it.each<DeploymentRuntimeState | null>([
    null,
    "configured",
    "assigned",
    "cached",
    "stopped",
    "failed",
  ])("allows persistent removal while runtime state is %s", (state) => {
    expect(deploymentRemovalGuard(state)).toEqual({
      allowed: true,
      reason: null,
    });
  });

  it("applies create, rename, and remove changes as complete desired maps", () => {
    const existing = deploymentDefaults("existing", "q4_k_m");
    const replacement = deploymentDefaults("replacement", "q8_0");
    const current: Record<string, ModelDeployment> = {
      keep: existing,
      rename: existing,
    };

    const renamed = applyDeploymentChange(current, {
      kind: "upsert",
      originalDeploymentId: "rename",
      deploymentId: "renamed",
      deployment: replacement,
    });
    expect(renamed).toEqual({ keep: existing, renamed: replacement });
    expect(current).toHaveProperty("rename");

    expect(
      applyDeploymentChange(renamed, {
        kind: "remove",
        deploymentId: "keep",
      }),
    ).toEqual({ renamed: replacement });
  });

  it("routes complete-map replacement through local optimistic concurrency", () => {
    const document = deploymentDocument("admin_managed", false);
    document.revision = 7;
    const deployments = {
      qwen: deploymentDefaults("qwen2.5-0.5b-instruct", "q4_k_m"),
    };

    expect(
      buildDeploymentMutation({
        document,
        clusterAuthority: null,
        catalogRevision: "catalog-v2",
        deployments,
      }),
    ).toEqual({
      kind: "local_put",
      request: { expected_revision: 7, deployments },
    });
  });

  it("routes an authority-node replacement through the next signed cluster revision", () => {
    const document = deploymentDocument("cluster_authority", true);
    const authority = clusterAuthority(false);
    const deployments = {
      qwen: deploymentDefaults("qwen2.5-0.5b-instruct", "q4_k_m"),
    };

    expect(
      buildDeploymentMutation({
        document,
        clusterAuthority: authority,
        catalogRevision: "catalog-v2",
        deployments,
      }),
    ).toEqual({
      kind: "signed_cluster_post",
      draft: {
        catalog_revision: "catalog-v2",
        revision: 8,
        deployments,
      },
    });
  });

  it("never emits a write command for read-only or unsafe authority state", () => {
    expect(
      buildDeploymentMutation({
        document: deploymentDocument("file_managed", true),
        clusterAuthority: clusterAuthority(false),
        catalogRevision: "catalog-v2",
        deployments: {},
      }),
    ).toEqual({ kind: "read_only" });

    const authority = clusterAuthority(false);
    authority.active_revision = Number.MAX_SAFE_INTEGER;
    expect(
      buildDeploymentMutation({
        document: deploymentDocument("cluster_authority", true),
        clusterAuthority: authority,
        catalogRevision: "catalog-v2",
        deployments: {},
      }),
    ).toEqual({ kind: "unsafe_revision" });
  });

  it("preserves the attempted map and compares it with the reloaded conflict state", () => {
    const attempted = {
      changed: deploymentDefaults("operator-choice", "q4_k_m"),
      added: deploymentDefaults("added", "q4_k_m"),
    };
    const current = {
      changed: deploymentDefaults("concurrent-choice", "q8_0"),
      removed: deploymentDefaults("removed", "q4_k_m"),
    };

    const conflict = createDeploymentConflictState({
      expectedRevision: 6,
      currentRevision: 7,
      attemptedDeployments: attempted,
      currentDeployments: current,
    });

    expect(conflict.expectedRevision).toBe(6);
    expect(conflict.currentRevision).toBe(7);
    expect(conflict.attemptedDeployments).toEqual(attempted);
    expect(conflict.attemptedDeployments).not.toBe(attempted);
    expect(conflict.comparison).toEqual({
      added: ["added"],
      changed: ["changed"],
      removed: ["removed"],
      preserved: [],
    });
  });

  it("keeps configured stopped deployments separate from canonical runtime state", () => {
    const desired = {
      configured: deploymentDefaults("configured-model", "q4_k_m"),
      stopped: deploymentDefaults("stopped-model", "q4_k_m"),
    };
    const runtime = [
      {
        deployment: "stopped",
        generation: 3,
        state: "stopped" as const,
        active_requests: 0,
        queued_requests: 0,
        engine: "llama_cpp" as const,
        driver_availability: "available" as const,
        artifact_digest: "a".repeat(64),
        selected_devices: [0],
        memory: null,
        port: null,
        reason_code: null,
        job_id: "job-3",
        last_error: null,
      },
    ];

    expect(deploymentRows(desired, runtime)).toEqual([
      {
        deploymentId: "configured",
        desired: desired.configured,
        runtime: null,
      },
      {
        deploymentId: "stopped",
        desired: desired.stopped,
        runtime: runtime[0],
      },
    ]);
  });

  it("keeps lifecycle state visible when management metadata is unavailable", () => {
    const runtime = [
      {
        deployment: "runtime-only",
        generation: 1,
        state: "ready" as const,
        active_requests: 1,
        queued_requests: 0,
        engine: "vllm" as const,
        driver_availability: "available" as const,
        artifact_digest: null,
        selected_devices: [],
        memory: null,
        port: 41000,
        reason_code: null,
        job_id: null,
        last_error: null,
      },
    ];

    expect(deploymentRows(null, runtime)).toEqual([
      {
        deploymentId: "runtime-only",
        desired: null,
        runtime: runtime[0],
      },
    ]);
  });
});
