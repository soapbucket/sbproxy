import { describe, expect, it } from "vitest";

import type {
  CatalogEntry,
  CatalogResponse,
  CatalogVariant,
  ClusterDeploymentAuthority,
  DeploymentDocument,
  DeploymentRuntimeState,
  ModelDeployment,
} from "../api";
import {
  applyDeploymentChange,
  authorityLabel,
  buildDeploymentMutation,
  catalogVariantDisabledReason,
  catalogVariantSupportLabel,
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

const PROTOTYPE_IDENTIFIERS = ["__proto__", "constructor", "toString"] as const;

function ownRecord<T>(entries: ReadonlyArray<readonly [string, T]>): Record<string, T> {
  const record = Object.create(null) as Record<string, T>;
  for (const [key, value] of entries) record[key] = value;
  return record;
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
    expect(nextClusterRevision(Number.MAX_SAFE_INTEGER - 1)).toBe(
      Number.MAX_SAFE_INTEGER,
    );
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

  it("allows only complete stable or preview variants and explains every disabled variant", () => {
    const base = catalogEntry().variants[0];
    const variants: CatalogVariant[] = [
      { ...base, id: "stable", stability: "stable" },
      { ...base, id: "preview", stability: "preview" },
      { ...base, id: "config", stability: "config_only" },
      { ...base, id: "unsupported", stability: "unsupported" },
      { ...base, id: "no-engine", stability: "stable", engines: [] },
      {
        ...base,
        id: "no-accelerator",
        stability: "preview",
        accelerators: [],
      },
    ];

    expect(
      deployableCatalogVariants(catalogEntry({ variants })).map(
        (variant) => variant.id,
      ),
    ).toEqual(["stable", "preview"]);

    expect(catalogVariantDisabledReason(variants[0])).toBeNull();
    expect(catalogVariantDisabledReason(variants[1])).toBeNull();
    expect(catalogVariantDisabledReason(variants[2])).toMatch(
      /configuration only/i,
    );
    expect(catalogVariantDisabledReason(variants[3])).toMatch(/unsupported/i);
    expect(catalogVariantDisabledReason(variants[4])).toMatch(/engine/i);
    expect(catalogVariantDisabledReason(variants[5])).toMatch(/accelerator/i);

    expect(catalogVariantSupportLabel(variants[0])).toBe("Stable");
    expect(catalogVariantSupportLabel(variants[1])).toBe("Preview");
    expect(catalogVariantSupportLabel(variants[2])).toBe("Config only");
    expect(catalogVariantSupportLabel(variants[3])).toBe("Unsupported");
    expect(catalogVariantSupportLabel(variants[4])).toBe("Incomplete");
    expect(catalogVariantSupportLabel(variants[5])).toBe("Incomplete");
  });

  it("creates a complete deployment using the backend-safe defaults", () => {
    const deployment = deploymentDefaults("qwen2.5-0.5b-instruct", "q4_k_m");
    expect(deployment).toEqual({
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
    expect(Object.getPrototypeOf(deployment.required_labels)).toBeNull();
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
        catalog: {
          schema_version: 1,
          catalog_revision: "catalog-v2",
          models: { "qwen2.5-0.5b-instruct": catalogEntry() },
        },
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

  it("preserves valid zero and null parser boundaries", () => {
    const draft = deploymentFormDefaults("zeroes", "model", "q4_k_m");
    draft.keepAliveSecs = "0";
    draft.maxConcurrency = "";
    draft.maxQueueDepth = "0";

    const result = parseDeploymentForm(draft, {
      requireLicenseAcknowledgement: false,
      existingDeploymentIds: [],
      catalog: {
        schema_version: 1,
        catalog_revision: "catalog-v2",
        models: { model: catalogEntry() },
      },
    });

    expect(result.value?.deployment).toEqual(
      expect.objectContaining({
        keep_alive_secs: 0,
        max_concurrency: null,
        max_queue_depth: 0,
      }),
    );
  });

  it("rejects a real duplicate deployment ID branch", () => {
    const draft = deploymentFormDefaults("duplicate", "model", "q4_k_m");
    const result = parseDeploymentForm(draft, {
      requireLicenseAcknowledgement: false,
      existingDeploymentIds: ["duplicate"],
      catalog: {
        schema_version: 1,
        catalog_revision: "catalog-v2",
        models: { model: catalogEntry() },
      },
    });

    expect(result.errors.deploymentId).toMatch(/already exists/i);
  });

  it("rejects duplicate and out-of-bounds label and spread input", () => {
    const duplicate = deploymentFormDefaults("placement", "model", "q4_k_m");
    duplicate.requiredLabels = "pool=gpu\npool=cpu";
    duplicate.spreadBy = "zone\nzone";
    const duplicateResult = parseDeploymentForm(duplicate, {
      requireLicenseAcknowledgement: false,
      existingDeploymentIds: [],
      catalog: {
        schema_version: 1,
        catalog_revision: "catalog-v2",
        models: { model: catalogEntry() },
      },
    });
    expect(duplicateResult.errors.requiredLabels).toMatch(/duplicated/i);
    expect(duplicateResult.errors.spreadBy).toMatch(/unique/i);

    const bounded = deploymentFormDefaults("placement", "model", "q4_k_m");
    bounded.requiredLabels = `pool=${"x".repeat(257)}`;
    bounded.spreadBy = Array.from({ length: 9 }, (_, index) => `zone${index}`).join(
      "\n",
    );
    const boundedResult = parseDeploymentForm(bounded, {
      requireLicenseAcknowledgement: false,
      existingDeploymentIds: [],
      catalog: {
        schema_version: 1,
        catalog_revision: "catalog-v2",
        models: { model: catalogEntry() },
      },
    });
    expect(boundedResult.errors.requiredLabels).toMatch(/bounded/i);
    expect(boundedResult.errors.spreadBy).toMatch(/at most 8/i);
  });

  it("rejects stale model and exact variant selections against the current catalog", () => {
    const catalog: CatalogResponse = {
      schema_version: 1,
      catalog_revision: "catalog-v2",
      models: { current: catalogEntry() },
    };
    const staleModel = deploymentFormDefaults("stale-model", "missing", "q4_k_m");
    const staleVariant = deploymentFormDefaults("stale-variant", "current", "gone");
    const nonRunnable = deploymentFormDefaults("non-runnable", "current", "config");
    catalog.models.current.variants.push({
      ...catalog.models.current.variants[0],
      id: "config",
      stability: "config_only",
    });

    expect(
      parseDeploymentForm(staleModel, {
        requireLicenseAcknowledgement: false,
        existingDeploymentIds: [],
        catalog,
      }).errors.model,
    ).toMatch(/catalog/i);
    expect(
      parseDeploymentForm(staleVariant, {
        requireLicenseAcknowledgement: false,
        existingDeploymentIds: [],
        catalog,
      }).errors.variant,
    ).toMatch(/catalog/i);
    expect(
      parseDeploymentForm(nonRunnable, {
        requireLicenseAcknowledgement: false,
        existingDeploymentIds: [],
        catalog,
      }).errors.variant,
    ).toMatch(/configuration only/i);
  });

  it.each(PROTOTYPE_IDENTIFIERS)(
    "parses and serializes the prototype-shaped required label %s",
    (identifier) => {
      const draft = deploymentFormDefaults("safe-labels", "model", "q4_k_m");
      draft.requiredLabels = `${identifier}=gpu`;

      const result = parseDeploymentForm(draft, {
        requireLicenseAcknowledgement: false,
        existingDeploymentIds: [],
        catalog: {
          schema_version: 1,
          catalog_revision: "catalog-v2",
          models: { model: catalogEntry() },
        },
      });

      expect(result.errors).toEqual({});
      expect(result.value).not.toBeNull();
      const labels = result.value?.deployment.required_labels as Record<string, string>;
      expect(Object.getPrototypeOf(labels)).toBeNull();
      expect(Object.hasOwn(labels, identifier)).toBe(true);
      expect(labels[identifier]).toBe("gpu");
      expect(JSON.parse(JSON.stringify(labels))).toEqual({ [identifier]: "gpu" });
    },
  );

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
      catalog: {
        schema_version: 1,
        catalog_revision: "catalog-v2",
        models: { "qwen2.5-0.5b-instruct": catalogEntry() },
      },
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
      expect(deploymentRemovalGuard(state, true)).toEqual({
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
  ])("allows persistent removal with a fresh snapshot while runtime state is %s", (state) => {
    expect(deploymentRemovalGuard(state, true)).toEqual({
      allowed: true,
      reason: null,
    });
  });

  it.each<DeploymentRuntimeState | null>([null, "stopped", "ready"])(
    "blocks removal with refresh guidance when runtime state %s is absent or stale",
    (state) => {
      expect(deploymentRemovalGuard(state, false)).toEqual({
        allowed: false,
        reason:
          "Refresh runtime lifecycle status before removing this deployment.",
      });
    },
  );

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

  it.each(PROTOTYPE_IDENTIFIERS)(
    "creates, renames, deeply clones, and serializes deployment ID %s safely",
    (identifier) => {
      const source = deploymentDefaults("source", "q4_k_m");
      source.required_labels = ownRecord([[identifier, "worker"]]);
      const created = applyDeploymentChange(ownRecord([]), {
        kind: "upsert",
        deploymentId: identifier,
        deployment: source,
      });

      expect(Object.getPrototypeOf(created)).toBeNull();
      expect(Object.hasOwn(created, identifier)).toBe(true);
      expect(created[identifier]).not.toBe(source);
      expect(Object.getPrototypeOf(created[identifier].required_labels)).toBeNull();
      expect(created[identifier].required_labels).not.toBe(source.required_labels);
      expect(JSON.parse(JSON.stringify(created))).toEqual({
        [identifier]: expect.objectContaining({
          model: "source",
          required_labels: { [identifier]: "worker" },
        }),
      });

      const renamed = applyDeploymentChange(created, {
        kind: "upsert",
        originalDeploymentId: identifier,
        deploymentId: `renamed-${identifier}`,
        deployment: source,
      });
      expect(Object.hasOwn(renamed, identifier)).toBe(false);
      expect(Object.hasOwn(renamed, `renamed-${identifier}`)).toBe(true);

      const renamedToSpecial = applyDeploymentChange(
        ownRecord([["ordinary", source]]),
        {
          kind: "upsert",
          originalDeploymentId: "ordinary",
          deploymentId: identifier,
          deployment: source,
        },
      );
      expect(Object.hasOwn(renamedToSpecial, "ordinary")).toBe(false);
      expect(Object.hasOwn(renamedToSpecial, identifier)).toBe(true);
    },
  );

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

  it("allows only locally advanceable optimistic revisions", () => {
    const initial = deploymentDocument("admin_managed", false);
    expect(
      buildDeploymentMutation({
        document: initial,
        clusterAuthority: null,
        catalogRevision: "catalog-v2",
        deployments: {},
      }).kind,
    ).toBe("local_put");

    initial.revision = Number.MAX_SAFE_INTEGER - 1;
    expect(
      buildDeploymentMutation({
        document: initial,
        clusterAuthority: null,
        catalogRevision: "catalog-v2",
        deployments: {},
      }).kind,
    ).toBe("local_put");

    initial.revision = Number.MAX_SAFE_INTEGER;
    expect(
      buildDeploymentMutation({
        document: initial,
        clusterAuthority: null,
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

  it.each(PROTOTYPE_IDENTIFIERS)(
    "compares prototype-shaped deployment ID %s using own properties only",
    (identifier) => {
      const attempted = ownRecord([
        [identifier, deploymentDefaults("operator-choice", "q4_k_m")],
      ]);
      const conflict = createDeploymentConflictState({
        expectedRevision: 1,
        currentRevision: 2,
        attemptedDeployments: attempted,
        currentDeployments: ownRecord([]),
      });

      expect(conflict.comparison).toEqual({
        added: [identifier],
        changed: [],
        removed: [],
        preserved: [],
      });
      expect(Object.getPrototypeOf(conflict.attemptedDeployments)).toBeNull();
      expect(Object.hasOwn(conflict.attemptedDeployments, identifier)).toBe(true);
    },
  );

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

  it.each(PROTOTYPE_IDENTIFIERS)(
    "keeps runtime-only deployment ID %s out of the inherited desired map",
    (identifier) => {
      const runtime = {
        deployment: identifier,
        generation: 1,
        state: "stopped" as const,
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

      expect(deploymentRows({}, [runtime])).toEqual([
        { deploymentId: identifier, desired: null, runtime },
      ]);
    },
  );
});
