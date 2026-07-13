import { describe, expect, it } from "vitest";

import type {
  CatalogEntry,
  CatalogResponse,
  ClusterDeploymentAuthority,
  DeploymentDocument,
} from "../api";
import {
  authorityLabel,
  deployableCatalogEntries,
  deploymentDefaults,
  deploymentMutationMode,
  nextClusterRevision,
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
});
