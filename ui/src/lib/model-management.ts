import type {
  CatalogEntry,
  CatalogResponse,
  ClusterDeploymentAuthority,
  DeploymentDocument,
  ModelDeployment,
  ModelHostAuthority,
} from "../api";

export type DeploymentMutationMode =
  | "local_put"
  | "signed_cluster_post"
  | "read_only";

const AUTHORITY_LABELS: Record<ModelHostAuthority, string> = {
  file_managed: "File managed",
  admin_managed: "Admin managed",
  cluster_authority: "Cluster authority",
};

export function authorityLabel(authority: ModelHostAuthority): string {
  return AUTHORITY_LABELS[authority];
}

export function deploymentMutationMode(
  document: DeploymentDocument,
  clusterAuthority: ClusterDeploymentAuthority | null,
): DeploymentMutationMode {
  if (document.authority === "admin_managed" && !document.read_only) {
    return "local_put";
  }
  if (
    document.authority === "cluster_authority" &&
    clusterAuthority?.configured === true &&
    !clusterAuthority.read_only
  ) {
    return "signed_cluster_post";
  }
  return "read_only";
}

export function nextClusterRevision(activeRevision: number | null): number | null {
  if (activeRevision === null) return 1;
  if (
    !Number.isSafeInteger(activeRevision) ||
    activeRevision < 0 ||
    activeRevision >= Number.MAX_SAFE_INTEGER
  ) {
    return null;
  }
  return activeRevision + 1;
}

export function isDeployableCatalogEntry(entry: CatalogEntry): boolean {
  return entry.variants.some(
    (variant) => variant.engines.length > 0 && variant.accelerators.length > 0,
  );
}

export function deployableCatalogEntries(
  catalog: CatalogResponse,
): Array<{ id: string; entry: CatalogEntry }> {
  return Object.entries(catalog.models)
    .filter(([, entry]) => isDeployableCatalogEntry(entry))
    .map(([id, entry]) => ({ id, entry }))
    .sort((left, right) => {
      if (left.id === right.id) return 0;
      return left.id < right.id ? -1 : 1;
    });
}

export function deploymentDefaults(
  model: string,
  variant: string | null = null,
): ModelDeployment {
  return {
    model,
    variant,
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
  };
}
