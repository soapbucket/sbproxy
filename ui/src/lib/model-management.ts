import type {
  CatalogEntry,
  CatalogResponse,
  CatalogVariant,
  ClusterDeploymentBundleDraft,
  ClusterDeploymentAuthority,
  DeploymentDocument,
  ModelDeployment,
  DeploymentReplacementRequest,
  DeploymentRuntimeStatus,
  DeploymentRuntimeState,
  ModelHostAuthority,
  ReconcilePlan,
} from "../api";

export type DeploymentMutationMode =
  | "local_put"
  | "signed_cluster_post"
  | "read_only";

export interface DeploymentFormDraft {
  deploymentId: string;
  model: string;
  variant: string;
  heterogeneousVariants: boolean;
  replicas: string;
  requiredLabels: string;
  spreadBy: string;
  pull: ModelDeployment["pull"];
  warm: boolean;
  keepAliveSecs: string;
  maxConcurrency: string;
  maxQueueDepth: string;
  queueTimeoutMs: string;
  engine: ModelDeployment["engine"];
  rollout: ModelDeployment["rollout"];
  licenseAcknowledged: boolean;
}

export type DeploymentFormField = keyof DeploymentFormDraft;

export interface DeploymentFormValue {
  deploymentId: string;
  deployment: ModelDeployment;
}

export interface DeploymentFormParseResult {
  value: DeploymentFormValue | null;
  errors: Partial<Record<DeploymentFormField, string>>;
}

export interface DeploymentFormParseOptions {
  requireLicenseAcknowledgement: boolean;
  existingDeploymentIds: readonly string[];
  originalDeploymentId?: string | null;
}

export type DeploymentChange =
  | {
      kind: "upsert";
      originalDeploymentId?: string | null;
      deploymentId: string;
      deployment: ModelDeployment;
    }
  | { kind: "remove"; deploymentId: string };

export type DeploymentMutationCommand =
  | { kind: "local_put"; request: DeploymentReplacementRequest }
  | { kind: "signed_cluster_post"; draft: ClusterDeploymentBundleDraft }
  | { kind: "read_only" }
  | { kind: "unsafe_revision" };

export interface DeploymentConflictState {
  expectedRevision: number | null;
  currentRevision: number | null;
  attemptedDeployments: Record<string, ModelDeployment>;
  currentDeployments: Record<string, ModelDeployment>;
  comparison: ReconcilePlan;
}

export interface ModelDeploymentRow {
  deploymentId: string;
  desired: ModelDeployment | null;
  runtime: DeploymentRuntimeStatus | null;
}

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
  return deployableCatalogVariants(entry).length > 0;
}

export function deployableCatalogVariants(
  entry: CatalogEntry,
): CatalogVariant[] {
  return entry.variants.filter(
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

function deploymentToFormDraft(
  deploymentId: string,
  deployment: ModelDeployment,
): DeploymentFormDraft {
  return {
    deploymentId,
    model: deployment.model,
    variant: deployment.variant ?? "",
    heterogeneousVariants: deployment.heterogeneous_variants,
    replicas: String(deployment.replicas),
    requiredLabels: Object.entries(deployment.required_labels)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n"),
    spreadBy: deployment.spread_by.join("\n"),
    pull: deployment.pull,
    warm: deployment.warm,
    keepAliveSecs:
      deployment.keep_alive_secs === null
        ? ""
        : String(deployment.keep_alive_secs),
    maxConcurrency:
      deployment.max_concurrency === null
        ? ""
        : String(deployment.max_concurrency),
    maxQueueDepth: String(deployment.max_queue_depth),
    queueTimeoutMs: String(deployment.queue_timeout_ms),
    engine: deployment.engine,
    rollout: deployment.rollout,
    licenseAcknowledged: false,
  };
}

export function deploymentFormDefaults(
  deploymentId: string,
  model: string,
  variant: string | null = null,
): DeploymentFormDraft {
  return deploymentToFormDraft(
    deploymentId,
    deploymentDefaults(model, variant),
  );
}

export function deploymentFormFromDeployment(
  deploymentId: string,
  deployment: ModelDeployment,
): DeploymentFormDraft {
  return deploymentToFormDraft(deploymentId, deployment);
}

const DEPLOYMENT_ID_PATTERN = /^[A-Za-z0-9._-]+$/;
const LABEL_KEY_PATTERN = /^[A-Za-z0-9._/-]+$/;

function parseBoundedInteger(
  raw: string,
  field: DeploymentFormField,
  errors: Partial<Record<DeploymentFormField, string>>,
  bounds: { minimum: number; maximum: number; optional?: boolean },
): number | null {
  const value = raw.trim();
  if (!value && bounds.optional) return null;
  if (!/^\d+$/.test(value)) {
    errors[field] = "Enter a whole number.";
    return null;
  }
  const parsed = Number(value);
  if (
    !Number.isSafeInteger(parsed) ||
    parsed < bounds.minimum ||
    parsed > bounds.maximum
  ) {
    errors[field] = `Enter a value from ${bounds.minimum} to ${bounds.maximum}.`;
    return null;
  }
  return parsed;
}

function parseRequiredLabels(
  raw: string,
  errors: Partial<Record<DeploymentFormField, string>>,
): Record<string, string> {
  const labels: Record<string, string> = {};
  const lines = raw
    .split(/\r?\n|,/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length > 64) {
    errors.requiredLabels = "Use at most 64 required labels.";
    return labels;
  }
  for (const line of lines) {
    const separator = line.indexOf("=");
    const key = separator >= 0 ? line.slice(0, separator).trim() : "";
    const value = separator >= 0 ? line.slice(separator + 1).trim() : "";
    if (
      !key ||
      key.length > 128 ||
      !LABEL_KEY_PATTERN.test(key) ||
      !value ||
      value.length > 256
    ) {
      errors.requiredLabels =
        "Enter one label per line as key=value using bounded label keys and values.";
      return labels;
    }
    if (Object.hasOwn(labels, key)) {
      errors.requiredLabels = `Required label ${key} is duplicated.`;
      return labels;
    }
    labels[key] = value;
  }
  return labels;
}

function parseSpreadKeys(
  raw: string,
  errors: Partial<Record<DeploymentFormField, string>>,
): string[] {
  const keys = raw
    .split(/\r?\n|,/)
    .map((key) => key.trim())
    .filter(Boolean);
  if (keys.length > 8) {
    errors.spreadBy = "Use at most 8 spread keys.";
    return keys;
  }
  if (
    keys.some(
      (key) =>
        key.length > 128 ||
        !LABEL_KEY_PATTERN.test(key) ||
        keys.indexOf(key) !== keys.lastIndexOf(key),
    )
  ) {
    errors.spreadBy =
      "Spread keys must be unique label keys using letters, numbers, dot, dash, underscore, or slash.";
  }
  return keys;
}

export function parseDeploymentForm(
  draft: DeploymentFormDraft,
  options: DeploymentFormParseOptions,
): DeploymentFormParseResult {
  const errors: Partial<Record<DeploymentFormField, string>> = {};
  const deploymentId = draft.deploymentId.trim();
  const model = draft.model.trim();
  const variant = draft.variant.trim() || null;

  if (
    !deploymentId ||
    deploymentId.length > 128 ||
    !DEPLOYMENT_ID_PATTERN.test(deploymentId)
  ) {
    errors.deploymentId =
      "Use up to 128 letters, numbers, dots, dashes, or underscores.";
  } else if (
    deploymentId !== options.originalDeploymentId &&
    options.existingDeploymentIds.includes(deploymentId)
  ) {
    errors.deploymentId = "A deployment with this ID already exists.";
  }
  if (!model) errors.model = "Choose a catalog model.";

  const replicas = parseBoundedInteger(draft.replicas, "replicas", errors, {
    minimum: 1,
    maximum: 1024,
  });
  const keepAliveSecs = parseBoundedInteger(
    draft.keepAliveSecs,
    "keepAliveSecs",
    errors,
    { minimum: 0, maximum: 31_536_000, optional: true },
  );
  const maxConcurrency = parseBoundedInteger(
    draft.maxConcurrency,
    "maxConcurrency",
    errors,
    { minimum: 1, maximum: 1_000_000, optional: true },
  );
  const maxQueueDepth = parseBoundedInteger(
    draft.maxQueueDepth,
    "maxQueueDepth",
    errors,
    { minimum: 0, maximum: 1_000_000 },
  );
  const queueTimeoutMs = parseBoundedInteger(
    draft.queueTimeoutMs,
    "queueTimeoutMs",
    errors,
    { minimum: 1, maximum: 86_400_000 },
  );

  if (
    replicas !== null &&
    replicas > 1 &&
    variant === null &&
    !draft.heterogeneousVariants
  ) {
    errors.variant =
      "Pin an exact variant or allow heterogeneous variants for multiple replicas.";
  }
  if (
    options.requireLicenseAcknowledgement &&
    !draft.licenseAcknowledged
  ) {
    errors.licenseAcknowledged =
      "Acknowledge the selected model license before saving.";
  }

  const requiredLabels = parseRequiredLabels(draft.requiredLabels, errors);
  const spreadBy = parseSpreadKeys(draft.spreadBy, errors);
  if (Object.keys(errors).length > 0) return { value: null, errors };

  return {
    errors,
    value: {
      deploymentId,
      deployment: {
        model,
        variant,
        heterogeneous_variants: draft.heterogeneousVariants,
        replicas: replicas as number,
        required_labels: requiredLabels,
        spread_by: spreadBy,
        pull: draft.pull,
        warm: draft.warm,
        keep_alive_secs: keepAliveSecs,
        max_concurrency: maxConcurrency,
        max_queue_depth: maxQueueDepth as number,
        queue_timeout_ms: queueTimeoutMs as number,
        engine: draft.engine,
        rollout: draft.rollout,
      },
    },
  };
}

export function deploymentRemovalGuard(
  state: DeploymentRuntimeState | null,
): { allowed: boolean; reason: string | null } {
  if (state === "ready" || state === "preparing" || state === "draining") {
    return {
      allowed: false,
      reason: "Stop this deployment before removing it from desired state.",
    };
  }
  return { allowed: true, reason: null };
}

function cloneDeployment(deployment: ModelDeployment): ModelDeployment {
  return {
    ...deployment,
    required_labels: { ...deployment.required_labels },
    spread_by: [...deployment.spread_by],
  };
}

function cloneDeploymentMap(
  deployments: Readonly<Record<string, ModelDeployment>>,
): Record<string, ModelDeployment> {
  return Object.fromEntries(
    Object.entries(deployments).map(([id, deployment]) => [
      id,
      cloneDeployment(deployment),
    ]),
  );
}

export function applyDeploymentChange(
  current: Readonly<Record<string, ModelDeployment>>,
  change: DeploymentChange,
): Record<string, ModelDeployment> {
  const next = cloneDeploymentMap(current);
  if (change.kind === "remove") {
    delete next[change.deploymentId];
    return next;
  }
  if (
    change.originalDeploymentId &&
    change.originalDeploymentId !== change.deploymentId
  ) {
    delete next[change.originalDeploymentId];
  }
  next[change.deploymentId] = cloneDeployment(change.deployment);
  return next;
}

export function buildDeploymentMutation(input: {
  document: DeploymentDocument;
  clusterAuthority: ClusterDeploymentAuthority | null;
  catalogRevision: string;
  deployments: Readonly<Record<string, ModelDeployment>>;
}): DeploymentMutationCommand {
  const mode = deploymentMutationMode(input.document, input.clusterAuthority);
  const deployments = cloneDeploymentMap(input.deployments);
  if (mode === "local_put") {
    return {
      kind: "local_put",
      request: {
        expected_revision: input.document.revision,
        deployments,
      },
    };
  }
  if (mode === "signed_cluster_post") {
    const revision = nextClusterRevision(
      input.clusterAuthority?.active_revision ?? null,
    );
    if (revision === null) return { kind: "unsafe_revision" };
    return {
      kind: "signed_cluster_post",
      draft: {
        catalog_revision: input.catalogRevision,
        revision,
        deployments,
      },
    };
  }
  return { kind: "read_only" };
}

function canonicalDeployment(deployment: ModelDeployment): ModelDeployment {
  return {
    ...cloneDeployment(deployment),
    required_labels: Object.fromEntries(
      Object.entries(deployment.required_labels).sort(([left], [right]) =>
        left.localeCompare(right),
      ),
    ),
  };
}

function deploymentsEqual(
  left: ModelDeployment,
  right: ModelDeployment,
): boolean {
  return (
    JSON.stringify(canonicalDeployment(left)) ===
    JSON.stringify(canonicalDeployment(right))
  );
}

export function createDeploymentConflictState(input: {
  expectedRevision: number | null;
  currentRevision: number | null;
  attemptedDeployments: Readonly<Record<string, ModelDeployment>>;
  currentDeployments: Readonly<Record<string, ModelDeployment>>;
}): DeploymentConflictState {
  const attemptedIds = Object.keys(input.attemptedDeployments).sort();
  const currentIds = Object.keys(input.currentDeployments).sort();
  const comparison: ReconcilePlan = {
    added: attemptedIds.filter((id) => !(id in input.currentDeployments)),
    changed: attemptedIds.filter(
      (id) =>
        id in input.currentDeployments &&
        !deploymentsEqual(
          input.attemptedDeployments[id],
          input.currentDeployments[id],
        ),
    ),
    removed: currentIds.filter((id) => !(id in input.attemptedDeployments)),
    preserved: attemptedIds.filter(
      (id) =>
        id in input.currentDeployments &&
        deploymentsEqual(
          input.attemptedDeployments[id],
          input.currentDeployments[id],
        ),
    ),
  };
  return {
    expectedRevision: input.expectedRevision,
    currentRevision: input.currentRevision,
    attemptedDeployments: cloneDeploymentMap(input.attemptedDeployments),
    currentDeployments: cloneDeploymentMap(input.currentDeployments),
    comparison,
  };
}

export function deploymentRows(
  desiredDeployments: Readonly<Record<string, ModelDeployment>> | null,
  runtimeDeployments: readonly DeploymentRuntimeStatus[],
): ModelDeploymentRow[] {
  const runtimeById = new Map(
    runtimeDeployments.map((runtime) => [runtime.deployment, runtime]),
  );
  const ids = new Set<string>([
    ...Object.keys(desiredDeployments ?? {}),
    ...runtimeById.keys(),
  ]);
  return [...ids]
    .sort((left, right) => left.localeCompare(right))
    .map((deploymentId) => ({
      deploymentId,
      desired: desiredDeployments?.[deploymentId] ?? null,
      runtime: runtimeById.get(deploymentId) ?? null,
    }));
}
