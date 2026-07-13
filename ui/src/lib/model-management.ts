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

export type WritableDeploymentMutationMode = Exclude<
  DeploymentMutationMode,
  "read_only"
>;

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

export interface CatalogEvidenceSelection {
  variants: CatalogVariant[];
  unavailableVariant: string | null;
}

export interface DeploymentFormParseOptions {
  mode?: WritableDeploymentMutationMode;
  requireLicenseAcknowledgement: boolean;
  existingDeploymentIds: readonly string[];
  originalDeploymentId?: string | null;
  catalog: CatalogResponse;
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
  status: number;
  body: string;
  expectedRevision: number | null;
  currentRevision: number | null;
  attemptedDeployments: Record<string, ModelDeployment>;
  currentDeployments: Record<string, ModelDeployment> | null;
  comparison: ReconcilePlan | null;
  proof: DeploymentConflictProof | null;
  reloadError: string | null;
}

export interface DeploymentConflictProof {
  mode: WritableDeploymentMutationMode;
  authority: ModelHostAuthority;
  revision: number | null;
  contentDigest: string | null;
  deploymentsFingerprint: string;
  catalogRevision: string;
  signerNodeId: string | null;
  signerKeyId: string | null;
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

function emptyRecord<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

function ownValue<T>(
  record: Readonly<Record<string, T>>,
  key: string,
): T | undefined {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}

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

export function nextSafeRevision(activeRevision: number | null): number | null {
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

export function nextClusterRevision(activeRevision: number | null): number | null {
  return nextSafeRevision(activeRevision);
}

export function isDeployableCatalogEntry(entry: CatalogEntry): boolean {
  return deployableCatalogVariants(entry).length > 0;
}

export function deployableCatalogVariants(
  entry: CatalogEntry,
): CatalogVariant[] {
  return entry.variants.filter(
    (variant) =>
      catalogVariantDisabledReason(variant, entry.allow_pickle === true) === null,
  );
}

export function catalogEvidenceSelection(
  entry: CatalogEntry | null,
  exactVariant: string,
): CatalogEvidenceSelection {
  if (!exactVariant) {
    return {
      variants: entry?.variants ?? [],
      unavailableVariant: null,
    };
  }

  const selected = entry?.variants.find(
    (variant) => variant.id === exactVariant,
  );
  return selected
    ? { variants: [selected], unavailableVariant: null }
    : { variants: [], unavailableVariant: exactVariant };
}

export function catalogVariantDisabledReason(
  variant: CatalogVariant,
  allowPickle = false,
): string | null {
  if (variant.stability === "config_only") {
    return "Configuration only; this variant is not runnable.";
  }
  if (variant.stability === "unsupported") {
    return "Unsupported by the model host runtime.";
  }
  if (variant.format === "pickle" && !allowPickle) {
    return "Pickle requires an explicit catalog allow_pickle opt-in.";
  }
  if (variant.engines.length === 0 && variant.accelerators.length === 0) {
    return "No executable engine or accelerator evidence is available.";
  }
  if (variant.engines.length === 0) {
    return "No executable engine evidence is available.";
  }
  if (variant.accelerators.length === 0) {
    return "No accelerator compatibility evidence is available.";
  }
  return null;
}

export function catalogVariantSupportLabel(
  variant: CatalogVariant,
  allowPickle = false,
): string {
  if (variant.stability === "config_only") return "Config only";
  if (variant.stability === "unsupported") return "Unsupported";
  if (catalogVariantDisabledReason(variant, allowPickle)) return "Incomplete";
  return variant.stability === "stable" ? "Stable" : "Preview";
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
    required_labels: emptyRecord<string>(),
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
  const labels = emptyRecord<string>();
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
  const selectedEntry = model
    ? ownValue(options.catalog.models, model)
    : undefined;
  if (!model) {
    errors.model = "Choose a catalog model.";
  } else if (!selectedEntry) {
    errors.model = "The selected model is no longer in the active catalog.";
  } else if (deployableCatalogVariants(selectedEntry).length === 0) {
    errors.model = "The selected catalog model has no runnable variants.";
  }

  if (selectedEntry && variant !== null) {
    const selectedVariant = selectedEntry.variants.find(
      (candidate) => candidate.id === variant,
    );
    if (!selectedVariant) {
      errors.variant =
        "The selected exact variant is no longer in the active catalog.";
    } else {
      const disabledReason = catalogVariantDisabledReason(
        selectedVariant,
        selectedEntry.allow_pickle === true,
      );
      if (disabledReason) errors.variant = disabledReason;
    }
  }

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
  if (options.mode === "local_put") {
    if (replicas !== null && replicas !== 1) {
      errors.replicas = "Local admin deployments must use exactly one replica.";
    }
    if (draft.heterogeneousVariants) {
      errors.heterogeneousVariants =
        "Heterogeneous variants require cluster authority placement.";
    }
    if (Object.keys(requiredLabels).length > 0) {
      errors.requiredLabels =
        "Required labels require cluster authority placement.";
    }
    if (spreadBy.length > 0) {
      errors.spreadBy = "Spread keys require cluster authority placement.";
    }
  }
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
  statusCurrent: boolean,
): { allowed: boolean; reason: string | null } {
  if (!statusCurrent) {
    return {
      allowed: false,
      reason: "Refresh runtime lifecycle status before removing this deployment.",
    };
  }
  if (state === "ready" || state === "preparing" || state === "draining") {
    return {
      allowed: false,
      reason: "Stop this deployment before removing it from desired state.",
    };
  }
  return { allowed: true, reason: null };
}

function cloneDeployment(deployment: ModelDeployment): ModelDeployment {
  const requiredLabels = emptyRecord<string>();
  for (const [key, value] of Object.entries(deployment.required_labels)) {
    requiredLabels[key] = value;
  }
  return {
    ...deployment,
    required_labels: requiredLabels,
    spread_by: [...deployment.spread_by],
  };
}

function cloneDeploymentMap(
  deployments: Readonly<Record<string, ModelDeployment>>,
): Record<string, ModelDeployment> {
  const clone = emptyRecord<ModelDeployment>();
  for (const [id, deployment] of Object.entries(deployments)) {
    clone[id] = cloneDeployment(deployment);
  }
  return clone;
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
    if (nextSafeRevision(input.document.revision) === null) {
      return { kind: "unsafe_revision" };
    }
    return {
      kind: "local_put",
      request: {
        expected_revision: input.document.revision,
        deployments,
      },
    };
  }
  if (mode === "signed_cluster_post") {
    const revision = nextSafeRevision(
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
  const requiredLabels = emptyRecord<string>();
  for (const [key, value] of Object.entries(deployment.required_labels).sort(
    ([left], [right]) => left.localeCompare(right),
  )) {
    requiredLabels[key] = value;
  }
  return {
    ...cloneDeployment(deployment),
    required_labels: requiredLabels,
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

export function deploymentMapFingerprint(
  deployments: Readonly<Record<string, ModelDeployment>>,
): string {
  return JSON.stringify(
    Object.keys(deployments)
      .sort((left, right) => left.localeCompare(right))
      .map((id) => [
        id,
        canonicalDeployment(
          ownValue(deployments, id) as ModelDeployment,
        ),
      ]),
  );
}

export function createDeploymentConflictState(input: {
  status?: number;
  body?: string;
  expectedRevision: number | null;
  currentRevision: number | null;
  attemptedDeployments: Readonly<Record<string, ModelDeployment>>;
  currentDeployments: Readonly<Record<string, ModelDeployment>>;
  proof?: DeploymentConflictProof | null;
}): DeploymentConflictState {
  const attemptedIds = Object.keys(input.attemptedDeployments).sort();
  const currentIds = Object.keys(input.currentDeployments).sort();
  const comparison: ReconcilePlan = {
    added: attemptedIds.filter(
      (id) => !Object.hasOwn(input.currentDeployments, id),
    ),
    changed: attemptedIds.filter(
      (id) => {
        const attempted = ownValue(input.attemptedDeployments, id);
        const current = ownValue(input.currentDeployments, id);
        return Boolean(
          attempted && current && !deploymentsEqual(attempted, current),
        );
      },
    ),
    removed: currentIds.filter(
      (id) => !Object.hasOwn(input.attemptedDeployments, id),
    ),
    preserved: attemptedIds.filter(
      (id) => {
        const attempted = ownValue(input.attemptedDeployments, id);
        const current = ownValue(input.currentDeployments, id);
        return Boolean(
          attempted && current && deploymentsEqual(attempted, current),
        );
      },
    ),
  };
  return {
    status: input.status ?? 409,
    body: input.body ?? "",
    expectedRevision: input.expectedRevision,
    currentRevision: input.currentRevision,
    attemptedDeployments: cloneDeploymentMap(input.attemptedDeployments),
    currentDeployments: cloneDeploymentMap(input.currentDeployments),
    comparison,
    proof: input.proof ?? null,
    reloadError: null,
  };
}

export function createPendingDeploymentConflictState(input: {
  status: number;
  body: string;
  expectedRevision: number | null;
  attemptedDeployments: Readonly<Record<string, ModelDeployment>>;
}): DeploymentConflictState {
  return {
    status: input.status,
    body: input.body,
    expectedRevision: input.expectedRevision,
    currentRevision: null,
    attemptedDeployments: cloneDeploymentMap(input.attemptedDeployments),
    currentDeployments: null,
    comparison: null,
    proof: null,
    reloadError: null,
  };
}

export function reconcileDeploymentConflictState(
  pending: DeploymentConflictState,
  input: {
    currentRevision: number | null;
    currentDeployments: Readonly<Record<string, ModelDeployment>>;
    proof: DeploymentConflictProof;
  },
): DeploymentConflictState {
  return createDeploymentConflictState({
    status: pending.status,
    body: pending.body,
    expectedRevision: pending.expectedRevision,
    currentRevision: input.currentRevision,
    attemptedDeployments: pending.attemptedDeployments,
    currentDeployments: input.currentDeployments,
    proof: input.proof,
  });
}

export function failDeploymentConflictReload(
  pending: DeploymentConflictState,
  reloadError: string,
): DeploymentConflictState {
  return {
    ...pending,
    currentRevision: null,
    currentDeployments: null,
    comparison: null,
    proof: null,
    reloadError,
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
      desired: desiredDeployments
        ? ownValue(desiredDeployments, deploymentId) ?? null
        : null,
      runtime: runtimeById.get(deploymentId) ?? null,
    }));
}
