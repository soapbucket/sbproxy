import { computed, onMounted, ref, watch } from "vue";
import {
  api,
  ApiError,
  type ClusterDeploymentAuthority,
  type ClusterDeploymentDocument,
  type DeploymentRuntimeStatus,
  type ModelDeployment,
  type ModelHostAuthority,
} from "../api";
import { useAsync } from "./useAsync";
import {
  applyDeploymentChange,
  buildDeploymentMutation,
  createPendingDeploymentConflictState,
  deployableCatalogEntries,
  deployableCatalogVariants,
  deploymentMutationMode,
  deploymentMapFingerprint,
  deploymentRemovalGuard,
  deploymentRows,
  failDeploymentConflictReload,
  nextSafeRevision,
  reconcileDeploymentConflictState,
  type DeploymentChange,
  type DeploymentConflictState,
  type DeploymentConflictProof,
  type DeploymentFormValue,
  type ModelDeploymentRow,
  type WritableDeploymentMutationMode,
} from "../lib/model-management";
import { findFamily, histogramAvgByLabel, parsePrometheus } from "../lib/metrics";

export interface ModelDeploymentEditorState {
  originalDeploymentId: string | null;
  initialDeployment: ModelDeployment | null;
  openingMode: WritableDeploymentMutationMode;
  baselineDeploymentId: string | null;
  baselineDeploymentFingerprint: string | null;
}

function apiErrorHasCode(error: ApiError | null, code: string): boolean {
  if (!error?.body) return false;
  try {
    const body: unknown = JSON.parse(error.body);
    return (
      typeof body === "object" &&
      body !== null &&
      Object.hasOwn(body, "code") &&
      (body as { code?: unknown }).code === code
    );
  } catch {
    return false;
  }
}

export function useModelManagement() {
  const statusReq = useAsync(() => api.modelHostStatus());
  const catalogReq = useAsync(() => api.modelHostCatalog());
  const deploymentsReq = useAsync(() => api.modelHostDeployments());
  const clusterStatusReq = useAsync(() => api.clusterStatus());
  const clusterBundleReq = useAsync(() => api.clusterDeployments());
  const metricsReq = useAsync(() => api.metrics());

  const banner = ref<{ tone: "ok" | "warn" | "err"; text: string } | null>(null);
  const lifecycleBusy = ref("");
  const mutationBusy = ref(false);
  const mutationError = ref<string | null>(null);
  const conflict = ref<DeploymentConflictState | null>(null);
  const pendingConflictChange = ref<DeploymentChange | null>(null);
  const pendingConflictMode = ref<"local_put" | "signed_cluster_post" | null>(
    null,
  );
  const editor = ref<ModelDeploymentEditorState | null>(null);

  async function refresh(): Promise<void> {
    await Promise.all([
      statusReq.run(),
      catalogReq.run(),
      deploymentsReq.run(),
      clusterStatusReq.run(),
      clusterBundleReq.run(),
      metricsReq.run(),
    ]);
  }

  onMounted(() => {
    void refresh();
  });

  const status = computed(() => statusReq.data.value);
  const catalog = computed(() => catalogReq.data.value);
  const deploymentDocument = computed(() => deploymentsReq.data.value);
  const clusterBundle = computed(() => clusterBundleReq.data.value);
  const clusterAuthority = computed<ClusterDeploymentAuthority | null>(
    () => clusterStatusReq.data.value?.deployment_authority ?? null,
  );
  const runtimeDeployments = computed<DeploymentRuntimeStatus[]>(
    () => status.value?.deployments ?? [],
  );
  const runtimeStatusCurrent = computed(
    () =>
      statusReq.succeeded.value &&
      statusReq.error.value === null &&
      Array.isArray(status.value?.deployments),
  );
  const readyDeployments = computed(
    () => runtimeDeployments.value.filter((runtime) => runtime.state === "ready").length,
  );
  const reservedMemory = computed(() =>
    runtimeDeployments.value.reduce(
      (total, runtime) => total + (runtime.memory?.total_bytes ?? 0),
      0,
    ),
  );
  const blockers = computed(() =>
    status.value?.local_serving?.ready === false
      ? status.value.local_serving.blockers ?? []
      : [],
  );

  const catalogModels = computed(() =>
    catalog.value ? deployableCatalogEntries(catalog.value) : [],
  );
  const previewOnlyCatalog = computed(
    () =>
      catalogModels.value.length > 0 &&
      catalogModels.value.every(({ entry }) =>
        deployableCatalogVariants(entry).every(
          (variant) => variant.stability === "preview",
        ),
      ),
  );

  const throughputByModel = computed<Record<string, number>>(() => {
    const text = metricsReq.data.value;
    const throughput = Object.create(null) as Record<string, number>;
    if (!text) return throughput;
    const values = histogramAvgByLabel(
      findFamily(
        parsePrometheus(text),
        "sbproxy_ai_output_throughput_tokens_per_second",
      ),
      "model",
    );
    for (const value of values) throughput[value.key] = value.value;
    return throughput;
  });

  const mutationMode = computed(() =>
    deploymentDocument.value
      ? deploymentMutationMode(deploymentDocument.value, clusterAuthority.value)
      : "read_only",
  );
  const catalogProofCurrent = computed(
    () => catalogReq.succeeded.value && catalogReq.error.value === null,
  );
  const managementProofCurrent = computed(
    () => deploymentsReq.succeeded.value && deploymentsReq.error.value === null,
  );
  const clusterAuthorityProofCurrent = computed(
    () => clusterStatusReq.succeeded.value && clusterStatusReq.error.value === null,
  );
  const initialClusterBundleAbsent = computed(
    () =>
      clusterBundleReq.error.value?.status === 404 &&
      apiErrorHasCode(
        clusterBundleReq.error.value,
        "deployment_bundle_missing",
      ) &&
      !clusterBundleReq.loading.value &&
      clusterAuthorityProofCurrent.value &&
      clusterAuthority.value?.active_revision === null,
  );
  const clusterBundleProofCurrent = computed(
    () =>
      clusterBundleReq.succeeded.value || initialClusterBundleAbsent.value,
  );
  const coherentClusterBundle = computed<ClusterDeploymentDocument | null>(() => {
    const authority = clusterAuthority.value;
    const activeBundle = clusterBundle.value;
    const activeCatalog = catalog.value;
    if (
      !clusterAuthorityProofCurrent.value ||
      !clusterBundleReq.succeeded.value ||
      clusterBundleReq.error.value !== null ||
      !catalogProofCurrent.value ||
      !authority ||
      !activeBundle ||
      !activeCatalog ||
      !authority.configured
    ) {
      return null;
    }
    if (
      authority.active_revision !== activeBundle.bundle.revision ||
      authority.active_content_digest !== activeBundle.bundle.content_digest ||
      authority.signer_node_id !== activeBundle.signer_node_id ||
      authority.verifying_key_id !== activeBundle.signer_key_id ||
      activeBundle.bundle.catalog_revision !== activeCatalog.catalog_revision
    ) {
      return null;
    }
    return activeBundle;
  });
  const canonicalDesiredDeployments = computed<
    Readonly<Record<string, ModelDeployment>> | null
  >(() => {
    const document = deploymentDocument.value;
    if (!document) return null;
    if (document.authority !== "cluster_authority") {
      return document.deployments;
    }
    if (initialClusterBundleAbsent.value) {
      return Object.create(null) as Record<string, ModelDeployment>;
    }
    return coherentClusterBundle.value?.bundle.deployments ?? null;
  });
  const effectiveDesiredRevision = computed<number | null | undefined>(() => {
    const document = deploymentDocument.value;
    if (!document) return undefined;
    if (document.authority !== "cluster_authority") return document.revision;
    if (initialClusterBundleAbsent.value) return null;
    return coherentClusterBundle.value?.bundle.revision;
  });
  const effectiveDesiredContentDigest = computed<
    string | null | undefined
  >(() => {
    const document = deploymentDocument.value;
    if (!document) return undefined;
    if (document.authority !== "cluster_authority") {
      return document.content_digest;
    }
    if (initialClusterBundleAbsent.value) return null;
    return coherentClusterBundle.value?.bundle.content_digest;
  });
  const rows = computed(() =>
    deploymentRows(
      canonicalDesiredDeployments.value,
      runtimeDeployments.value,
    ),
  );
  const hasSafePersistentRevision = computed(
    () => {
      if (mutationMode.value === "signed_cluster_post") {
        return (
          nextSafeRevision(clusterAuthority.value?.active_revision ?? null) !==
          null
        );
      }
      if (mutationMode.value === "local_put") {
        return nextSafeRevision(deploymentDocument.value?.revision ?? null) !== null;
      }
      return true;
    },
  );
  const clusterBundleAllowsPublication = computed(() => {
    if (deploymentDocument.value?.authority !== "cluster_authority") return true;
    if (!clusterBundleProofCurrent.value) return false;
    const authority = clusterAuthority.value;
    if (!authority || !authority.configured || authority.read_only) return false;
    if (initialClusterBundleAbsent.value) return true;
    const activeBundle = coherentClusterBundle.value;
    return activeBundle !== null && !activeBundle.read_only;
  });
  const canMutate = computed(
    () =>
      Boolean(deploymentDocument.value) &&
      Boolean(catalog.value) &&
      managementProofCurrent.value &&
      catalogProofCurrent.value &&
      catalogModels.value.length > 0 &&
      mutationMode.value !== "read_only" &&
      hasSafePersistentRevision.value &&
      (deploymentDocument.value?.authority !== "cluster_authority" ||
        (clusterAuthorityProofCurrent.value &&
          clusterBundleAllowsPublication.value)),
  );

  function canonicalDesiredDeployment(
    deploymentId: string,
  ): ModelDeployment | null {
    const deployments = canonicalDesiredDeployments.value;
    return deployments && Object.hasOwn(deployments, deploymentId)
      ? deployments[deploymentId]
      : null;
  }

  function deploymentBaselineFingerprint(
    deploymentId: string,
    deployment: ModelDeployment,
  ): string {
    const singleton = Object.create(null) as Record<string, ModelDeployment>;
    singleton[deploymentId] = deployment;
    return deploymentMapFingerprint(singleton);
  }

  function upsertSessionError(
    activeEditor: ModelDeploymentEditorState,
    change: Extract<DeploymentChange, { kind: "upsert" }>,
  ): string | null {
    if (mutationMode.value !== activeEditor.openingMode) {
      return "Desired-state authority changed after this editor opened. Your draft is preserved. Reopen the editor under the current authority before saving.";
    }
    const desired = canonicalDesiredDeployments.value;
    if (!desired) {
      return "Reload the current desired deployment map before saving.";
    }
    if (activeEditor.baselineDeploymentId !== null) {
      const currentDeployment = canonicalDesiredDeployment(
        activeEditor.baselineDeploymentId,
      );
      if (
        !currentDeployment ||
        activeEditor.baselineDeploymentFingerprint === null ||
        deploymentBaselineFingerprint(
          activeEditor.baselineDeploymentId,
          currentDeployment,
        ) !== activeEditor.baselineDeploymentFingerprint
      ) {
        return "The deployment changed or disappeared after this editor opened. Your draft is preserved. Reopen the editor from the current desired state before saving.";
      }
    }
    if (
      change.deploymentId !== activeEditor.originalDeploymentId &&
      Object.hasOwn(desired, change.deploymentId)
    ) {
      return "A deployment with this ID already exists in the current desired state. Your draft is preserved. Reopen the editor or choose another deployment ID before saving.";
    }
    return null;
  }

  const currentMutationProof = computed<DeploymentConflictProof | null>(() => {
    const document = deploymentDocument.value;
    const activeCatalog = catalog.value;
    const baseDeployments = canonicalDesiredDeployments.value;
    const mode = mutationMode.value;
    if (
      !canMutate.value ||
      !document ||
      !activeCatalog ||
      !baseDeployments ||
      mode === "read_only"
    ) {
      return null;
    }
    const signedBundle = coherentClusterBundle.value;
    return {
      mode,
      authority: document.authority,
      revision:
        mode === "signed_cluster_post"
          ? clusterAuthority.value?.active_revision ?? null
          : document.revision,
      contentDigest:
        mode === "signed_cluster_post"
          ? signedBundle?.bundle.content_digest ??
            clusterAuthority.value?.active_content_digest ??
            null
          : document.content_digest,
      deploymentsFingerprint: deploymentMapFingerprint(baseDeployments),
      catalogRevision: activeCatalog.catalog_revision,
      signerNodeId:
        mode === "signed_cluster_post"
          ? signedBundle?.signer_node_id ??
            clusterAuthority.value?.signer_node_id ??
            null
          : null,
      signerKeyId:
        mode === "signed_cluster_post"
          ? signedBundle?.signer_key_id ??
            clusterAuthority.value?.verifying_key_id ??
            null
          : null,
    };
  });

  function conflictProofsEqual(
    left: DeploymentConflictProof,
    right: DeploymentConflictProof,
  ): boolean {
    return (
      left.mode === right.mode &&
      left.authority === right.authority &&
      left.revision === right.revision &&
      left.contentDigest === right.contentDigest &&
      left.deploymentsFingerprint === right.deploymentsFingerprint &&
      left.catalogRevision === right.catalogRevision &&
      left.signerNodeId === right.signerNodeId &&
      left.signerKeyId === right.signerKeyId
    );
  }

  const conflictRetryAllowed = computed(
    () => {
      const activeConflict = conflict.value;
      const currentProof = currentMutationProof.value;
      return Boolean(
        activeConflict?.comparison &&
          activeConflict.proof &&
          currentProof &&
          conflictProofsEqual(activeConflict.proof, currentProof) &&
          !mutationBusy.value,
      );
    },
  );

  const conflictProofInputsSettled = computed(() => {
    const proof = conflict.value?.proof;
    if (!proof || catalogReq.loading.value || deploymentsReq.loading.value) {
      return false;
    }
    return (
      proof.mode !== "signed_cluster_post" ||
      (!clusterStatusReq.loading.value && !clusterBundleReq.loading.value)
    );
  });

  watch(
    [currentMutationProof, conflictProofInputsSettled],
    ([currentProof, settled]) => {
      const activeConflict = conflict.value;
      if (
        !settled ||
        !activeConflict?.comparison ||
        !activeConflict.proof ||
        (currentProof &&
          conflictProofsEqual(activeConflict.proof, currentProof))
      ) {
        return;
      }
      const reloadError =
        "Current authority proof changed or became unavailable. Reload current state or reopen the draft before retrying.";
      conflict.value = failDeploymentConflictReload(
        activeConflict,
        reloadError,
      );
      mutationError.value = reloadError;
    },
    { flush: "sync" },
  );

  const persistentGuidance = computed(() => {
    const document = deploymentDocument.value;
    if (!document) {
      return "Deployment ownership is unavailable. Retry desired state before making persistent changes.";
    }
    if (document.authority === "file_managed") {
      return "Persistent changes are read-only here. Edit proxy.model_host.deployments in sb.yml, then reload SBproxy.";
    }
    if (!managementProofCurrent.value) {
      return "Persistent changes are paused until the current desired deployment map is reloaded successfully.";
    }
    if (document.authority === "admin_managed" && document.read_only) {
      return "Persistent changes are read-only on this node. Use the admin-managed node that owns the deployment store.";
    }
    if (document.authority === "cluster_authority") {
      if (!clusterAuthorityProofCurrent.value || !clusterAuthority.value) {
        return "Persistent changes are read-only until this node can verify cluster deployment authority state.";
      }
      if (!clusterAuthority.value.configured) {
        return "Persistent changes are read-only because no cluster deployment authority is configured.";
      }
      if (clusterAuthority.value.read_only) {
        return "Persistent changes are read-only on this node. Open this view on the configured authority node to publish a signed deployment revision.";
      }
      if (!clusterBundleAllowsPublication.value) {
        return "Persistent changes are paused until the active signed deployment bundle can be verified on this authority node.";
      }
    }
    if (!catalogProofCurrent.value || !catalog.value) {
      return "Persistent changes are paused until the active model catalog is available.";
    }
    if (catalogModels.value.length === 0) {
      return "Persistent changes are paused because the active catalog has no complete stable or preview variants with engines and accelerators.";
    }
    if (!hasSafePersistentRevision.value) {
      return "The active deployment revision cannot be advanced safely through JSON. Use an authority workflow that preserves the full revision integer.";
    }
    return null;
  });

  const authorityDescription = computed(() => {
    const document = deploymentDocument.value;
    if (!document) return "Desired-state ownership could not be loaded.";
    if (document.authority === "file_managed") {
      return "SBproxy configuration owns the complete deployment map.";
    }
    if (document.authority === "admin_managed") {
      return document.read_only
        ? "This node reads an admin-managed deployment map but cannot change its persistent state."
        : "This node's versioned admin store owns and can replace the complete deployment map.";
    }
    if (!clusterAuthorityProofCurrent.value || !clusterAuthority.value) {
      return "Cluster deployment authority ownership has not been verified on this node.";
    }
    if (!clusterAuthority.value.configured) {
      return "No cluster deployment authority is configured, so this node cannot sign revisions.";
    }
    return clusterAuthority.value.read_only
      ? "This node verifies signed deployment revisions; the configured authority node signs them."
      : "This configured authority node signs and publishes complete deployment revisions.";
  });

  const refreshing = computed(
    () =>
      statusReq.loading.value ||
      catalogReq.loading.value ||
      deploymentsReq.loading.value ||
      clusterStatusReq.loading.value ||
      clusterBundleReq.loading.value ||
      metricsReq.loading.value,
  );

  function errorText(error: unknown): string {
    if (error instanceof ApiError) {
      if (error.body) {
        try {
          const body = JSON.parse(error.body) as { error?: unknown };
          if (typeof body.error === "string") return body.error;
        } catch {
          // Fall back to the bounded transport hint.
        }
      }
      return error.hint;
    }
    return error instanceof Error ? error.message : "The operation failed.";
  }

  function proofFailure(label: string, error: ApiError | null): string {
    return `${label}: ${error ? errorText(error) : "fresh proof is unavailable"}`;
  }

  async function reloadConflictProof(): Promise<boolean> {
    const pending = conflict.value;
    const mode = pendingConflictMode.value;
    if (!pending || !mode) return false;

    const requests = [catalogReq.run(), deploymentsReq.run()];
    if (mode === "signed_cluster_post") {
      requests.push(clusterStatusReq.run(), clusterBundleReq.run());
    }
    await Promise.all(requests);

    const failures: string[] = [];
    if (!catalogProofCurrent.value) {
      failures.push(proofFailure("Catalog reload failed", catalogReq.error.value));
    }
    if (!managementProofCurrent.value) {
      failures.push(
        proofFailure("Desired-state reload failed", deploymentsReq.error.value),
      );
    }
    if (mode === "signed_cluster_post") {
      if (!clusterAuthorityProofCurrent.value) {
        failures.push(
          proofFailure(
            "Cluster authority reload failed",
            clusterStatusReq.error.value,
          ),
        );
      }
      if (!clusterBundleProofCurrent.value) {
        failures.push(
          proofFailure(
            "Signed bundle reload failed",
            clusterBundleReq.error.value,
          ),
        );
      }
    }

    const currentDocument = deploymentDocument.value;
    if (!currentDocument) {
      failures.push("Desired-state reload failed: no current map was returned");
    }
    const expectedAuthority: ModelHostAuthority =
      mode === "local_put" ? "admin_managed" : "cluster_authority";
    if (
      currentDocument &&
      (currentDocument.authority !== expectedAuthority ||
        mutationMode.value !== mode)
    ) {
      const reloadError =
        "Deployment authority changed while the conflict was reloading. Reopen the editor or removal draft under the current authority before retrying.";
      conflict.value = failDeploymentConflictReload(pending, reloadError);
      mutationError.value = reloadError;
      return false;
    }
    const currentProof = currentMutationProof.value;
    const currentDeployments = canonicalDesiredDeployments.value;
    if (!currentProof || !currentDeployments) {
      failures.push(
        "Authority reload failed: no coherent current mutation proof was returned",
      );
    }
    if (
      failures.length > 0 ||
      !currentDocument ||
      !currentProof ||
      !currentDeployments
    ) {
      const reloadError = failures.join(" ");
      conflict.value = failDeploymentConflictReload(pending, reloadError);
      mutationError.value =
        `Revision conflict ${pending.status}. The raw response and your draft are preserved. ${reloadError}`;
      return false;
    }

    conflict.value = reconcileDeploymentConflictState(pending, {
      currentRevision: currentProof.revision,
      currentDeployments,
      proof: currentProof,
    });
    mutationError.value =
      "A revision conflict occurred. The current authority state was reloaded and your draft is preserved for comparison.";
    return true;
  }

  async function reloadAfterMutationFailure(
    mode: WritableDeploymentMutationMode,
  ): Promise<string | null> {
    const requests = [
      catalogReq.run(),
      deploymentsReq.run(),
      statusReq.run(),
    ];
    if (mode === "signed_cluster_post") {
      requests.push(clusterStatusReq.run(), clusterBundleReq.run());
    }
    await Promise.all(requests);

    const failures: string[] = [];
    if (!catalogProofCurrent.value) {
      failures.push(proofFailure("catalog", catalogReq.error.value));
    }
    if (!managementProofCurrent.value) {
      failures.push(proofFailure("desired state", deploymentsReq.error.value));
    }
    if (!runtimeStatusCurrent.value) {
      failures.push(proofFailure("runtime status", statusReq.error.value));
    }
    if (mode === "signed_cluster_post") {
      if (!clusterAuthorityProofCurrent.value) {
        failures.push(
          proofFailure("cluster authority", clusterStatusReq.error.value),
        );
      }
      if (!clusterBundleProofCurrent.value) {
        failures.push(
          proofFailure("signed bundle", clusterBundleReq.error.value),
        );
      }
    }
    return failures.length > 0 ? failures.join(" ") : null;
  }

  async function mutateDesiredState(change: DeploymentChange) {
    if (mutationBusy.value) return;
    const document = deploymentDocument.value;
    const activeCatalog = catalog.value;
    if (!document || !activeCatalog || !canMutate.value) {
      mutationError.value = persistentGuidance.value ?? "Persistent mutation is unavailable.";
      return;
    }

    const baseDeployments = canonicalDesiredDeployments.value;
    if (!baseDeployments) {
      mutationError.value =
        "Persistent mutation is paused until one coherent signed deployment snapshot is available.";
      return;
    }
    const attempted = applyDeploymentChange(baseDeployments, change);
    const command = buildDeploymentMutation({
      document,
      clusterAuthority: clusterAuthority.value,
      catalogRevision: activeCatalog.catalog_revision,
      deployments: attempted,
    });
    if (command.kind === "read_only") {
      mutationError.value = persistentGuidance.value ?? "Persistent desired state is read-only.";
      return;
    }
    if (command.kind === "unsafe_revision") {
      mutationError.value =
        "The active deployment revision cannot be advanced safely through JSON.";
      return;
    }

    const expectedRevision =
      command.kind === "local_put"
        ? command.request.expected_revision
        : command.draft.revision === 1
          ? null
          : command.draft.revision - 1;
    mutationBusy.value = true;
    mutationError.value = null;
    banner.value = null;
    try {
      if (command.kind === "local_put") {
        await api.replaceModelHostDeployments(command.request);
      } else {
        await api.publishClusterDeployments(command.draft);
      }
      conflict.value = null;
      pendingConflictChange.value = null;
      pendingConflictMode.value = null;
      editor.value = null;
      banner.value = {
        tone: "ok",
        text:
          command.kind === "local_put"
            ? "Desired deployment map saved."
            : "Signed deployment revision published.",
      };
      await Promise.all([
        deploymentsReq.run(),
        statusReq.run(),
        clusterStatusReq.run(),
        clusterBundleReq.run(),
      ]);
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        pendingConflictChange.value = change;
        pendingConflictMode.value = command.kind;
        conflict.value = createPendingDeploymentConflictState({
          status: error.status,
          body: error.body,
          expectedRevision,
          attemptedDeployments: attempted,
        });
        mutationError.value =
          `Revision conflict ${error.status}. The raw response and your draft are preserved while current authority state reloads.`;
        await reloadConflictProof();
      } else {
        const failure = errorText(error);
        const reloadFailure = await reloadAfterMutationFailure(command.kind);
        mutationError.value = reloadFailure
          ? `${failure} Your draft is preserved, but current state could not be fully reloaded: ${reloadFailure}`
          : `${failure} Current desired state and runtime status were reloaded because authority state may have advanced. Your draft is preserved.`;
      }
    } finally {
      mutationBusy.value = false;
    }
  }

  function openAddDeployment() {
    mutationError.value = null;
    conflict.value = null;
    pendingConflictChange.value = null;
    pendingConflictMode.value = null;
    const mode = mutationMode.value;
    if (!canMutate.value || !catalog.value || mode === "read_only") {
      banner.value = {
        tone: "err",
        text: persistentGuidance.value ?? "No deployable catalog entry is available.",
      };
      return;
    }
    editor.value = {
      originalDeploymentId: null,
      initialDeployment: null,
      openingMode: mode,
      baselineDeploymentId: null,
      baselineDeploymentFingerprint: null,
    };
  }

  function openEditDeployment(row: ModelDeploymentRow) {
    const desired = canonicalDesiredDeployment(row.deploymentId);
    const mode = mutationMode.value;
    if (
      !desired ||
      !canMutate.value ||
      !catalog.value ||
      mode === "read_only"
    ) {
      return;
    }
    mutationError.value = null;
    conflict.value = null;
    pendingConflictChange.value = null;
    pendingConflictMode.value = null;
    editor.value = {
      originalDeploymentId: row.deploymentId,
      initialDeployment: desired,
      openingMode: mode,
      baselineDeploymentId: row.deploymentId,
      baselineDeploymentFingerprint: deploymentBaselineFingerprint(
        row.deploymentId,
        desired,
      ),
    };
  }

  async function saveDeployment(value: DeploymentFormValue): Promise<void> {
    const activeEditor = editor.value;
    if (!activeEditor) return;
    if (conflict.value && !conflictRetryAllowed.value) {
      mutationError.value =
        "Reload current authority state successfully before saving the preserved draft.";
      return;
    }
    const change = {
      kind: "upsert" as const,
      originalDeploymentId: activeEditor.originalDeploymentId,
      deploymentId: value.deploymentId,
      deployment: value.deployment,
    };
    const sessionError = upsertSessionError(activeEditor, change);
    if (sessionError) {
      mutationError.value = sessionError;
      return;
    }
    await mutateDesiredState(change);
  }

  async function removeDeployment(row: ModelDeploymentRow): Promise<void> {
    if (!canonicalDesiredDeployment(row.deploymentId)) {
      banner.value = {
        tone: "warn",
        text: "This deployment is not present in the current desired map. Refresh before removing it.",
      };
      return;
    }
    const currentRuntime = runtimeDeployments.value.find(
      (runtime) => runtime.deployment === row.deploymentId,
    );
    const guard = deploymentRemovalGuard(
      currentRuntime?.state ?? null,
      runtimeStatusCurrent.value,
    );
    if (!guard.allowed) {
      banner.value = { tone: "warn", text: guard.reason as string };
      return;
    }
    if (!canMutate.value) {
      banner.value = {
        tone: "err",
        text: persistentGuidance.value ?? "Persistent desired state is read-only.",
      };
      return;
    }
    conflict.value = null;
    pendingConflictChange.value = null;
    pendingConflictMode.value = null;
    await mutateDesiredState({ kind: "remove", deploymentId: row.deploymentId });
  }

  async function retryConflict(): Promise<void> {
    const pendingChange = pendingConflictChange.value;
    if (!conflictRetryAllowed.value || !pendingChange) return;
    if (pendingChange.kind === "upsert") {
      const activeEditor = editor.value;
      if (!activeEditor) return;
      const sessionError = upsertSessionError(activeEditor, pendingChange);
      if (sessionError) {
        mutationError.value = sessionError;
        return;
      }
    }
    if (pendingChange.kind === "remove") {
      mutationBusy.value = true;
      banner.value = null;
      try {
        await statusReq.run();
      } finally {
        mutationBusy.value = false;
      }
      const currentRuntime = runtimeDeployments.value.find(
        (runtime) => runtime.deployment === pendingChange.deploymentId,
      );
      const guard = deploymentRemovalGuard(
        currentRuntime?.state ?? null,
        runtimeStatusCurrent.value,
      );
      if (!guard.allowed) {
        banner.value = { tone: "warn", text: guard.reason as string };
        return;
      }
      if (
        currentRuntime &&
        currentRuntime.state !== "stopped" &&
        currentRuntime.state !== "configured" &&
        currentRuntime.state !== "failed"
      ) {
        banner.value = {
          tone: "warn",
          text: "Wait for this deployment to stop before retrying removal.",
        };
        return;
      }
      if (!conflictRetryAllowed.value) return;
    }
    await mutateDesiredState(pendingChange);
  }

  async function reloadConflict(): Promise<void> {
    if (!conflict.value || !pendingConflictMode.value || mutationBusy.value) return;
    mutationBusy.value = true;
    try {
      await reloadConflictProof();
    } finally {
      mutationBusy.value = false;
    }
  }

  function dismissConflict() {
    conflict.value = null;
    pendingConflictChange.value = null;
    pendingConflictMode.value = null;
    mutationError.value = null;
  }

  async function runLifecycle(
    action: "load" | "stop" | "reset",
    deploymentId: string,
  ) {
    if (lifecycleBusy.value) return;
    lifecycleBusy.value = `${action}:${deploymentId}`;
    banner.value = null;
    try {
      if (action === "load") await api.modelHostLoad(deploymentId);
      if (action === "stop") await api.modelHostStop(deploymentId);
      if (action === "reset") await api.modelHostReset(deploymentId);
      banner.value = {
        tone: "ok",
        text:
          action === "load"
            ? `Loading ${deploymentId}.`
            : action === "stop"
              ? `Draining and stopping ${deploymentId}.`
              : `Reset ${deploymentId}.`,
      };
      await Promise.all([statusReq.run(), metricsReq.run()]);
    } catch (error) {
      banner.value = { tone: "err", text: errorText(error) };
    } finally {
      lifecycleBusy.value = "";
    }
  }

  function closeEditor() {
    if (mutationBusy.value) return;
    editor.value = null;
    conflict.value = null;
    pendingConflictChange.value = null;
    pendingConflictMode.value = null;
    mutationError.value = null;
  }

  return {
    statusReq,
    catalogReq,
    deploymentsReq,
    clusterStatusReq,
    clusterBundleReq,
    banner,
    lifecycleBusy,
    mutationBusy,
    mutationError,
    conflict,
    editor,
    status,
    catalog,
    deploymentDocument,
    clusterBundle,
    coherentClusterBundle,
    canonicalDesiredDeployments,
    effectiveDesiredRevision,
    effectiveDesiredContentDigest,
    clusterAuthority,
    runtimeDeployments,
    runtimeStatusCurrent,
    rows,
    readyDeployments,
    reservedMemory,
    blockers,
    catalogModels,
    previewOnlyCatalog,
    throughputByModel,
    initialClusterBundleAbsent,
    canMutate,
    conflictRetryAllowed,
    persistentGuidance,
    authorityDescription,
    refreshing,
    refresh,
    openAddDeployment,
    openEditDeployment,
    saveDeployment,
    removeDeployment,
    retryConflict,
    reloadConflict,
    dismissConflict,
    runLifecycle,
    closeEditor,
  };
}
